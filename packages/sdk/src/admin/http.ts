/**
 * Internal HTTP helper used by `AgentumAdminClient` sub-surfaces.
 *
 * Carries the same retry + timeout + error-mapping semantics as
 * `AgentumClient.request()` so the admin surface behaves identically on
 * the wire. Transport is intentionally duplicated for now — a future
 * sprint should extract a shared transport and have both clients delegate
 * to it (TODO: consolidate with `client.ts::AgentumClient.request`).
 */

import {
  AgentumAuthError,
  AgentumClientConfig,
  AgentumConflictError,
  AgentumError,
  AgentumNotFoundError,
  AgentumPermissionError,
  AgentumRoleInsufficientError,
} from "../types.js";
import { redact } from "../client.js";
import {
  formatTraceparent,
  resolveTraceContext,
  type TracingProvider,
} from "../tracing.js";

const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);
const RETRYABLE_NET_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "ENOTFOUND",
  "EAI_AGAIN",
  "UND_ERR_SOCKET",
  "UND_ERR_CONNECT_TIMEOUT",
]);

function networkErrorCode(err: unknown): string | null {
  if (!err || typeof err !== "object") return null;
  const e = err as { code?: string; cause?: { code?: string } };
  if (typeof e.code === "string") return e.code;
  if (e.cause && typeof e.cause.code === "string") return e.cause.code;
  return null;
}

export interface AdminHttpOptions {
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  /** When `true`, `path` is treated as an already-absolute URL. */
  absoluteUrl?: boolean;
}

/**
 * Internal HTTP client for admin-plane calls. Not exported from the
 * package root — callers use `AgentumAdminClient` and its sub-surfaces.
 */
export class AdminHttpClient {
  private readonly baseUrl: string;
  private readonly fetch: typeof globalThis.fetch;
  private readonly defaultHeaders: Record<string, string>;
  private readonly apiKey: string | null;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryDelayMs: number;
  private readonly httpsAgent: unknown | null;
  private token: string | null;
  private tokenRefreshFn: (() => Promise<string>) | null;
  private readonly tracingProvider: TracingProvider | null;

  constructor(config: AgentumClientConfig) {
    if (!config.baseUrl || typeof config.baseUrl !== "string") {
      throw new AgentumError("Invalid baseUrl: must be a non-empty string");
    }
    if (!config.baseUrl.startsWith("http://") && !config.baseUrl.startsWith("https://")) {
      throw new AgentumError(`Invalid baseUrl "${config.baseUrl}": must start with http:// or https://`);
    }
    try {
      new URL(config.baseUrl);
    } catch {
      throw new AgentumError(`Invalid baseUrl "${config.baseUrl}": not a valid URL`);
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.fetch = config.fetch ?? globalThis.fetch;
    this.apiKey = config.apiKey ?? null;
    this.token = config.token ?? null;
    this.timeoutMs = config.timeoutMs ?? 15_000;
    this.retries = config.retries ?? 3;
    this.retryDelayMs = config.retryDelayMs ?? 250;
    this.tokenRefreshFn = config.tokenRefreshFn ?? null;
    this.defaultHeaders = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...config.defaultHeaders,
      ...(config.tenantId ? { "X-Tenant-ID": config.tenantId } : {}),
    };
    this.httpsAgent = this.buildHttpsAgent(config);
    this.tracingProvider = (config.tracingProvider ?? null) as TracingProvider | null;
  }

  private buildHttpsAgent(cfg: AgentumClientConfig): unknown | null {
    const rejectUnauthorized = cfg.tlsRejectUnauthorized;
    const caPath = cfg.tlsCaPath;
    if (rejectUnauthorized === undefined && !caPath) return null;
    if (!this.baseUrl.startsWith("https://")) return null;
    // Custom TLS is Node CommonJS only; see `client.ts::buildHttpsAgent` for
    // the full rationale. Users on ESM / Edge / browsers needing custom TLS
    // should pass a pre-configured `fetch` via config instead.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const req = (globalThis as unknown as { require?: (id: string) => any }).require;
    if (!req) return null;
    try {
      const https = req("https");
      const fs = req("fs");
      const opts: Record<string, unknown> = {
        rejectUnauthorized: rejectUnauthorized !== false,
        keepAlive: true,
      };
      if (caPath) opts.ca = fs.readFileSync(caPath);
      return new https.Agent(opts);
    } catch {
      return null;
    }
  }

  setToken(token: string): this {
    this.token = token;
    return this;
  }

  clearToken(): this {
    this.token = null;
    return this;
  }

  setTokenRefreshFn(fn: (() => Promise<string>) | null): this {
    this.tokenRefreshFn = fn;
    return this;
  }

  private buildHeaders(
    extra?: Record<string, string>,
    traceparent?: string,
  ): Record<string, string> {
    const headers: Record<string, string> = { ...this.defaultHeaders };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    if (
      traceparent &&
      !(extra && Object.prototype.hasOwnProperty.call(extra, "traceparent"))
    ) {
      headers["traceparent"] = traceparent;
    }
    if (extra) Object.assign(headers, extra);
    return headers;
  }

  private url(path: string): string {
    return `${this.baseUrl}/api/v1/${path.replace(/^\//, "")}`;
  }

  private backoffDelay(attempt: number, prevMs: number): number {
    const base = this.retryDelayMs;
    const cap = base * Math.pow(2, Math.min(attempt, 10));
    const lo = base;
    const hi = Math.min(cap, Math.max(base * 3, prevMs * 3));
    return lo + Math.random() * (hi - lo);
  }

  async request<T>(method: string, path: string, options: AdminHttpOptions = {}): Promise<T> {
    let url = options.absoluteUrl ? path : this.url(path);

    if (options.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(options.query)) {
        if (v !== undefined && v !== null) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    // Resolve W3C trace context once per request so retries share the
    // same traceparent (the same logical operation).
    const traceCtx = resolveTraceContext(this.tracingProvider);
    const traceparent = formatTraceparent(traceCtx);

    let lastError: unknown;
    let lastDelay = 0;
    let refreshedOnce = false;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        const delay = this.backoffDelay(attempt, lastDelay);
        lastDelay = delay;
        await new Promise((resolve) => setTimeout(resolve, delay));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      let response: Response;
      try {
        const fetchInit: Record<string, unknown> = {
          method,
          headers: this.buildHeaders(options.headers, traceparent),
          signal: controller.signal,
        };
        if (options.body !== undefined) fetchInit.body = JSON.stringify(options.body);
        if (this.httpsAgent) {
          fetchInit.dispatcher = this.httpsAgent;
          fetchInit.agent = this.httpsAgent;
        }
        response = await this.fetch(url, fetchInit as RequestInit);
      } catch (err) {
        clearTimeout(timer);
        if ((err as Error).name === "AbortError") {
          throw new AgentumError(`Request timed out after ${this.timeoutMs}ms: ${method} ${path}`);
        }
        const code = networkErrorCode(err);
        if (code && RETRYABLE_NET_CODES.has(code) && attempt < this.retries) {
          lastError = new AgentumError(`Network error (${code}): ${(err as Error).message}`);
          continue;
        }
        throw new AgentumError(`Network error: ${(err as Error).message}`);
      }
      clearTimeout(timer);

      let body: unknown = undefined;
      const contentType = response.headers.get("content-type") ?? "";
      if (contentType.includes("application/json") && response.status !== 204) {
        try {
          body = await response.json();
        } catch {
          body = undefined;
        }
      }

      if (!response.ok) {
        const msg =
          typeof body === "object" && body !== null && "error" in body
            ? String((body as Record<string, unknown>)["error"])
            : `HTTP ${response.status}`;

        if (
          response.status === 401 &&
          this.tokenRefreshFn !== null &&
          !refreshedOnce &&
          attempt < this.retries
        ) {
          refreshedOnce = true;
          try {
            const fresh = await this.tokenRefreshFn();
            this.token = fresh;
            attempt -= 1;
            continue;
          } catch {
            // Fall through and surface the original 401.
          }
        }

        if (RETRYABLE_STATUSES.has(response.status) && attempt < this.retries) {
          const retryAfter = response.headers.get("retry-after");
          if (retryAfter) {
            const seconds = Number(retryAfter);
            const waitMs = isNaN(seconds)
              ? Math.max(0, new Date(retryAfter).getTime() - Date.now())
              : seconds * 1000;
            if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
          }
          lastError = new AgentumError(msg, response.status, redact(body));
          continue;
        }

        const redactedBody = redact(body);
        switch (response.status) {
          case 401: throw new AgentumAuthError(msg, redactedBody);
          case 403: {
            // Server tags role-gate failures with `code: "role_insufficient"`
            // plus `required` / `actual` strings so callers can programmatically
            // distinguish missing-role from policy-denied without string matching.
            if (
              redactedBody !== null &&
              typeof redactedBody === "object" &&
              (redactedBody as { code?: unknown }).code === "role_insufficient"
            ) {
              const b = redactedBody as { required?: unknown; actual?: unknown };
              const required = typeof b.required === "string" ? b.required : "";
              const actual = typeof b.actual === "string" ? b.actual : "";
              throw new AgentumRoleInsufficientError(required, actual, redactedBody);
            }
            throw new AgentumPermissionError(msg, redactedBody);
          }
          case 404: throw new AgentumNotFoundError(path, redactedBody);
          case 409: throw new AgentumConflictError(msg, redactedBody);
          default:  throw new AgentumError(msg, response.status, redactedBody);
        }
      }

      return body as T;
    }

    throw lastError;
  }

  get<T>(path: string, query?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.request<T>("GET", path, query !== undefined ? { query } : {});
  }

  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, { body });
  }

  put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PUT", path, { body });
  }

  delete<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("DELETE", path, body !== undefined ? { body } : {});
  }
}
