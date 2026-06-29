/**
 * Agentum TypeScript SDK — Core HTTP client.
 *
 * Uses the Fetch API (Node 18+ built-in, or any polyfill) so it works in
 * browsers, Deno, edge runtimes, and Node.js without extra dependencies.
 */

import {
  AgentumClientConfig,
  AgentumConflictError,
  AgentumError,
  AgentumNotFoundError,
  AgentumPermissionError,
  AgentumAuthError,
  Agent,
  Alert,
  AuditErrorInfo,
  AuditEvent,
  AuditIngestRequest,
  ComplianceReport,
  ConnectOptions,
  CreateProposalRequest,
  CreateProposalResponse,
  CredentialLease,
  DelegationResponse,
  DelegationVerifyResponse,
  HitlDecision,
  HitlDecisionResponse,
  HitlRequest,
  HealthResponse,
  IssueDelegationRequest,
  IssueCredentialRequest,
  ListAgentsQuery,
  ListProposalsQuery,
  ListProposalsResponse,
  McpServer,
  PaginatedResponse,
  PolicyProposal,
  MitmProxyConfig,
  MitmProxyOptions,
  PolicySimulateRequest,
  PolicySimulateResponse,
  RegisterAgentRequest,
  RegisterAgentResponse,
  Session,
  ShadowAgent,
  UpdateAgentRequest,
  WithdrawProposalResponse,
} from "./types.js";
import { resolveAnonymousClientId } from "./anonymous-id.js";
import { getRuntime } from "./init.js";
import { AgentumSession } from "./session.js";
import {
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "./evaluation/cedar-client.js";
import {
  parseMaxAgeMs,
  SimulateDecisionCache,
  stableStringify,
} from "./simulate-cache.js";
import {
  formatTraceparent,
  resolveTraceContext,
  type TraceContext,
  type TracingProvider,
} from "./tracing.js";
import { freshnessHeaders } from "./audit/freshness.js";
import { runPiiPipeline, isPiiPipelineNoOp } from "./pii/pipeline.js";
import { PiiSelfCheckFailedError } from "./pii/text-scanner.js";

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

const SECRET_KEY_RE = /token|secret|password|authorization|api[-_]?key/i;

/**
 * Build the `startSession` opts bag from a `ConnectOptions`-shaped object,
 * forwarding `sourceIp` and `anonymousClientId` when present. Returns
 * `undefined` when neither field is set so the call site matches the
 * previous ternary pattern (`opts.sourceIp !== undefined ? {…} : undefined`).
 * `exactOptionalPropertyTypes` requires we omit absent fields rather than
 * assign `undefined`.
 */
function buildStartSessionOpts(opts: {
  sourceIp?: string;
  anonymousClientId?: string;
}): { sourceIp?: string; anonymousClientId?: string } | undefined {
  const out: { sourceIp?: string; anonymousClientId?: string } = {};
  if (opts.sourceIp !== undefined) out.sourceIp = opts.sourceIp;
  if (opts.anonymousClientId !== undefined) out.anonymousClientId = opts.anonymousClientId;
  return Object.keys(out).length > 0 ? out : undefined;
}

// One-shot guard so `registerAgent`'s deprecation warning fires at most once
// per process. Matches Node's `util.deprecate` behaviour and keeps long-running
// services from spamming logs.
let warnedRegisterAgentDeprecation = false;

/**
 * Return a shallow-redacted copy of `value` with any field whose key matches
 * {@link SECRET_KEY_RE} replaced by the string `"[REDACTED]"`. Used before
 * surfacing payloads to user-supplied error handlers / logs so bearer
 * tokens, API keys, and passwords never leak.
 *
 * Arrays and plain objects are walked recursively up to a small depth cap
 * to prevent cycle/large-object blow-up. Non-plain objects (Dates, Errors)
 * are returned as-is.
 */
export function redact<T>(value: T, depth = 0): T {
  if (depth > 4 || value === null || value === undefined) return value;
  if (Array.isArray(value)) {
    return value.map((v) => redact(v, depth + 1)) as unknown as T;
  }
  if (typeof value === "object" && !(value instanceof Date) && !(value instanceof Error) && !(value instanceof RegExp)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY_RE.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redact(v, depth + 1);
      }
    }
    return out as unknown as T;
  }
  return value;
}

/**
 * Default handler invoked when the audit buffer overflows or ingest
 * repeatedly fails. Emits a single-line structured `console.warn` so
 * operators can grep/ingest it from logs without parsing free text.
 *
 * Headers / error payloads are passed through {@link redact} first so
 * bearer tokens and API keys never reach application logs.
 */
function defaultAuditErrorHandler(info: AuditErrorInfo): void {
  const payload: Record<string, unknown> = {
    level: "warn",
    source: "agentum-sdk",
    component: "audit-buffer",
    reason: info.reason,
  };
  if (info.dropped !== undefined) payload.dropped = info.dropped;
  if (info.bufferedRemaining !== undefined) payload.buffered_remaining = info.bufferedRemaining;
  if (info.attempt !== undefined) payload.attempt = info.attempt;
  if (info.error !== undefined) {
    const err = info.error;
    payload.error = err instanceof Error ? err.message : String(err);
    if (err instanceof AgentumError && err.body !== undefined) {
      payload.error_body = redact(err.body);
    }
  }
  // eslint-disable-next-line no-console
  console.warn(JSON.stringify(payload));
}

/**
 * Extract a Node-style error code from a fetch rejection. Undici wraps the
 * underlying syscall error in `cause`; older runtimes expose it on the top
 * level. Returns `null` if no recognisable code is present.
 */
function networkErrorCode(err: unknown): string | null {
  if (!err || typeof err !== "object") return null;
  const e = err as { code?: string; cause?: { code?: string } };
  if (typeof e.code === "string") return e.code;
  if (e.cause && typeof e.cause.code === "string") return e.cause.code;
  return null;
}

export class AgentumClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly fetch: typeof globalThis.fetch;
  private readonly defaultHeaders: Record<string, string>;
  private readonly apiKey: string | null;
  private readonly retries: number;
  private readonly retryDelayMs: number;
  private readonly httpsAgent: unknown | null;
  private token: string | null;
  private tokenRefreshFn: (() => Promise<string>) | null;
  /** Optional caller-supplied W3C trace context provider.
   *  `null` means "probe `@opentelemetry/api`, else mint a random id". */
  private readonly tracingProvider: TracingProvider | null;
  /** Client-side decision cache for {@link simulatePolicy}. */
  private readonly simulateCache: SimulateDecisionCache<PolicySimulateResponse>;

  // ── Lazy per-agent CedarToolCallClient cache ──────────────────────────────
  // Constructed on first `evaluateToolCall(agentId, ...)` for a given agentId
  // so the LangChain enforce path can route through the rich
  // `ToolCallEvaluation` producer (the same one `init()` wires for the
  // autopatch plane). Unbounded by design — entries are cheap thin HTTP-
  // client wrappers; revisit with an LRU if cardinality is observed to bite.
  private readonly _evaluators = new Map<string, CedarToolCallClient>();

  // ── Audit buffer state ────────────────────────────────────────────────────
  private readonly auditBufferSize: number;
  private readonly auditFlushIntervalMs: number;
  private readonly auditFlushBatchSize: number;
  private readonly auditMaxBackoffMs: number;
  private readonly auditBufferEnabled: boolean;
  private readonly onAuditError: (info: AuditErrorInfo) => void;
  private auditBuffer: AuditIngestRequest[] = [];
  private auditFlushTimer: ReturnType<typeof setInterval> | null = null;
  private auditBackoffMs = 0;
  private auditBackoffDeadline = 0;
  private auditFlushing = false;
  private auditClosed = false;

  constructor(config: AgentumClientConfig | string) {
    // Accept a plain URL string for quick setup: new AgentumClient("http://...")
    const cfg: AgentumClientConfig =
      typeof config === "string" ? { baseUrl: config } : config;

    if (!cfg.baseUrl || typeof cfg.baseUrl !== "string") {
      throw new AgentumError("Invalid baseUrl: must be a non-empty string");
    }
    if (!cfg.baseUrl.startsWith("http://") && !cfg.baseUrl.startsWith("https://")) {
      throw new AgentumError(`Invalid baseUrl "${cfg.baseUrl}": must start with http:// or https://`);
    }
    // Use the URL constructor for full parse validation (catches malformed URLs
    // that pass the prefix check, e.g. "http://[invalid").
    try {
      new URL(cfg.baseUrl);
    } catch {
      throw new AgentumError(`Invalid baseUrl "${cfg.baseUrl}": not a valid URL`);
    }
    this.baseUrl = cfg.baseUrl.replace(/\/$/, "");
    this.timeoutMs = cfg.timeoutMs ?? 15_000;
    this.fetch = cfg.fetch ?? globalThis.fetch;
    this.token = cfg.token ?? null;
    this.apiKey = cfg.apiKey ?? null;
    this.retries = cfg.retries ?? 3;
    this.retryDelayMs = cfg.retryDelayMs ?? 250;
    this.tokenRefreshFn = cfg.tokenRefreshFn ?? null;
    this.defaultHeaders = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...cfg.defaultHeaders,
      ...(cfg.tenantId ? { "X-Tenant-ID": cfg.tenantId } : {}),
    };

    this.auditBufferSize = Math.max(1, cfg.auditBufferSize ?? 1000);
    this.auditFlushIntervalMs = Math.max(50, cfg.auditFlushIntervalMs ?? 2000);
    this.auditFlushBatchSize = Math.max(1, cfg.auditFlushBatchSize ?? 100);
    this.auditMaxBackoffMs = Math.max(this.auditFlushIntervalMs, cfg.auditMaxBackoffMs ?? 60_000);
    this.auditBufferEnabled = !cfg.disableAuditBuffer;
    this.onAuditError = cfg.onAuditError ?? defaultAuditErrorHandler;
    this.tracingProvider = cfg.tracingProvider ?? null;

    this.simulateCache = new SimulateDecisionCache<PolicySimulateResponse>(
      cfg.policyCache ?? {},
    );

    // TLS config — only applied for https baseUrls, and only in Node.js.
    this.httpsAgent = this.buildHttpsAgent(cfg);
  }

  /**
   * Construct a Node `https.Agent` honouring `tlsRejectUnauthorized` and
   * `tlsCaPath`. Returns `null` in non-Node runtimes, for plaintext
   * base URLs, or when no overrides were supplied (the default global
   * agent handles validation).
   */
  private buildHttpsAgent(cfg: AgentumClientConfig): unknown | null {
    const rejectUnauthorized = cfg.tlsRejectUnauthorized;
    const caPath = cfg.tlsCaPath;
    if (rejectUnauthorized === undefined && !caPath) return null;
    if (!this.baseUrl.startsWith("https://")) return null;
    // Custom TLS is Node CommonJS only. `globalThis.require` is defined in
    // CJS but undefined in browsers, Edge runtimes (Cloudflare / Vercel), and
    // ESM. In those environments, users who need `rejectUnauthorized=false`
    // or a custom CA should pass a pre-configured `fetch` with an attached
    // agent via the `fetch` config option. Dropping the `eval("require")`
    // fallback keeps the SDK compatible with bundlers that refuse to ship
    // dynamic-code-evaluation (as Next.js Edge middleware does).
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
      if (caPath) {
        opts.ca = fs.readFileSync(caPath);
      }
      return new https.Agent(opts);
    } catch {
      return null;
    }
  }

  // ── Auth ─────────────────────────────────────────────────────────────────

  /** Set the Bearer JWT used for authenticated API calls. */
  setToken(token: string): this {
    this.token = token;
    return this;
  }

  /** Remove the Bearer JWT. */
  clearToken(): this {
    this.token = null;
    return this;
  }

  /** Return the currently configured bearer token, if any. */
  getToken(): string | null {
    return this.token;
  }

  /**
   * Install (or replace) the callback used to refresh a stale session
   * JWT when an authenticated request returns `401`. Returning a fresh
   * token causes the original request (and the audit flusher) to retry
   * once with the new credential; throwing surfaces the auth error.
   */
  setTokenRefreshFn(fn: (() => Promise<string>) | null): this {
    this.tokenRefreshFn = fn;
    return this;
  }

  // ── Internal HTTP helpers ─────────────────────────────────────────────────

  /**
   * Resolve a W3C trace context for the next outbound request. Exposed so
   * the AgentumSession audit emitter can pin the same trace id on emitted
   * audit events (see `emitAuditEvent`).
   */
  currentTraceContext(): TraceContext {
    return resolveTraceContext(this.tracingProvider);
  }

  private buildHeaders(
    extra?: Record<string, string>,
    traceContext?: TraceContext,
  ): Record<string, string> {
    const headers: Record<string, string> = { ...this.defaultHeaders };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    // Inject W3C traceparent on every outbound call unless the caller
    // explicitly supplied one (e.g. a framework middleware that already
    // owns the header).
    if (traceContext && !(extra && Object.prototype.hasOwnProperty.call(extra, "traceparent"))) {
      headers["traceparent"] = formatTraceparent(traceContext);
    }
    if (extra) {
      Object.assign(headers, extra);
    }
    return headers;
  }

  private url(path: string): string {
    return `${this.baseUrl}/api/v1/${path.replace(/^\//, "")}`;
  }

  /**
   * Compute the delay for retry `attempt` using **decorrelated jitter**
   * (AWS-style): `sleep = min(cap, random_between(base, prev * 3))`.
   *
   * This keeps small base delays near the lower bound and spreads larger
   * delays across a wider range, avoiding the "thundering herd" that a
   * fixed-exponential schedule produces and the "too-aggressive" retry
   * that full jitter (rand(0, cap)) allows for attempt 1.
   */
  private backoffDelay(attempt: number, prevMs: number): number {
    const base = this.retryDelayMs;
    const cap = base * Math.pow(2, Math.min(attempt, 10));
    const lo = base;
    const hi = Math.min(cap, Math.max(base * 3, prevMs * 3));
    return lo + Math.random() * (hi - lo);
  }

  private async request<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: Record<string, string | number | boolean | undefined>;
      headers?: Record<string, string>;
      absoluteUrl?: boolean;
    } = {},
  ): Promise<T> {
    const { body } = await this.requestWithResponse<T>(method, path, options);
    return body;
  }

  /**
   * Like {@link request} but also surfaces the response `Headers` so callers
   * can read `Cache-Control`, `ETag`, `X-Agentum-Policy-Generation`, etc.
   * Used by the `simulatePolicy` cache wrapper; pre-existing callers continue
   * to call {@link request} (body-only).
   */
  private async requestWithResponse<T>(
    method: string,
    path: string,
    options: {
      body?: unknown;
      query?: Record<string, string | number | boolean | undefined>;
      headers?: Record<string, string>;
      absoluteUrl?: boolean;
    } = {},
  ): Promise<{ body: T; headers: Headers }> {
    let url = options.absoluteUrl ? path : this.url(path);

    // Append query parameters
    if (options.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(options.query)) {
        if (v !== undefined && v !== null) {
          params.set(k, String(v));
        }
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    // Resolve the trace context once per request (not per retry) so every
    // attempt of the same logical call carries the same traceparent. Retries
    // are SDK-internal implementation detail, not separate distributed
    // operations.
    const traceContext = this.currentTraceContext();

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
          headers: this.buildHeaders(options.headers, traceContext),
          signal: controller.signal,
        };
        if (options.body !== undefined) {
          fetchInit.body = JSON.stringify(options.body);
        }
        if (this.httpsAgent) {
          // Undici (global fetch) uses `dispatcher`; node-fetch uses `agent`.
          fetchInit.dispatcher = this.httpsAgent;
          fetchInit.agent = this.httpsAgent;
        }
        response = await this.fetch(url, fetchInit as RequestInit);
      } catch (err) {
        clearTimeout(timer);
        if ((err as Error).name === "AbortError") {
          // Timeouts are user-configured and not retried (consistent with
          // pre-existing behavior; retry windows would multiply wall-clock wait).
          throw new AgentumError(`Request timed out after ${this.timeoutMs}ms: ${method} ${path}`);
        }
        // Retry on transient network-layer failures (socket reset, DNS, etc.)
        const code = networkErrorCode(err);
        if (code && RETRYABLE_NET_CODES.has(code) && attempt < this.retries) {
          lastError = new AgentumError(`Network error (${code}): ${(err as Error).message}`);
          continue;
        }
        throw new AgentumError(`Network error: ${(err as Error).message}`);
      }
      clearTimeout(timer);

      // Parse body (may be empty for 204)
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

        // 401 + refresh callback: refresh the JWT once and retry with it.
        // If the refresh attempt ITSELF fails with auth (the API key behind
        // the refresh hook was revoked), short-circuit with a specific
        // message — the developer needs to mint a new key, retrying won't
        // help. Distinguishing this from a plain JWT-expiry saves real time
        // when debugging "why is my agent suddenly down?".
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
            // Don't burn a backoff slot on a deterministic retry.
            attempt -= 1;
            continue;
          } catch (refreshErr) {
            // If the refresh failure was itself an auth error (401), the
            // underlying API key has been revoked or expired. Surface a
            // distinct, actionable error rather than letting the original
            // 401 propagate as if it were a transient session issue.
            if (refreshErr instanceof AgentumAuthError) {
              throw new AgentumAuthError(
                `${msg} — token refresh failed with 401: the underlying API key has been revoked or expired. Mint a new key and update your SDK config.`,
                redact(body),
              );
            }
            // Other refresh errors (network, transient): fall through and
            // surface the original 401 unchanged.
          }
        }

        // Retry on transient server errors if attempts remain
        if (RETRYABLE_STATUSES.has(response.status) && attempt < this.retries) {
          // Respect Retry-After header (seconds integer or HTTP-date)
          const retryAfter = response.headers.get("retry-after");
          if (retryAfter) {
            const seconds = Number(retryAfter);
            const waitMs = isNaN(seconds)
              ? Math.max(0, new Date(retryAfter).getTime() - Date.now())
              : seconds * 1000;
            if (waitMs > 0) {
              await new Promise((resolve) => setTimeout(resolve, waitMs));
            }
          }
          lastError = new AgentumError(msg, response.status, redact(body));
          continue;
        }

        const redactedBody = redact(body);
        switch (response.status) {
          case 401: {
            // If the caller is using a session JWT without an API key + refresh
            // hook, the token has expired and no auto-refresh is wired up.
            // Surface that specifically — generic "401 Unauthorized" sends
            // people hunting for credential bugs that don't exist.
            const tokenOnlyNoRefresh =
              this.token !== null && this.tokenRefreshFn === null && this.apiKey === null;
            const enriched = tokenOnlyNoRefresh
              ? `${msg} — session token has likely expired. Configure \`apiKey\` (long-lived, agent-scoped) to enable automatic session refresh, or call \`connect()\` again to mint a fresh session.`
              : msg;
            throw new AgentumAuthError(enriched, redactedBody);
          }
          case 403: throw new AgentumPermissionError(msg, redactedBody);
          case 404: throw new AgentumNotFoundError(path, redactedBody);
          case 409: throw new AgentumConflictError(msg, redactedBody);
          default:  throw new AgentumError(msg, response.status, redactedBody);
        }
      }

      return { body: body as T, headers: response.headers };
    }

    throw lastError;
  }

  private get<T>(path: string, query?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.request<T>("GET", path, query !== undefined ? { query } : {});
  }

  private post<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    return this.request<T>("POST", path, headers !== undefined ? { body, headers } : { body });
  }

  private put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PUT", path, { body });
  }

  private delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }

  // ── Health ────────────────────────────────────────────────────────────────

  /**
   * Check if the Agentum API is reachable and healthy.
   * @rbac Public — no authentication required.
   */
  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", `${this.baseUrl}/health`, { absoluteUrl: true });
  }

  // ── Chain-of-thought capture ──────────────────────────────────────────────

  private captureCache = new Map<string, { enabled: boolean; cachedAt: number }>();

  /**
   * Check if conditional chain-of-thought capture is active for this session.
   *
   * Framework wrappers (LangChain callbacks, Vercel AI hooks) poll this method
   * every 30s. When `true`, they emit `agent_reasoning_step`,
   * `agent_plan_step`, or `agent_observation` events containing intermediate
   * reasoning traces (thoughts, tool calls, observations).
   *
   * Capture is OFF by default. Operators explicitly enable it via the audit
   * console (`POST /api/v1/audit/capture`) for debugging or compliance
   * investigations. Payloads are 10–50× normal event sizes and carry heightened
   * PII risk (model IP, raw prompts, tool results).
   *
   * @param sessionId - Session UUID to check. If undefined, checks tenant-wide capture.
   *                    Pattern: `sessionId="abc-123"` queries `scope=session:abc-123`.
   * @returns `true` if at least one active trigger exists for the scope, `false` otherwise.
   *          Cache TTL is 30 seconds (instance-level).
   *
   * @example
   * ```ts
   * const client = new AgentumClient({ baseUrl: "http://localhost:8080" });
   * await client.connect({ agentId: "my-agent" });
   * if (await client.captureEnabled()) {
   *   await client.auditEvent({
   *     eventType: "agent_reasoning_step",
   *     agentId: "my-agent",
   *     detail: { kind: "thought", content_masked: "analyzing query..." },
   *   });
   * }
   * ```
   */
  async captureEnabled(sessionId?: string): Promise<boolean> {
    // Determine scope from sessionId or fall back to tenant-wide
    const scope = sessionId ? `session:${sessionId}` : "tenant";

    // Check cache (30-second TTL)
    const now = Date.now();
    const cached = this.captureCache.get(scope);
    if (cached && now - cached.cachedAt < 30_000) {
      return cached.enabled;
    }

    // Query API: GET /api/v1/audit/capture?scope=...
    try {
      const resp = await this.get<{ triggers: unknown[]; count: number }>(
        `audit/capture?scope=${encodeURIComponent(scope)}`
      );
      const enabled = resp.triggers.length > 0;
      this.captureCache.set(scope, { enabled, cachedAt: now });
      return enabled;
    } catch (e) {
      // Graceful degradation: if capture-check fails, default to OFF
      // (capture is opt-in, so false-negative is safer than false-positive)
      console.debug(`Capture check for ${scope} failed:`, e);
      this.captureCache.set(scope, { enabled: false, cachedAt: now });
      return false;
    }
  }

  // ── Agents ────────────────────────────────────────────────────────────────

  /**
   * Internal: POST /agents. Used by the deprecated public `registerAgent`
   * and by `connect()` (the first-party onramp). Kept private so callers are
   * steered toward `AgentumAdminClient.agents.register()` or the high-level
   * `connect()`, without triggering the public-method deprecation warning.
   */
  private registerAgentInternal(req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    return this.post<RegisterAgentResponse>("agents", {
      ...req,
      framework: req.framework ?? "agentum-ts-sdk",
      declared_tools: req.declared_tools ?? [],
      data_classes: req.data_classes ?? [],
    });
  }

  /**
   * Register a new agent. Returns agent details + an initial session JWT.
   *
   * @deprecated Use `AgentumAdminClient.agents.register()`.
   * Agent registration is an admin-plane operation and will move off
   * `AgentumClient` in a future minor release. Runtime code should use
   * {@link AgentumClient.connect} (which onboards and opens a session in
   * one call) instead of invoking this method directly.
   *
   * @rbac Requires `admin` role (API key or HMAC auth). `operator` role is **not** sufficient.
   * Use `startSession` (which requires `operator`) for subsequent session creation.
   *
   * @example
   * const agent = await client.registerAgent({
   *   name: "my-bot",
   *   owner_email: "owner@example.com",
   *   purpose: "data processing",
   *   framework: "langchain",
   * });
   * client.setToken(agent.session_jwt);
   */
  registerAgent(req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    if (!warnedRegisterAgentDeprecation) {
      warnedRegisterAgentDeprecation = true;
      // eslint-disable-next-line no-console
      console.warn(
        "[agentum] AgentumClient.registerAgent() is deprecated. " +
          "Use AgentumAdminClient.agents.register() for admin-plane calls, " +
          "or AgentumClient.connect() for the one-shot onboarding flow.",
      );
    }
    return this.registerAgentInternal(req);
  }

  /**
   * Fetch a single agent by ID.
   * @rbac Requires `operator` or `admin` role.
   */
  getAgent(agentId: string): Promise<Agent> {
    return this.get<Agent>(`agents/${agentId}`);
  }

  /**
   * List agents with optional filters. Returns a flat array; the server may
   * return either a bare array or a `PaginatedResponse` — both are handled.
   * @rbac Requires `operator` or `admin` role.
   */
  async listAgents(query?: ListAgentsQuery): Promise<Agent[]> {
    const result = await this.get<Agent[] | { agents: Agent[] } | PaginatedResponse<Agent>>("agents", {
      status: query?.status,
      team: query?.team,
      search: query?.search,
      limit: query?.limit,
      offset: query?.offset,
    });
    if (Array.isArray(result)) return result;
    if ("items" in result) return result.items;
    if ("agents" in result) return result.agents ?? [];
    return [];
  }

  /**
   * Async iterator over agents that transparently pages through all
   * results. Uses `limit` as the page size (default 100). Yields one
   * `Agent` at a time so callers can `for await (const a of ...)`
   * without materialising the full list.
   *
   * Terminates when the server returns fewer rows than `limit` or an
   * empty page. Safe to break out of mid-iteration.
   */
  async *listAgentsIterator(query?: ListAgentsQuery): AsyncGenerator<Agent, void, void> {
    const pageSize = query?.limit ?? 100;
    let offset = query?.offset ?? 0;
    for (;;) {
      const page = await this.listAgents({ ...query, limit: pageSize, offset });
      for (const agent of page) yield agent;
      if (page.length < pageSize) return;
      offset += page.length;
    }
  }

  /**
   * Update mutable fields of an agent.
   * @rbac Requires `operator` or `admin` role.
   */
  updateAgent(agentId: string, req: UpdateAgentRequest): Promise<Agent> {
    return this.put<Agent>(`agents/${agentId}`, req);
  }

  /**
   * Trigger the kill-switch: revoke all credentials and quarantine the agent.
   * @rbac Requires `admin` role.
   */
  killAgent(agentId: string): Promise<Agent> {
    return this.post<Agent>(`agents/${agentId}/kill`);
  }

  // ── Sessions ──────────────────────────────────────────────────────────────

  /**
   * Start a new session for the given agent.
   * Returns a session ID and a JWT that must be passed to `setToken()`.
   *
   * `user` optionally binds the session to an end-user identity — see
   * [[UserBinding]]. Trusted-mode (`{id, email, attributes?}`) is forwarded
   * as the request's `user` field; verified-mode (`{token}`) is forwarded as
   * `user_token`. Both are optional.
   *
   * `sourceIp` is forwarded as `source_ip` on the StartSession request so
   * the server-side session record carries the caller's IP for audit /
   * Cedar `context.source_ip` gating.
   *
   * @rbac Requires a valid session JWT (returned by `registerAgent`).
   */
  async startSession(
    agentId: string,
    user?: import("./types.js").UserBinding,
    opts?: { sourceIp?: string; anonymousClientId?: string },
  ): Promise<Session> {
    const body: Record<string, unknown> = { agent_id: agentId };
    if (user) {
      if ("token" in user) {
        body["user_token"] = user.token;
      } else if ("service" in user) {
        body["service"] = user.service;
        if (user.source) {
          body["service_source"] = user.source;
        }
      } else {
        body["user"] = user;
      }
    }
    if (opts?.sourceIp) {
      body["source_ip"] = opts.sourceIp;
    }

    // Resolve anonymous client ID via the tiered ladder. The per-call
    // override always wins; otherwise we fall back to the value
    // resolved by `init()` for client-side contexts. Server SDK contexts
    // SHOULD pass the override per-request — `resolveAnonymousClientId`
    // returns undefined in Node-service contexts to avoid pinning every
    // request to a single agent_users row. Resolution is best-effort and
    // never throws; if it yields undefined the backend falls back to a
    // per-IP UUIDv5. NOTE: backend owns the `anon:` prefix — do not add
    // one here (double-prefixing fragments anonymous user counts).
    const runtimeAnonId = getRuntime()?.anonymousClientId;
    const anonymousClientId = await resolveAnonymousClientId(
      opts?.anonymousClientId ?? runtimeAnonId,
    );
    if (anonymousClientId) {
      body["anonymous_client_id"] = anonymousClientId;
    }

    return this.post<Session>("sessions", body);
  }

  /**
   * End an active session.
   * @rbac Requires the session JWT for this session.
   */
  endSession(sessionId: string): Promise<void> {
    return this.post<void>(`sessions/${sessionId}/end`);
  }

  /**
   * Fetch session details.
   * @rbac Requires `operator` or `admin` role.
   */
  getSession(sessionId: string): Promise<Session> {
    return this.get<Session>(`sessions/${sessionId}`);
  }

  /**
   * List all sessions, optionally filtered by agent.
   * Returns a flat array; handles both bare-array and paginated server responses.
   * @rbac Requires `operator` or `admin` role.
   */
  async listSessions(options?: { agentId?: string; limit?: number; offset?: number }): Promise<Session[]> {
    const result = await this.get<Session[] | { sessions: Session[] } | PaginatedResponse<Session>>("sessions", {
      agent_id: options?.agentId,
      limit: options?.limit,
      offset: options?.offset,
    });
    if (Array.isArray(result)) return result;
    if ("items" in result) return result.items;
    return result.sessions;
  }

  // ── Policy ────────────────────────────────────────────────────────────────

  /**
   * Simulate a Cedar policy decision without performing the action.
   * @rbac Requires the session JWT for the agent being evaluated.
   *
   * Decisions are cached in-process for the duration advertised by the
   * server (`Cache-Control: max-age`). Identical
   * requests hit the cache until it expires or the server signals a
   * policy change via an incremented `X-Agentum-Policy-Generation`
   * header. Disable the cache via `new AgentumClient({policyCache:
   * {enabled: false}})`; evict manually via {@link invalidatePolicyCache}.
   *
   * @returns `{ outcome: "Allow" | "Deny", rule_id, reason }`
   */
  async simulatePolicy(
    req: PolicySimulateRequest,
  ): Promise<PolicySimulateResponse> {
    const cacheKey = SimulateDecisionCache.key(
      req.agent_id,
      req.action,
      req.resource,
      stableStringify(req.user),
      stableStringify(req.context),
    );
    const cached = this.simulateCache.get(cacheKey);
    if (cached !== undefined) return cached;

    const { body, headers } = await this.requestWithResponse<PolicySimulateResponse>(
      "POST",
      "policies/simulate",
      { body: req },
    );

    // Generation changes come from any policy write site; observing them
    // here gives us cross-caller eviction without a webhook dependency.
    this.simulateCache.observeGeneration(
      headers.get("x-agentum-policy-generation"),
    );

    // HITL advice on a Deny must bypass the client cache so middleware
    // can re-trigger the approval escalation on the next call. The server
    // also emits `Cache-Control: no-store` in this case; the explicit
    // guard here is defence in depth.
    const hasAdvice = Array.isArray(body.advice) && body.advice.length > 0;
    if (!hasAdvice) {
      const ttlMs = parseMaxAgeMs(headers) ?? 0;
      this.simulateCache.put(cacheKey, body, ttlMs);
    }

    return body;
  }

  /**
   * Drop every cached `simulatePolicy` decision. Useful after a dashboard
   * policy edit, a deploy-time bundle sync, or any
   * time the caller knows the policy changed and wants immediate
   * consistency without waiting for the generation header fan-out.
   *
   * No-op when the cache is disabled.
   */
  invalidatePolicyCache(): void {
    this.simulateCache.invalidateAll();
  }

  /**
   * Return `true` if Cedar policy allows `action` on `resource`.
   *
   * **Refresh semantics:** this wrapper does NOT catch refresh errors —
   * callers that need fail-soft behaviour should wrap in try/catch or use
   * {@link AgentumSession.isAllowed}, which returns `{outcome:"deny"}`
   * with `reason:"refresh_failed"` if JWT refresh fails.
   *
   * @rbac Requires the session JWT for `agentId`.
   */
  async isAllowed(agentId: string, action: string, resource: string): Promise<boolean> {
    const result = await this.simulatePolicy({ agent_id: agentId, action, resource });
    return result.outcome === "Allow";
  }

  /**
   * Evaluate a single tool call against Cedar policy, returning the rich
   * {@link ToolCallEvaluation} (decision + `policyHash` /
   * `decisionSource` / `evaluatedLocally` / `pdpLatencyUs` observability)
   * rather than the boolean collapse produced by {@link AgentumClient.isAllowed}.
   *
   * Backs the LangChain framework integrations (`enforceAllTools`,
   * `AgentumPolicyTool`, `withAgentumGuard`) so framework-side audit emits
   * can carry the same observability fields the autopatch plane already
   * emits via `LocalPdpDecision`.
   *
   * **Wiring contract:** requires an `apiKey` on the client (`X-Api-Key` is
   * how `CedarToolCallClient` authenticates against
   * `/api/v1/sdk/evaluate-tool-call`). Throws when `apiKey` is unset —
   * callers can catch and fall back to `isAllowed` for backwards compat
   * with clients constructed against a JWT-only auth surface.
   *
   * Per-agent evaluators are lazy-cached so multi-agent processes don't
   * pay construction cost on every call. Cache is unbounded — see field
   * declaration comment.
   */
  async evaluateToolCall(
    agentId: string,
    req: { toolName: string; arguments?: unknown },
  ): Promise<ToolCallEvaluation> {
    if (!this.apiKey) {
      throw new AgentumError(
        "AgentumClient.evaluateToolCall: apiKey is required (CedarToolCallClient auth) — " +
          "construct the client with an `apiKey` or fall back to `isAllowed` for backwards compat",
      );
    }
    let ev = this._evaluators.get(agentId);
    if (!ev) {
      ev = new CedarToolCallClient({
        baseUrl: this.baseUrl,
        apiKey: this.apiKey,
        agentId,
        failMode: "deny",
      });
      this._evaluators.set(agentId, ev);
    }
    return ev.evaluateToolCall(req);
  }

  /**
   * Record a HITL post-approval grant on the per-agent evaluator.
   * Called by {@link AgentumSession.requestApproval} after an operator
   * approval resolves so that the next identical tool call within the
   * grant TTL short-circuits `evaluateToolCall` to `allow` without
   * re-prompting.
   *
   * Lazy-constructs the evaluator if absent (mirrors
   * {@link AgentumClient.evaluateToolCall}). When the client has no
   * `apiKey` the evaluator cannot be constructed (`CedarToolCallClient`
   * requires it) — in that case the call is a silent no-op so the
   * boolean-only `isAllowed` path keeps working.
   */
  async recordApprovalGrant(args: {
    agentId: string;
    toolName: string;
    ttlMs: number;
    requestId?: string;
    /** Tool-call arguments the approval covered. Canonical-JSON SHA-256
     *  hashed into the grant key so an approval for one args shape cannot
     *  unlock different args. Absent/undefined hashes as JSON `null`. */
    toolArgs?: unknown;
  }): Promise<void> {
    if (!this.apiKey) return;
    let ev = this._evaluators.get(args.agentId);
    if (!ev) {
      ev = new CedarToolCallClient({
        baseUrl: this.baseUrl,
        apiKey: this.apiKey,
        agentId: args.agentId,
        failMode: "deny",
      });
      this._evaluators.set(args.agentId, ev);
    }
    return ev.recordApprovalGrant(args);
  }

  /**
   * R45b / INTEG-B1 — should a Deny carrying `require_hitl` advice be
   * auto-escalated to a HITL approval round-trip for the given agent?
   * Consulted by the framework guards (Express / Fastify / NestJS) before
   * escalating.
   *
   * Returns `true` ONLY when the `addon.policy.hitl` addon is explicitly
   * `"enabled"` in the live PDP snapshot. The SAFE default on `"unknown"`
   * (no evaluator yet / cold start / central-only / PDP not wired) and on
   * `"disabled"` is to NOT escalate — auto-escalating with no approver wired
   * hangs the request, so we let the original Deny stand. This replaces the
   * prior fail-OPEN behavior (`isAddonEnabled` returned `true` on an empty
   * snapshot), which could hang a deployment that had simply not yet seen a
   * PDP authorize.
   */
  isHitlAddonEnabled(agentId: string): boolean {
    const ev = this._evaluators.get(agentId);
    if (!ev) return false; // unknown (no snapshot) → SAFE default: don't escalate
    return ev.featureState("addon.policy.hitl") === "enabled";
  }

  // ── Policy proposals ──────────────────────────────────────────────────────

  /**
   * Create a pending policy proposal. Operator+ role; Admin not required.
   * Callers MUST set exactly one of `cedar_source` or `declarative_spec` —
   * the server returns 422 for both or neither.
   *
   * The proposal sits in `pending` until an Admin approves it via
   * {@link AgentumAdminClient.policies.approveProposal} (anti-self-approval
   * enforced server-side). Nothing is written to `{agent_id}.cedar` until
   * approval fires.
   *
   * @rbac Requires a valid operator API key (`apiKey`/`token` on the client).
   */
  proposePolicy(req: CreateProposalRequest): Promise<CreateProposalResponse> {
    return this.post<CreateProposalResponse>("policies/proposals", req);
  }

  /**
   * List policy proposals visible to the caller. Tenant-scoped unless the
   * caller is SuperAdmin; scoped-agent keys are further narrowed to their
   * bound agent.
   *
   * @rbac Requires Operator+.
   */
  async listPolicyProposals(
    query?: ListProposalsQuery,
  ): Promise<ListProposalsResponse> {
    const q: Record<string, string | undefined> = {};
    if (query?.status) q.status = query.status;
    if (query?.agent_id) q.agent_id = query.agent_id;
    return this.get<ListProposalsResponse>("policies/proposals", q);
  }

  /**
   * Fetch a single proposal by id. 404 for cross-tenant / out-of-scope rows
   * (existence-hiding, same precedent as admin_keys).
   *
   * @rbac Requires Operator+.
   */
  getPolicyProposal(proposalId: string): Promise<PolicyProposal> {
    return this.get<PolicyProposal>(`policies/proposals/${proposalId}`);
  }

  /**
   * Withdraw a proposal. Only the original proposer (matched by email) may
   * withdraw — others get 403. Only pending proposals can be withdrawn; a
   * withdrawn/approved/rejected proposal returns 409.
   *
   * Audit records the transition with `detail.withdrawn_by_proposer=true`
   * under the `PolicyProposalRejected` event variant.
   *
   * @rbac Requires Operator+ AND the caller's email must equal the proposal's
   *  `proposed_by`.
   */
  withdrawPolicyProposal(proposalId: string): Promise<WithdrawProposalResponse> {
    return this.post<WithdrawProposalResponse>(
      `policies/proposals/${proposalId}/withdraw`,
      {},
    );
  }

  // ── Audit ─────────────────────────────────────────────────────────────────

  /**
   * Fetch recent audit events.
   * Returns a flat array; handles both bare-array and paginated server responses.
   * @rbac Requires `auditor`, `operator`, or `admin` role.
   */
  async listAudit(options?: { limit?: number; offset?: number; agentId?: string }): Promise<AuditEvent[]> {
    const result = await this.get<AuditEvent[] | { events: AuditEvent[] } | PaginatedResponse<AuditEvent>>("audit", {
      limit: options?.limit,
      offset: options?.offset,
      agent_id: options?.agentId,
    });
    if (Array.isArray(result)) return result;
    if ("items" in result) return result.items;
    return result.events;
  }

  /**
   * Ingest a custom audit event.
   *
   * By default, events are appended to an in-process ring buffer and
   * flushed asynchronously. If the buffer is full, the oldest event is
   * dropped and `onAuditError` is invoked with `reason: "overflow"`.
   * Transient ingest failures are retried with exponential backoff up to
   * `auditMaxBackoffMs`. Audit must never break the agent — this method
   * does not throw.
   *
   * **Refresh semantics:** intentionally fail-soft. Events are enqueued
   * regardless of JWT staleness; the background flusher handles 401 by
   * calling `tokenRefreshFn` and retrying once.
   *
   * Pass `disableAuditBuffer: true` in the client config to restore the
   * synchronous best-effort behaviour.
   * @rbac Requires the session JWT for the emitting agent.
   */
  async ingestAuditEvent(req: AuditIngestRequest): Promise<void> {
    // Back-compat: accept the legacy `details` key and remap to `detail`.
    const legacy = req as AuditIngestRequest & { details?: Record<string, unknown> };
    if (legacy.details !== undefined && req.detail === undefined) {
      // eslint-disable-next-line no-console
      console.warn(
        "[agentum] AuditIngestRequest.details is deprecated — use `detail` (singular).",
      );
      req = { ...req, detail: legacy.details };
      delete (req as { details?: unknown }).details;
    }
    // Stamp the active trace id, span id, and parent span id on the event at
    // emit time so buffered events keep their original span context instead
    // of picking up whatever span is active at flush time. Callers that have
    // already populated these fields win (explicit trumps implicit).
    if (req.trace_id === undefined) {
      const ctx = this.currentTraceContext();
      req = {
        ...req,
        trace_id: ctx.traceId,
        span_id: ctx.spanId,
        // Parent span id requires SDK-level span tracking which isn't
        // implemented yet — SDKs emit events from the same span they
        // were created in. Framework wrappers can override if needed.
        // parent_span_id: undefined
      };
    }
    if (!this.auditBufferEnabled) {
      // Y05 — run the PII pipeline before the wire emit. Fail-CLOSED:
      // on `PiiSelfCheckFailedError` we drop the event entirely rather
      // than emit unmasked-with-warning (per `.claude/rules/pii.md`
      // invariant #11). Non-PII errors propagate to the catch below
      // where they are swallowed — audit must never break the agent.
      //
      // Sync fast-path: when neither the trie nor the scanner has any
      // work to do (the pre-Y02 default, and the test default when
      // pii state is not configured) we skip the `await` entirely so
      // the fetch mock is still invoked synchronously from inside
      // `this.post` — callers like the OpenAI streaming wrapper inspect
      // `fetch.mock.calls` immediately after invoking the wrapper.
      let scrubbed: AuditIngestRequest | null = req;
      if (req.detail !== undefined && !isPiiPipelineNoOp()) {
        scrubbed = await this.applyPiiPipelineOrDrop(req);
      }
      if (scrubbed === null) return; // dropped by self-check
      try {
        // Q4: send replay-prevention headers on every audit POST.
        // Central default `audit_ingest_require_freshness` is TRUE post-Q4;
        // requests without these headers are rejected on net-new tenants.
        await this.post("audit/ingest", scrubbed, freshnessHeaders());
      } catch {
        // Audit must never break the agent
      }
      return;
    }
    if (this.auditClosed) {
      this.onAuditError({ reason: "dropped_on_close", dropped: 1 });
      return;
    }
    if (this.auditBuffer.length >= this.auditBufferSize) {
      // Drop-oldest overflow policy — preserve most-recent signal.
      this.auditBuffer.shift();
      this.onAuditError({
        reason: "overflow",
        dropped: 1,
        bufferedRemaining: this.auditBuffer.length,
      });
    }
    this.auditBuffer.push(req);
    this.ensureAuditFlushTimer();
  }

  /** Return the current in-memory audit buffer size. Exposed for tests. */
  auditBufferLength(): number {
    return this.auditBuffer.length;
  }

  /**
   * Force an immediate flush of the audit buffer. Useful in tests and
   * before deliberate shutdown. Honours current backoff state — if the
   * buffer is in backoff from a recent failure, this call becomes a
   * no-op until the backoff window elapses. Use `close()` to guarantee
   * a best-effort drain.
   */
  async flushAuditBuffer(): Promise<void> {
    await this.drainAuditBuffer(false);
  }

  /**
   * Drain the audit buffer and stop all background timers. After
   * `close()` resolves, further `ingestAuditEvent` calls drop the event
   * and emit `onAuditError` with `reason: "dropped_on_close"`.
   *
   * Best-effort: a final flush is attempted, but any events still
   * buffered after the final flush (e.g. due to server error) are
   * reported via `onAuditError` and dropped.
   */
  async close(): Promise<void> {
    this.auditClosed = true;
    if (this.auditFlushTimer) {
      clearInterval(this.auditFlushTimer);
      this.auditFlushTimer = null;
    }
    // Force one final drain pass, ignoring backoff.
    await this.drainAuditBuffer(true);
    if (this.auditBuffer.length > 0) {
      const dropped = this.auditBuffer.length;
      this.auditBuffer = [];
      this.onAuditError({ reason: "dropped_on_close", dropped });
    }
  }

  /**
   * Y05 — run the PII pipeline on `req.detail`. Returns the scrubbed
   * request on success, or `null` when Stage D self-check failed and
   * the caller MUST drop the event entirely (fail-CLOSED per
   * `.claude/rules/pii.md` invariant #11).
   *
   * Non-PII errors (programmer bugs in the pipeline) propagate — they
   * are not leaks and silently swallowing them would hide real issues.
   * The two call sites (`ingestAuditEvent` non-buffered branch + the
   * batch flusher) each have their own catch around the wire POST that
   * swallows transport / contract errors per the audit-must-never-break
   * invariant; a thrown pipeline bug surfaces there.
   *
   * On self-check failure we emit a structured warn line (single-line
   * JSON, matching the file's existing audit-error envelope) so
   * operators can grep for `pii_self_check_failed_total` in their log
   * pipeline. The pattern id is included; the residual sample is NOT
   * — it is by construction still raw PII (see
   * `text-scanner.ts::PiiSelfCheckFailedError`).
   */
  private async applyPiiPipelineOrDrop(
    req: AuditIngestRequest,
  ): Promise<AuditIngestRequest | null> {
    if (req.detail === undefined) return req;
    try {
      const { detail: scrubbedDetail, pii_key_id } = await runPiiPipeline(
        req.detail,
        req.tool ?? "*",
      );
      // Preserve the structurally-shared identity when the pipeline was
      // a no-op (no trie, no scanner) AND no hash/tokenize fired —
      // avoids an extra object allocation on the audit hot path. When
      // Y06 produced a `pii_key_id`, we must allocate even if `detail`
      // is identity-equal so the field reaches the wire.
      if (scrubbedDetail === req.detail && pii_key_id === undefined) {
        return req;
      }
      const out: AuditIngestRequest = {
        ...req,
        detail: scrubbedDetail as Record<string, unknown>,
      };
      if (pii_key_id !== undefined) out.pii_key_id = pii_key_id;
      return out;
    } catch (err) {
      if (err instanceof PiiSelfCheckFailedError) {
        // eslint-disable-next-line no-console
        console.warn(
          JSON.stringify({
            level: "warn",
            source: "agentum-sdk",
            component: "pii-pipeline",
            metric: "pii_self_check_failed_total",
            reason: "pii_self_check_failed",
            pattern: err.unmaskedPatternId,
            event_type: req.event_type,
            // tool is operator-visible context (a manifest field), not PII.
            tool: req.tool,
          }),
        );
        return null; // caller drops the event entirely
      }
      throw err;
    }
  }

  private ensureAuditFlushTimer(): void {
    if (this.auditFlushTimer || this.auditClosed) return;
    this.auditFlushTimer = setInterval(() => {
      void this.drainAuditBuffer(false);
    }, this.auditFlushIntervalMs);
    // Don't hold the Node event loop open solely for the flush timer.
    const t = this.auditFlushTimer as unknown as { unref?: () => void };
    if (typeof t.unref === "function") t.unref();
  }

  private async drainAuditBuffer(ignoreBackoff: boolean): Promise<void> {
    if (this.auditFlushing) return;
    if (this.auditBuffer.length === 0) return;
    if (!ignoreBackoff && this.auditBackoffDeadline > Date.now()) return;

    this.auditFlushing = true;
    let attempt = 0;
    try {
      while (this.auditBuffer.length > 0) {
        // Snapshot a batch and attempt delivery as a single POST. The
        // server is all-or-nothing: a single bad event 4xx's the whole
        // batch (no per-event status). Re-prepend the *whole* batch on
        // transport / 5xx so ordering is preserved.
        const batch = this.auditBuffer.splice(0, this.auditFlushBatchSize);
        // Y05 — scrub every event through the PII pipeline before the
        // batch POST. Events whose self-check fails are dropped (filtered
        // out of the batch); the remaining events are POSTed together.
        // Fail-CLOSED is enforced per-event so a single leaking event
        // does not poison the whole batch. Skip the per-event walk
        // entirely when both stages are no-ops (pre-Y02 default).
        let scrubbedBatch: AuditIngestRequest[];
        if (isPiiPipelineNoOp()) {
          scrubbedBatch = batch;
        } else {
          scrubbedBatch = [];
          for (const ev of batch) {
            const s =
              ev.detail === undefined
                ? ev
                : await this.applyPiiPipelineOrDrop(ev);
            if (s !== null) scrubbedBatch.push(s);
          }
        }
        if (scrubbedBatch.length === 0) {
          // Whole batch was dropped (every event failed self-check).
          // Reset backoff since the wire op never happened — we did not
          // fail to deliver, we deliberately did not emit.
          this.auditBackoffMs = 0;
          this.auditBackoffDeadline = 0;
          if (!ignoreBackoff) break;
          continue;
        }
        try {
          // Q4: send replay-prevention headers on every audit POST.
          // Each batch gets its own nonce + timestamp; a retry of the
          // same batch (the 5xx path below re-prepends and re-enters
          // this loop) regenerates the headers so a single nonce is
          // never sent twice.
          await this.post<{ ingested: number }>(
            "audit/ingest/batch",
            { events: scrubbedBatch },
            freshnessHeaders(),
          );
          // Success: reset backoff.
          this.auditBackoffMs = 0;
          this.auditBackoffDeadline = 0;
        } catch (err) {
          attempt += 1;
          const base = this.auditBackoffMs > 0 ? this.auditBackoffMs * 2 : this.auditFlushIntervalMs;
          this.auditBackoffMs = Math.min(base, this.auditMaxBackoffMs);
          this.auditBackoffDeadline = Date.now() + this.auditBackoffMs;

          // 401: drop the batch. Buffering forever against a dead token
          // just grows memory. Pause the flusher with backoff so we don't
          // hot-loop on a fresh 401.
          if (err instanceof AgentumAuthError) {
            this.onAuditError({
              reason: "ingest_failed",
              attempt,
              dropped: batch.length,
              bufferedRemaining: this.auditBuffer.length,
              error: err,
            });
            return;
          }

          // Other 4xx (e.g. 422 missing agent_id, 403 wrong scope): the
          // payload is malformed for the server contract. Don't retry —
          // we'd loop forever against a permanent error. Drop the batch
          // and surface via onAuditError.
          if (
            err instanceof AgentumError &&
            typeof err.statusCode === "number" &&
            err.statusCode >= 400 &&
            err.statusCode < 500
          ) {
            this.onAuditError({
              reason: "ingest_failed",
              attempt,
              dropped: batch.length,
              bufferedRemaining: this.auditBuffer.length,
              error: err,
            });
            return;
          }

          // Transport / 5xx: re-prepend the whole batch (server is
          // all-or-nothing) so the next drain retries with full ordering.
          this.auditBuffer = batch.concat(this.auditBuffer);
          this.onAuditError({
            reason: "ingest_failed",
            attempt,
            bufferedRemaining: this.auditBuffer.length,
            error: err,
          });
          return; // Defer further attempts until the backoff window clears.
        }

        // On forced (close) drains we loop to completion; on periodic
        // drains we exit after one successful batch to keep latency low.
        if (!ignoreBackoff) break;
      }
    } finally {
      this.auditFlushing = false;
    }
  }

  // ── Alerts ────────────────────────────────────────────────────────────────

  /**
   * List security alerts, optionally filtered by severity or agent.
   * Returns a flat array; handles both bare-array and paginated server responses.
   * @rbac Requires `operator` or `admin` role.
   */
  async listAlerts(options?: { severity?: string; agentId?: string; limit?: number }): Promise<Alert[]> {
    const result = await this.get<Alert[] | { alerts: Alert[] } | PaginatedResponse<Alert>>("alerts", {
      severity: options?.severity,
      agent_id: options?.agentId,
      limit: options?.limit,
    });
    if (Array.isArray(result)) return result;
    if ("items" in result) return result.items;
    return result.alerts;
  }

  /**
   * Acknowledge an alert.
   * @rbac Requires `operator` or `admin` role.
   */
  ackAlert(alertId: string, ackedBy?: string): Promise<Alert> {
    return this.post<Alert>(`alerts/${alertId}/ack`, { acked_by: ackedBy });
  }

  // ── Vault / Credentials ───────────────────────────────────────────────────

  /**
   * Issue a short-lived vault credential for an agent and service.
   * @rbac Requires the session JWT for the requesting agent.
   *
   * @example
   * const cred = await client.issueCredential({ agent_id, service_name: "stripe" });
   * // use cred.value as the API key — expires at cred.expires_at
   */
  issueCredential(req: IssueCredentialRequest): Promise<CredentialLease> {
    return this.post<CredentialLease>("vault/issue", req);
  }

  /**
   * Revoke a vault credential lease before its TTL expires.
   * @rbac Requires `operator` or `admin` role.
   */
  revokeCredential(leaseId: string): Promise<void> {
    return this.delete<void>(`vault/leases/${leaseId}`);
  }

  // ── Shadow Agents ─────────────────────────────────────────────────────────

  /**
   * List detected shadow (unregistered) agents.
   * @rbac Requires `operator` or `admin` role.
   */
  async listShadowAgents(): Promise<ShadowAgent[]> {
    const result = await this.get<ShadowAgent[] | { shadow_agents: ShadowAgent[] }>("shadow");
    return Array.isArray(result) ? result : result.shadow_agents;
  }

  /**
   * Promote a shadow agent to a registered agent.
   * @rbac Requires `operator` or `admin` role.
   */
  promoteShadowAgent(shadowId: string, req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    return this.post<RegisterAgentResponse>(`shadow/${shadowId}/promote`, req);
  }

  // ── MCP Servers ───────────────────────────────────────────────────────────

  /**
   * List registered MCP servers.
   * @rbac Requires `operator` or `admin` role.
   */
  async listMcpServers(): Promise<McpServer[]> {
    const result = await this.get<McpServer[] | { servers: McpServer[] }>("mcp/servers");
    return Array.isArray(result) ? result : result.servers;
  }

  /**
   * Get a single MCP server by ID.
   * @rbac Requires `operator` or `admin` role.
   */
  getMcpServer(serverId: string): Promise<McpServer> {
    return this.get<McpServer>(`mcp/servers/${serverId}`);
  }

  // ── HITL (Human-in-the-Loop) ──────────────────────────────────────────────

  /**
   * List pending HITL approval requests.
   * @rbac Requires `operator` or `admin` role.
   */
  async listHitlRequests(): Promise<HitlRequest[]> {
    const result = await this.get<HitlRequest[] | { requests: HitlRequest[] }>("hitl/requests");
    return Array.isArray(result) ? result : result.requests;
  }

  /**
   * Fetch a single HITL approval request by ID.
   * @rbac Requires `operator` or `admin` role.
   */
  getHitlRequest(requestId: string): Promise<HitlRequest> {
    return this.get<HitlRequest>(`hitl/requests/${requestId}`);
  }

  /**
   * Approve or deny a pending HITL request.
   * @rbac Requires `operator` or `admin` role.
   *
   * @param requestId  The HITL request ID to decide on.
   * @param decision   `{ decision: "approve" | "deny", reason?: string }`
   */
  decideHitlRequest(requestId: string, decision: HitlDecision): Promise<HitlDecisionResponse> {
    return this.post<HitlDecisionResponse>(`hitl/requests/${requestId}/decide`, decision);
  }

  /**
   * Create a HITL approval request via the agent-facing route.
   * Authenticates with the session JWT — the server reads `agent_id` and
   * `tenant_id` from the JWT, never from the body. Returns immediately with
   * the new request_id; callers should poll `getHitlAgentRequest()` until
   * status becomes terminal.
   *
   * Most callers want {@link AgentumSession.requestApproval} instead, which
   * handles the polling loop.
   *
   * @rbac Requires the session JWT (Bearer token).
   */
  createHitlAgentRequest(body: {
    action: string;
    resource: string;
    context?: unknown;
    reason?: string;
    timeout_seconds?: number;
    required_approvals?: number;
  }): Promise<{ request_id: string; status: "pending" }> {
    return this.post("hitl/agent/requests", body);
  }

  /**
   * Fetch the current state of an agent-created HITL request.
   * Cross-agent access is rejected with 404 (existence-hiding) — the JWT
   * agent must own the request.
   *
   * @rbac Requires the session JWT (Bearer token).
   */
  getHitlAgentRequest(requestId: string): Promise<{
    request_id: string;
    agent_id: string;
    status: "pending" | "approved" | "denied" | "timeout";
    action: string;
    resource: string;
    context: unknown;
    created_at: string;
    decided_at: string | null;
    decided_by: string[];
    reason: string | null;
  }> {
    return this.get(`hitl/agent/requests/${requestId}`);
  }

  // ── Delegation ────────────────────────────────────────────────────────────

  /**
   * Issue a delegation token allowing one agent to act on behalf of another.
   * @rbac Requires the session JWT for `agentId`.
   *
   * @param agentId    The delegating agent's ID (the principal granting authority).
   * @param delegateId The agent ID receiving the delegation.
   * @param scope      List of actions/resources the delegate may perform.
   * @returns `{ delegation_token: string; expires_at: string }`
   */
  issueDelegation(
    agentId: string,
    delegateId: string,
    scope: string[],
    ttlSeconds?: number,
  ): Promise<DelegationResponse> {
    const req: IssueDelegationRequest = { delegate_id: delegateId, scope };
    if (ttlSeconds !== undefined) req.ttl_seconds = ttlSeconds;
    return this.post<DelegationResponse>(`agents/${agentId}/delegate`, req);
  }

  /**
   * Verify a delegation JWT token for a given agent.
   * @rbac Requires `operator` or `admin` role.
   *
   * @param agentId  The agent ID whose delegation chain is being verified.
   * @param token    The delegation JWT to verify.
   */
  verifyDelegation(agentId: string, token: string): Promise<DelegationVerifyResponse> {
    return this.get<DelegationVerifyResponse>(`agents/${agentId}/delegate/verify`, { token });
  }

  // ── Compliance ────────────────────────────────────────────────────────────

  /**
   * Fetch the compliance report for all agents.
   * @rbac Requires `auditor`, `operator`, or `admin` role.
   */
  async listComplianceReport(): Promise<ComplianceReport[]> {
    const result = await this.get<ComplianceReport[] | { report: ComplianceReport[] }>("compliance/report");
    return Array.isArray(result) ? result : result.report;
  }

  // ── High-level lifecycle ──────────────────────────────────────────────────

  /**
   * Shared config snapshot used to fork isolated session clients.
   * Propagates audit-buffer tuning, TLS overrides, and tenant headers so
   * every forked session behaves identically to the parent outside of
   * token / tenant isolation.
   */
  private sessionClientConfig(): AgentumClientConfig {
    const cfg: AgentumClientConfig = {
      baseUrl: this.baseUrl,
      timeoutMs: this.timeoutMs,
      fetch: this.fetch,
      defaultHeaders: { ...this.defaultHeaders },
      retries: this.retries,
      retryDelayMs: this.retryDelayMs,
      auditBufferSize: this.auditBufferSize,
      auditFlushIntervalMs: this.auditFlushIntervalMs,
      auditFlushBatchSize: this.auditFlushBatchSize,
      auditMaxBackoffMs: this.auditMaxBackoffMs,
      onAuditError: this.onAuditError,
      disableAuditBuffer: !this.auditBufferEnabled,
    };
    if (this.apiKey) cfg.apiKey = this.apiKey;
    return cfg;
  }

  /**
   * Overlay per-session overrides on the shared config snapshot.
   * `tenantId` replaces any inherited `X-Tenant-ID` default header so
   * per-request tenancy is honoured without mutating the parent client.
   */
  private forkConfig(overrides: { tenantId?: string | undefined; token?: string | undefined }): AgentumClientConfig {
    const cfg = this.sessionClientConfig();
    if (overrides.tenantId !== undefined) {
      const headers = { ...(cfg.defaultHeaders ?? {}) };
      headers["X-Tenant-ID"] = overrides.tenantId;
      cfg.defaultHeaders = headers;
      cfg.tenantId = overrides.tenantId;
    }
    if (overrides.token !== undefined) cfg.token = overrides.token;
    return cfg;
  }

  /**
   * One-shot onboarding: register an agent, open a tracked session, and
   * return an `AgentumSession` whose client is pre-authenticated.
   * @rbac Requires `operator` or `admin` role (via `apiKey` in config).
   *
   * @example
   * await using session = await client.connect({
   *   name: "my-bot",
   *   owner_email: "owner@example.com",
   *   purpose: "process customer data",
   *   framework: "langchain",
   * });
   */
  async connect(opts: ConnectOptions): Promise<AgentumSession> {
    const registration = await this.registerAgentInternal(opts);

    // Isolated client carrying the registration JWT to call startSession.
    // We deliberately do NOT call this.setToken() — mutating the shared client's
    // token would corrupt any other concurrent session managed through this instance.
    const tempClient = new AgentumClient(
      this.forkConfig({ tenantId: opts.tenantId, token: registration.session_jwt }),
    );
    const startSessionOpts = buildStartSessionOpts(opts);
    const session = await tempClient.startSession(
      registration.agent_id,
      opts.user,
      startSessionOpts,
    );
    await tempClient.close();

    // Each AgentumSession owns its own isolated client with the session JWT.
    // session.jwt is always present in startSession responses (jwt? is optional only
    // because getSession does not re-vend the token).
    const agentId = registration.agent_id;
    const sessionClient = new AgentumClient(
      this.forkConfig({ tenantId: opts.tenantId, token: session.jwt }),
    );

    // A single long-lived refresh client avoids allocating (and leaking)
    // an AgentumClient per refresh call.
    const refreshClient = new AgentumClient(this.forkConfig({ tenantId: opts.tenantId }));
    const refreshFn = () =>
      refreshClient
        .startSession(agentId, opts.user, startSessionOpts)
        .then((s) => ({ jwt: s.jwt!, session_id: s.session_id }));

    // session.jwt is always present in startSession responses (Session.jwt is
    // only optional in the type because getSession() does not re-vend the token).
    const agentumSession = new AgentumSession(sessionClient, agentId, session.session_id, session.jwt!, {
      refreshFn,
      ownsClient: true,
      refreshClient,
    });

    // Best-effort Cedar policy probe — warn if no policy is configured.
    if (!opts.skipPolicyCheck) {
      sessionClient
        .simulatePolicy({ agent_id: agentId, action: "__probe__", resource: "__probe__" })
        .then((probe) => {
          if (probe.outcome === "Deny" && !probe.rule_id) {
            console.warn(
              `[agentum] Agent ${agentId} has no Cedar policy — ` +
              `all isAllowed() calls will return Deny until a policy is created.`,
            );
          }
        })
        .catch(() => {
          // Network/auth errors are a separate problem, not a missing-policy signal.
        });
    }

    return agentumSession;
  }

  /**
   * Open a tracked session for an agent that is already registered.
   * Use this when you have an existing `agentId` and want a new session.
   * @rbac Requires `operator` or `admin` role (via `apiKey` in config).
   *
   * @example
   * const session = await client.connectExisting("existing-agent-id");
   */
  async connectExisting(
    agentId: string,
    opts: {
      skipPolicyCheck?: boolean;
      user?: import("./types.js").UserBinding;
      tenantId?: string;
      sourceIp?: string;
      anonymousClientId?: string;
    } = {},
  ): Promise<AgentumSession> {
    // Use a temp client scoped to the management auth for the startSession call.
    const tempClient = new AgentumClient(this.forkConfig({ tenantId: opts.tenantId }));
    const startSessionOpts = buildStartSessionOpts(opts);
    const session = await tempClient.startSession(
      agentId,
      opts.user,
      startSessionOpts,
    );
    await tempClient.close();

    const sessionClient = new AgentumClient(
      this.forkConfig({ tenantId: opts.tenantId, token: session.jwt }),
    );

    const refreshClient = new AgentumClient(this.forkConfig({ tenantId: opts.tenantId }));
    const refreshFn = () =>
      refreshClient
        .startSession(agentId, opts.user, startSessionOpts)
        .then((s) => ({ jwt: s.jwt!, session_id: s.session_id }));

    // session.jwt is always present in startSession responses (Session.jwt is
    // only optional in the type because getSession() does not re-vend the token).
    const agentumSession = new AgentumSession(sessionClient, agentId, session.session_id, session.jwt!, {
      refreshFn,
      ownsClient: true,
      refreshClient,
    });

    if (!opts.skipPolicyCheck) {
      sessionClient
        .simulatePolicy({ agent_id: agentId, action: "__probe__", resource: "__probe__" })
        .then((probe) => {
          if (probe.outcome === "Deny" && !probe.rule_id) {
            console.warn(
              `[agentum] Agent ${agentId} has no Cedar policy — ` +
              `all isAllowed() calls will return Deny until a policy is created.`,
            );
          }
        })
        .catch(() => {
          // Network/auth errors are a separate problem, not a missing-policy signal.
        });
    }

    return agentumSession;
  }

  // ── MITM proxy configuration ──────────────────────────────────────────────

  /**
   * Route the current process's outbound HTTP traffic through the Agentum
   * MITM gateway in one call.
   *
   * Enrolls the caller with the gateway, downloads the gateway CA cert,
   * and (by default) sets `HTTPS_PROXY` / `HTTP_PROXY` /
   * `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` so any library that respects
   * standard proxy / CA env vars — `fetch`, `undici`, OpenAI, Anthropic,
   * `axios`, `got`, `node-fetch` — transparently routes through the
   * gateway. Returns the resolved `{proxyUrl, caPath, ...}` so callers
   * that opt out of `setProcessEnv` can wire them into a custom HTTP
   * client.
   *
   * The returned `proxyToken` is short-lived (1 h by default). Call
   * `configureMitmProxy()` again before expiry to refresh.
   *
   * @rbac Requires the client to carry an API key (admin or operator).
   *
   * @example
   * const client = new AgentumClient({ baseUrl: "http://localhost:7071", apiKey: "sk-..." });
   * await client.configureMitmProxy({ name: "my-bot", purpose: "call OpenAI" });
   * // All subsequent fetch() / OpenAI SDK calls now route through Agentum.
   */
  async configureMitmProxy(opts: MitmProxyOptions = {}): Promise<MitmProxyConfig> {
    const apiKey = opts.apiKey ?? this.apiKey;
    if (!apiKey) {
      throw new AgentumError(
        "configureMitmProxy requires an API key. Pass opts.apiKey or configure AgentumClient with apiKey.",
      );
    }

    const name = opts.name ?? detectScriptName();
    const purpose = opts.purpose ?? "SDK-governed agent";

    // 1. Enroll with the gateway — returns agent/session ids + proxy_token.
    const enrollResp = await this.fetch(`${this.baseUrl}/api/v1/launcher/enroll`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Api-Key": apiKey,
      },
      body: JSON.stringify({
        api_key: apiKey,
        name,
        purpose,
        platform: `${process.platform}-${process.arch}`,
        launcher_version: "agentum-ts-sdk-0.1.0",
        deployment_mode: "sdk-mitm",
      }),
    });
    if (enrollResp.status !== 201) {
      const body = await enrollResp.text();
      if (enrollResp.status === 403) {
        throw new AgentumAuthError(`Invalid API key: ${body}`);
      }
      throw new AgentumError(`Enrollment failed (${enrollResp.status}): ${body}`, enrollResp.status);
    }
    const enrollBody = (await enrollResp.json()) as {
      agent_id: string;
      session_id: string;
      session_jwt: string;
      proxy_token: string;
      proxy_token_expires_at: string;
    };

    // 2. Fetch CA cert (public endpoint).
    const caResp = await this.fetch(`${this.baseUrl}/api/v1/gateway/ca-cert`);
    if (caResp.status !== 200) {
      throw new AgentumError(`Failed to fetch CA cert: ${caResp.status}`, caResp.status);
    }
    const pem = await caResp.text();
    if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
      throw new AgentumError("Gateway returned invalid CA cert (not PEM)");
    }

    // 3. Resolve proxy URL. Plan defaults to baseUrl host with port 7070;
    //    the MITM gateway expects proxy_token:x as basic-auth creds.
    const proxyPort = opts.proxyPort ?? 7070;
    let proxyUrl: string;
    if (opts.proxyUrl) {
      try {
        const u = new URL(opts.proxyUrl);
        if (!u.username) u.username = enrollBody.proxy_token;
        if (!u.password) u.password = "x";
        proxyUrl = u.toString();
      } catch {
        throw new AgentumError(`Invalid proxyUrl "${opts.proxyUrl}": not a valid URL`);
      }
    } else {
      const base = new URL(this.baseUrl);
      proxyUrl = `http://${encodeURIComponent(enrollBody.proxy_token)}:x@${base.hostname}:${proxyPort}`;
    }

    // 4. Resolve CA path + persist it. Loaded via `await import` so the
    //    module stays importable in edge / browser bundles that exclude Node
    //    built-ins — runtime use still requires Node.
    const installCa = opts.installCa ?? "env-only";
    let caPath = opts.caPath ?? "";
    let fs: typeof import("fs");
    let path: typeof import("path");
    let os: typeof import("os");
    try {
      fs = await import("fs");
      path = await import("path");
      os = await import("os");
    } catch {
      throw new AgentumError(
        "configureMitmProxy requires a Node.js runtime (fs/path/os). Not supported in browsers or edge runtimes.",
      );
    }
    if (!caPath) {
      const caDir = path.join(os.homedir(), ".agentum");
      fs.mkdirSync(caDir, { recursive: true });
      caPath = path.join(caDir, "ca.pem");
    } else {
      fs.mkdirSync(path.dirname(caPath), { recursive: true });
    }
    fs.writeFileSync(caPath, pem);

    if (installCa === "system") {
      console.warn(
        "[agentum] configureMitmProxy: installCa='system' is not yet implemented — " +
          "falling back to env-only. CA written to " + caPath,
      );
    }

    // 5. Optionally publish env vars. Any HTTP client that respects proxy /
    //    CA env vars (OpenAI, Anthropic, undici, httpx-via-env) will now
    //    route through the gateway with the CA trusted.
    if (opts.setProcessEnv !== false && installCa !== "never") {
      process.env.HTTPS_PROXY = proxyUrl;
      process.env.HTTP_PROXY = proxyUrl;
      process.env.https_proxy = proxyUrl;
      process.env.http_proxy = proxyUrl;
      process.env.NODE_EXTRA_CA_CERTS = caPath;
      process.env.SSL_CERT_FILE = caPath;
    }

    return {
      agentId: enrollBody.agent_id,
      sessionId: enrollBody.session_id,
      sessionJwt: enrollBody.session_jwt,
      proxyToken: enrollBody.proxy_token,
      proxyTokenExpiresAt: enrollBody.proxy_token_expires_at,
      proxyUrl,
      caPath,
    };
  }
}

function detectScriptName(): string {
  try {
    const argv = (globalThis as unknown as { process?: { argv?: string[] } }).process?.argv;
    const entry = argv?.[1];
    if (!entry) return "node-agent";
    const base = entry.split(/[\\/]/).pop() ?? entry;
    return base.replace(/\.(m?js|ts|cjs)$/, "") || "node-agent";
  } catch {
    return "node-agent";
  }
}
