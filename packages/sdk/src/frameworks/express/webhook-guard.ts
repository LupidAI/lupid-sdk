/**
 * agentumWebhookGuard — inbound-webhook authorization middleware.
 *
 * Gates webhook endpoints with a Cedar policy check bound to a non-human
 * **service identity** (`{ service, source? }` UserBinding).
 *
 * Unlike {@link agentumGuard}, this middleware is **self-contained** — it
 * does NOT require `agentumMiddleware()` to have run first. It mints and
 * pools its own service-identity sessions.
 *
 * Flow:
 *   1. Pool/mint a service session via `client.connectExisting(agentId, { user: { service, source? }})`.
 *   2. Gate on `session.isAllowed("webhook.receive", source)` — Cedar sees
 *      `context.user.trust === "service"` and `context.user.id === <serviceIdentity>`
 *      because the JWT carries those claims from the service session mint.
 *   3. On Allow: attach `req.agentum = { session, agentId, sessionId, service }`,
 *      emit a `webhook_receive` audit event, and call `next()`.
 *   4. On Deny: respond 403 + emit `request_denied` audit event (source=webhook).
 *
 * @example
 * ```ts
 * app.post("/webhooks/github",
 *   agentumWebhookGuard({
 *     runtime: client,
 *     agentId: process.env.AGENTUM_AGENT_ID!,
 *     source: "github",
 *     serviceIdentity: "github-webhook",
 *   }),
 *   async (req, res) => {
 *     // req.agentum.session is available for downstream tool gating
 *     res.json({ ok: true });
 *   }
 * );
 * ```
 */

import type { AgentumClient } from "../../client.js";
import { AgentumError } from "../../types.js";
import type { AgentumSession } from "../../session.js";
import type {
  AgentumMiddleware,
  AgentumNext,
  AgentumRequest,
  AgentumRequestContext,
  AgentumResponse,
} from "./types.js";

// ── Options ────────────────────────────────────────────────────────────────────

export interface AgentumWebhookGuardOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set (service-mint auth). */
  runtime?: AgentumClient;
  /** Alias for `runtime` (keeps parity with `agentumMiddleware`). */
  client?: AgentumClient;

  /** Pre-registered agent ID that owns the webhook endpoint. */
  agentId: string;

  /** Optional tenant UUID — forwarded as `X-Tenant-ID` on the session client. */
  tenantId?: string;

  /**
   * Cedar resource the webhook maps to. Matched against
   * `resource == "<source>"` in a `permit(... action == "webhook.receive", ...)`
   * rule. Typical values: `"github"`, `"stripe"`, `"slack"`, `"linear"`.
   */
  source: string;

  /**
   * Non-human principal identity bound into the session JWT. Cedar sees
   * `context.user.id === serviceIdentity` and `context.user.trust === "service"`.
   * Example: `"github-webhook"`, `"stripe-webhook"`.
   */
  serviceIdentity: string;

  /**
   * Optional **human-readable origin** of the webhook — forwarded as the
   * `service_source` field on session start so it appears in audit as
   * `user_id=<serviceIdentity>, detail.service_source=<serviceSource>`.
   * Useful for distinguishing `main` vs `develop` GitHub hook installs, etc.
   */
  serviceSource?: string;

  /**
   * Cedar action string. Default: `"webhook.receive"`. Override when your
   * policy uses a different action vocabulary (e.g. `"webhook.github.push"`).
   */
  action?: string;

  /**
   * Called when Cedar denies the request. Default: respond 403 with a
   * structured JSON body.
   */
  onDeny?: (req: AgentumRequest, res: AgentumResponse, reason: string) => void;

  /**
   * Called when session mint or `isAllowed` throws (network / auth error).
   * Default: respond 503 — webhook-side fail-closed because most webhook
   * senders retry on 5xx, which is the recoverable behaviour.
   */
  onError?: (err: unknown, req: AgentumRequest, res: AgentumResponse, next: AgentumNext) => void;

  /** Max pooled service sessions. Default: 16. */
  maxPoolSize?: number;
}

// ── Service-session pool ────────────────────────────────────────────────────────

const DEFAULT_POOL_SIZE = 16;

/** LRU pool of service-identity sessions, keyed per (agentId, tenantId, service). */
class ServiceSessionPool {
  private readonly _pool = new Map<string, AgentumSession>();
  private readonly _inflight = new Map<string, Promise<AgentumSession>>();
  private readonly _maxSize: number;

  constructor(maxSize: number) {
    this._maxSize = Math.max(1, maxSize | 0);
  }

  private _get(key: string): AgentumSession | undefined {
    const s = this._pool.get(key);
    if (!s) return undefined;
    this._pool.delete(key);
    this._pool.set(key, s);
    return s;
  }

  private _evictIfFull(key: string): void {
    if (this._pool.size >= this._maxSize && !this._pool.has(key)) {
      const oldest = this._pool.keys().next().value;
      if (oldest !== undefined) {
        const evicted = this._pool.get(oldest);
        this._pool.delete(oldest);
        evicted?.close().catch(() => {});
      }
    }
  }

  async getOrCreate(key: string, create: () => Promise<AgentumSession>): Promise<AgentumSession> {
    const existing = this._get(key);
    if (existing) {
      if (!existing.isExpired()) return existing;
      this._pool.delete(key);
      existing.close().catch(() => {});
    }
    const inflight = this._inflight.get(key);
    if (inflight) return inflight;

    const promise = create()
      .then((session) => {
        this._inflight.delete(key);
        this._evictIfFull(key);
        this._pool.set(key, session);
        return session;
      })
      .catch((err) => {
        this._inflight.delete(key);
        throw err;
      });
    this._inflight.set(key, promise);
    return promise;
  }

  async closeAll(): Promise<void> {
    const sessions = [...this._pool.values()];
    this._pool.clear();
    await Promise.allSettled(sessions.map((s) => s.close()));
  }
}

// ── Public factory ─────────────────────────────────────────────────────────────

/**
 * Build the Express-compatible webhook-guard middleware. Returns a handler
 * with a `close()` method that drains the service-session pool. Call
 * `await guard.close()` on process shutdown.
 */
export function agentumWebhookGuard(
  opts: AgentumWebhookGuardOptions,
): AgentumMiddleware {
  const client = opts.runtime ?? opts.client;
  if (!client) {
    throw new AgentumError("agentumWebhookGuard: `runtime` (or `client`) is required");
  }
  if (!opts.agentId) {
    throw new AgentumError("agentumWebhookGuard: `agentId` is required");
  }
  if (!opts.source) {
    throw new AgentumError("agentumWebhookGuard: `source` is required");
  }
  if (!opts.serviceIdentity) {
    throw new AgentumError("agentumWebhookGuard: `serviceIdentity` is required");
  }

  const source = opts.source;
  const serviceIdentity = opts.serviceIdentity;
  const serviceSource = opts.serviceSource;
  const action = opts.action ?? "webhook.receive";
  const agentId = opts.agentId;
  const tenantId = opts.tenantId;

  const pool = new ServiceSessionPool(opts.maxPoolSize ?? DEFAULT_POOL_SIZE);

  const defaultOnDeny = (_req: AgentumRequest, res: AgentumResponse, reason: string): void => {
    res.status(403).json({ error: reason });
  };
  const onDeny = opts.onDeny ?? defaultOnDeny;
  const defaultOnError = (
    err: unknown,
    _req: AgentumRequest,
    res: AgentumResponse,
    _next: AgentumNext,
  ): void => {
    const message = err instanceof Error ? err.message : String(err);
    res.status(503).json({ error: "agentum_webhook_guard_error", message });
  };
  const onError = opts.onError ?? defaultOnError;

  const poolKey = `${agentId}:${tenantId ?? "system"}:svc:${serviceIdentity}`;

  const handler: AgentumMiddleware = Object.assign(
    async (req: AgentumRequest, res: AgentumResponse, next: AgentumNext): Promise<void> => {
      // 1. Pool / mint the service session
      let session: AgentumSession;
      try {
        session = await pool.getOrCreate(poolKey, () =>
          client.connectExisting(agentId, {
            skipPolicyCheck: true,
            user: serviceSource
              ? { service: serviceIdentity, source: serviceSource }
              : { service: serviceIdentity },
            ...(tenantId !== undefined ? { tenantId } : {}),
          }),
        );
      } catch (err) {
        onError(err, req, res, next);
        return;
      }

      // 2. Cedar gate
      let allowed: boolean;
      try {
        allowed = await session.isAllowed(action, source);
      } catch (err) {
        onError(err, req, res, next);
        return;
      }

      if (!allowed) {
        const reason = `Agentum: webhook ${source} denied by policy (${action})`;
        void session
          .ingestAuditEvent({
            event_type: "request_denied",
            detail: { action, resource: source, source: "webhook", service: serviceIdentity },
          })
          .catch(() => {});
        onDeny(req, res, reason);
        return;
      }

      // 3. Attach context so downstream handlers can call session.isAllowed
      //    for per-tool gating and session.ingestAuditEvent.
      const ctx: AgentumRequestContext = {
        session,
        agentId: session.agentId,
        sessionId: session.sessionId,
        service: serviceIdentity,
        ...(tenantId !== undefined ? { tenantId } : {}),
      };
      req.agentum = ctx;

      // 4. Audit the accepted inbound webhook
      void session
        .ingestAuditEvent({
          event_type: "webhook_receive",
          detail: {
            source,
            service: serviceIdentity,
            ...(serviceSource ? { service_source: serviceSource } : {}),
            method: req.method,
            path: req.path,
          },
        })
        .catch(() => {});

      next();
    },
    {
      async close(): Promise<void> {
        await pool.closeAll();
      },
    },
  );

  return handler;
}
