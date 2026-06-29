/**
 * Express.js middleware for Agentum multi-tenant agent IAM.
 *
 * Injects an authenticated `AgentumSession` into every request so route
 * handlers can call `req.agentum.session.isAllowed(action, resource)` — or,
 * more typically, combine this middleware with `agentumGuard()` for
 * declarative per-route Cedar enforcement.
 *
 * @example
 * ```ts
 * import express from "express";
 * import { AgentumClient } from "@lupid/sdk";
 * import { agentumMiddleware, agentumGuard } from "@lupid/sdk/frameworks/express";
 *
 * const app = express();
 * const runtime = new AgentumClient({ baseUrl: BASE_URL, apiKey: API_KEY });
 *
 * app.use(agentumMiddleware({
 *   runtime,
 *   agentId: AGENT_ID,
 *   userFromRequest: (req) => USERS[req.signedCookies.user] ?? null,
 * }));
 *
 * app.get("/api/orders",
 *   agentumGuard({ action: "http.get", resource: "api.example.com", pathLike: "/orders*" }),
 *   (req, res) => res.json({ orders: [...] })
 * );
 * ```
 */

import { AgentumError } from "../../types.js";
import type { AgentumSession } from "../../session.js";
import { CircuitBreaker } from "./circuit-breaker.js";
import { DecisionCache } from "./decision-cache.js";
import { HealthMonitor } from "./health-check.js";
import type {
  AgentumMiddleware,
  AgentumMiddlewareOptions,
  AgentumNext,
  AgentumRequest,
  AgentumRequestContext,
  AgentumRequestInternals,
  AgentumResponse,
  AgentumUser,
  FailMode,
  ResolvedAgentIdentity,
} from "./types.js";

// Re-exports — `agentumGuard`, types, helper classes — so consumers can
// `import ... from "@lupid/sdk/frameworks/express"`.
export { agentumGuard } from "./guard.js";
export { agentumExpressAdapter } from "./dimensions.js";
export {
  autoRegisterMiddleware,
  type AutoRegisterOptions,
} from "./auto-register.js";
export { agentumWebhookGuard } from "./webhook-guard.js";
export type { AgentumWebhookGuardOptions } from "./webhook-guard.js";
export { DecisionCache, hashContext } from "./decision-cache.js";
export { CircuitBreaker } from "./circuit-breaker.js";
export { HealthMonitor } from "./health-check.js";
export type {
  AgentumGuardOptions,
  AgentumMiddleware,
  AgentumMiddlewareOptions,
  AgentumNext,
  AgentumRequest,
  AgentumRequestContext,
  AgentumRequestHandler,
  AgentumResponse,
  AgentumUser,
  CircuitBreakerOptions,
  DecisionCacheOptions,
  FailMode,
  GuardDecision,
  HealthCheckOptions,
  ResolvedAgentIdentity,
  SessionCacheOptions,
} from "./types.js";

// ── Session LRU pool ───────────────────────────────────────────────────────────

const DEFAULT_SESSION_POOL_SIZE = 256;

class SessionPool {
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
 * Create the per-app middleware. Returns an Express-compatible handler with
 * a `close()` method that tears down the background health monitor. Always
 * `await middleware.close()` on shutdown (SIGTERM / SIGINT) in long-running
 * processes, or Node's event loop will be held open by the interval timer.
 */
export function agentumMiddleware(opts: AgentumMiddlewareOptions): AgentumMiddleware {
  const client = opts.runtime ?? opts.client;
  if (!client) {
    throw new AgentumError("agentumMiddleware: `runtime` (or legacy `client`) is required");
  }
  const resolveAgent = opts.resolveAgent;
  const userFromRequest = opts.userFromRequest;
  const tokenFromRequest = opts.tokenFromRequest;
  const boundAgentId = opts.agentId;

  if (userFromRequest && tokenFromRequest) {
    throw new AgentumError(
      "agentumMiddleware: `userFromRequest` and `tokenFromRequest` are mutually exclusive",
    );
  }
  if (!resolveAgent && !boundAgentId) {
    throw new AgentumError(
      "agentumMiddleware: either `agentId` (with optional `userFromRequest`) or `resolveAgent` must be provided",
    );
  }

  const mode = opts.mode ?? "enforce";
  const failMode: FailMode = opts.failMode ?? "closed";

  // ── Session pool ─────────────────────────────────────────────────────────────
  const poolMaxSize =
    opts.sessionCache?.maxSize ?? opts.maxPoolSize ?? DEFAULT_SESSION_POOL_SIZE;
  const pool = new SessionPool(poolMaxSize);

  // ── Decision cache ───────────────────────────────────────────────────────────
  const dcOpts = opts.decisionCache ?? {};
  const dcEnabled = dcOpts.enabled !== false;
  const decisionCache = dcEnabled
    ? new DecisionCache({
        maxSize: dcOpts.maxSize ?? 10_000,
        ttlMs: dcOpts.ttlMs ?? 15_000,
      })
    : null;

  // ── Circuit breaker ──────────────────────────────────────────────────────────
  const cbOpts = opts.circuitBreaker ?? {};
  const cbEnabled = cbOpts.enabled !== false;
  const circuitBreaker = cbEnabled
    ? new CircuitBreaker({
        failureThreshold: cbOpts.failureThreshold ?? 5,
        resetTimeoutMs: cbOpts.resetTimeoutMs ?? 30_000,
      })
    : null;

  // ── Health monitor ───────────────────────────────────────────────────────────
  const hcOpts = opts.healthCheck ?? {};
  const hcEnabled = hcOpts.enabled !== false;
  const healthMonitor = hcEnabled
    ? new HealthMonitor({
        client,
        intervalMs: hcOpts.intervalMs ?? 30_000,
      })
    : null;

  // ── Handlers ─────────────────────────────────────────────────────────────────
  const defaultOnDeny = (_req: AgentumRequest, res: AgentumResponse, _next: AgentumNext, reason: string): void => {
    res.status(403).json({ error: reason });
  };
  const onDeny = opts.onDeny ?? defaultOnDeny;
  const defaultOnUnauth = (_req: AgentumRequest, res: AgentumResponse, _next: AgentumNext): void => {
    res.status(401).json({ error: "unauthenticated" });
  };
  const onUnauthenticated = opts.onUnauthenticated ?? defaultOnUnauth;
  const onSessionMintError =
    opts.onSessionMintError ??
    ((err, _req, _res, next) => {
      next(err);
    });

  const handler: AgentumMiddleware = Object.assign(
    async (req: AgentumRequest, res: AgentumResponse, next: AgentumNext): Promise<void> => {
      // ── 0. Idempotent guard (G-F fix) ────────────────────────────────────────
      // When this middleware is mounted on nested routers (e.g.
      // `app.use(agentumMw); router.use(agentumMw)` — happens naturally in
      // LibreChat where `agents/index.js` and the inner `v1` router both
      // wrap auth+telemetry), Express invokes it once per mount in the
      // request chain. Without this guard each pass would mint a fresh
      // session, emit a duplicate `request_start` audit, and re-run the
      // legacy enforce-mode policy check — producing 3+ DB writes for one
      // logical request and inflating the sessions table at scale.
      //
      // The session pool's LRU partly absorbs this (same poolKey reuses the
      // session), but `ingestAuditEvent` and `isAllowed` still fire each
      // time. Stashing the resolved context on `req.agentum` and short-
      // circuiting subsequent passes makes the middleware truly per-request
      // idempotent regardless of how many routers it's mounted on.
      if (req.agentum) {
        next();
        return;
      }

      // ── 1. Resolve user / agent identity ─────────────────────────────────────
      let user: AgentumUser | null = null;
      let userToken: string | null = null;
      if (userFromRequest) {
        try {
          user = await userFromRequest(req);
        } catch (err) {
          next(err);
          return;
        }
        if (user === null) {
          onUnauthenticated(req, res, next);
          return;
        }
      } else if (tokenFromRequest) {
        try {
          userToken = await tokenFromRequest(req);
        } catch (err) {
          next(err);
          return;
        }
        if (userToken === null) {
          onUnauthenticated(req, res, next);
          return;
        }
      }

      let identity: ResolvedAgentIdentity;
      if (resolveAgent) {
        try {
          identity = await resolveAgent(req);
        } catch (err) {
          next(err);
          return;
        }
      } else {
        identity = { agentId: boundAgentId! };
      }

      const tenantId = identity.tenantId;

      // Pool key combines agent + tenant + user (so two users of the same agent
      // get distinct sessions — required for user-scoped JWT claims). For
      // verified-mode tokens, the last 32 chars of the signature portion act
      // as a stable-enough fingerprint for LRU keying (JWT signatures are
      // unique per-user-per-token).
      const userKey = user
        ? `${user.id}`
        : userToken
          ? `tok:${userToken.slice(-32)}`
          : "anon";
      const agentKey = identity.agentId ?? identity.name ?? "unknown";
      const poolKey = `${agentKey}:${tenantId ?? "system"}:${userKey}`;

      // ── 2. Pool / mint session ───────────────────────────────────────────────
      let session: AgentumSession;
      try {
        session = await pool.getOrCreate(poolKey, () => {
          const userBinding = user
            ? { user: { id: user.id, email: user.email } as const }
            : userToken
              ? { user: { token: userToken } as const }
              : {};
          if (identity.agentId) {
            return client.connectExisting(identity.agentId, {
              skipPolicyCheck: true,
              ...(tenantId !== undefined ? { tenantId } : {}),
              ...userBinding,
            });
          }
          return client.connect({
            name: identity.name ?? "express-agent",
            owner_email: identity.ownerEmail ?? "express@agentum.local",
            purpose: identity.purpose ?? "express-middleware",
            skipPolicyCheck: true,
            ...(tenantId !== undefined ? { tenantId } : {}),
            ...userBinding,
          });
        });
      } catch (err) {
        onSessionMintError(err, req, res, next);
        return;
      }

      // ── 3. Inject request context ────────────────────────────────────────────
      const internals: AgentumRequestInternals = {
        agentId: session.agentId,
        ...(user ? { user } : {}),
        decisionCache,
        circuitBreaker,
        healthMonitor,
        failMode,
      };
      const ctx: AgentumRequestContext = {
        session,
        agentId: session.agentId,
        sessionId: session.sessionId,
        ...(tenantId !== undefined ? { tenantId } : {}),
        ...(user ? { user } : {}),
        _internals: internals,
      };
      req.agentum = ctx;

      // ── 4. Best-effort request_start audit ───────────────────────────────────
      void session
        .ingestAuditEvent({
          event_type: "request_start",
          detail: { method: req.method, path: req.path },
        })
        .catch(() => {});

      // ── 5. Legacy blanket enforce-mode gate ──────────────────────────────────
      // Kept for back-compat with the pre-1.5.1 middleware. New code should
      // use `agentumGuard()` per-route instead.
      if (mode === "enforce") {
        const action = `http.${req.method.toLowerCase()}`;
        let allowed: boolean;
        try {
          allowed = await session.isAllowed(action, req.path);
        } catch {
          allowed = false;
        }
        if (!allowed) {
          const reason = `Agentum: request denied by policy (${action} ${req.path})`;
          void session
            .ingestAuditEvent({
              event_type: "request_denied",
              detail: { action, path: req.path },
            })
            .catch(() => {});
          onDeny(req, res, next, reason);
          return;
        }
      }

      // ── 6. Request_end on actual response finish ─────────────────────────────
      res.on("finish", () => {
        void session
          .ingestAuditEvent({
            event_type: "request_end",
            detail: { method: req.method, path: req.path, status_code: res.statusCode },
          })
          .catch(() => {});
      });

      next();
    },
    {
      async close(): Promise<void> {
        healthMonitor?.stop();
        await pool.closeAll();
      },
    },
  );

  return handler;
}
