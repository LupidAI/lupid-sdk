/**
 * Fastify plugin for Agentum multi-tenant agent IAM.
 *
 * Registers a `preHandler` hook that mints (or reuses) a per-user
 * `AgentumSession` and attaches it to `request.agentum`. Pair with
 * `agentumGuard()` on individual routes for declarative Cedar enforcement.
 *
 * @example
 * ```ts
 * import Fastify from "fastify";
 * import { AgentumClient } from "@lupid/sdk";
 * import { agentumPlugin, agentumGuard } from "@lupid/sdk/frameworks/fastify";
 *
 * const app = Fastify();
 * const runtime = new AgentumClient({ baseUrl: BASE_URL, apiKey: API_KEY });
 *
 * const plugin = agentumPlugin();
 * await app.register(plugin, {
 *   runtime,
 *   agentId: AGENT_ID,
 *   userFromRequest: (req) => USERS[req.headers["x-demo-user"] as string] ?? null,
 * });
 *
 * app.get(
 *   "/api/orders",
 *   { preHandler: agentumGuard({ action: "http.get", resource: "api.example.com" }) },
 *   async () => ({ orders: [] })
 * );
 *
 * app.addHook("onClose", async () => { await plugin.close(); });
 * ```
 */

import type { AgentumClient } from "../../client.js";
import { AgentumError } from "../../types.js";
import type { AgentumSession } from "../../session.js";
import { CircuitBreaker } from "../express/circuit-breaker.js";
import { DecisionCache } from "../express/decision-cache.js";
import { HealthMonitor } from "../express/health-check.js";
import type {
  AgentumFastifyPlugin,
  AgentumFastifyPluginOptions,
  AgentumRequestContext,
  AgentumRequestInternals,
  AgentumUser,
  FailMode,
  FastifyInstanceLike,
  FastifyReplyLike,
  FastifyRequestLike,
  ResolvedAgentIdentity,
} from "./types.js";

export { agentumGuard } from "./guard.js";
export { DecisionCache, hashContext } from "../express/decision-cache.js";
export { CircuitBreaker } from "../express/circuit-breaker.js";
export { HealthMonitor } from "../express/health-check.js";

export type {
  AgentumFastifyPlugin,
  AgentumFastifyPluginOptions,
  AgentumGuardFastifyOptions,
  AgentumRequestContext,
  AgentumRequestInternals,
  AgentumUser,
  CircuitBreakerOptions,
  DecisionCacheOptions,
  FailMode,
  FastifyInstanceLike,
  FastifyPreHandler,
  FastifyReplyLike,
  FastifyRequestLike,
  GuardDecision,
  HealthCheckOptions,
  ResolvedAgentIdentity,
  SessionCacheOptions,
} from "./types.js";

// ── Session LRU pool (duplicated from Express for independence) ───────────────

const DEFAULT_SESSION_POOL_SIZE = 256;

class SessionPool {
  private readonly _pool = new Map<string, AgentumSession>();
  private readonly _inflight = new Map<string, Promise<AgentumSession>>();
  private readonly _maxSize: number;

  constructor(maxSize: number) {
    this._maxSize = Math.max(1, maxSize | 0);
  }

  private _getLru(key: string): AgentumSession | undefined {
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
    const existing = this._getLru(key);
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
 * Build the Agentum Fastify plugin. The returned value is a Fastify-compatible
 * plugin function AND exposes a `close()` method that tears down the session
 * pool + background health monitor. Call `close()` on `fastify.addHook("onClose", ...)`.
 */
export function agentumPlugin(): AgentumFastifyPlugin {
  let sessionPool: SessionPool | null = null;
  let healthMonitor: HealthMonitor | null = null;

  const plugin = Object.assign(
    async (fastify: FastifyInstanceLike, opts: AgentumFastifyPluginOptions): Promise<void> => {
      const client: AgentumClient | undefined = opts.runtime ?? opts.client;
      if (!client) {
        throw new AgentumError("agentumPlugin: `runtime` (or legacy `client`) is required");
      }
      const boundAgentId = opts.agentId;
      const resolveAgent = opts.resolveAgent;
      if (!boundAgentId && !resolveAgent) {
        throw new AgentumError(
          "agentumPlugin: either `agentId` or `resolveAgent` must be provided",
        );
      }

      const failMode: FailMode = opts.failMode ?? "closed";

      const poolMaxSize =
        opts.sessionCache?.maxSize ?? opts.maxPoolSize ?? DEFAULT_SESSION_POOL_SIZE;
      sessionPool = new SessionPool(poolMaxSize);

      const dcOpts = opts.decisionCache ?? {};
      const dcEnabled = dcOpts.enabled !== false;
      const decisionCache = dcEnabled
        ? new DecisionCache({ maxSize: dcOpts.maxSize ?? 10_000, ttlMs: dcOpts.ttlMs ?? 15_000 })
        : null;

      const cbOpts = opts.circuitBreaker ?? {};
      const cbEnabled = cbOpts.enabled !== false;
      const circuitBreaker = cbEnabled
        ? new CircuitBreaker({
            failureThreshold: cbOpts.failureThreshold ?? 5,
            resetTimeoutMs: cbOpts.resetTimeoutMs ?? 30_000,
          })
        : null;

      const hcOpts = opts.healthCheck ?? {};
      const hcEnabled = hcOpts.enabled !== false;
      healthMonitor = hcEnabled
        ? new HealthMonitor({ client, intervalMs: hcOpts.intervalMs ?? 30_000 })
        : null;

      const userFromRequest = opts.userFromRequest;
      const onUnauthenticated =
        opts.onUnauthenticated ??
        ((_req: FastifyRequestLike, reply: FastifyReplyLike) => {
          reply.code(401).send({ error: "unauthenticated" });
        });
      const onSessionMintError =
        opts.onSessionMintError ??
        ((err: unknown, _req: FastifyRequestLike, reply: FastifyReplyLike) => {
          reply
            .code(502)
            .send({ error: "agentum_session_mint_failed", message: (err as Error)?.message ?? String(err) });
        });

      // Best-effort decorate — tolerated when the Fastify instance doesn't
      // support the call (older versions, stubs in tests).
      try {
        fastify.decorateRequest?.("agentum", null);
      } catch {
        /* ignore — decoration is purely ergonomic */
      }

      const preHandler = async (
        req: FastifyRequestLike,
        reply: FastifyReplyLike,
      ): Promise<void> => {
          // ── 1. Resolve user / agent ─────────────────────────────────────────
          let user: AgentumUser | null = null;
          if (userFromRequest) {
            try {
              user = await userFromRequest(req);
            } catch (err) {
              reply.code(500).send({
                error: "user_resolution_failed",
                message: (err as Error)?.message ?? String(err),
              });
              return;
            }
            if (user === null) {
              onUnauthenticated(req, reply);
              return;
            }
          }

          let identity: ResolvedAgentIdentity;
          if (resolveAgent) {
            try {
              identity = await resolveAgent(req);
            } catch (err) {
              reply.code(500).send({
                error: "agent_resolution_failed",
                message: (err as Error)?.message ?? String(err),
              });
              return;
            }
          } else {
            identity = { agentId: boundAgentId! };
          }
          const tenantId = identity.tenantId;

          // ── 2. Pool / mint session ───────────────────────────────────────────
          const userKey = user ? `${user.id}` : "anon";
          const agentKey = identity.agentId ?? identity.name ?? "unknown";
          const poolKey = `${agentKey}:${tenantId ?? "system"}:${userKey}`;

          let session: AgentumSession;
          try {
            session = await sessionPool!.getOrCreate(poolKey, () => {
              if (identity.agentId) {
                return client.connectExisting(identity.agentId, {
                  skipPolicyCheck: true,
                  ...(tenantId !== undefined ? { tenantId } : {}),
                  ...(user ? { user: { id: user.id, email: user.email } } : {}),
                });
              }
              return client.connect({
                name: identity.name ?? "fastify-agent",
                owner_email: identity.ownerEmail ?? "fastify@agentum.local",
                purpose: identity.purpose ?? "fastify-plugin",
                skipPolicyCheck: true,
                ...(tenantId !== undefined ? { tenantId } : {}),
                ...(user ? { user: { id: user.id, email: user.email } } : {}),
              });
            });
          } catch (err) {
            onSessionMintError(err, req, reply);
            return;
          }

          // ── 3. Inject request context ────────────────────────────────────────
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

          // ── 4. Best-effort request_start audit ───────────────────────────────
          const method = req.method;
          const path = stripQuery(req.url);
          void session
            .ingestAuditEvent({ event_type: "request_start", detail: { method, path } })
            .catch(() => {});
      };

      fastify.addHook("preHandler", preHandler as (...args: unknown[]) => unknown);
    },
    {
      async close(): Promise<void> {
        healthMonitor?.stop();
        await sessionPool?.closeAll();
      },
    },
  ) as AgentumFastifyPlugin;

  return plugin;
}

function stripQuery(url: string): string {
  const q = url.indexOf("?");
  return q >= 0 ? url.slice(0, q) : url;
}

// Drop-in auto-register preset. Mirrors Express's `autoRegisterMiddleware`.
// Wraps `agentumPlugin` with env-driven lazy `ensureAgent()` resolution so
// customer code drops to ~3 LOC.
export {
  autoRegisterPlugin,
  type AutoRegisterPluginOptions,
} from "./auto-register.js";
