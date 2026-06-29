/**
 * `withAgentumWebhookGuard` — inbound webhook authorization HOF for Next.js
 * App Router route handlers.
 *
 * Mirrors the Express `agentumWebhookGuard` surface, adapted to Next.js's
 * handler-returns-`Response` contract. Runs in the **Node runtime**
 * (`export const runtime = "nodejs"`) because the service-session pool is
 * long-lived; Edge isolates may recycle between requests and invalidate the
 * pool.
 *
 * Flow:
 *   1. Pool/mint a service-identity session via `client.connectExisting(...)`
 *      with `user: { service: serviceIdentity, source?: serviceSource }`.
 *   2. Gate on `session.isAllowed("webhook.receive", source)`.
 *   3. On Allow: invoke the wrapped handler with a `WebhookContext` carrying
 *      the session, emit a `webhook_receive` audit event.
 *   4. On Deny: respond 403, emit `request_denied` audit event.
 *
 * @example
 * ```ts
 * // app/api/webhooks/github/route.ts
 * import { AgentumClient } from "@lupid/sdk";
 * import {
 *   createAgentumWebhookRuntime,
 * } from "@lupid/sdk/frameworks/nextjs";
 *
 * export const runtime = "nodejs";
 *
 * const agentum = createAgentumWebhookRuntime({
 *   runtime: new AgentumClient({ baseUrl: process.env.AGENTUM_BASE_URL!, apiKey: process.env.AGENTUM_API_KEY! }),
 *   agentId: process.env.AGENTUM_AGENT_ID!,
 * });
 *
 * export const POST = agentum.withAgentumWebhookGuard(
 *   { source: "github", serviceIdentity: "github-webhook" },
 *   async (req, ctx) => {
 *     // ctx.session is available for downstream tool gating
 *     return Response.json({ ok: true });
 *   },
 * );
 * ```
 */

import type { AgentumClient } from "../../client.js";
import { AgentumError } from "../../types.js";
import type { AgentumSession } from "../../session.js";
import type { NextRequestLike, RouteHandlerContext } from "./types.js";

const JSON_HEADERS = { "content-type": "application/json" };

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

// ── Options ────────────────────────────────────────────────────────────────────

export interface AgentumWebhookRuntimeOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  runtime: AgentumClient;
  /** Pre-registered agent ID that owns webhook endpoints. */
  agentId: string;
  /** Optional tenant UUID — forwarded as `X-Tenant-ID`. */
  tenantId?: string;
  /** Max pooled service sessions. Default: 16. */
  maxPoolSize?: number;
}

export interface AgentumWebhookGuardOptions {
  /** Cedar resource (e.g. `"github"`). Matches `resource == "<source>"`. */
  source: string;
  /** Service identity (e.g. `"github-webhook"`). Bound into JWT as `user.id`. */
  serviceIdentity: string;
  /** Human-readable origin — forwarded as `service_source` on session start. */
  serviceSource?: string;
  /** Cedar action. Default: `"webhook.receive"`. */
  action?: string;
  /**
   * Called when Cedar denies. Default: 403 JSON.
   */
  onDeny?: (req: NextRequestLike, reason: string) => Response | Promise<Response>;
  /**
   * Called when session mint or `isAllowed` throws. Default: 503 — webhook
   * senders retry on 5xx, which is the recoverable behaviour.
   */
  onError?: (req: NextRequestLike, err: unknown) => Response | Promise<Response>;
}

/** Context passed to the wrapped webhook handler on Allow. */
export interface WebhookContext extends RouteHandlerContext {
  agentum: {
    session: AgentumSession;
    agentId: string;
    sessionId: string;
    service: string;
    tenantId?: string;
  };
}

/** Wrapped webhook-handler signature. */
export type WebhookRouteHandler<Req extends NextRequestLike = NextRequestLike> = (
  req: Req,
  ctx: WebhookContext,
) => Promise<Response> | Response;

/** Long-lived runtime wrapping the service-session pool. */
export interface AgentumWebhookRuntime {
  withAgentumWebhookGuard<Req extends NextRequestLike = NextRequestLike>(
    opts: AgentumWebhookGuardOptions,
    handler: WebhookRouteHandler<Req>,
  ): (req: Req, ctx: RouteHandlerContext) => Promise<Response>;
  /** Release pooled sessions. Call on process shutdown. */
  close(): Promise<void>;
}

// ── Service-session pool ────────────────────────────────────────────────────────

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

/** Build the long-lived webhook runtime. Call once at module scope. */
export function createAgentumWebhookRuntime(
  opts: AgentumWebhookRuntimeOptions,
): AgentumWebhookRuntime {
  if (!opts.runtime) {
    throw new AgentumError("createAgentumWebhookRuntime: `runtime` is required");
  }
  if (!opts.agentId) {
    throw new AgentumError("createAgentumWebhookRuntime: `agentId` is required");
  }
  const client = opts.runtime;
  const agentId = opts.agentId;
  const tenantId = opts.tenantId;
  const pool = new ServiceSessionPool(opts.maxPoolSize ?? 16);

  return {
    withAgentumWebhookGuard<Req extends NextRequestLike = NextRequestLike>(
      guardOpts: AgentumWebhookGuardOptions,
      handler: WebhookRouteHandler<Req>,
    ): (req: Req, ctx: RouteHandlerContext) => Promise<Response> {
      if (!guardOpts.source) {
        throw new AgentumError("withAgentumWebhookGuard: `source` is required");
      }
      if (!guardOpts.serviceIdentity) {
        throw new AgentumError("withAgentumWebhookGuard: `serviceIdentity` is required");
      }

      const source = guardOpts.source;
      const serviceIdentity = guardOpts.serviceIdentity;
      const serviceSource = guardOpts.serviceSource;
      const action = guardOpts.action ?? "webhook.receive";
      const onDeny =
        guardOpts.onDeny ??
        ((_req: NextRequestLike, reason: string) => jsonResponse(403, { error: reason }));
      const onError =
        guardOpts.onError ??
        ((_req: NextRequestLike, err: unknown) => {
          const message = err instanceof Error ? err.message : String(err);
          return jsonResponse(503, { error: "agentum_webhook_guard_error", message });
        });

      const poolKey = `${agentId}:${tenantId ?? "system"}:svc:${serviceIdentity}`;

      return async (req: Req, _ctx: RouteHandlerContext): Promise<Response> => {
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
          return onError(req, err);
        }

        // 2. Cedar gate
        let allowed: boolean;
        try {
          allowed = await session.isAllowed(action, source);
        } catch (err) {
          return onError(req, err);
        }

        if (!allowed) {
          const reason = `Agentum: webhook ${source} denied by policy (${action})`;
          void session
            .ingestAuditEvent({
              event_type: "request_denied",
              detail: { action, resource: source, source: "webhook", service: serviceIdentity },
            })
            .catch(() => {});
          return onDeny(req, reason);
        }

        // 3. Audit the accepted inbound webhook
        void session
          .ingestAuditEvent({
            event_type: "webhook_receive",
            detail: {
              source,
              service: serviceIdentity,
              ...(serviceSource ? { service_source: serviceSource } : {}),
              method: req.method,
            },
          })
          .catch(() => {});

        // 4. Invoke the wrapped handler with the webhook context
        const webhookCtx: WebhookContext = {
          params: Promise.resolve({}),
          agentum: {
            session,
            agentId: session.agentId,
            sessionId: session.sessionId,
            service: serviceIdentity,
            ...(tenantId !== undefined ? { tenantId } : {}),
          },
        };
        return handler(req, webhookCtx);
      };
    },
    async close() {
      await pool.closeAll();
    },
  };
}
