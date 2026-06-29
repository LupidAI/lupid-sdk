/**
 * `withAgentumGuard` — per-route Cedar policy enforcement for App Router
 * route handlers (`app/api/.../route.ts`).
 *
 * Intended to run in the **Node runtime** (`export const runtime = "nodejs"`)
 * because it holds long-lived state (decision cache, circuit breaker, health
 * monitor). If you run it in the Edge runtime it still works, but the cache
 * and breaker state reset on each new isolate — you get no resilience
 * benefit there.
 *
 * @example
 * ```ts
 * // app/api/orders/route.ts
 * import { AgentumClient } from "@lupid/sdk";
 * import { createAgentumRuntime, withAgentumGuard } from "@lupid/sdk/frameworks/nextjs";
 *
 * export const runtime = "nodejs";
 *
 * const agentum = createAgentumRuntime({
 *   runtime: new AgentumClient({ baseUrl: process.env.AGENTUM_BASE_URL!, apiKey: process.env.AGENTUM_API_KEY! }),
 *   agentId: process.env.AGENTUM_AGENT_ID!,
 * });
 *
 * const userFromRequest = (req: NextRequestLike) => {
 *   const email = req.headers.get("x-demo-user");
 *   return email ? { id: email, email } : null;
 * };
 *
 * export const GET = agentum.withAgentumGuard(
 *   { action: "http.get", resource: "api.example.com", userFromRequest },
 *   async (req) => Response.json({ orders: [] }),
 * );
 * ```
 */

import { AgentumError } from "../../types.js";
import type { PolicySimulateResponse } from "../../types.js";
import { DecisionCache, hashContext } from "../express/decision-cache.js";
import { CircuitBreaker } from "../express/circuit-breaker.js";
import { HealthMonitor } from "../express/health-check.js";
import type {
  AgentumGuardNextOptions,
  AgentumNextInternals,
  AgentumNextRuntimeOptions,
  GuardDecision,
  NextRequestLike,
  NextRouteHandler,
  RouteHandlerContext,
} from "./types.js";
import type { FailMode } from "../express/types.js";
import {
  pdpObservabilityDetailRaw,
  pdpTopLevelFieldsRaw,
} from "../_pdp-observability.js";

const JSON_HEADERS = { "content-type": "application/json" };

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * Holder for the per-app Agentum runtime. Build once at module scope, reuse
 * across all route handlers.
 *
 * `close()` tears down the background health monitor — call on process
 * shutdown or Node will hold the event loop open via the interval timer.
 */
export interface AgentumNextRuntime {
  /** @internal */
  readonly _internals: AgentumNextInternals;
  /** Wrap a route handler with Cedar enforcement. */
  withAgentumGuard<
    Req extends NextRequestLike = NextRequestLike,
    Ctx extends RouteHandlerContext = RouteHandlerContext,
  >(
    opts: AgentumGuardNextOptions,
    handler: NextRouteHandler<Req, Ctx>,
  ): NextRouteHandler<Req, Ctx>;
  /** Release background resources (health-monitor interval). */
  close(): Promise<void>;
}

/**
 * Create the long-lived runtime object. Call once at module scope and reuse.
 *
 * The returned object exposes `withAgentumGuard`, which wraps App Router
 * route handlers with Cedar enforcement. It also composes a decision cache,
 * circuit breaker, and health monitor — matching the semantics of
 * `@lupid/sdk/frameworks/express`.
 */
export function createAgentumRuntime(opts: AgentumNextRuntimeOptions): AgentumNextRuntime {
  if (!opts.runtime) {
    throw new AgentumError("createAgentumRuntime: `runtime` is required");
  }
  if (!opts.agentId) {
    throw new AgentumError("createAgentumRuntime: `agentId` is required");
  }

  const dcOpts = opts.decisionCache ?? {};
  const dcEnabled = dcOpts.enabled !== false;
  const decisionCache = dcEnabled
    ? new DecisionCache({
        maxSize: dcOpts.maxSize ?? 10_000,
        ttlMs: dcOpts.ttlMs ?? 15_000,
      })
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
  const healthMonitor = hcEnabled
    ? new HealthMonitor({
        client: opts.runtime,
        intervalMs: hcOpts.intervalMs ?? 30_000,
      })
    : null;

  const internals: AgentumNextInternals = {
    client: opts.runtime,
    agentId: opts.agentId,
    tenantId: opts.tenantId,
    decisionCache,
    circuitBreaker,
    healthMonitor,
    failMode: opts.failMode ?? "closed",
  };

  const runtime: AgentumNextRuntime = {
    _internals: internals,
    withAgentumGuard<
      Req extends NextRequestLike = NextRequestLike,
      Ctx extends RouteHandlerContext = RouteHandlerContext,
    >(
      guardOpts: AgentumGuardNextOptions,
      handler: NextRouteHandler<Req, Ctx>,
    ): NextRouteHandler<Req, Ctx> {
      return wrapHandler<Req, Ctx>(internals, guardOpts, handler);
    },
    async close() {
      internals.healthMonitor?.stop();
    },
  };
  return runtime;
}

// ── Core wrapper ───────────────────────────────────────────────────────────────

function wrapHandler<Req extends NextRequestLike, Ctx extends RouteHandlerContext>(
  internals: AgentumNextInternals,
  opts: AgentumGuardNextOptions,
  handler: NextRouteHandler<Req, Ctx>,
): NextRouteHandler<Req, Ctx> {
  const onDeny =
    opts.onDeny ??
    ((decision) =>
      jsonResponse(403, {
        error: "forbidden",
        rule_id: decision.rule_id,
        reason: decision.reason,
        source: decision.source,
      }));
  const onUnauthenticated =
    opts.onUnauthenticated ?? (() => jsonResponse(401, { error: "unauthenticated" }));

  return async (req, ctx): Promise<Response> => {
    // ── 1. Resolve user ─────────────────────────────────────────────────────
    let user;
    try {
      user = await opts.userFromRequest(req);
    } catch (err) {
      return jsonResponse(500, {
        error: "user_resolution_failed",
        message: (err as Error)?.message ?? String(err),
      });
    }
    if (user === null) return onUnauthenticated(req);

    // ── 2. Build Cedar inputs ───────────────────────────────────────────────
    const path =
      typeof opts.pathLike === "function"
        ? opts.pathLike(req)
        : opts.pathLike ?? defaultPath(req);
    const extra = opts.contextExtra ? opts.contextExtra(req) : undefined;
    const cedarContext: Record<string, unknown> = { path, ...(extra ?? {}) };

    const failMode: FailMode = opts.failModeOverride ?? internals.failMode;
    const skipCache = opts.skipCache === true;
    const cache = internals.decisionCache;
    const breaker = internals.circuitBreaker;
    const health = internals.healthMonitor;

    const cacheKey = cache
      ? DecisionCache.key(user.id, opts.action, opts.resource, hashContext(cedarContext))
      : null;

    // ── 3. Cache check ──────────────────────────────────────────────────────
    if (cache && cacheKey && !skipCache) {
      const cached = cache.get(cacheKey);
      if (cached)
        return dispatch<Req, Ctx>(
          toDecision(cached, "cache"),
          req,
          ctx,
          handler,
          onDeny,
          internals,
          opts,
        );
    }

    // ── 4. Breaker / health short-circuit ───────────────────────────────────
    if (breaker && breaker.shouldSkip()) {
      return dispatch<Req, Ctx>(
        fallback(failMode, cache, cacheKey, "breaker-open"),
        req,
        ctx,
        handler,
        onDeny,
        internals,
        opts,
      );
    }
    if (health && !health.reachable) {
      return dispatch<Req, Ctx>(
        fallback(failMode, cache, cacheKey, "health-down"),
        req,
        ctx,
        handler,
        onDeny,
        internals,
        opts,
      );
    }

    // ── 5. Fresh simulatePolicy call ────────────────────────────────────────
    let result: PolicySimulateResponse;
    try {
      result = await internals.client.simulatePolicy({
        agent_id: internals.agentId,
        action: opts.action,
        resource: opts.resource,
        context: cedarContext,
        user: { id: user.id, email: user.email, trust: user.trust ?? "trusted" },
      });
    } catch (_err) {
      if (breaker) breaker.recordFailure();
      return dispatch<Req, Ctx>(
        fallback(failMode, cache, cacheKey, ("fail-" + failMode) as GuardDecision["source"]),
        req,
        ctx,
        handler,
        onDeny,
        internals,
        opts,
      );
    }

    if (breaker) breaker.recordSuccess();
    if (cache && cacheKey) cache.put(cacheKey, result);
    return dispatch<Req, Ctx>(
      toDecision(result, "network"),
      req,
      ctx,
      handler,
      onDeny,
      internals,
      opts,
    );
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function defaultPath(req: NextRequestLike): string {
  if (req.nextUrl) return req.nextUrl.pathname;
  try {
    return new URL(req.url).pathname;
  } catch {
    return "/";
  }
}

function toDecision(res: PolicySimulateResponse, source: GuardDecision["source"]): GuardDecision {
  return {
    allowed: res.outcome === "Allow",
    outcome: res.outcome,
    rule_id: res.rule_id,
    reason: res.reason,
    source,
    // Preserve policy_hash / decision_source from the simulate response
    // so dispatch() can thread them into request_denied audits.
    ...(res.policy_hash !== undefined ? { policy_hash: res.policy_hash } : {}),
    ...(res.decision_source !== undefined ? { decision_source: res.decision_source } : {}),
  };
}

function fallback(
  mode: FailMode,
  cache: DecisionCache | null,
  cacheKey: string | null,
  source: GuardDecision["source"],
): GuardDecision {
  if (mode === "open") {
    return { allowed: true, outcome: "Allow", rule_id: null, reason: "fail_open", source };
  }
  if (mode === "cached" && cache && cacheKey) {
    const stale = cache.getStale(cacheKey);
    if (stale) {
      return {
        allowed: stale.outcome === "Allow",
        outcome: stale.outcome,
        rule_id: stale.rule_id,
        reason: stale.reason,
        source,
      };
    }
  }
  return { allowed: false, outcome: "Deny", rule_id: null, reason: "fail_closed", source };
}

async function dispatch<Req extends NextRequestLike, Ctx extends RouteHandlerContext>(
  decision: GuardDecision,
  req: Req,
  ctx: Ctx,
  handler: NextRouteHandler<Req, Ctx>,
  onDeny: NonNullable<AgentumGuardNextOptions["onDeny"]>,
  internals: AgentumNextInternals,
  opts: AgentumGuardNextOptions,
): Promise<Response> {
  if (decision.allowed) return handler(req, ctx);
  // Emit a best-effort request_denied audit before invoking onDeny.
  // policy_hash + decision_source land at the top level (joinable with
  // LocalPdpDecision); rule_id / reason go inside `detail` via the raw
  // helper. `decision.source` (guard-internal breaker/cache trace) stays
  // in `detail` — it is *not* the wire `decision_source` field.
  const topObs = pdpTopLevelFieldsRaw({
    ...(decision.policy_hash !== undefined ? { policy_hash: decision.policy_hash } : {}),
    ...(decision.decision_source !== undefined
      ? { decision_source: decision.decision_source }
      : {}),
  });
  const detailObs = pdpObservabilityDetailRaw({
    rule_id: decision.rule_id,
    reason: decision.reason,
  });
  void internals.client
    .ingestAuditEvent({
      event_type: "request_denied",
      outcome: "deny",
      agent_id: internals.agentId,
      // TODO: AgentumNextRuntimeOptions does not carry a `sessionId`
      // today; widening the options bag is deferred. Emit empty string
      // so the audit row is queryable by agent_id; backfill later.
      session_id: "",
      ...topObs,
      detail: {
        action: opts.action,
        resource: opts.resource,
        framework: "nextjs.route-handler",
        source: decision.source,
        ...detailObs,
      },
    })
    .catch(() => {});
  return onDeny(decision, req);
}
