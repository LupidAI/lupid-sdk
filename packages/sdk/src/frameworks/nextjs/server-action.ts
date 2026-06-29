/**
 * `withAgentumServerAction` — wrap a Next.js Server Action with Cedar
 * policy enforcement.
 *
 * Unlike route handlers, server actions have no request object: they receive
 * their own typed arguments (form data, primitives, etc.). Auth context must
 * be read inside the action itself — typically via `next/headers` (`cookies()`,
 * `headers()`). To avoid taking `next` as a runtime dep, the wrapper accepts
 * a caller-provided `getUser()` resolver and returns a `ServerActionGuardResult`
 * tagged union (ok / unauthenticated / forbidden / policy_check_failed).
 *
 * @example
 * ```ts
 * // app/actions.ts
 * "use server";
 *
 * import { cookies } from "next/headers";
 * import { agentum } from "@/lib/agentum"; // createAgentumRuntime(...)
 * import { withAgentumServerAction } from "@lupid/sdk/frameworks/nextjs";
 *
 * export const deleteOrder = withAgentumServerAction(
 *   agentum,
 *   {
 *     action: "http.delete",
 *     resource: "api.example.com",
 *     pathLike: (arg) => `/orders/${(arg as { orderId: string }).orderId}`,
 *     getUser: async () => {
 *       const email = (await cookies()).get("demo_user")?.value;
 *       return email ? { id: email, email } : null;
 *     },
 *   },
 *   async ({ orderId }: { orderId: string }) => {
 *     // ... the action body runs only on Allow
 *     return { deleted: orderId };
 *   },
 * );
 * ```
 *
 * The caller component checks `result.ok` before consuming `result.data`:
 *
 * ```tsx
 * const result = await deleteOrder({ orderId: "ord_1" });
 * if (!result.ok) {
 *   if (result.error === "unauthenticated") redirect("/login");
 *   return <div>Denied: {result.decision?.reason ?? "policy"}</div>;
 * }
 * return <div>Deleted: {result.data.deleted}</div>;
 * ```
 */

import type { PolicySimulateResponse } from "../../types.js";
import { DecisionCache, hashContext } from "../express/decision-cache.js";
import type {
  AgentumNextInternals,
  AgentumServerActionGuardOptions,
  GuardDecision,
  ServerActionGuardResult,
} from "./types.js";
import type { AgentumNextRuntime } from "./route-handler.js";
import type { FailMode } from "../express/types.js";
import {
  pdpObservabilityDetailRaw,
  pdpTopLevelFieldsRaw,
} from "../_pdp-observability.js";

/**
 * Wrap a Server Action with Cedar enforcement. Returns a function with the
 * same signature as the input action, but the return type is narrowed to
 * `ServerActionGuardResult<T>`.
 */
export function withAgentumServerAction<Args extends unknown[], T>(
  runtime: AgentumNextRuntime,
  opts: AgentumServerActionGuardOptions,
  action: (...args: Args) => Promise<T> | T,
): (...args: Args) => Promise<ServerActionGuardResult<T>> {
  const internals = runtime._internals;

  return async (...args: Args): Promise<ServerActionGuardResult<T>> => {
    // ── 1. Resolve user ────────────────────────────────────────────────────
    let user;
    try {
      user = await opts.getUser();
    } catch {
      return { ok: false, error: "policy_check_failed" };
    }
    if (user === null) return { ok: false, error: "unauthenticated" };

    // ── 2. Build Cedar inputs ──────────────────────────────────────────────
    const firstArg = args[0];
    const path =
      typeof opts.pathLike === "function"
        ? opts.pathLike(firstArg)
        : opts.pathLike ?? "/";
    const extra = opts.contextExtra ? opts.contextExtra(firstArg) : undefined;
    const cedarContext: Record<string, unknown> = { path, ...(extra ?? {}) };

    const failMode: FailMode = opts.failModeOverride ?? internals.failMode;
    const skipCache = opts.skipCache === true;
    const cache = internals.decisionCache;
    const breaker = internals.circuitBreaker;
    const health = internals.healthMonitor;

    const cacheKey = cache
      ? DecisionCache.key(user.id, opts.action, opts.resource, hashContext(cedarContext))
      : null;

    // ── 3. Cache check ─────────────────────────────────────────────────────
    if (cache && cacheKey && !skipCache) {
      const cached = cache.get(cacheKey);
      if (cached) return dispatch(toDecision(cached, "cache"), action, args, internals, opts);
    }

    // ── 4. Breaker / health short-circuit ──────────────────────────────────
    if (breaker && breaker.shouldSkip()) {
      return dispatch(
        fallback(failMode, cache, cacheKey, "breaker-open"),
        action,
        args,
        internals,
        opts,
      );
    }
    if (health && !health.reachable) {
      return dispatch(
        fallback(failMode, cache, cacheKey, "health-down"),
        action,
        args,
        internals,
        opts,
      );
    }

    // ── 5. Fresh simulatePolicy call ───────────────────────────────────────
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
      return dispatch(
        fallback(failMode, cache, cacheKey, ("fail-" + failMode) as GuardDecision["source"]),
        action,
        args,
        internals,
        opts,
      );
    }

    if (breaker) breaker.recordSuccess();
    if (cache && cacheKey) cache.put(cacheKey, result);
    return dispatch(toDecision(result, "network"), action, args, internals, opts);
  };
}

// ── Helpers (duplicated from route-handler.ts to keep exports minimal) ─────────

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

async function dispatch<Args extends unknown[], T>(
  decision: GuardDecision,
  action: (...args: Args) => Promise<T> | T,
  args: Args,
  internals: AgentumNextInternals,
  opts: AgentumServerActionGuardOptions,
): Promise<ServerActionGuardResult<T>> {
  if (decision.allowed) {
    const data = await action(...args);
    return { ok: true, data };
  }
  // Emit a best-effort request_denied audit before returning the
  // tagged-error result. policy_hash + decision_source land at the top
  // level (joinable with LocalPdpDecision); rule_id / reason go inside
  // `detail` via the raw helper. `decision.source` (guard-internal
  // breaker/cache trace) stays in `detail` — it is *not* the wire
  // `decision_source` field.
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
        framework: "nextjs.server-action",
        source: decision.source,
        ...detailObs,
      },
    })
    .catch(() => {});
  return { ok: false, error: "forbidden", decision };
}
