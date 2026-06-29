/**
 * agentumGuard — per-route Cedar enforcement for Fastify.
 *
 * Returns a Fastify `preHandler`-compatible async function that either
 * resolves silently (Allow) or calls `reply.send()` with a 403 body (Deny).
 * Fastify short-circuits the route when the reply is sent in a hook.
 */

import { DecisionCache, hashContext } from "../express/decision-cache.js";
import type {
  AgentumGuardFastifyOptions,
  FastifyPreHandler,
  FastifyReplyLike,
  FastifyRequestLike,
  FailMode,
  GuardDecision,
} from "./types.js";
import type { PolicySimulateResponse } from "../../types.js";
import {
  AgentumHitlDeniedError,
  AgentumHitlTimeoutError,
  parseHitlAdvice,
} from "../../types.js";
import type {
  HitlRequestInfo,
  HitlRequestOverride,
} from "../express/types.js";
import {
  pdpObservabilityDetailRaw,
  pdpTopLevelFieldsRaw,
} from "../_pdp-observability.js";

export function agentumGuard(opts: AgentumGuardFastifyOptions): FastifyPreHandler {
  return async (req, reply): Promise<void> => {
    const ctx = req.agentum;
    if (!ctx || !ctx._internals) {
      reply.code(500).send({
        error: "agentum_plugin_missing",
        hint: "agentumPlugin() must be registered before agentumGuard() is used",
      });
      return;
    }

    const internals = ctx._internals;
    const action = opts.action;
    const resource = opts.resource;
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
    const user = internals.user;

    const cacheKey =
      cache && user
        ? DecisionCache.key(user.id, action, resource, hashContext(cedarContext))
        : null;

    if (cache && cacheKey && !skipCache) {
      const cached = cache.get(cacheKey);
      if (cached) return dispatch(toDecision(cached, "cache"), req, reply, opts, ctx);
    }

    if (breaker && breaker.shouldSkip()) {
      return dispatch(fallback(failMode, cache, cacheKey, "breaker-open"), req, reply, opts, ctx);
    }
    if (health && !health.reachable) {
      return dispatch(fallback(failMode, cache, cacheKey, "health-down"), req, reply, opts, ctx);
    }

    let result: PolicySimulateResponse;
    try {
      result = await ctx.session.client.simulatePolicy({
        agent_id: internals.agentId,
        action,
        resource,
        context: cedarContext,
        ...(user ? { user: { id: user.id, email: user.email, trust: user.trust ?? "trusted" } } : {}),
      });
    } catch (err) {
      if (breaker) breaker.recordFailure();
      if (failMode === "open") {
        void ctx.session
          .ingestAuditEvent({
            event_type: "policy_check_degraded",
            detail: {
              action,
              resource,
              path,
              fail_mode: "open",
              error: (err as Error)?.message ?? String(err),
            },
          })
          .catch(() => {});
      }
      return dispatch(
        fallback(failMode, cache, cacheKey, ("fail-" + failMode) as GuardDecision["source"]),
        req,
        reply,
        opts,
        ctx,
      );
    }

    if (breaker) breaker.recordSuccess();

    // HITL escalation for Deny+require_hitl. R45b / INTEG-B1 — additionally
    // gated on the `addon.policy.hitl` enforcement-bundle addon; we escalate
    // ONLY when it is explicitly enabled in the live PDP snapshot. SAFE
    // default on `"unknown"` (cold start / central-only / PDP not wired) and
    // on `"disabled"` is to NOT escalate so the Deny stands — auto-escalating
    // with no approver wired hangs the request.
    const shouldEscalate =
      opts.autoEscalateHitl !== false && ctx.session.isHitlAddonEnabled();
    if (shouldEscalate && result.outcome === "Deny") {
      const parsed = parseHitlAdvice(result.advice);
      if (parsed) {
        const hitlDecision = await runHitlEscalation(ctx, req, opts, result, parsed);
        if (hitlDecision) {
          return dispatch(hitlDecision, req, reply, opts, ctx);
        }
      }
    }

    if (cache && cacheKey && (result.outcome === "Allow" || !result.advice?.length)) {
      cache.put(cacheKey, result);
    }
    return dispatch(toDecision(result, "network"), req, reply, opts, ctx);
  };
}

async function runHitlEscalation(
  ctx: NonNullable<FastifyRequestLike["agentum"]>,
  req: FastifyRequestLike,
  opts: AgentumGuardFastifyOptions,
  result: PolicySimulateResponse,
  parsed: { requiredApprovals?: number; timeoutSeconds?: number },
): Promise<GuardDecision | null> {
  const info: HitlRequestInfo = {
    action: opts.action,
    resource: opts.resource,
    advice: result.advice ?? [],
    ...(parsed.requiredApprovals !== undefined
      ? { requiredApprovals: parsed.requiredApprovals }
      : {}),
    ...(parsed.timeoutSeconds !== undefined
      ? { timeoutSeconds: parsed.timeoutSeconds }
      : {}),
  };
  let override: HitlRequestOverride | null = null;
  if (opts.onHitlRequested) {
    try {
      override = (await opts.onHitlRequested(info, req)) ?? null;
    } catch {
      override = null;
    }
  }

  const timeoutMs =
    override?.timeoutMs ??
    (parsed.timeoutSeconds !== undefined ? parsed.timeoutSeconds * 1000 : undefined);
  const requiredApprovals = override?.requiredApprovals ?? parsed.requiredApprovals;

  try {
    const approval = await ctx.session.requestApproval({
      action: opts.action,
      resource: opts.resource,
      ...(override?.context !== undefined ? { context: override.context } : {}),
      ...(override?.reason !== undefined ? { reason: override.reason } : {}),
      ...(timeoutMs !== undefined ? { timeout: timeoutMs } : {}),
      ...(requiredApprovals !== undefined ? { requiredApprovals } : {}),
    });
    return {
      allowed: true,
      outcome: "Allow",
      rule_id: result.rule_id,
      reason: `hitl_approved_by:${approval.decided_by}`,
      source: "hitl-approved",
    };
  } catch (err) {
    if (err instanceof AgentumHitlDeniedError) {
      return {
        allowed: false,
        outcome: "Deny",
        rule_id: result.rule_id,
        reason: `hitl_denied_by:${err.decidedBy}`,
        source: "hitl-denied",
      };
    }
    if (err instanceof AgentumHitlTimeoutError) {
      return {
        allowed: false,
        outcome: "Deny",
        rule_id: result.rule_id,
        reason: "hitl_timeout",
        source: "hitl-timeout",
      };
    }
    return {
      allowed: false,
      outcome: "Deny",
      rule_id: result.rule_id,
      reason: `hitl_error:${(err as Error)?.message ?? String(err)}`,
      source: "hitl-denied",
    };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function defaultPath(req: FastifyRequestLike): string {
  if (req.routerPath) return req.routerPath;
  try {
    // `url` may be a full path + query or just a pathname.
    const q = req.url.indexOf("?");
    return q >= 0 ? req.url.slice(0, q) : req.url;
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
    // Preserve policy_hash / decision_source from the simulate response so
    // dispatch() can thread them into request_denied audits.
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

function dispatch(
  decision: GuardDecision,
  req: FastifyRequestLike,
  reply: FastifyReplyLike,
  opts: AgentumGuardFastifyOptions,
  ctx: NonNullable<FastifyRequestLike["agentum"]>,
): void {
  if (decision.allowed) return;
  // Thread policy_hash + decision_source at the top level (joinable against
  // LocalPdpDecision) and rule_id / reason via the raw helper into `detail`.
  // `decision.source` (guard-internal breaker/cache trace) stays in `detail`
  // — it is *not* the wire `decision_source` field.
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
  void ctx.session
    .ingestAuditEvent({
      event_type: "request_denied",
      outcome: "deny",
      ...topObs,
      detail: {
        action: opts.action,
        resource: opts.resource,
        source: decision.source,
        ...detailObs,
      },
    })
    .catch(() => {});

  if (opts.onDeny) {
    opts.onDeny(decision, req, reply);
    return;
  }
  reply.code(403).send({
    error: "forbidden",
    rule_id: decision.rule_id,
    reason: decision.reason,
    source: decision.source,
  });
}
