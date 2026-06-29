/**
 * agentumGuard — per-route Cedar policy enforcement.
 *
 * Reads the per-request session (injected by `agentumMiddleware`), consults
 * the decision cache, circuit breaker, and health monitor, and either calls
 * `next()` (Allow) or `onDeny()` (Deny / fail-closed).
 *
 * @example
 * ```ts
 * app.get("/api/orders",
 *   agentumGuard({ action: "http.get", resource: "api.example.com" }),
 *   (req, res) => res.json({ orders: [...] })
 * );
 * ```
 */

import { DecisionCache, hashContext } from "./decision-cache.js";
import type {
  AgentumGuardOptions,
  AgentumNext,
  AgentumRequest,
  AgentumRequestHandler,
  AgentumResponse,
  FailMode,
  GuardDecision,
} from "./types.js";
import type { PolicySimulateResponse } from "../../types.js";
import { parseHitlAdvice } from "../../types.js";
import { AgentumHitlDeniedError, AgentumHitlTimeoutError } from "../../types.js";
import {
  pdpObservabilityDetailRaw,
  pdpTopLevelFieldsRaw,
} from "../_pdp-observability.js";

/** Build the per-route middleware. */
export function agentumGuard(opts: AgentumGuardOptions): AgentumRequestHandler {
  return async (req, res, next) => {
    const ctx = req.agentum;
    if (!ctx || !ctx._internals) {
      // The middleware never ran — fail loudly; this is a wiring bug, not a
      // policy decision. Returning 500 matches Express's convention for a
      // misconfigured guard (cf. express-validator, helmet).
      res
        .status(500)
        .json({ error: "agentum_middleware_missing", hint: "agentumMiddleware() must run before agentumGuard()" });
      return;
    }

    const internals = ctx._internals;
    const action = opts.action;
    const resource = opts.resource;
    const path = typeof opts.pathLike === "function" ? opts.pathLike(req) : (opts.pathLike ?? req.path);
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

    // ── 1. Cache check ─────────────────────────────────────────────────────────
    if (cache && cacheKey && !skipCache) {
      const cached = cache.get(cacheKey);
      if (cached) {
        return dispatch(toDecision(cached, "cache"), req, res, next, opts, ctx);
      }
    }

    // ── 2. Breaker / health short-circuit ──────────────────────────────────────
    if (breaker && breaker.shouldSkip()) {
      return dispatch(fallback(failMode, cache, cacheKey, "breaker-open"), req, res, next, opts, ctx);
    }
    if (health && !health.reachable) {
      return dispatch(fallback(failMode, cache, cacheKey, "health-down"), req, res, next, opts, ctx);
    }

    // ── 3. Fresh simulatePolicy call ───────────────────────────────────────────
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
      // Emit a degraded-mode audit event when open-failing so operators know
      // Cedar is not actually gating this request. Best-effort; don't await.
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
      return dispatch(fallback(failMode, cache, cacheKey, "fail-" + failMode as GuardDecision["source"]), req, res, next, opts, ctx);
    }

    if (breaker) breaker.recordSuccess();

    // If the Deny carries `require_hitl` advice, escalate to HITL via
    // session.requestApproval. On approval we reverse to Allow; on
    // deny/timeout we keep the Deny shape but surface the HITL reason.
    //
    // R45b / INTEG-B1 — escalation is additionally gated on the
    // `addon.policy.hitl` enforcement-bundle addon. We escalate ONLY when the
    // addon is explicitly enabled in the live PDP snapshot. SAFE default on
    // `"unknown"` (cold start / central-only / PDP not wired) and on
    // `"disabled"` is to NOT escalate (`isHitlAddonEnabled` returns false) so
    // the original Deny stands — auto-escalating with no approver wired hangs
    // the request.
    const shouldEscalate =
      opts.autoEscalateHitl !== false && // default true
      ctx.session.isHitlAddonEnabled();
    if (shouldEscalate && result.outcome === "Deny") {
      const parsed = parseHitlAdvice(result.advice);
      if (parsed) {
        const hitlDecision = await runHitlEscalation(
          ctx,
          req,
          opts,
          result,
          parsed,
        );
        if (hitlDecision) {
          // Skip the decision cache for HITL outcomes — a cached HITL-approved
          // decision would bypass re-approval on a subsequent call. The
          // non-HITL Deny stays out of the cache too (see below).
          return dispatch(hitlDecision, req, res, next, opts, ctx);
        }
      }
    }

    // Non-HITL path: populate the cache with the fresh decision. Deny
    // decisions carrying advice deliberately bypass the cache (skipping
    // `put`) so a subsequent request re-evaluates and re-escalates —
    // otherwise the cache would shortcut around HITL.
    if (cache && cacheKey && (result.outcome === "Allow" || !result.advice?.length)) {
      cache.put(cacheKey, result);
    }
    return dispatch(toDecision(result, "network"), req, res, next, opts, ctx);
  };
}

/**
 * Execute the HITL escalation round-trip for a Deny that carried a
 * `@advice("require_hitl[:params]")` annotation. Returns the resulting
 * {@link GuardDecision} or `null` if the hook cancelled (treat as Deny).
 */
async function runHitlEscalation(
  ctx: NonNullable<AgentumRequest["agentum"]>,
  req: AgentumRequest,
  opts: AgentumGuardOptions,
  result: PolicySimulateResponse,
  parsed: { requiredApprovals?: number; timeoutSeconds?: number },
): Promise<GuardDecision | null> {
  const info: import("./types.js").HitlRequestInfo = {
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
  let override: import("./types.js").HitlRequestOverride | null = null;
  if (opts.onHitlRequested) {
    try {
      override = (await opts.onHitlRequested(info, req)) ?? null;
    } catch (err) {
      // Hook bug — treat as no override, don't break the flow.
      override = null;
      void ctx.session
        .ingestAuditEvent({
          event_type: "request_denied",
          detail: {
            action: opts.action,
            resource: opts.resource,
            reason: "hitl_hook_threw",
            error: (err as Error)?.message ?? String(err),
          },
        })
        .catch(() => {});
    }
    if (override === null) {
      // Explicit cancel — treat as normal Deny.
      return null;
    }
  }

  const timeoutMs =
    override?.timeoutMs ??
    (parsed.timeoutSeconds !== undefined
      ? parsed.timeoutSeconds * 1000
      : undefined);
  const requiredApprovals =
    override?.requiredApprovals ?? parsed.requiredApprovals;

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
    // Unexpected error in the HITL round-trip (network, auth). Fall back to
    // the original Deny — we fail closed rather than allow on an unknown
    // failure mode.
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

/**
 * Resolve the fail-mode fallback.
 *   - closed: Deny.
 *   - open:   Allow (caller emits degraded audit).
 *   - cached: last-known-good decision; falls back to closed if no stale hit.
 *
 * `source` records whether we got here via a breaker short-circuit, a
 * health-check short-circuit, or a real simulatePolicy failure.
 */
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
    // No stale value — fall through to closed behaviour.
  }
  return { allowed: false, outcome: "Deny", rule_id: null, reason: "fail_closed", source };
}

function dispatch(
  decision: GuardDecision,
  req: AgentumRequest,
  res: AgentumResponse,
  next: AgentumNext,
  opts: AgentumGuardOptions,
  ctx: NonNullable<AgentumRequest["agentum"]>,
): void {
  if (decision.allowed) {
    next();
    return;
  }
  // Best-effort audit; don't block the response.
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
    opts.onDeny(decision, req, res);
    return;
  }
  res.status(403).json({
    error: "forbidden",
    rule_id: decision.rule_id,
    reason: decision.reason,
    source: decision.source,
  });
}
