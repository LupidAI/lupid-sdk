/**
 * `AgentumGuard` — a NestJS `CanActivate` implementation.
 *
 * Two construction patterns:
 *
 * 1. **Singleton (simplest):** call `setAgentumRuntime(createAgentumRuntime(opts))`
 *    at bootstrap, then use `@UseGuards(AgentumGuard)` directly. NestJS's DI
 *    instantiates the guard (zero-arg constructor) and each guard instance
 *    reads the module-scoped runtime.
 *
 * 2. **Bound factory (DI-friendly):** call `agentumGuardClass(runtime)` to get
 *    a subclass with the runtime baked in. Use with `@UseGuards(MyGuard)`.
 *    Preferred when multiple AgentumClient configurations coexist in one app.
 *
 * The decorator pattern (`@AgentumGuardFor({action, resource})`) is the same
 * in both.
 */

import { AgentumError } from "../../types.js";
import {
  AgentumHitlDeniedError,
  AgentumHitlTimeoutError,
  parseHitlAdvice,
} from "../../types.js";
import { DecisionCache, hashContext } from "../express/decision-cache.js";
import { getAgentumGuardOptions } from "./decorator.js";
import type {
  AgentumGuardForOptions,
  AgentumNestInternals,
  AgentumNestRuntime,
  CanActivateLike,
  ExecutionContextLike,
  GuardDecision,
  HitlRequestInfo,
  HitlRequestOverride,
  NestHttpRequestLike,
  NestHttpResponseLike,
} from "./types.js";
import type { FailMode } from "../express/types.js";
import type { PolicySimulateResponse } from "../../types.js";
import {
  pdpObservabilityDetailRaw,
  pdpTopLevelFieldsRaw,
} from "../_pdp-observability.js";

// ── Module-scoped singleton ────────────────────────────────────────────────────

let SINGLETON: AgentumNestRuntime | null = null;

/**
 * Register the global Agentum runtime that the default `AgentumGuard` consults.
 * Call once at bootstrap; overwriting is allowed (the previous runtime's
 * `close()` is *not* called — the caller owns lifecycle).
 */
export function setAgentumRuntime(runtime: AgentumNestRuntime | null): void {
  SINGLETON = runtime;
}

/** Retrieve the currently-bound runtime. Returns `null` if none was set. */
export function getAgentumRuntime(): AgentumNestRuntime | null {
  return SINGLETON;
}

// ── The guard class ────────────────────────────────────────────────────────────

/**
 * Default guard class — reads the module-scoped runtime set via
 * `setAgentumRuntime()`. Throws at `canActivate` time if no runtime is set so
 * the wiring error surfaces loudly instead of silently denying every request.
 */
export class AgentumGuard implements CanActivateLike {
  protected getRuntime(): AgentumNestRuntime {
    if (!SINGLETON) {
      throw new AgentumError(
        "AgentumGuard: no runtime registered. Call setAgentumRuntime(createAgentumRuntime({...})) at bootstrap, or use agentumGuardClass(runtime).",
      );
    }
    return SINGLETON;
  }

  async canActivate(context: ExecutionContextLike): Promise<boolean> {
    return canActivateImpl(this.getRuntime(), context);
  }
}

/**
 * Build a new guard class bound to a specific runtime. Use this when you want
 * to avoid the module-scoped singleton — each call returns a fresh class so
 * two guards with different runtimes can coexist in the same NestJS app.
 */
export function agentumGuardClass(runtime: AgentumNestRuntime): new () => CanActivateLike {
  if (!runtime) {
    throw new AgentumError("agentumGuardClass: runtime is required");
  }
  return class BoundAgentumGuard extends AgentumGuard {
    protected override getRuntime(): AgentumNestRuntime {
      return runtime;
    }
  };
}

// ── Shared canActivate implementation ──────────────────────────────────────────

async function canActivateImpl(
  runtime: AgentumNestRuntime,
  context: ExecutionContextLike,
): Promise<boolean> {
  const internals = runtime._internals;
  const http = context.switchToHttp();
  const req = http.getRequest<NestHttpRequestLike>();
  const res = http.getResponse<NestHttpResponseLike>();

  const handler = context.getHandler();
  const opts = getAgentumGuardOptions(handler as (...args: unknown[]) => unknown);
  if (!opts) {
    // No @AgentumGuardFor on this handler — fail-closed with a wiring-error
    // shaped body so the developer notices immediately.
    writeJson(res, 500, {
      error: "agentum_guard_missing_metadata",
      hint: "Add @AgentumGuardFor({ action, resource }) to the route handler",
    });
    return false;
  }

  const user = await internals.userFromRequest(req);
  if (user === null) {
    if (internals.onUnauthenticated) {
      internals.onUnauthenticated(req, res);
    } else {
      writeJson(res, 401, { error: "unauthenticated" });
    }
    return false;
  }

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

  // ── Cache check ─────────────────────────────────────────────────────────────
  if (cache && cacheKey && !skipCache) {
    const cached = cache.get(cacheKey);
    if (cached) return resolve(toDecision(cached, "cache"), req, res, opts, internals);
  }

  // ── Breaker / health short-circuit ──────────────────────────────────────────
  if (breaker && breaker.shouldSkip()) {
    return resolve(
      fallback(failMode, cache, cacheKey, "breaker-open"),
      req,
      res,
      opts,
      internals,
    );
  }
  if (health && !health.reachable) {
    return resolve(
      fallback(failMode, cache, cacheKey, "health-down"),
      req,
      res,
      opts,
      internals,
    );
  }

  // ── Fresh simulatePolicy ────────────────────────────────────────────────────
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
    return resolve(
      fallback(failMode, cache, cacheKey, ("fail-" + failMode) as GuardDecision["source"]),
      req,
      res,
      opts,
      internals,
    );
  }

  if (breaker) breaker.recordSuccess();

  // HITL escalation for a Deny carrying `require_hitl` — mirrors the Express
  // guard's `runHitlEscalation`. R45b / INTEG-B1: gated on the LIVE
  // `addon.policy.hitl` snapshot via `internals.hitlAddonEnabled()`, which
  // re-reads the evaluator on each call (NOT a creation-time snapshot). SAFE
  // (INC-B) default on `"unknown"` (cold start / central-only / PDP not wired)
  // and on `"disabled"` is to NOT escalate so the original Deny stands —
  // auto-escalating with no approver wired hangs the request.
  // SDK-HITL-A — `approvalSession` is absent when the async bootstrap could not
  // reach central at construction time; without a Bearer-authenticated session
  // we cannot create an approval request, so HITL is cleanly disabled and the
  // original Deny stands (fail-CLOSED).
  const shouldEscalate =
    opts.autoEscalateHitl !== false &&
    internals.approvalSession !== undefined &&
    internals.hitlAddonEnabled();
  if (shouldEscalate && result.outcome === "Deny") {
    // HITL-1 — prefer the engine-derived `hitl_pending` flag when the API
    // serialised it; fall back to re-parsing `advice` on older APIs.
    const parsed =
      result.hitl_pending === true
        ? parseHitlAdvice(result.advice) ?? {}
        : result.hitl_pending === false
          ? null
          : parseHitlAdvice(result.advice);
    if (parsed) {
      const hitlDecision = await runHitlEscalation(internals, req, opts, result, parsed);
      if (hitlDecision) {
        // Skip the decision cache for HITL outcomes — a cached HITL-approved
        // decision would bypass re-approval on a subsequent call.
        return resolve(hitlDecision, req, res, opts, internals);
      }
    }
  }

  // Non-HITL path: Deny decisions carrying advice deliberately bypass the
  // cache (skip `put`) so a subsequent request re-evaluates and re-escalates.
  if (cache && cacheKey && (result.outcome === "Allow" || !result.advice?.length)) {
    cache.put(cacheKey, result);
  }
  return resolve(toDecision(result, "network"), req, res, opts, internals);
}

/**
 * Execute the HITL escalation round-trip for a Deny that carried a
 * `require_hitl` directive. Mirrors the Express guard's `runHitlEscalation`,
 * adapted to the NestJS runtime's long-lived `approvalSession` (the runtime
 * has no per-request session). Returns the resulting {@link GuardDecision},
 * or `null` if the `onHitlRequested` hook cancelled (treat as a plain Deny).
 */
async function runHitlEscalation(
  internals: AgentumNestInternals,
  req: NestHttpRequestLike,
  opts: AgentumGuardForOptions,
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
  const approvalSession = internals.approvalSession;
  if (!approvalSession) {
    // Defensive: the caller (`shouldEscalate`) already guards this, but a null
    // approval session means we cannot create the request — let the Deny stand.
    return null;
  }
  let override: HitlRequestOverride | null = null;
  if (opts.onHitlRequested) {
    try {
      override = (await opts.onHitlRequested(info, req)) ?? null;
    } catch {
      // Hook bug — treat as no override, don't break the flow.
      override = null;
    }
    if (override === null) {
      // Explicit cancel — treat as a normal Deny.
      return null;
    }
  }

  const timeoutMs =
    override?.timeoutMs ??
    (parsed.timeoutSeconds !== undefined ? parsed.timeoutSeconds * 1000 : undefined);
  const requiredApprovals = override?.requiredApprovals ?? parsed.requiredApprovals;

  try {
    const approval = await approvalSession.requestApproval({
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
    // the original Deny — fail closed rather than allow on an unknown failure.
    return {
      allowed: false,
      outcome: "Deny",
      rule_id: result.rule_id,
      reason: `hitl_error:${(err as Error)?.message ?? String(err)}`,
      source: "hitl-denied",
    };
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function resolve(
  decision: GuardDecision,
  req: NestHttpRequestLike,
  res: NestHttpResponseLike,
  opts: AgentumGuardForOptions,
  internals: AgentumNestInternals,
): boolean {
  if (decision.allowed) return true;
  // Emit a best-effort request_denied audit before invoking onDeny /
  // writing the default 403. policy_hash + decision_source land at the
  // top level (joinable with LocalPdpDecision); rule_id / reason go
  // inside `detail` via the raw helper. `decision.source` (guard-internal
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
      // TODO: AgentumNestRuntimeOptions does not carry a `sessionId`
      // today; widening the options bag is deferred. Emit empty string
      // so the audit row is queryable by agent_id; backfill later.
      session_id: "",
      ...topObs,
      detail: {
        action: opts.action,
        resource: opts.resource,
        framework: "nestjs",
        source: decision.source,
        ...detailObs,
      },
    })
    .catch(() => {});
  if (opts.onDeny) {
    opts.onDeny(decision, req, res);
  } else {
    writeJson(res, 403, {
      error: "forbidden",
      rule_id: decision.rule_id,
      reason: decision.reason,
      source: decision.source,
    });
  }
  return false;
}

function toDecision(res: PolicySimulateResponse, source: GuardDecision["source"]): GuardDecision {
  return {
    allowed: res.outcome === "Allow",
    outcome: res.outcome,
    rule_id: res.rule_id,
    reason: res.reason,
    source,
    // Preserve policy_hash / decision_source from the simulate response
    // so resolve() can thread them into request_denied audits.
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

function defaultPath(req: NestHttpRequestLike): string {
  if (req.routerPath) return req.routerPath;
  if (req.path) return req.path;
  if (req.originalUrl) return stripQuery(req.originalUrl);
  if (req.url) return stripQuery(req.url);
  return "/";
}

function stripQuery(url: string): string {
  const q = url.indexOf("?");
  return q >= 0 ? url.slice(0, q) : url;
}

function writeJson(res: NestHttpResponseLike, status: number, body: unknown): void {
  // Handle both Express (`status` + `json`) and Fastify (`code` + `send`) shapes.
  const setStatus = res.status ?? res.code;
  if (typeof setStatus === "function") {
    setStatus.call(res, status);
  } else {
    res.statusCode = status;
  }
  const writeBody = res.json ?? res.send;
  if (typeof writeBody === "function") {
    writeBody.call(res, body);
  }
}
