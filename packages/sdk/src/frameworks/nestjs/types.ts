/**
 * Public types for the NestJS framework integration.
 *
 * Duck-typed against `@nestjs/common` so we don't take a runtime dependency on
 * it. The structural shapes here match the subset of the NestJS surface we
 * need (`ExecutionContext`, `HttpArgumentsHost`, `CanActivate`). Callers pass
 * real NestJS types and TypeScript accepts them.
 */

import type { AgentumClient } from "../../client.js";
import type { AgentumSession } from "../../session.js";
import type { DecisionCache } from "../express/decision-cache.js";
import type { CircuitBreaker } from "../express/circuit-breaker.js";
import type { HealthMonitor } from "../express/health-check.js";
import type {
  AgentumUser,
  FailMode,
  HitlRequestInfo,
  HitlRequestOverride,
} from "../express/types.js";

export type { AgentumUser, FailMode } from "../express/types.js";
export type { HitlRequestInfo, HitlRequestOverride } from "../express/types.js";
export { DecisionCache, hashContext } from "../express/decision-cache.js";
export { CircuitBreaker } from "../express/circuit-breaker.js";
export { HealthMonitor } from "../express/health-check.js";

// ── Structural request / context ──────────────────────────────────────────────

/**
 * The underlying HTTP request NestJS hands to `getRequest()`. Under Express
 * that's `express.Request`; under Fastify it's `FastifyRequest`. We only rely
 * on the shared shape.
 */
export interface NestHttpRequestLike {
  readonly method: string;
  readonly url?: string;
  readonly originalUrl?: string;
  readonly path?: string;
  readonly routerPath?: string;
  readonly headers: Record<string, string | string[] | undefined>;
}

/**
 * The response handed back by `getResponse()`. We only send JSON bodies via
 * the default deny path; an overridden `onDeny` gets the raw object.
 */
export interface NestHttpResponseLike {
  status?(code: number): NestHttpResponseLike;
  code?(code: number): NestHttpResponseLike;
  json?(body: unknown): unknown;
  send?(body: unknown): unknown;
  statusCode?: number;
}

/** Structural subset of `HttpArgumentsHost` from `@nestjs/common`. */
export interface HttpArgumentsHostLike {
  getRequest<T = NestHttpRequestLike>(): T;
  getResponse<T = NestHttpResponseLike>(): T;
}

/** Structural subset of `ExecutionContext` from `@nestjs/common`. */
export interface ExecutionContextLike {
  switchToHttp(): HttpArgumentsHostLike;
  getHandler(): (...args: unknown[]) => unknown;
  getClass?(): unknown;
}

/** Structural subset of `CanActivate` from `@nestjs/common`. */
export interface CanActivateLike {
  canActivate(context: ExecutionContextLike): boolean | Promise<boolean>;
}

// ── Runtime (shared state across guards) ───────────────────────────────────────

/**
 * Long-lived object holding the AgentumClient + resilience primitives. Build
 * once at module startup (e.g. in a NestJS `forRoot`) and reuse across guards.
 */
export interface AgentumNestRuntimeOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  runtime: AgentumClient;
  /** Pre-bound agent ID. */
  agentId: string;
  /** Optional tenant UUID — forwarded as `X-Tenant-ID` on simulate calls. */
  tenantId?: string;

  /**
   * Resolve the authenticated user for the given request. Returning `null`
   * signals unauthenticated — the guard returns `false` and an `onUnauthenticated`
   * response is sent if supplied, otherwise a 401 JSON body is written.
   */
  userFromRequest: (
    req: NestHttpRequestLike,
  ) => AgentumUser | null | Promise<AgentumUser | null>;

  decisionCache?: {
    enabled?: boolean;
    maxSize?: number;
    ttlMs?: number;
  };
  circuitBreaker?: {
    enabled?: boolean;
    failureThreshold?: number;
    resetTimeoutMs?: number;
  };
  healthCheck?: {
    enabled?: boolean;
    intervalMs?: number;
  };
  failMode?: FailMode;

  /**
   * Called when `userFromRequest` returns `null`. Default: write 401 JSON to
   * `res` and return. The function runs just before `canActivate` returns
   * `false`; the caller (NestJS) will abort the request.
   */
  onUnauthenticated?: (req: NestHttpRequestLike, res: NestHttpResponseLike) => void;
}

/** @internal */
export interface AgentumNestInternals {
  client: AgentumClient;
  agentId: string;
  tenantId: string | undefined;
  userFromRequest: AgentumNestRuntimeOptions["userFromRequest"];
  decisionCache: DecisionCache | null;
  circuitBreaker: CircuitBreaker | null;
  healthMonitor: HealthMonitor | null;
  failMode: FailMode;
  onUnauthenticated?: AgentumNestRuntimeOptions["onUnauthenticated"];
  /**
   * HITL-6 — **live** getter for the `addon.policy.hitl` enforcement-bundle
   * addon state. Re-reads the evaluator snapshot on EACH `canActivate`
   * (delegates to {@link AgentumClient.isHitlAddonEnabled}); it is NOT a
   * creation-time snapshot — a stale snapshot would either suppress
   * escalation after the addon is enabled, or escalate after it is disabled.
   * Returns `true` only when the addon is explicitly `"enabled"` in the live
   * PDP snapshot; `"unknown"` / `"disabled"` → `false` (INC-B safe default:
   * do not escalate, the Deny stands).
   */
  hitlAddonEnabled: () => boolean;
  /**
   * HITL-6 / SDK-HITL-A — session used to drive
   * {@link AgentumSession.requestApproval} during HITL escalation. The NestJS
   * runtime has no per-request session (unlike Express/Fastify), so the factory
   * mints one bound to the agent.
   *
   * **Auth contract (SDK-HITL-A):** the server's HITL agent endpoints
   * (`POST/GET /hitl/agent/requests*`) authenticate via `Authorization: Bearer`
   * (the agent session JWT) only — they do NOT read `X-API-Key`. The synchronous
   * {@link createAgentumRuntime} builds this session over the shared API-key
   * client with an empty JWT, which 401s on any API-key-only deployment (the
   * common case). Use {@link createAgentumRuntimeAsync}, which mints a real
   * agent session via `client.connectExisting(agentId)` — that session carries a
   * Bearer JWT and a `refreshFn` (backed by a long-lived API-key refresh
   * client), so it re-mints the JWT before expiry and never 401s mid-run.
   *
   * `undefined` when the async bootstrap could not reach central at construction
   * time — HITL escalation is then cleanly disabled (the Deny stands,
   * fail-CLOSED) rather than crashing the app.
   */
  approvalSession?: AgentumSession;
}

/** The runtime handle. Call `close()` on application shutdown. */
export interface AgentumNestRuntime {
  /** @internal */
  readonly _internals: AgentumNestInternals;
  /** Release background resources (health-monitor interval). */
  close(): Promise<void>;
}

// ── Guard options attached by the decorator ───────────────────────────────────

export interface AgentumGuardForOptions {
  /** Cedar action string, e.g. `"http.post"`. */
  action: string;
  /** Cedar resource string. */
  resource: string;
  /**
   * Path sent as `context.path`. Static or derived from the request. Defaults
   * to the request's route template (`routerPath`) or URL pathname.
   */
  pathLike?: string | ((req: NestHttpRequestLike) => string);
  /** Extra Cedar context — merged into the default `{ path }`. */
  contextExtra?: (req: NestHttpRequestLike) => Record<string, unknown>;
  /** Called on Deny. Default: write 403 JSON to the response. */
  onDeny?: (
    decision: GuardDecision,
    req: NestHttpRequestLike,
    res: NestHttpResponseLike,
  ) => void;
  /** Bypass the decision cache. */
  skipCache?: boolean;
  /** Per-route fail-mode override. */
  failModeOverride?: FailMode;

  /**
   * HITL-6 — HITL escalation via Cedar `@advice("require_hitl")`. When `true`
   * (default), a Deny whose simulate response carries `hitl_pending` (or, on
   * older APIs, a `require_hitl[:params]` advice) auto-escalates via
   * `session.requestApproval(...)` instead of sending 403 — but ONLY when the
   * live `hitlAddonEnabled()` getter reports the `addon.policy.hitl` addon is
   * enabled. On approval the guard returns `true`; on deny/timeout it falls
   * through to `onDeny` (or 403) with the HITL reason in `decision.reason`.
   *
   * Set to `false` to treat advice-carrying denials as plain denials.
   */
  autoEscalateHitl?: boolean;

  /**
   * HITL-6 — hook invoked immediately before `session.requestApproval()`
   * fires. Returning an object overrides/augments the approval request
   * (reason, timeout, requiredApprovals, context); returning `null` cancels
   * the escalation and lets the original Deny stand.
   */
  onHitlRequested?: (
    info: HitlRequestInfo,
    req: NestHttpRequestLike,
  ) => HitlRequestOverride | null | Promise<HitlRequestOverride | null>;
}

export interface GuardDecision {
  allowed: boolean;
  outcome: "Allow" | "Deny";
  rule_id: string | null;
  reason: string | null;
  source:
    | "network"
    | "cache"
    | "fail-closed"
    | "fail-open"
    | "fail-cached"
    | "breaker-open"
    | "health-down"
    // HITL-6 escalation outcomes. `hitl-approved` reverses a Deny+advice to an
    // Allow after human approval; `hitl-denied` / `hitl-timeout` keep the Deny
    // shape but carry the HITL reason through.
    | "hitl-approved"
    | "hitl-denied"
    | "hitl-timeout";
  /**
   * sha256 hex of the policy bundle that produced this decision. Carried
   * through from `PolicySimulateResponse.policy_hash`. Absent on fail-mode
   * fallbacks and on older API versions.
   */
  policy_hash?: string;
  /**
   * Wire-vocabulary `DecisionSource::as_str()`. Threaded as long-form into
   * `request_denied` audits so operators can join on `policy_hash` across
   * `LocalPdpDecision` and framework-guard rows.
   */
  decision_source?:
    | "central_evaluated"
    | "central_cache_hit"
    | "local_pdp_evaluated"
    | "local_pdp_cache_hit";
}
