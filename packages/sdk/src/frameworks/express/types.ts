/**
 * Public types for the Express framework integration.
 *
 * Split out so the main `index.ts`, `guard.ts`, and helper modules can share
 * declarations without circular imports.
 */

import type { AgentumClient } from "../../client.js";
import type { AgentumSession } from "../../session.js";
import type { DecisionCache } from "./decision-cache.js";
import type { CircuitBreaker } from "./circuit-breaker.js";
import type { HealthMonitor } from "./health-check.js";

// ── Request / response / next — Express-compatible structural types ─────────────
// These are duplicated (not imported from "express") so Express is not a hard
// dependency. Express's own types are structurally assignable to these.

export interface AgentumRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  agentum?: AgentumRequestContext;
}

export interface AgentumResponse {
  status(code: number): AgentumResponse;
  json(body: unknown): void;
  statusCode?: number;
  on(event: string, listener: () => void): void;
  end(): void;
}

export type AgentumNext = (err?: unknown) => void;

export type AgentumRequestHandler = (
  req: AgentumRequest,
  res: AgentumResponse,
  next: AgentumNext,
) => Promise<void> | void;

// ── User / agent identity shapes ────────────────────────────────────────────────

/**
 * Canonical user shape the middleware forwards into simulatePolicy.
 *
 * Trust is narrowed to `"trusted" | "verified"` because `PolicySimulateRequest`
 * does not yet accept `"service"` (that shape is only valid on session binding).
 * Service identities flow through `agentumWebhookGuard`, which bypasses
 * `agentumGuard`.
 */
export interface AgentumUser {
  id: string;
  email: string;
  trust?: "trusted" | "verified";
  attributes?: Record<string, unknown>;
}

/** The agent identity resolved from an incoming request (legacy shape). */
export interface ResolvedAgentIdentity {
  /** Existing registered agent ID. Mutually exclusive with `name`. */
  agentId?: string;
  /** Display name — used when registering a new agent on first request. */
  name?: string;
  /** Optional owner e-mail for auto-registration. */
  ownerEmail?: string;
  /** Optional purpose for auto-registration. */
  purpose?: string;
  /** Optional tenant UUID — injected as `X-Tenant-ID` header on the session client. */
  tenantId?: string;
}

/**
 * Context injected into `req.agentum` by the middleware.
 *
 * `_internals` is consumed by `agentumGuard()`; application code should not
 * depend on its shape (undocumented, subject to change without notice).
 */
export interface AgentumRequestContext {
  session: AgentumSession;
  agentId: string;
  sessionId: string;
  tenantId?: string;
  /** The user binding resolved from `userFromRequest`, if supplied. */
  user?: AgentumUser;
  /**
   * Service identity name when the context was created by
   * `agentumWebhookGuard()`. Mutually exclusive with `user` — webhook sessions
   * have no end-user binding. Example: `"github-webhook"`.
   */
  service?: string;
  /** @internal — do not depend on this shape. */
  _internals?: AgentumRequestInternals;
}

/** @internal */
export interface AgentumRequestInternals {
  agentId: string;
  user?: AgentumUser;
  decisionCache: DecisionCache | null;
  circuitBreaker: CircuitBreaker | null;
  healthMonitor: HealthMonitor | null;
  failMode: FailMode;
}

// ── Resilience knobs ────────────────────────────────────────────────────────────

export type FailMode = "closed" | "open" | "cached";

export interface DecisionCacheOptions {
  /** When `false`, no caching — every call hits the network. Default: `true`. */
  enabled?: boolean;
  /** Maximum number of cached decisions. Default: `10_000`. */
  maxSize?: number;
  /** How long a cached decision is considered fresh, in milliseconds. Default: `15_000`. */
  ttlMs?: number;
}

export interface CircuitBreakerOptions {
  enabled?: boolean;
  /** Consecutive failures required to open the breaker. Default: `5`. */
  failureThreshold?: number;
  /** How long the breaker stays open before a probe attempt, in milliseconds. Default: `30_000`. */
  resetTimeoutMs?: number;
}

export interface HealthCheckOptions {
  enabled?: boolean;
  /** How often to probe, in milliseconds. Default: `30_000`. */
  intervalMs?: number;
  /** Absolute URL or path relative to `client.baseUrl`. Default: `/health`. */
  endpoint?: string;
}

export interface SessionCacheOptions {
  maxSize?: number;
  ttlMs?: number;
}

// ── Middleware options ──────────────────────────────────────────────────────────

export interface AgentumMiddlewareOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  client?: AgentumClient;
  /** Alias for `client` matching the plan's naming. If both are set, `runtime` wins. */
  runtime?: AgentumClient;

  /** Pre-bound agent ID. Required when `userFromRequest` is used and `resolveAgent` is absent. */
  agentId?: string;

  /**
   * Resolve the agent identity per-request (legacy shape). Return `{ agentId }` to
   * use an existing agent, or `{ name, ownerEmail, purpose }` to auto-register.
   * Mutually exclusive with top-level `agentId` + `userFromRequest`, but the two
   * shapes may coexist (resolveAgent wins if both present).
   */
  resolveAgent?: (
    req: AgentumRequest,
  ) => ResolvedAgentIdentity | Promise<ResolvedAgentIdentity>;

  /**
   * Extract the authenticated user for the current request. Returning `null`
   * signals the request is unauthenticated — the middleware will call
   * `onUnauthenticated` (or 401 by default) instead of minting a session.
   */
  userFromRequest?: (
    req: AgentumRequest,
  ) => AgentumUser | null | Promise<AgentumUser | null>;

  /**
   * Verified-mode alternative to `userFromRequest`. Returns a raw user JWT
   * that Agentum's backend will verify against the tenant's configured IdP.
   * Mutually exclusive with `userFromRequest`; supplying both throws at
   * startup. Returning `null` signals unauthenticated — the middleware calls
   * `onUnauthenticated`.
   *
   * The session is minted with `user: { token }`; the decoded user claim
   * flows into Cedar context at the runtime gateway.
   *
   * Caveat: `agentumGuard` calls `simulatePolicy`, which authenticates by
   * API key (not session JWT) and does not re-verify the token. Policies
   * gated only on `action`/`resource`/`context.path` evaluate correctly;
   * policies that reference `context.user.*` will see no user in the
   * simulate context. For user-aware verified-mode gating, use a
   * hand-written `session.isAllowed(...)` check on the runtime gateway
   * path (which does inspect the session claims).
   */
  tokenFromRequest?: (
    req: AgentumRequest,
  ) => string | null | Promise<string | null>;

  /**
   * - `"enforce"` (legacy): 403 on `session.isAllowed(http.<verb>, path)` returning `false`.
   * - `"observe"` (legacy): log decisions but never block.
   *
   * Prefer per-route `agentumGuard()` to this blanket check — it honours the
   * decision cache, circuit breaker, and fail-mode.
   */
  mode?: "enforce" | "observe";

  /** Called when a request is denied in legacy `mode: "enforce"`. */
  onDeny?: (
    req: AgentumRequest,
    res: AgentumResponse,
    next: AgentumNext,
    reason: string,
  ) => void;

  /** Called when `userFromRequest` returns `null`. Default: 401 + JSON body. */
  onUnauthenticated?: (
    req: AgentumRequest,
    res: AgentumResponse,
    next: AgentumNext,
  ) => void;

  /** Called when session mint throws. Default: forward to `next(err)`. */
  onSessionMintError?: (
    err: unknown,
    req: AgentumRequest,
    res: AgentumResponse,
    next: AgentumNext,
  ) => void;

  /** Session LRU pool size. Default: `256` (legacy alias: `maxPoolSize`). */
  maxPoolSize?: number;
  sessionCache?: SessionCacheOptions;

  decisionCache?: DecisionCacheOptions;
  failMode?: FailMode;
  circuitBreaker?: CircuitBreakerOptions;
  healthCheck?: HealthCheckOptions;
}

/**
 * Returned by `agentumMiddleware()`. Callable as Express middleware, with a
 * `close()` hook to tear down the background health monitor (mandatory in
 * tests or short-lived processes; otherwise Node will keep running).
 */
export type AgentumMiddleware = AgentumRequestHandler & {
  close(): Promise<void>;
};

// ── agentumGuard ────────────────────────────────────────────────────────────────

export interface AgentumGuardOptions {
  /** Cedar action string, e.g. `"http.get"`. */
  action: string;
  /** Cedar resource string, e.g. `"api.example.com"`. */
  resource: string;
  /**
   * Cedar context path. Defaults to `req.path`. Can be a static string or a
   * function of the request (`req => "/orders/" + req.params.id`).
   */
  pathLike?: string | ((req: AgentumRequest) => string);
  /** Extra Cedar context key/value pairs; merged into the default `{ path }`. */
  contextExtra?: (req: AgentumRequest) => Record<string, unknown>;
  /** Called when Cedar returns Deny. Default: 403 + structured JSON body. */
  onDeny?: (
    decision: GuardDecision,
    req: AgentumRequest,
    res: AgentumResponse,
  ) => void;
  /**
   * If `true`, bypass the decision cache — always hit the network. Use for
   * safety-critical actions (lab orders, financial transactions).
   */
  skipCache?: boolean;
  /** Per-route override of the middleware's fail-mode. */
  failModeOverride?: FailMode;

  /**
   * HITL escalation via Cedar `@advice("require_hitl")`.
   * When `true` (default), a Deny whose simulate response carries a
   * `require_hitl[:params]` advice automatically calls
   * `session.requestApproval(...)` instead of sending 403. On approval the
   * guard calls `next()`; on deny/timeout it falls through to `onDeny`
   * (or the default 403) with the HITL decision reason surfaced in
   * `decision.reason`.
   *
   * Set to `false` to treat advice-carrying denials as plain denials
   * (useful for probe endpoints or when a route owns its own HITL flow).
   */
  autoEscalateHitl?: boolean;

  /**
   * Hook invoked immediately before `session.requestApproval()` fires.
   * Returning an object lets the caller override/augment the approval
   * request — e.g. inject a human-readable `reason`, override the
   * timeout, or cancel by returning `null`.
   */
  onHitlRequested?: (
    info: HitlRequestInfo,
    req: AgentumRequest,
  ) => HitlRequestOverride | null | Promise<HitlRequestOverride | null>;
}

/**
 * Context passed to {@link AgentumGuardOptions.onHitlRequested}. Describes
 * the pending approval the middleware is about to create.
 */
export interface HitlRequestInfo {
  action: string;
  resource: string;
  /** Params parsed from the Cedar `@advice("require_hitl:...")` value. */
  requiredApprovals?: number;
  timeoutSeconds?: number;
  /** Raw advice strings as returned by simulatePolicy, for inspection. */
  advice: string[];
}

/** Return value of {@link AgentumGuardOptions.onHitlRequested}. */
export interface HitlRequestOverride {
  /** Human-readable context shown on the HITL dashboard. */
  reason?: string;
  /** Override the Cedar-supplied timeout (milliseconds). */
  timeoutMs?: number;
  /** Override the Cedar-supplied `required_approvals` count. */
  requiredApprovals?: number;
  /** Extra Cedar context to persist on the approval request. */
  context?: Record<string, unknown>;
}

/** Result of a guard evaluation, passed to `onDeny`. */
export interface GuardDecision {
  allowed: boolean;
  outcome: "Allow" | "Deny";
  rule_id: string | null;
  reason: string | null;
  /**
   * How the decision was reached — useful for audit / debugging.
   * `"network"` = fresh simulatePolicy call, `"cache"` = LRU hit,
   * `"fail-closed" | "fail-open" | "fail-cached"` = simulatePolicy failed,
   * `"breaker-open"` = circuit breaker is open, `"health-down"` = health
   * monitor reports server unreachable.
   */
  source:
    | "network"
    | "cache"
    | "fail-closed"
    | "fail-open"
    | "fail-cached"
    | "breaker-open"
    | "health-down"
    // HITL-escalation outcomes. `hitl-approved` reverses a Deny+advice to an
    // Allow after human approval; `hitl-denied` / `hitl-timeout` keep the Deny
    // shape but carry the HITL reason through.
    | "hitl-approved"
    | "hitl-denied"
    | "hitl-timeout";
  /**
   * sha256 hex of the policy bundle that produced this decision.
   * Carried through from `PolicySimulateResponse.policy_hash`. Absent on
   * fail-mode fallbacks (which never consulted Cedar) and on API versions
   * that predate the field.
   */
  policy_hash?: string;
  /**
   * Wire-vocabulary `DecisionSource::as_str()`. From a simulate
   * round-trip this is always a `"central_*" | "local_pdp_*"` value when
   * present. Threaded as long-form into `request_denied` audits so
   * operators can join on `policy_hash` across `LocalPdpDecision` and
   * framework-guard rows.
   */
  decision_source?:
    | "central_evaluated"
    | "central_cache_hit"
    | "local_pdp_evaluated"
    | "local_pdp_cache_hit";
}
