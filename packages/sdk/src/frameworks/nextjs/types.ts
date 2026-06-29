/**
 * Public types for the Next.js framework integration.
 *
 * Duck-typed against `next/server` — `NextRequest` extends `globalThis.Request`
 * and `NextResponse` extends `globalThis.Response`. Using the standard Web
 * primitives keeps this module dep-free of `next` itself, and works in both
 * the Edge and Node runtimes.
 */

import type { AgentumClient } from "../../client.js";
import type { DecisionCache } from "../express/decision-cache.js";
import type { CircuitBreaker } from "../express/circuit-breaker.js";
import type { HealthMonitor } from "../express/health-check.js";
import type { FailMode, AgentumUser } from "../express/types.js";

// Re-export the shared primitives so consumers don't need to cross-import.
export type { FailMode, AgentumUser } from "../express/types.js";
export { DecisionCache, hashContext } from "../express/decision-cache.js";
export { CircuitBreaker } from "../express/circuit-breaker.js";
export { HealthMonitor } from "../express/health-check.js";

// ── Structural request / response (subset of NextRequest / NextResponse) ───────

/**
 * Structural subset of `NextRequest`. `NextRequest` extends the standard
 * `Request` and adds `nextUrl` + `cookies`. We only rely on the `Request`
 * surface here; callers pass their real `NextRequest` and TS accepts it.
 */
export interface NextRequestLike {
  readonly url: string;
  readonly method: string;
  readonly headers: { get(name: string): string | null };
  readonly nextUrl?: { pathname: string; search: string };
  // Body-reading methods (optional — some guards don't need them).
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
}

/**
 * Structural subset of `NextResponse`. We construct responses via the standard
 * `Response` constructor (also edge-safe) so we don't need to take a runtime
 * dependency on `next/server`.
 */
export type NextResponseLike = Response;

/** Route-handler params/context provided by Next.js for dynamic segments. */
export interface RouteHandlerContext {
  params: Record<string, string | string[]> | Promise<Record<string, string | string[]>>;
}

// ── Shared guard decision ─────────────────────────────────────────────────────

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
    | "health-down";
  /**
   * sha256 hex of the policy bundle that produced this decision.
   * Carried through from `PolicySimulateResponse.policy_hash`. Absent on
   * fail-mode fallbacks and on API versions that predate the field.
   */
  policy_hash?: string;
  /**
   * Wire-vocabulary `DecisionSource::as_str()`. Threaded as
   * long-form into `request_denied` audits so operators can join on
   * `policy_hash` across `LocalPdpDecision` and framework-guard rows.
   */
  decision_source?:
    | "central_evaluated"
    | "central_cache_hit"
    | "local_pdp_evaluated"
    | "local_pdp_cache_hit";
}

// ── Runtime (shared state across route handlers) ───────────────────────────────

/**
 * Long-lived object holding the AgentumClient + resilience primitives. Created
 * once per process (module scope) and reused across route handlers. Not used
 * by Edge middleware — that path is stateless per request.
 */
export interface AgentumNextRuntimeOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  runtime: AgentumClient;
  /** Pre-bound agent ID. */
  agentId: string;
  /** Optional tenant UUID; forwarded as `X-Tenant-ID` on the session client. */
  tenantId?: string;

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
}

/** @internal — shared resilience state. */
export interface AgentumNextInternals {
  client: AgentumClient;
  agentId: string;
  tenantId: string | undefined;
  decisionCache: DecisionCache | null;
  circuitBreaker: CircuitBreaker | null;
  healthMonitor: HealthMonitor | null;
  failMode: FailMode;
}

// ── Middleware options (Edge-runtime `middleware.ts`) ─────────────────────────

export interface AgentumNextMiddlewareOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  runtime: AgentumClient;
  /** Pre-bound agent ID. */
  agentId: string;
  /** Optional tenant UUID. */
  tenantId?: string;

  /**
   * Resolve the user for this request. Return `null` to signal unauthenticated
   * (middleware returns 401 or calls `onUnauthenticated`). Synchronous or
   * async; runs in Edge runtime — no Node-only APIs allowed.
   */
  userFromRequest: (req: NextRequestLike) => AgentumUser | null | Promise<AgentumUser | null>;

  /**
   * Derive `(action, resource, context)` for the simulatePolicy call. The
   * default derives `action = http.<method>` and `resource` from the request
   * host; the context has `{ path }`. Return `null` to skip authorization
   * entirely (middleware allows the request through).
   */
  deriveRequest?: (
    req: NextRequestLike,
  ) =>
    | { action: string; resource: string; context?: Record<string, unknown> }
    | null
    | Promise<{ action: string; resource: string; context?: Record<string, unknown> } | null>;

  /** `matcher` glob patterns — informational only; Next.js uses `export const config`. */
  matcher?: string | string[];

  /** Called when `userFromRequest` returns `null`. Default: 401 JSON response. */
  onUnauthenticated?: (req: NextRequestLike) => Response | Promise<Response>;

  /** Called on Deny. Default: 403 JSON response. */
  onDeny?: (req: NextRequestLike, decision: GuardDecision) => Response | Promise<Response>;

  /**
   * Called when `simulatePolicy` throws. Default: fail-closed with 503 JSON.
   * Match the `failMode` semantics of `withAgentumGuard` if you want parity.
   */
  onError?: (req: NextRequestLike, err: unknown) => Response | Promise<Response>;
}

// ── withAgentumGuard (route handlers) ──────────────────────────────────────────

export interface AgentumGuardNextOptions {
  /** Cedar action string. */
  action: string;
  /** Cedar resource string. */
  resource: string;
  /** Path sent as `context.path`. Static or derived from the request. */
  pathLike?: string | ((req: NextRequestLike) => string);
  /** Extra Cedar context key/value pairs merged into the default `{ path }`. */
  contextExtra?: (req: NextRequestLike) => Record<string, unknown>;
  /** Resolve the user for this request. Return `null` for unauthenticated. */
  userFromRequest: (req: NextRequestLike) => AgentumUser | null | Promise<AgentumUser | null>;
  /** Called on Deny. Default: 403 JSON. */
  onDeny?: (decision: GuardDecision, req: NextRequestLike) => Response | Promise<Response>;
  /** Called when `userFromRequest` returns `null`. Default: 401 JSON. */
  onUnauthenticated?: (req: NextRequestLike) => Response | Promise<Response>;
  /** Bypass the decision cache — always hit the network. */
  skipCache?: boolean;
  /** Per-route override of the middleware's fail-mode. */
  failModeOverride?: FailMode;
}

/**
 * Signature of a Next.js App Router route handler.
 *
 * The `Req` type parameter lets callers type their handler with the real
 * `NextRequest` from `next/server` (which structurally extends
 * `NextRequestLike`); the wrapper still only relies on the `NextRequestLike`
 * surface internally.
 */
export type NextRouteHandler<
  Req extends NextRequestLike = NextRequestLike,
  Ctx extends RouteHandlerContext = RouteHandlerContext,
> = (req: Req, ctx: Ctx) => Promise<Response> | Response;

// ── withAgentumServerAction ────────────────────────────────────────────────────

/**
 * Server actions don't receive a `req` object — they receive their own
 * arguments (form data, primitives, etc.). The auth context must be read from
 * `next/headers` (`cookies()`, `headers()`) inside the caller-provided resolver.
 *
 * We duck-type this as "caller-side resolver returning a user" so the SDK
 * doesn't need `next` as a runtime dep.
 */
export interface AgentumServerActionGuardOptions {
  /** Cedar action string. */
  action: string;
  /** Cedar resource string. */
  resource: string;
  /**
   * Path sent as `context.path`. For server actions this is typically a
   * synthetic resource id like `/orders/42`. Static or a function of the
   * wrapped action's first argument.
   */
  pathLike?: string | ((arg: unknown) => string);
  /** Extra Cedar context; called with the wrapped action's first argument. */
  contextExtra?: (arg: unknown) => Record<string, unknown>;
  /**
   * Caller-side user resolver. Server actions typically read cookies via
   * `import { cookies } from "next/headers"`; this function does that lookup
   * and hands back the user. Return `null` for unauthenticated.
   */
  getUser: () => AgentumUser | null | Promise<AgentumUser | null>;
  /** Bypass the decision cache. */
  skipCache?: boolean;
  /** Per-action fail-mode override. */
  failModeOverride?: FailMode;
}

/**
 * The deny / unauthenticated sentinels a wrapped server action can return.
 * Server actions can't send an HTTP status; throwing is ugly from the client.
 * Instead, the wrapper returns a tagged union so callers can check and render.
 */
export type ServerActionGuardResult<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: "unauthenticated" | "forbidden" | "policy_check_failed";
      decision?: GuardDecision;
    };
