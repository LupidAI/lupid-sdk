/**
 * Next.js framework integration for Agentum multi-tenant agent IAM.
 *
 * Three surfaces:
 *
 * 1. **`agentumMiddleware`** — Edge-compatible middleware for `middleware.ts`.
 *    Stateless per request; short-circuits with 401/403/503 when user
 *    resolution fails, policy denies, or the Agentum endpoint is unreachable.
 *
 * 2. **`createAgentumRuntime` + `withAgentumGuard`** — HOF for App Router
 *    route handlers (`app/api/* /route.ts`). Uses a long-lived runtime with
 *    decision cache, circuit breaker, and health monitor. Intended for the
 *    Node runtime (`export const runtime = "nodejs"`).
 *
 * 3. **`withAgentumServerAction`** — Wraps a Server Action. User resolution
 *    is caller-provided (typically via `next/headers`); returns a tagged
 *    `ServerActionGuardResult<T>` so components can branch on allow / deny
 *    without a thrown exception.
 *
 * All three share the same `DecisionCache`, `CircuitBreaker`, and
 * `HealthMonitor` primitives as `@lupid/sdk/frameworks/express`.
 */

export { agentumMiddleware } from "./middleware.js";
export {
  createAgentumRuntime,
  type AgentumNextRuntime,
} from "./route-handler.js";
export { withAgentumServerAction } from "./server-action.js";
export {
  createAgentumWebhookRuntime,
  type AgentumWebhookRuntime,
  type AgentumWebhookRuntimeOptions,
  type AgentumWebhookGuardOptions,
  type WebhookContext,
  type WebhookRouteHandler,
} from "./webhook-guard.js";

export type {
  AgentumGuardNextOptions,
  AgentumNextMiddlewareOptions,
  AgentumNextRuntimeOptions,
  AgentumServerActionGuardOptions,
  GuardDecision,
  NextRequestLike,
  NextResponseLike,
  NextRouteHandler,
  RouteHandlerContext,
  ServerActionGuardResult,
  FailMode,
  AgentumUser,
} from "./types.js";

// Re-export the shared resilience primitives so consumers can tune or
// instrument them without depending on the `/frameworks/express` subpath.
export {
  DecisionCache,
  hashContext,
  CircuitBreaker,
  HealthMonitor,
} from "./types.js";

// Drop-in auto-register preset. Mirrors Express's `autoRegisterMiddleware`.
// Lazy `ensureAgent()` resolution + env-driven config; reduces customer NextJS
// code to ~3 LOC + 4 env vars.
export {
  autoRegisterMiddleware,
  withAgentumAutoRegister,
  type AutoRegisterMiddlewareOptions,
  type AutoRegisterRouteHandlerOptions,
} from "./auto-register.js";
