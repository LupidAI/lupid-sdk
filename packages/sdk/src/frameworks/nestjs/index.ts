/**
 * NestJS framework integration for Agentum multi-tenant agent IAM.
 *
 * Two surfaces:
 *
 * 1. **`AgentumGuard` + `setAgentumRuntime`** — simplest path. Register a
 *    module-scoped runtime once at bootstrap, then use `@UseGuards(AgentumGuard)`
 *    on controllers or methods.
 *
 * 2. **`agentumGuardClass(runtime)`** — DI-friendly factory. Returns a guard
 *    subclass bound to a specific runtime. Use when multiple AgentumClient
 *    configurations coexist in one NestJS app.
 *
 * Both patterns use `@AgentumGuardFor({ action, resource })` as a method
 * decorator to attach the Cedar action/resource metadata to the route handler.
 *
 * @example
 * ```ts
 * // main.ts
 * import { AgentumClient } from "@lupid/sdk";
 * import { createAgentumRuntime, setAgentumRuntime } from "@lupid/sdk/frameworks/nestjs";
 *
 * const runtime = createAgentumRuntime({
 *   runtime: new AgentumClient({ baseUrl, apiKey }),
 *   agentId: AGENT_ID,
 *   userFromRequest: (req) => USERS[req.headers["x-demo-user"] as string] ?? null,
 * });
 * setAgentumRuntime(runtime);
 *
 * // orders.controller.ts
 * import { Controller, Get, UseGuards } from "@nestjs/common";
 * import { AgentumGuard, AgentumGuardFor } from "@lupid/sdk/frameworks/nestjs";
 *
 * @Controller("orders")
 * @UseGuards(AgentumGuard)
 * export class OrdersController {
 *   @Get()
 *   @AgentumGuardFor({ action: "http.get", resource: "api.example.com" })
 *   async list() { return { orders: [] }; }
 * }
 * ```
 */

export { createAgentumRuntime, createAgentumRuntimeAsync } from "./runtime.js";
// Env-driven auto-register helper. Mirrors the Express + Fastify + NextJS
// auto-register presets but adapted to NestJS's async bootstrap. See
// `auto-register.ts` for the customer-facing usage.
export {
  autoRegisterAgentumRuntime,
  type AutoRegisterRuntimeOptions,
} from "./auto-register.js";
export {
  AgentumGuard,
  agentumGuardClass,
  setAgentumRuntime,
  getAgentumRuntime,
} from "./guard.js";
export { AgentumGuardFor } from "./decorator.js";

export type {
  AgentumGuardForOptions,
  AgentumNestRuntime,
  AgentumNestRuntimeOptions,
  AgentumUser,
  CanActivateLike,
  ExecutionContextLike,
  FailMode,
  GuardDecision,
  HitlRequestInfo,
  HitlRequestOverride,
  HttpArgumentsHostLike,
  NestHttpRequestLike,
  NestHttpResponseLike,
} from "./types.js";

// Re-export resilience primitives so consumers can tune or instrument them.
export {
  DecisionCache,
  hashContext,
  CircuitBreaker,
  HealthMonitor,
} from "./types.js";
