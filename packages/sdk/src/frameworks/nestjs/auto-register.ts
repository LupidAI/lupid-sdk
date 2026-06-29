/**
 * Drop-in env-driven auto-register helper for NestJS.
 *
 * NestJS's module bootstrap is async, so the customer-side onboarding
 * shape is "build a runtime in your `bootstrap()`":
 *
 * ```ts
 * // main.ts
 * import {
 *   autoRegisterAgentumRuntime,
 *   setAgentumRuntime,
 * } from "@lupid/sdk/frameworks/nestjs";
 *
 * async function bootstrap() {
 *   const runtime = await autoRegisterAgentumRuntime({
 *     framework: "langgraph",
 *   });
 *   if (runtime) setAgentumRuntime(runtime);
 *
 *   const app = await NestFactory.create(AppModule);
 *   await app.listen(3000);
 * }
 * ```
 *
 * Reads env (`AGENTUM_BASE_URL`, `AGENTUM_API_KEY`, `AGENTUM_AGENT_NAME`,
 * `AGENTUM_AGENT_FRAMEWORK`, `AGENTUM_DECLARED_TOOLS`), calls the
 * universal `ensureAgent()`, and wraps `createAgentumRuntime()` with
 * the resolved `agentId`. Returns `null` when env isn't configured so
 * non-Agentum dev environments boot unchanged.
 */

import { AgentumClient } from "../../client.js";
import { ensureAgent } from "../../ensure-agent.js";
import type { AgentCapabilities, AgentMcpServer } from "../../ensure-agent.js";
import { createAgentumRuntime } from "./runtime.js";
import type { AgentumNestRuntime, AgentumNestRuntimeOptions } from "./types.js";

export interface AutoRegisterRuntimeOptions {
  /** Defaults to `process.env.AGENTUM_BASE_URL`. */
  baseUrl?: string;
  /** Defaults to `process.env.AGENTUM_API_KEY`. */
  apiKey?: string;
  /** Defaults to `process.env.AGENTUM_AGENT_NAME`. */
  agentName?: string;
  /** Pre-resolved agent UUID. Skips `/sdk/register`. Useful for tests. */
  agentId?: string;
  /** Defaults to `process.env.AGENTUM_AGENT_FRAMEWORK` or `'agentum-sdk'`. */
  framework?: string;
  /** Free-text purpose written on first-create. */
  purpose?: string;
  /** CSV string or `string[]`. Defaults to `process.env.AGENTUM_DECLARED_TOOLS`. */
  declaredTools?: string | string[];
  /** Capabilities-v2 booleans synced via `ensureAgent`. */
  capabilities?: AgentCapabilities;
  /** Per-agent MCP-server inventory synced via `ensureAgent`. */
  mcpServers?: AgentMcpServer[];
  /** Required by `createAgentumRuntime`. The customer's per-request
   *  user resolver — typically pulls `req.user.{id,email}` populated by
   *  Passport / NestJS guards. Defaults to a Passport-compatible resolver. */
  userFromRequest?: AgentumNestRuntimeOptions["userFromRequest"];
  /** Custom logger; defaults to `console`. */
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Forwarded to `createAgentumRuntime`. */
  decisionCache?: AgentumNestRuntimeOptions["decisionCache"];
  circuitBreaker?: AgentumNestRuntimeOptions["circuitBreaker"];
  healthCheck?: AgentumNestRuntimeOptions["healthCheck"];
  failMode?: AgentumNestRuntimeOptions["failMode"];
}

const DEFAULT_FRAMEWORK = "agentum-sdk";

/**
 * Build a NestJS runtime with env-driven `ensureAgent()` resolution.
 *
 * Returns `null` when env isn't configured (caller should treat as
 * no-op signal — typically skip `setAgentumRuntime` or fall back to a
 * mock runtime in dev).
 */
export async function autoRegisterAgentumRuntime(
  options: AutoRegisterRuntimeOptions = {},
): Promise<AgentumNestRuntime | null> {
  const logger = options.logger ?? console;

  const baseUrl = options.baseUrl ?? process.env.AGENTUM_BASE_URL;
  const apiKey = options.apiKey ?? process.env.AGENTUM_API_KEY;
  const agentName = options.agentName ?? process.env.AGENTUM_AGENT_NAME;
  const explicitAgentId = options.agentId ?? process.env.AGENTUM_AGENT_ID;

  if (!baseUrl || !apiKey || (!agentName && !explicitAgentId)) {
    logger.log(
      "[agentum] autoRegisterAgentumRuntime: env not configured (need AGENTUM_BASE_URL, " +
        "AGENTUM_API_KEY, AGENTUM_AGENT_NAME) — returning null",
    );
    return null;
  }

  let agentId: string;
  if (explicitAgentId) {
    agentId = explicitAgentId;
  } else {
    const ensureOpts: import("../../ensure-agent.js").EnsureAgentOptions = {
      baseUrl,
      apiKey,
      name: agentName!,
      sharedUserModel: true,
      logger,
    };
    if (options.framework !== undefined) {
      ensureOpts.framework = options.framework;
    } else if (process.env.AGENTUM_AGENT_FRAMEWORK !== undefined) {
      ensureOpts.framework = process.env.AGENTUM_AGENT_FRAMEWORK;
    } else {
      ensureOpts.framework = DEFAULT_FRAMEWORK;
    }
    if (options.purpose !== undefined) ensureOpts.purpose = options.purpose;
    if (options.declaredTools !== undefined)
      ensureOpts.declaredTools = options.declaredTools;
    if (options.capabilities !== undefined)
      ensureOpts.capabilities = options.capabilities;
    if (options.mcpServers !== undefined)
      ensureOpts.mcpServers = options.mcpServers;

    const result = await ensureAgent(ensureOpts);
    agentId = result.agentId;
  }

  const userFromRequest = options.userFromRequest ?? defaultUserFromRequest;

  const runtimeOpts: AgentumNestRuntimeOptions = {
    runtime: new AgentumClient({ baseUrl, apiKey }),
    agentId,
    userFromRequest,
  };
  if (options.decisionCache !== undefined)
    runtimeOpts.decisionCache = options.decisionCache;
  if (options.circuitBreaker !== undefined)
    runtimeOpts.circuitBreaker = options.circuitBreaker;
  if (options.healthCheck !== undefined)
    runtimeOpts.healthCheck = options.healthCheck;
  if (options.failMode !== undefined) runtimeOpts.failMode = options.failMode;

  return createAgentumRuntime(runtimeOpts);
}

/**
 * Default user resolver — keys off `req.user.{id, email}`, the shape
 * Passport.js + NestJS auth guards produce.
 */
function defaultUserFromRequest(
  req: unknown,
): { id: string; email: string } | null {
  const u = (req as { user?: { id?: string | number; email?: string } }).user;
  if (!u || u.id === undefined || u.id === null) return null;
  const id = String(u.id);
  return {
    id,
    email: u.email ?? `${id}@unknown.local`,
  };
}
