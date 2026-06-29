/**
 * @lupid/sdk — TypeScript SDK for the Agentum Agentic IAM platform.
 *
 * Quick start:
 * ```ts
 * import { AgentumClient } from "@lupid/sdk";
 *
 * const client = new AgentumClient({ baseUrl: "http://localhost:7071", apiKey: "your-api-key" });
 *
 * const session = await client.connect({
 *   name: "my-bot",
 *   owner_email: "owner@example.com",
 *   purpose: "process customer data",
 *   framework: "langchain",
 * });
 *
 * const allowed = await session.isAllowed("http.post", "https://api.example.com");
 * if (!allowed) throw new Error("Policy denied");
 *
 * await session.close();
 * ```
 *
 * Framework wrappers:
 * - `@lupid/sdk/frameworks/langchain`  — LangChain.js callback handler + policy tool
 * - `@lupid/sdk/frameworks/vercel-ai`  — Vercel AI SDK middleware
 * - `@lupid/sdk/frameworks/openai`     — OpenAI Assistants + Chat Completions guard
 * - `@lupid/sdk/frameworks/express`    — Express.js middleware with session pooling
 * - `@lupid/sdk/frameworks/nextjs`     — Next.js App Router middleware, route-handler, and Server Action guards
 */

export { AgentumClient } from "./client.js";
export {
  ensureAgent,
  type EnsureAgentOptions,
  type EnsureAgentResult,
} from "./ensure-agent.js";
export { AgentumSession, type AgentumSessionOptions } from "./session.js";
export {
  AgentumAdminClient,
  type AgentumAdminClientConfig,
  AgentsApi,
  PoliciesApi,
  type AgentPolicyRecord,
  type ApplyDeclarativeResponse,
  PolicyBuilder,
  type ApplyDeclarativeResult,
  type AllActionsRuleInput,
  type ApprovalConfigInput,
  type HttpRuleInput,
  type McpRuleInput,
  type RoleInput,
  type WhenContextInput,
  type WhenUserInput,
  McpApi,
  ApiKeysApi,
  AgentumAgentAdminClient,
  type AgentumAgentAdminClientConfig,
} from "./admin/index.js";
export * from "./types.js";
export {
  formatTraceparent,
  mintTraceContext,
  parseTraceparent,
  resolveTraceContext,
  type TraceContext,
  type TracingProvider,
} from "./tracing.js";
export {
  SimulateDecisionCache,
  parseMaxAgeMs,
  stableStringify,
  type SimulateCacheOptions,
} from "./simulate-cache.js";
export {
  init,
  shutdown,
  getRuntime,
  _resetForTests,
  AgentumInitError,
  type InitOptions,
  type AgentumRuntime,
} from "./init.js";
export {
  CedarToolCallClient,
  type CedarClientOptions,
  type ToolCallEvaluation,
  type DenyCode,
} from "./evaluation/cedar-client.js";
export {
  installOpenAIPatch,
  uninstallOpenAIPatch,
} from "./instrumentation/openai-patch.js";
export {
  installAnthropicPatch,
  uninstallAnthropicPatch,
} from "./instrumentation/anthropic-patch.js";
export {
  installMcpStdioPatch,
  uninstallMcpStdioPatch,
  isMcpStdioPatched,
  namespacedToolName,
  type McpStdioPatchOptions,
} from "./instrumentation/mcp-stdio-patch.js";
export {
  installFetchInterceptor,
  type FetchInterceptorOptions,
  type FetchInterceptorRuntime,
} from "./instrumentation/fetch-interceptor.js";
export {
  installUndiciDispatcherInterceptor,
  type UndiciDispatcherInterceptorOptions,
  type UndiciInterceptorRuntime,
  type UndiciDispatcher,
} from "./instrumentation/undici-dispatcher-interceptor.js";
export {
  withAgentumContext,
  getAgentumContext,
  contextToProxyHeaders,
  type AgentumContext,
} from "./instrumentation/context.js";
export { getActiveSchema } from "./manifest/state.js";
// Agent-manifest binding-mode dispatcher. Public so consumers can catch
// `BindingModeNotYetSupportedError` deliberately (e.g. in a wrapper that
// prints a migration note) and so they can typecheck against the shared
// `BindingMode` union.
export {
  ALL_BINDING_MODES,
  ACTIVE_BINDING_MODES,
  DEFERRED_BINDING_MODES,
  MVP3_REFERENCE_TICKETS,
  BindingModeNotYetSupportedError,
  InvalidBindingModeError,
  extractBindingMode,
  runPerModeScan,
  type BindingMode,
  type BindingScanLogger,
  type PerModeScanResult,
} from "./binding/index.js";
// Expose the manifest validator so the parity-check script (and operator
// tooling) can call it directly. `validate` accepts an already-parsed
// `TenantSchema`; `parseAndValidate` accepts the raw POJO from
// `YAML.parse(...)` or the HTTP body.
export {
  parseAndValidate,
  validate as validateManifest,
} from "./manifest/validator.js";
export type {
  ValidationIssue,
  ValidationIssueCode,
} from "./manifest/errors.js";
export {
  HostRegistry,
  classifyUrl,
  addLlmHosts,
  type Provider,
  type WireShape,
  type HostMatch,
} from "./instrumentation/host-registry.js";

export const VERSION = "0.1.0";

// Default export: convenience namespace so customers can do
//   import agentum from '@lupid/sdk';
//   await agentum.init();
import { init as _init, getRuntime as _getRuntime } from "./init.js";
import { ensureAgent as _ensureAgent } from "./ensure-agent.js";
const agentum = {
  init: _init,
  getRuntime: _getRuntime,
  ensureAgent: _ensureAgent,
};
export default agentum;
