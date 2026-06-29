/**
 * LangChain.js integration for Agentum.
 *
 * Provides:
 * 1. `AgentumCallbackHandler` — logs every LLM call, tool use, and chain event to Agentum audit.
 * 2. `AgentumPolicyTool`     — LangChain tool that gate-checks Cedar policy before execution.
 * 3. `withAgentumGuard`      — higher-order function wrapping any LangChain tool with a policy check.
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from "@langchain/openai";
 * import { AgentumClient } from "@lupid/sdk";
 * import { AgentumCallbackHandler, AgentumPolicyTool } from "@lupid/sdk/frameworks/langchain";
 *
 * const client = new AgentumClient({ baseUrl: "http://localhost:7071" });
 * const agent  = await client.registerAgent({ name: "lc-bot", owner_email: "owner@acme.com", purpose: "qa" });
 * client.setToken(agent.session_jwt);
 *
 * const handler = new AgentumCallbackHandler({ client, agentId: agent.agent_id, sessionId: agent.agent_id });
 * const llm = new ChatOpenAI({ callbacks: [handler] });
 * ```
 */

import { AgentumClient } from "../client.js";
import type { AgentumSession } from "../session.js";
import type { ToolCallEvaluation } from "../evaluation/cedar-client.js";
import {
  pdpObservabilityDetail,
  pdpTopLevelFields,
  warnEvaluatorFallbackOnce as warnEvaluatorFallbackOnceShared,
} from "./_pdp-observability.js";

// No peer import needed — AgentumCallbackHandler is structurally compatible
// with LangChain's BaseCallbackHandler via TypeScript's structural typing.

// PDP observability helpers (`pdpObservabilityDetail`, `pdpTopLevelFields`,
// `mapDecisionSourceToAudit`, `warnEvaluatorFallbackOnce`) live in
// `./_pdp-observability.ts` so `openai.ts` and `vercel-ai.ts` can reuse
// them. The LangChain-specific call sites below pass `"langchain"` to the
// parameterized fallback warner.
function warnEvaluatorFallbackOnce(): void {
  warnEvaluatorFallbackOnceShared("langchain");
}

// ── Callback handler ──────────────────────────────────────────────────────────

export interface AgentumCallbackHandlerOptions {
  /** Use a live AgentumSession as the single source of client/agentId/sessionId. */
  session?: AgentumSession;
  client?: AgentumClient;
  agentId?: string;
  sessionId?: string;
  /**
   * Called when an audit event POST fails. Useful for observability / alerting
   * without blocking the agent. The handler itself always swallows the error.
   */
  onAuditError?: (err: Error) => void;
}

/**
 * LangChain.js `BaseCallbackHandler`-compatible handler that emits Agentum audit events.
 *
 * Attach to any LangChain LLM, tool, or chain to get automatic audit logging.
 * Failures are silently swallowed so the handler never blocks the agent.
 *
 * Can be constructed with a live session for automatic credential propagation:
 * ```ts
 * new AgentumCallbackHandler({ session })
 * ```
 * Or with explicit fields (backward-compatible):
 * ```ts
 * new AgentumCallbackHandler({ client, agentId, sessionId })
 * ```
 */
export class AgentumCallbackHandler {
  private readonly client: AgentumClient;
  private readonly agentId: string;
  private readonly sessionId: string;
  private readonly onAuditError?: (err: Error) => void;

  /** Required by the LangChain callback interface. */
  readonly name = "AgentumCallbackHandler";

  constructor({ session, client, agentId, sessionId, onAuditError }: AgentumCallbackHandlerOptions) {
    if (session) {
      this.client    = session.client;
      this.agentId   = session.agentId;
      this.sessionId = session.sessionId;
    } else {
      if (!client || !agentId || !sessionId) {
        throw new Error(
          "AgentumCallbackHandler: provide either `session` or all of `client`, `agentId`, `sessionId`",
        );
      }
      this.client    = client;
      this.agentId   = agentId;
      this.sessionId = sessionId;
    }
    if (onAuditError) this.onAuditError = onAuditError;
  }

  private emit(
    eventType: string,
    detail: Record<string, unknown>,
    extras?: {
      policy_hash?: string;
      decision_source?: "inproc";
      cache_hit?: boolean;
    },
  ): void {
    const p = this.client.ingestAuditEvent({
      agent_id: this.agentId,
      session_id: this.sessionId,
      event_type: eventType,
      outcome: "ok",
      ...(extras ?? {}),
      detail,
    });
    if (this.onAuditError) {
      void p.catch((err: unknown) => {
        try { this.onAuditError!(err instanceof Error ? err : new Error(String(err))); } catch { /* ignore */ }
      });
    } else {
      void p.catch(() => { /* swallow */ });
    }
  }

  // LLM
  handleLLMStart(_serialized: Record<string, unknown>, prompts: string[]): void {
    // Capture inputs synchronously (zero-copy string join), then defer ALL
    // CPU work (SHA-256 + SimHash64) and the HTTP POST to a microtask.
    // LangChain proceeds to the actual LLM call in ~0 ns — no hashing block.
    const combined = prompts.join("\n");
    const model    = (_serialized["id"] as string[] | undefined)?.at(-1) ?? "unknown";
    void Promise.resolve().then(() => {
      this.emit("llm_call", {
        model,
        prompt_preview: combined.slice(0, 500),
        prompt_tokens:  Math.ceil(combined.length / 4),
        framework:      "langchain",
      });
    });
  }
  handleLLMEnd(): void { this.emit("llm_end", {}); }
  handleLLMError(error: Error): void { this.emit("llm_error", { error: error.message }); }

  // Chat-model variants (delegate to LLM handlers so both code paths emit audit).
  async handleChatModelStart(
    serialized: Record<string, unknown>,
    messages: Array<Array<{ content?: unknown; _getType?: () => string }>>,
  ): Promise<void> {
    // Flatten a best-effort text view of the chat messages for hashing / preview.
    const flat: string[] = [];
    for (const convo of messages ?? []) {
      for (const m of convo ?? []) {
        const role    = typeof m._getType === "function" ? m._getType() : "message";
        const content = typeof m.content === "string" ? m.content : JSON.stringify(m.content ?? "");
        flat.push(`${role}: ${content}`);
      }
    }
    await this.handleLLMStart(serialized, [flat.join("\n")]);
  }
  handleChatModelEnd(): void { this.emit("llm_end", { kind: "chat_model" }); }

  // Agent executor events.
  handleAgentAction(action: { tool?: string; toolInput?: unknown; log?: string }): void {
    this.emit("agent_action", {
      tool:       action.tool ?? "unknown",
      tool_input: action.toolInput ?? null,
      log_length: typeof action.log === "string" ? action.log.length : 0,
    });
  }
  handleAgentEnd(action: { log?: string; returnValues?: Record<string, unknown> }): void {
    this.emit("agent_end", {
      log_length:       typeof action.log === "string" ? action.log.length : 0,
      return_value_keys: Object.keys(action.returnValues ?? {}),
    });
  }

  // Retriever events.
  handleRetrieverStart(serialized: Record<string, unknown>, query: string): void {
    const id = (serialized["id"] as string[] | undefined) ?? [];
    this.emit("retriever_start", {
      retriever:   id[id.length - 1] ?? "unknown",
      query_length: typeof query === "string" ? query.length : 0,
    });
  }
  handleRetrieverEnd(documents: Array<{ pageContent?: string }>): void {
    const docs = Array.isArray(documents) ? documents : [];
    this.emit("retriever_end", {
      doc_count:   docs.length,
      total_chars: docs.reduce((n, d) => n + (d?.pageContent?.length ?? 0), 0),
    });
  }
  handleRetrieverError(error: Error): void {
    this.emit("retriever_error", { error: error.message });
  }

  // Tools
  handleToolStart(serialized: Record<string, unknown>, input: string): void {
    this.emit("tool_start", { tool: serialized["name"] as string, input_length: input.length });
  }
  handleToolEnd(output: string): void {
    this.emit("tool_end", { output_length: output.length });
  }
  handleToolError(error: Error): void { this.emit("tool_error", { error: error.message }); }

  // Chains
  handleChainStart(serialized: Record<string, unknown>): void {
    const id = (serialized["id"] as string[] | undefined) ?? [];
    this.emit("chain_start", { chain: id[id.length - 1] ?? "unknown" });
  }
  handleChainEnd(): void { this.emit("chain_end", {}); }
  handleChainError(error: Error): void { this.emit("chain_error", { error: error.message }); }
}

// ── Policy tool ───────────────────────────────────────────────────────────────

export interface AgentumPolicyToolOptions {
  client: AgentumClient;
  agentId: string;
  /** Optional session id for audit attribution. Defaults to `agentId`. */
  sessionId?: string;
  /** When `true`, returns "DENIED" string instead of throwing PermissionError. Default: false. */
  softDeny?: boolean;
}

/**
 * LangChain-compatible tool that runs a Cedar policy check.
 *
 * Include in an agent's tool array so the LLM can confirm an action is
 * allowed before executing it.
 */
export class AgentumPolicyTool {
  readonly name = "agentum_policy_check";
  readonly description =
    "Check if an action on a resource is permitted by Agentum policy. " +
    "Input: JSON string with 'action' (e.g. 'http.post') and 'resource' (URI). " +
    "Returns 'ALLOWED' or throws PermissionError.";

  private readonly client: AgentumClient;
  private readonly agentId: string;
  private readonly sessionId: string;
  private readonly softDeny: boolean;

  constructor({ client, agentId, sessionId, softDeny = false }: AgentumPolicyToolOptions) {
    this.client    = client;
    this.agentId   = agentId;
    this.sessionId = sessionId ?? agentId;
    this.softDeny  = softDeny;
  }

  private emitDeny(
    action: string,
    detail: Record<string, unknown>,
    extras?: {
      policy_hash?: string;
      decision_source?: "inproc";
      cache_hit?: boolean;
    },
  ): void {
    void this.client.ingestAuditEvent({
      agent_id:   this.agentId,
      session_id: this.sessionId,
      event_type: "policy_deny",
      outcome:    "deny",
      ...(extras ?? {}),
      detail: { ...(action ? { action } : {}), ...detail },
    });
  }

  async invoke(input: string | { action: string; resource: string }): Promise<string> {
    let action: string;
    let resource: string;

    if (typeof input === "string") {
      try {
        const parsed = JSON.parse(input) as Record<string, unknown>;
        action   = String(parsed["action"] ?? "");
        resource = String(parsed["resource"] ?? "*");
      } catch {
        const snippet = input.length > 120 ? `${input.slice(0, 120)}…` : input;
        this.emitDeny("", { reason: "invalid_input", input_snippet: snippet });
        if (this.softDeny) return "DENIED: invalid input";
        throw new Error("AgentumPolicyTool: invalid JSON input");
      }
    } else {
      action   = input.action;
      resource = input.resource;
    }

    // Prefer the rich evaluateToolCall path so audit events carry PDP
    // observability fields. Fall back to isAllowed when the client is
    // missing an apiKey (legacy wiring) so backwards compat is preserved.
    let evaluation: ToolCallEvaluation | null = null;
    let allowed: boolean;
    try {
      evaluation = await this.client.evaluateToolCall(this.agentId, {
        toolName: action,
        arguments: { resource },
      });
      allowed = evaluation.decision === "allow";
    } catch (err) {
      // Distinguish "no apiKey wired" (backwards-compat fallback) from
      // transport/refresh failures (fail-CLOSED deny).
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("apiKey is required")) {
        warnEvaluatorFallbackOnce();
        allowed = await this.client.isAllowed(this.agentId, action, resource);
      } else {
        this.emitDeny(action, { reason: "refresh_failed", resource });
        const msg = `Agentum policy denied: action=${action} resource=${resource}`;
        if (this.softDeny) return `DENIED: ${msg}`;
        throw new Error(`PermissionError: ${msg}`);
      }
    }

    if (!allowed) {
      const extras = evaluation ? pdpTopLevelFields(evaluation) : undefined;
      const obsDetail = evaluation ? pdpObservabilityDetail(evaluation) : {};
      this.emitDeny(
        action,
        { reason: "policy_deny", resource, ...obsDetail },
        extras,
      );
      const msg = `Agentum policy denied: action=${action} resource=${resource}`;
      if (this.softDeny) return `DENIED: ${msg}`;
      throw new Error(`PermissionError: ${msg}`);
    }

    return "ALLOWED";
  }

  /** Alias for LangChain compatibility (`_call` is the standard method name). */
  _call(input: string): Promise<string> {
    return this.invoke(input);
  }
}

// ── withAgentumGuard HOF ──────────────────────────────────────────────────────

/**
 * Wrap any async function with an Agentum Cedar policy guard.
 *
 * @example
 * ```ts
 * const safeFetch = withAgentumGuard(fetch, {
 *   client,
 *   agentId,
 *   action: "http.get",
 *   resource: "https://api.example.com",
 * });
 * // Will throw PermissionError if policy denies
 * const data = await safeFetch("https://api.example.com/data");
 * ```
 */
export function withAgentumGuard<T extends (...args: never[]) => Promise<unknown>>(
  fn: T,
  options: {
    client: AgentumClient;
    agentId: string;
    action: string;
    resource?: string;
    /**
     * Optional session id for audit attribution. When set, the
     * `policy_deny` audit emission carries it on the top-level
     * `session_id` field; when absent, the emission falls back to an
     * empty string (mirroring `cedar-client.ts:574` semantics — the
     * ClickHouse `audit_events.session_id` column is a non-Nullable
     * `String` and stores empty for "no session attribution"). Non-
     * breaking addition; existing callers continue to work.
     */
    sessionId?: string;
  },
): T {
  const { client, agentId, action, resource = "*", sessionId } = options;

  return (async (...args: Parameters<T>) => {
    // Switch to evaluateToolCall so the policy_deny emit can carry PDP
    // observability. Falls back to isAllowed when the client is missing
    // an apiKey (backwards compat) and skips the audit emit in that case
    // (no rich evaluation to attach observability to).
    let evaluation: ToolCallEvaluation | null = null;
    let allowed: boolean;
    try {
      evaluation = await client.evaluateToolCall(agentId, {
        toolName: action,
        arguments: { resource },
      });
      allowed = evaluation.decision === "allow";
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("apiKey is required")) {
        warnEvaluatorFallbackOnce();
        allowed = await client.isAllowed(agentId, action, resource);
      } else {
        // refresh / transport failure — fail-CLOSED. Emit a deny with
        // reason: "refresh_failed" so audit still records the denial.
        void client
          .ingestAuditEvent({
            agent_id: agentId,
            session_id: sessionId ?? "",
            event_type: "policy_deny",
            outcome: "deny",
            detail: {
              action,
              resource,
              framework: "langchain.withAgentumGuard",
              reason: "refresh_failed",
            },
          })
          .catch(() => {
            /* audit is best-effort */
          });
        throw new Error(
          `PermissionError: Agentum policy denied: agent=${agentId} action=${action} resource=${resource}`,
        );
      }
    }

    if (!allowed) {
      if (evaluation) {
        void client
          .ingestAuditEvent({
            agent_id: agentId,
            session_id: sessionId ?? "",
            event_type: "policy_deny",
            outcome: "deny",
            ...pdpTopLevelFields(evaluation),
            detail: {
              action,
              resource,
              framework: "langchain.withAgentumGuard",
              ...pdpObservabilityDetail(evaluation),
            },
          })
          .catch(() => {
            /* audit is best-effort */
          });
      }
      throw new Error(
        `PermissionError: Agentum policy denied: agent=${agentId} action=${action} resource=${resource}`,
      );
    }
    return fn(...args);
  }) as T;
}

// ── enforceAllTools: batch-wrap every tool with a Cedar check ─────────────────

/**
 * A LangChain-compatible tool. Structurally typed to avoid a peer-dep on
 * `@langchain/core` — any object exposing a `name` and one of the standard
 * execution methods (`_call`, `invoke`, `call`) is accepted.
 */
export interface LangChainToolLike {
  name: string;
  description?: string;
  // LangChain historically dispatches through one of these; different
  // versions prefer different entry points, so we wrap all present ones.
  _call?(input: unknown, ...rest: unknown[]): Promise<unknown> | unknown;
  invoke?(input: unknown, ...rest: unknown[]): Promise<unknown> | unknown;
  call?(input: unknown, ...rest: unknown[]): Promise<unknown> | unknown;
  [key: string]: unknown;
}

export type EnforceAllToolsOnDeny = "throw" | "return_error_string" | "silent_skip";

export interface EnforceAllToolsOptions<T extends LangChainToolLike = LangChainToolLike> {
  /** Live session — provides agentId + credential refresh + audit attribution. */
  session: AgentumSession;
  /** Cedar action to evaluate, e.g. `"mcp.tool.call"`. */
  actionPrefix: string;
  /** Cedar resource derivation from the tool. Default: `tool.name`. */
  resourceFn?: (tool: T) => string;
  /**
   * Behaviour on policy deny:
   *   - `"throw"`                — raise `Error` (default).
   *   - `"return_error_string"`  — resolve with `"DENIED: …"` string.
   *   - `"silent_skip"`          — resolve with empty string (no error).
   */
  onDeny?: EnforceAllToolsOnDeny;
}

/**
 * Wrap EVERY LangChain tool in the given list with a Cedar policy guard.
 *
 * Before each tool's execution (`_call` / `invoke` / `call`), calls
 * {@link AgentumSession.isAllowed} with `(actionPrefix, resourceFn(tool))`.
 * On deny: emits an `mcp_tool_deny` audit event and applies `onDeny`.
 * On allow: runs the original method and emits `mcp_tool_call`.
 *
 * Returns a NEW array of shallow-copied tool objects. Original tools are
 * left untouched, so direct LangChain callback handlers attached to the
 * source tools are unaffected.
 *
 * @example
 * ```ts
 * import { enforceAllTools } from '@lupid/sdk/frameworks/langchain';
 *
 * const guardedTools = enforceAllTools(originalTools, {
 *   session,
 *   actionPrefix: 'mcp.tool.call',
 *   resourceFn: (tool) => tool.name,
 *   onDeny: 'throw',
 * });
 *
 * const agent = new AgentExecutor({ tools: guardedTools, ... });
 * ```
 */
/** Marks a tool already wrapped by {@link enforceAllTools} so a repeat pass
 *  doesn't double-evaluate / double-audit. Same idempotency contract as the
 *  `Symbol.for("agentum.*.patched")` markers on the instrumentation patches. */
const ENFORCED_TAG = Symbol.for("agentum.langchain.enforced");

export function enforceAllTools<T extends LangChainToolLike>(
  tools: readonly T[],
  options: EnforceAllToolsOptions<T>,
): T[] {
  const { session, actionPrefix, resourceFn, onDeny = "throw" } = options;
  const resolveResource: (tool: T) => string = resourceFn ?? ((t) => t.name);

  return tools.map((tool) => {
    // Idempotency guard (mirrors the `Symbol.for("agentum.*.patched")`
    // contract the instrumentation patches use): re-wrapping an already
    // enforced tool would run the Cedar check — and emit an audit event —
    // twice per call. Return such tools unchanged.
    if ((tool as Record<symbol, unknown>)[ENFORCED_TAG]) {
      return tool;
    }
    const resource = resolveResource(tool);
    const wrapped: T = Object.create(Object.getPrototypeOf(tool) as object) as T;
    Object.assign(wrapped, tool);

    const runGuarded = async (
      methodName: "_call" | "invoke" | "call",
      args: unknown[],
    ): Promise<unknown> => {
      const original = tool[methodName] as
        | ((...a: unknown[]) => Promise<unknown> | unknown)
        | undefined;
      if (typeof original !== "function") {
        throw new Error(
          `enforceAllTools: tool "${tool.name}" has no callable "${methodName}"`,
        );
      }

      // Prefer the rich evaluateToolCall path. On apiKey-missing, fall
      // back to isAllowed (backwards compat) and emit without
      // observability fields. On other errors (refresh / transport),
      // fail-CLOSED with a `reason: "refresh_failed"` deny.
      let evaluation: ToolCallEvaluation | null = null;
      let allowed: boolean;
      try {
        evaluation = await session.evaluateToolCall({
          toolName: tool.name,
          arguments: { resource },
        });
        allowed = evaluation.decision === "allow";
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("apiKey is required")) {
          warnEvaluatorFallbackOnce();
          try {
            allowed = await session.isAllowed(actionPrefix, resource);
          } catch {
            allowed = false;
          }
        } else {
          // refresh / transport failure — fail-CLOSED.
          void session
            .ingestAuditEvent({
              event_type: "mcp_tool_deny",
              outcome: "deny",
              detail: {
                tool: tool.name,
                action: actionPrefix,
                resource,
                framework: "langchain",
                on_deny: onDeny,
                reason: "refresh_failed",
              },
            })
            .catch(() => { /* audit is best-effort */ });
          const denyMsg = `PermissionError: Agentum policy denied: tool=${tool.name} action=${actionPrefix} resource=${resource}`;
          if (onDeny === "throw") throw new Error(denyMsg);
          if (onDeny === "return_error_string") return `DENIED: ${denyMsg}`;
          return "";
        }
      }

      if (!allowed) {
        const extras = evaluation ? pdpTopLevelFields(evaluation) : undefined;
        const obsDetail = evaluation ? pdpObservabilityDetail(evaluation) : {};
        void session
          .ingestAuditEvent({
            event_type: "mcp_tool_deny",
            outcome: "deny",
            ...(extras ?? {}),
            detail: {
              tool: tool.name,
              action: actionPrefix,
              resource,
              framework: "langchain",
              on_deny: onDeny,
              ...obsDetail,
            },
          })
          .catch(() => { /* audit is best-effort */ });

        const message = `PermissionError: Agentum policy denied: tool=${tool.name} action=${actionPrefix} resource=${resource}`;
        if (onDeny === "throw") throw new Error(message);
        if (onDeny === "return_error_string") return `DENIED: ${message}`;
        // silent_skip
        return "";
      }

      const result = await original.apply(tool, args);

      const allowExtras = evaluation ? pdpTopLevelFields(evaluation) : undefined;
      const allowObsDetail = evaluation ? pdpObservabilityDetail(evaluation) : {};
      void session
        .ingestAuditEvent({
          event_type: "mcp_tool_call",
          outcome: "ok",
          ...(allowExtras ?? {}),
          detail: {
            tool: tool.name,
            action: actionPrefix,
            resource,
            framework: "langchain",
            result_preview:
              typeof result === "string" ? result.slice(0, 200) : typeof result,
            ...allowObsDetail,
          },
        })
        .catch(() => { /* audit is best-effort */ });

      return result;
    };

    if (typeof tool._call === "function") {
      (wrapped as { _call: (...a: unknown[]) => Promise<unknown> })._call = (
        ...a: unknown[]
      ) => runGuarded("_call", a);
    }
    if (typeof tool.invoke === "function") {
      (wrapped as { invoke: (...a: unknown[]) => Promise<unknown> }).invoke = (
        ...a: unknown[]
      ) => runGuarded("invoke", a);
    }
    if (typeof tool.call === "function") {
      (wrapped as { call: (...a: unknown[]) => Promise<unknown> }).call = (
        ...a: unknown[]
      ) => runGuarded("call", a);
    }

    // Stamp so a second enforceAllTools() pass over the same array is a no-op.
    (wrapped as Record<symbol, unknown>)[ENFORCED_TAG] = true;
    return wrapped;
  });
}
