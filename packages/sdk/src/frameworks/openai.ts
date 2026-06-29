/**
 * OpenAI SDK integration for Agentum.
 *
 * Provides:
 * 1. `wrapOpenAIClient`        — wraps an `openai` client instance with audit logging + policy gates.
 * 2. `AgentumAssistantRunner`  — lifecycle manager for OpenAI Assistants API runs.
 * 3. `policyFunctionTool`      — creates an OpenAI function-tool spec + guarded executor.
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { AgentumClient } from "@lupid/sdk";
 * import { wrapOpenAIClient } from "@lupid/sdk/frameworks/openai";
 *
 * const agentum = new AgentumClient({ baseUrl: "http://localhost:7071" });
 * const reg     = await agentum.registerAgent({ name: "oai-bot", owner_email: "owner@acme.com", purpose: "assistant" });
 * agentum.setToken(reg.session_jwt);
 *
 * const openai  = wrapOpenAIClient(new OpenAI(), { client: agentum, agentId: reg.agent_id, sessionId: reg.agent_id });
 * const resp    = await openai.chat.completions.create({ model: "gpt-4o", messages: [...] });
 * ```
 */

import { AgentumClient } from "../client.js";
import type { AgentumSession } from "../session.js";
import type { ToolCallEvaluation } from "../evaluation/cedar-client.js";
import {
  ingestOpenAIChunk,
  newOpenAIStreamState,
  type OpenAIStreamState,
} from "../instrumentation/_parsers.js";
import {
  pdpObservabilityDetail,
  pdpTopLevelFields,
  warnEvaluatorFallbackOnce,
} from "./_pdp-observability.js";

/** Extract a prompt string from an OpenAI chat completion request args. */
function extractPromptFromArgs(args: unknown[]): string {
  try {
    const req = args[0] as Record<string, unknown>;
    const messages = req["messages"] as Array<{ role: string; content: string }> | undefined;
    if (!messages) return "";
    return messages.map(m => `${m.role}: ${m.content ?? ""}`).join("\n");
  } catch {
    return "";
  }
}

/**
 * Relay an OpenAI SSE-style chat completion stream to the caller while
 * aggregating tool-call deltas (merged by `choices[0].delta.tool_calls[i].index`)
 * and the final `finish_reason` / `usage`. One audit event is emitted per
 * completed tool call at stream end, plus a single `llm_end` or `llm_error`
 * event — never before the consumer has finished iterating.
 *
 * Parser logic lives in `instrumentation/_parsers.ts` and is shared with
 * the auto-init monkeypatch path.
 */
function relayOpenAIStream(
  source: AsyncIterable<Record<string, unknown>>,
  emit: (event: { event_type: string; outcome: "ok" | "error"; tool?: string; detail?: Record<string, unknown> }) => void,
): AsyncIterable<Record<string, unknown>> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Record<string, unknown>> {
      const it = source[Symbol.asyncIterator]();
      const state: OpenAIStreamState = newOpenAIStreamState();
      let finalized = false;

      const finalize = (): void => {
        if (finalized) return;
        finalized = true;
        for (const [idx, tc] of state.toolCalls) {
          const evt: { event_type: string; outcome: "ok" | "error"; tool?: string; detail?: Record<string, unknown> } = {
            event_type: "tool_call",
            outcome:    "ok",
            detail: {
              index:          idx,
              tool_call_id:   tc.id,
              tool_type:      tc.type,
              function_name:  tc.function.name,
              function_args:  tc.function.arguments,
            },
          };
          if (tc.function.name) evt.tool = tc.function.name;
          emit(evt);
        }
        emit({
          event_type: "llm_end",
          outcome:    "ok",
          detail: {
            finish_reason:    state.finishReason ?? null,
            tool_call_count:  state.toolCalls.size,
            usage:            state.usage ?? null,
            streamed:         true,
          },
        });
      };

      return {
        async next(): Promise<IteratorResult<Record<string, unknown>>> {
          try {
            const step = await it.next();
            if (step.done) {
              finalize();
              return step;
            }
            ingestOpenAIChunk(state, step.value);
            return step;
          } catch (err) {
            finalized = true;
            emit({
              event_type: "llm_error",
              outcome:    "error",
              detail:     { error: (err as Error).message, streamed: true },
            });
            throw err;
          }
        },
        async return(value?: Record<string, unknown> | PromiseLike<Record<string, unknown>>): Promise<IteratorResult<Record<string, unknown>>> {
          finalize();
          if (typeof it.return === "function") return it.return(value);
          return { value: value as Record<string, unknown>, done: true };
        },
        async throw(err?: unknown): Promise<IteratorResult<Record<string, unknown>>> {
          if (!finalized) {
            finalized = true;
            emit({
              event_type: "llm_error",
              outcome:    "error",
              detail:     { error: (err as Error)?.message ?? String(err), streamed: true },
            });
          }
          if (typeof it.throw === "function") return it.throw(err);
          throw err;
        },
      };
    },
  };
}

export interface OpenAIWrapOptions {
  /** Use a live AgentumSession as the single source of client/agentId/sessionId. */
  session?: AgentumSession;
  client?: AgentumClient;
  agentId?: string;
  sessionId?: string;
  /** Optional Cedar action checked before every chat completion. */
  policyAction?: string;
  policyResource?: string;
}

/** Resolve client/agentId/sessionId from either a session or explicit fields. */
function resolveOpenAIOpts(opts: OpenAIWrapOptions): {
  client: AgentumClient;
  agentId: string;
  sessionId: string;
} {
  if (opts.session) {
    return {
      client:    opts.session.client,
      agentId:   opts.session.agentId,
      sessionId: opts.session.sessionId,
    };
  }
  if (!opts.client || !opts.agentId || !opts.sessionId) {
    throw new Error(
      "wrapOpenAIClient: provide either `session` or all of `client`, `agentId`, `sessionId`",
    );
  }
  return { client: opts.client, agentId: opts.agentId, sessionId: opts.sessionId };
}

/**
 * Wraps an OpenAI SDK client, injecting Agentum audit events and optional
 * Cedar policy checks before every `chat.completions.create` call.
 */
export function wrapOpenAIClient<T extends object>(openaiClient: T, opts: OpenAIWrapOptions): T {
  const { client, agentId, sessionId } = resolveOpenAIOpts(opts);
  const { policyAction, policyResource = "*" } = opts;

  // Health-check: verify the expected openai SDK structure is present at
  // wrap time so callers get an actionable error immediately rather than a
  // silent proxy failure on the first LLM call.
  const maybeChat = (openaiClient as Record<string, unknown>)["chat"];
  const maybeCreate = maybeChat && typeof maybeChat === "object"
    ? ((maybeChat as Record<string, unknown>)["completions"] as Record<string, unknown> | undefined)?.["create"]
    : undefined;
  if (!maybeCreate || typeof maybeCreate !== "function") {
    throw new Error(
      "wrapOpenAIClient: openaiClient does not have `chat.completions.create`. " +
      "Pass a valid OpenAI SDK instance (e.g. `new OpenAI()`).",
    );
  }

  return new Proxy(openaiClient, {
    get(target, prop) {
      const value = (target as Record<string | symbol, unknown>)[prop];

      // Intercept chat.completions.create
      if (prop === "chat" && typeof value === "object" && value !== null) {
        return new Proxy(value as object, {
          get(chatTarget, chatProp) {
            const chatValue = (chatTarget as Record<string | symbol, unknown>)[chatProp];
            if (chatProp === "completions" && typeof chatValue === "object") {
              return new Proxy(chatValue as object, {
                get(compTarget, compProp) {
                  const compValue = (compTarget as Record<string | symbol, unknown>)[compProp];
                  if (compProp === "create" && typeof compValue === "function") {
                    return async (...args: unknown[]) => {
                      // Policy gate — emit policy_deny BEFORE throwing so the
                      // denied attempt is always visible in the audit trail.
                      if (policyAction) {
                        // Prefer the rich evaluateToolCall path so the
                        // policy_deny emit carries PDP observability fields.
                        // Fall back to isAllowed when the client is missing an
                        // apiKey (backwards compat); fail-CLOSED on other
                        // transport/refresh errors with reason: "refresh_failed".
                        let evaluation: ToolCallEvaluation;
                        try {
                          evaluation = await client.evaluateToolCall(agentId, {
                            toolName: policyAction,
                            arguments: { resource: policyResource },
                          });
                        } catch (err) {
                          if (err instanceof Error && err.message.includes("apiKey is required")) {
                            warnEvaluatorFallbackOnce("openai");
                            const allowed = await client.isAllowed(agentId, policyAction, policyResource);
                            evaluation = { decision: allowed ? "allow" : "deny", ttlMs: 0 };
                          } else {
                            evaluation = { decision: "deny", ttlMs: 0, reason: "refresh_failed" };
                          }
                        }
                        if (evaluation.decision === "deny") {
                          void client.ingestAuditEvent({
                            agent_id: agentId,
                            session_id: sessionId,
                            event_type: "policy_deny",
                            outcome: "deny",
                            ...pdpTopLevelFields(evaluation),
                            detail: {
                              action: policyAction,
                              resource: policyResource,
                              reason: "cedar_policy_denied",
                              framework: "openai",
                              ...pdpObservabilityDetail(evaluation),
                            },
                          });
                          throw new Error(
                            `PermissionError: Agentum denied LLM call: action=${policyAction} resource=${policyResource}`,
                          );
                        }
                      }
                      const promptText = extractPromptFromArgs(args);
                      const reqModel  = ((args[0] as Record<string, unknown>)?.["model"] as string | undefined) ?? "unknown";
                      void client.ingestAuditEvent({
                        agent_id: agentId,
                        session_id: sessionId,
                        // Canonical event type is "llm_call" with detail.phase
                        // distinguishing pre-response emission from a paired
                        // llm_end after the response.
                        event_type: "llm_call",
                        outcome: "ok",
                        detail: {
                          phase:          "start",
                          model:          reqModel,
                          provider:       "openai",
                          prompt_preview: promptText.slice(0, 500),
                          prompt_tokens:  Math.ceil(promptText.length / 4),
                        },
                      });
                      const isStream = Boolean((args[0] as Record<string, unknown> | undefined)?.["stream"]);
                      try {
                        const result = await (compValue as (...a: unknown[]) => Promise<unknown>)(...args);
                        if (isStream && result && typeof (result as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
                          return relayOpenAIStream(
                            result as AsyncIterable<Record<string, unknown>>,
                            (event) => void client.ingestAuditEvent({
                              agent_id:  agentId,
                              session_id: sessionId,
                              ...event,
                            }),
                          );
                        }
                        void client.ingestAuditEvent({
                          agent_id: agentId,
                          session_id: sessionId,
                          event_type: "llm_end",
                          outcome: "ok",
                        });
                        return result;
                      } catch (err) {
                        void client.ingestAuditEvent({
                          agent_id: agentId,
                          session_id: sessionId,
                          event_type: "llm_error",
                          outcome: "error",
                          detail: { error: (err as Error).message },
                        });
                        throw err;
                      }
                    };
                  }
                  return compValue;
                },
              });
            }
            return chatValue;
          },
        });
      }

      return value;
    },
  });
}

// ── Assistants API runner ──────────────────────────────────────────────────────

export interface AssistantRunnerOptions {
  /** Use a live AgentumSession as the single source of client/agentId/sessionId. */
  session?: AgentumSession;
  client?: AgentumClient;
  agentId?: string;
  sessionId?: string;
  /** Poll interval in ms while waiting for run completion. Default: 1000. */
  pollIntervalMs?: number;
  /** Max wait time in ms before giving up. Default: 120_000. */
  maxWaitMs?: number;
}

export interface AssistantRun {
  run_id: string;
  thread_id: string;
  status: string;
  required_action?: unknown;
  last_error?: unknown;
}

/**
 * Manages the lifecycle of an OpenAI Assistants API run, with built-in
 * Agentum audit logging and Cedar policy checks for tool calls.
 */
export class AgentumAssistantRunner {
  private readonly agentumClient: AgentumClient;
  private readonly agentId: string;
  private readonly sessionId: string;
  private readonly pollIntervalMs: number;
  private readonly maxWaitMs: number;

  constructor(opts: AssistantRunnerOptions) {
    const resolved = resolveOpenAIOpts(opts);
    this.agentumClient  = resolved.client;
    this.agentId        = resolved.agentId;
    this.sessionId      = resolved.sessionId;
    this.pollIntervalMs = opts.pollIntervalMs ?? 1_000;
    this.maxWaitMs      = opts.maxWaitMs ?? 120_000;
  }

  /**
   * Wait for an OpenAI run to complete, emitting audit events at each poll.
   * If the run requires tool calls, emits `tool_call` audit events.
   */
  async waitForCompletion(
    openaiRunsApi: {
      retrieve: (threadId: string, runId: string) => Promise<AssistantRun>;
    },
    threadId: string,
    runId: string,
  ): Promise<AssistantRun> {
    const deadline = Date.now() + this.maxWaitMs;
    let run: AssistantRun;

    do {
      if (Date.now() > deadline) {
        throw new Error(`Agentum: OpenAI run ${runId} did not complete within ${this.maxWaitMs}ms`);
      }
      await new Promise((r) => setTimeout(r, this.pollIntervalMs));
      run = await openaiRunsApi.retrieve(threadId, runId);

      void this.agentumClient.ingestAuditEvent({
        agent_id: this.agentId,
        session_id: this.sessionId,
        event_type: "assistant_run_poll",
        outcome: "ok",
        detail: { run_id: runId, status: run.status },
      });

      if (run.status === "requires_action" && run.required_action) {
        void this.agentumClient.ingestAuditEvent({
          agent_id: this.agentId,
          session_id: this.sessionId,
          event_type: "tool_call",
          outcome: "ok",
          detail: { run_id: runId },
        });
      }
    } while (!["completed", "failed", "cancelled", "expired"].includes(run.status));

    const outcome = run.status === "completed" ? "ok" : "error";
    void this.agentumClient.ingestAuditEvent({
      agent_id: this.agentId,
      session_id: this.sessionId,
      event_type: "assistant_run_end",
      outcome,
      detail: { run_id: runId, status: run.status },
    });

    return run;
  }
}

// ── policyFunctionTool ─────────────────────────────────────────────────────────

export interface PolicyFunctionToolOptions<TArgs extends Record<string, unknown>, TResult> {
  client: AgentumClient;
  agentId: string;
  /**
   * Optional session id for audit attribution. When set, the
   * `policy_deny` audit emission carries it on the top-level
   * `session_id` field; when absent, the emission falls back to an empty
   * string (matching the ClickHouse `audit_events.session_id` "no session
   * attribution" convention). Non-breaking addition; existing callers
   * continue to work.
   */
  sessionId?: string;
  /** Cedar action checked before execution, e.g. "tool:web_search". */
  action: string;
  resource?: string;
  /** OpenAI function spec. */
  spec: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
  /** The implementation to execute after policy pass. */
  execute: (args: TArgs) => Promise<TResult>;
}

/**
 * Creates an OpenAI function tool definition + a Cedar-guarded executor.
 *
 * @returns `{ toolSpec, execute }` — add `toolSpec` to the `tools` array and
 *   call `execute` when OpenAI returns a `function` tool call.
 *
 * @example
 * ```ts
 * const { toolSpec, execute } = policyFunctionTool({
 *   client, agentId,
 *   action: "tool:web_search",
 *   spec: { name: "web_search", description: "Search the web", parameters: { ... } },
 *   execute: async ({ query }) => fetchResults(query),
 * });
 *
 * const resp = await openai.chat.completions.create({ model: "gpt-4o", tools: [toolSpec], ... });
 * // On tool_call response:
 * const result = await execute(JSON.parse(toolCall.function.arguments));
 * ```
 */
export function policyFunctionTool<TArgs extends Record<string, unknown>, TResult>(
  opts: PolicyFunctionToolOptions<TArgs, TResult>,
): {
  toolSpec: { type: "function"; function: typeof opts.spec };
  execute: (args: TArgs) => Promise<TResult>;
} {
  const { client, agentId, sessionId, action, resource = "*", spec, execute } = opts;

  const guardedExecute = async (args: TArgs): Promise<TResult> => {
    // Prefer the rich evaluateToolCall path. On apiKey-missing,
    // fall back to isAllowed (backwards compat) and emit without
    // observability fields. On other errors (refresh / transport),
    // fail-CLOSED with `reason: "refresh_failed"`. Emits a `policy_deny`
    // audit row on deny — without it, a denied tool call leaves no audit trail.
    let evaluation: ToolCallEvaluation;
    try {
      evaluation = await client.evaluateToolCall(agentId, {
        toolName: spec.name,
        arguments: args,
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes("apiKey is required")) {
        warnEvaluatorFallbackOnce("openai");
        const allowed = await client.isAllowed(agentId, action, resource);
        evaluation = { decision: allowed ? "allow" : "deny", ttlMs: 0 };
      } else {
        evaluation = { decision: "deny", ttlMs: 0, reason: "refresh_failed" };
      }
    }
    if (evaluation.decision === "deny") {
      void client.ingestAuditEvent({
        agent_id: agentId,
        session_id: sessionId ?? "",
        event_type: "policy_deny",
        outcome: "deny",
        ...pdpTopLevelFields(evaluation),
        detail: {
          tool: spec.name,
          action,
          resource,
          framework: "openai.policyFunctionTool",
          ...pdpObservabilityDetail(evaluation),
        },
      });
      throw new Error(
        `PermissionError: Agentum denied tool=${spec.name} action=${action} resource=${resource}`,
      );
    }
    return execute(args);
  };

  return {
    toolSpec: { type: "function", function: spec },
    execute: guardedExecute,
  };
}
