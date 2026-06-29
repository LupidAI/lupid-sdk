/**
 * Vercel AI SDK integration for Agentum.
 *
 * Provides:
 * 1. `createAgentumMiddleware` — wraps any Vercel AI model with policy checks + audit logging.
 * 2. `agentumTool`            — wraps a `tool()` definition with a Cedar policy guard.
 * 3. `AgentumTelemetry`       — structured telemetry object for use with `experimental_telemetry`.
 *
 * @example
 * ```ts
 * import { openai } from "@ai-sdk/openai";
 * import { generateText } from "ai";
 * import { AgentumClient } from "@lupid/sdk";
 * import { createAgentumMiddleware } from "@lupid/sdk/frameworks/vercel-ai";
 *
 * const client = new AgentumClient({ baseUrl: "http://localhost:7071" });
 * const reg    = await client.registerAgent({ name: "vai-bot", owner_email: "owner@acme.com", purpose: "chat" });
 * client.setToken(reg.session_jwt);
 *
 * const middleware = createAgentumMiddleware({ client, agentId: reg.agent_id, sessionId: reg.agent_id });
 * const model = middleware.wrapLanguageModel(openai("gpt-4o"));
 *
 * const { text } = await generateText({ model, prompt: "Summarize..." });
 * ```
 */

import { AgentumClient } from "../client.js";
import type { AgentumSession } from "../session.js";
import type { ToolCallEvaluation } from "../evaluation/cedar-client.js";
import {
  pdpObservabilityDetail,
  pdpTopLevelFields,
  warnEvaluatorFallbackOnce,
} from "./_pdp-observability.js";

// ── Middleware ─────────────────────────────────────────────────────────────────

export interface AgentumMiddlewareOptions {
  /** Use a live AgentumSession as the single source of client/agentId/sessionId. */
  session?: AgentumSession;
  client?: AgentumClient;
  agentId?: string;
  sessionId?: string;
  /** If set, every language model call checks this policy action first. */
  policyAction?: string;
  /** Default resource for policy checks. Default: "*". */
  policyResource?: string;
}

/** Resolve client/agentId/sessionId from session or explicit fields. */
function resolveVercelOpts(opts: { session?: AgentumSession; client?: AgentumClient; agentId?: string; sessionId?: string; }): {
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
      "createAgentumMiddleware: provide either `session` or all of `client`, `agentId`, `sessionId`",
    );
  }
  return { client: opts.client, agentId: opts.agentId, sessionId: opts.sessionId };
}

/**
 * Creates an Agentum middleware object compatible with the Vercel AI SDK's
 * `wrapLanguageModel` pattern (AI SDK >= 3.x `experimental_telemetry`-style).
 *
 * The middleware is framework-agnostic: it wraps the model's `doGenerate` and
 * `doStream` methods rather than patching the Vercel AI SDK internals.
 */
export function createAgentumMiddleware(opts: AgentumMiddlewareOptions) {
  const { client, agentId, sessionId } = resolveVercelOpts(opts);
  const { policyAction, policyResource = "*" } = opts;

  async function beforeGenerate(): Promise<void> {
    // Emit audit event
    void client.ingestAuditEvent({
      agent_id: agentId,
      session_id: sessionId,
      // The Rust enum has `LlmCall` for outbound LLM events.
      // detail.phase distinguishes "before LLM call" from a paired llm_end.
      event_type: "llm_call",
      outcome: "ok",
      detail: { phase: "start" },
    });

    // Optional policy gate
    if (policyAction) {
      // Prefer the rich evaluateToolCall path so the mcp_tool_deny
      // emit carries PDP observability. Fall back to isAllowed when the
      // client is missing an apiKey (backwards compat); fail-CLOSED with
      // reason: "refresh_failed" on other transport errors.
      let evaluation: ToolCallEvaluation;
      try {
        evaluation = await client.evaluateToolCall(agentId, {
          toolName: policyAction,
          arguments: { resource: policyResource },
        });
      } catch (err) {
        if (err instanceof Error && err.message.includes("apiKey is required")) {
          warnEvaluatorFallbackOnce("vercel-ai");
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
          event_type: "mcp_tool_deny",
          tool: policyAction,
          resource: policyResource ?? "*",
          outcome: "deny",
          ...pdpTopLevelFields(evaluation),
          detail: {
            reason: "cedar_policy_denied",
            action: policyAction,
            resource: policyResource,
            framework: "vercel-ai",
            ...pdpObservabilityDetail(evaluation),
          },
        });
        throw new Error(
          `PermissionError: Agentum policy denied LLM call: action=${policyAction} resource=${policyResource}`,
        );
      }
    }
  }

  function afterGenerate(
    outputTokens?: number,
    toolCalls: Array<Record<string, unknown>> = [],
  ): void {
    for (const tc of toolCalls) {
      void client.ingestAuditEvent({
        agent_id: agentId,
        session_id: sessionId,
        event_type: "tool_call",
        outcome: "ok",
        detail: tc,
      });
    }
    void client.ingestAuditEvent({
      agent_id: agentId,
      session_id: sessionId,
      event_type: "llm_end",
      outcome: "ok",
      detail: { output_tokens: outputTokens ?? 0, tool_call_count: toolCalls.length },
    });
  }

  function afterGenerateError(error: Error): void {
    void client.ingestAuditEvent({
      agent_id: agentId,
      session_id: sessionId,
      // The Rust enum has `LlmError`. detail.streaming distinguishes from
      // non-streaming errors caught by onError below.
      event_type: "llm_error",
      outcome: "error",
      detail: { error: error.message, streaming: true },
    });
  }

  function onError(error: Error): void {
    void client.ingestAuditEvent({
      agent_id: agentId,
      session_id: sessionId,
      event_type: "llm_error",
      outcome: "error",
      detail: { error: error.message },
    });
  }

  /**
   * Extract any tool-call parts from a Vercel AI `doStream` chunk. The shape
   * varies between the v1 (`{ type: "tool-call", ... }`) and v2 (`{ type: "tool-call-delta" }`)
   * transports, so we match defensively and fall back to ignoring unknown shapes.
   */
  function extractToolCallFromChunk(chunk: unknown): Record<string, unknown> | null {
    if (!chunk || typeof chunk !== "object") return null;
    const c = chunk as Record<string, unknown>;
    const type = c["type"];
    if (type === "tool-call" || type === "tool-call-delta") {
      return {
        tool_call_id: c["toolCallId"] ?? c["id"] ?? null,
        tool_name:    c["toolName"]   ?? c["name"] ?? null,
        args:         c["args"] ?? c["argsDelta"] ?? c["arguments"] ?? null,
      };
    }
    return null;
  }

  function extractUsageFromChunk(chunk: unknown): number | undefined {
    if (!chunk || typeof chunk !== "object") return undefined;
    const c = chunk as Record<string, unknown>;
    if (c["type"] === "finish" || c["type"] === "step-finish") {
      const usage = c["usage"] as Record<string, unknown> | undefined;
      const tokens = usage?.["completionTokens"] ?? usage?.["outputTokens"];
      if (typeof tokens === "number") return tokens;
    }
    return undefined;
  }

  return {
    /**
     * Wrap a Vercel AI language model with Agentum audit + policy checking.
     * The returned object proxies all methods, injecting lifecycle hooks.
     */
    wrapLanguageModel<T extends { doGenerate: (...args: unknown[]) => Promise<unknown> }>(model: T): T {
      return new Proxy(model, {
        get(target, prop) {
          if (prop === "doGenerate") {
            return async (...args: unknown[]) => {
              await beforeGenerate();
              try {
                const result = await (target.doGenerate as (...a: unknown[]) => Promise<unknown>)(...args);
                afterGenerate();
                return result;
              } catch (err) {
                onError(err as Error);
                throw err;
              }
            };
          }
          if (prop === "doStream") {
            return async (...args: unknown[]) => {
              await beforeGenerate();
              let upstream: unknown;
              try {
                const doStreamFn = (target as unknown as { doStream: (...a: unknown[]) => Promise<unknown> }).doStream.bind(target);
                upstream = await doStreamFn(...args);
              } catch (err) {
                onError(err as Error);
                throw err;
              }

              // Vercel AI returns `{ stream: ReadableStream | AsyncIterable, ... }` (v2)
              // or a raw async iterable (v1). Support both by wrapping the iterable.
              const toolCalls: Array<Record<string, unknown>> = [];
              let outputTokens: number | undefined;

              const wrapIterable = <C>(source: AsyncIterable<C>): AsyncIterable<C> => ({
                [Symbol.asyncIterator](): AsyncIterator<C> {
                  const it = source[Symbol.asyncIterator]();
                  return {
                    async next(): Promise<IteratorResult<C>> {
                      try {
                        const step = await it.next();
                        if (step.done) {
                          afterGenerate(outputTokens, toolCalls);
                          return step;
                        }
                        const tc = extractToolCallFromChunk(step.value);
                        if (tc) toolCalls.push(tc);
                        const usage = extractUsageFromChunk(step.value);
                        if (usage !== undefined) outputTokens = usage;
                        return step;
                      } catch (err) {
                        afterGenerateError(err as Error);
                        throw err;
                      }
                    },
                    async return(value?: C | PromiseLike<C>): Promise<IteratorResult<C>> {
                      afterGenerate(outputTokens, toolCalls);
                      if (typeof it.return === "function") return it.return(value);
                      return { value: value as C, done: true };
                    },
                    async throw(err?: unknown): Promise<IteratorResult<C>> {
                      afterGenerateError(err as Error);
                      if (typeof it.throw === "function") return it.throw(err);
                      throw err;
                    },
                  };
                },
              });

              // Preserves both the ReadableStream and async-iterable shapes the
              // Vercel AI SDK returns. Consumers use `.getReader()` (v2 web
              // streams) or `for await` (v1 async iterables); breaking either
              // would regress real integrations. A TransformStream taps v2
              // chunks so audit fires on drain (not on stream open) while the
              // ReadableStream API stays intact.
              const isReadableStream = (v: unknown): v is ReadableStream<unknown> =>
                typeof v === "object" &&
                v !== null &&
                typeof (v as { getReader?: unknown }).getReader === "function" &&
                typeof (v as { pipeThrough?: unknown }).pipeThrough === "function";

              const wrapReadable = (source: ReadableStream<unknown>): ReadableStream<unknown> => {
                const transform = new TransformStream<unknown, unknown>({
                  transform(chunk, controller) {
                    const tc = extractToolCallFromChunk(chunk);
                    if (tc) toolCalls.push(tc);
                    const usage = extractUsageFromChunk(chunk);
                    if (usage !== undefined) outputTokens = usage;
                    controller.enqueue(chunk);
                  },
                  flush() {
                    afterGenerate(outputTokens, toolCalls);
                  },
                });
                return source.pipeThrough(transform);
              };

              // Case 1: upstream is `{ stream: ReadableStream, ... }` (v2 web-streams).
              if (
                upstream &&
                typeof upstream === "object" &&
                "stream" in (upstream as Record<string, unknown>) &&
                isReadableStream((upstream as { stream: unknown }).stream)
              ) {
                const inner = (upstream as { stream: ReadableStream<unknown> }).stream;
                return { ...(upstream as Record<string, unknown>), stream: wrapReadable(inner) };
              }
              // Case 2: upstream is an async iterable directly (v1).
              if (upstream && typeof (upstream as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
                return wrapIterable(upstream as AsyncIterable<unknown>);
              }
              // Case 3: upstream is `{ stream: AsyncIterable, ... }` (v2 iterable variant).
              if (
                upstream &&
                typeof upstream === "object" &&
                "stream" in (upstream as Record<string, unknown>) &&
                (upstream as { stream: unknown }).stream &&
                typeof ((upstream as { stream: AsyncIterable<unknown> }).stream)[Symbol.asyncIterator] === "function"
              ) {
                const inner = (upstream as { stream: AsyncIterable<unknown> }).stream;
                return { ...(upstream as Record<string, unknown>), stream: wrapIterable(inner) };
              }
              // Unknown shape — emit end now so audit is not lost, return as-is.
              afterGenerate(outputTokens, toolCalls);
              return upstream;
            };
          }
          return (target as Record<string | symbol, unknown>)[prop];
        },
      });
    },

    /** Emit a tool-call audit event. Call this before running each tool. */
    async auditToolCall(tool: string, resource: string, action?: string): Promise<void> {
      // Policy check if action specified
      let evaluation: ToolCallEvaluation | null = null;
      if (action) {
        // Prefer the rich evaluateToolCall path. `auditToolCall`
        // only sees string args, so pass `{ resource }` as the evaluator
        // arguments envelope. Fall back to isAllowed on apiKey-missing;
        // fail-CLOSED with `reason: "refresh_failed"` on other errors.
        try {
          evaluation = await client.evaluateToolCall(agentId, {
            toolName: action,
            arguments: { resource },
          });
        } catch (err) {
          if (err instanceof Error && err.message.includes("apiKey is required")) {
            warnEvaluatorFallbackOnce("vercel-ai");
            const allowed = await client.isAllowed(agentId, action, resource);
            evaluation = { decision: allowed ? "allow" : "deny", ttlMs: 0 };
          } else {
            evaluation = { decision: "deny", ttlMs: 0, reason: "refresh_failed" };
          }
        }
        if (evaluation.decision === "deny") {
          void client.ingestAuditEvent({
            agent_id: agentId,
            session_id: sessionId,
            event_type: "mcp_tool_deny",
            tool,
            resource,
            outcome: "deny",
            ...pdpTopLevelFields(evaluation),
            detail: {
              reason: "cedar_policy_denied",
              action,
              resource,
              framework: "vercel-ai",
              ...pdpObservabilityDetail(evaluation),
            },
          });
          throw new Error(`PermissionError: Agentum denied tool=${tool} action=${action} resource=${resource}`);
        }
      }
      // The allow emit also carries observability so operators can
      // measure PDP hit-rate via `tool_call` (allow) rows filtered on
      // `detail.evaluated_locally = true`.
      void client.ingestAuditEvent({
        agent_id: agentId,
        session_id: sessionId,
        event_type: "tool_call",
        tool,
        resource,
        outcome: "ok",
        ...(evaluation ? pdpTopLevelFields(evaluation) : {}),
        ...(evaluation
          ? { detail: { framework: "vercel-ai", ...pdpObservabilityDetail(evaluation) } }
          : {}),
      });
    },
  };
}

// ── agentumTool ───────────────────────────────────────────────────────────────

export interface AgentumToolOptions<TArgs, TResult> {
  client: AgentumClient;
  agentId: string;
  /**
   * Optional session id for audit attribution. When set, the
   * `mcp_tool_deny` emit carries it on the top-level `session_id`
   * field; when absent, the emission falls back to an empty string
   * (the ClickHouse `audit_events.session_id` column is non-Nullable
   * `String` and stores empty for "no session attribution"). Non-breaking
   * addition.
   */
  sessionId?: string;
  /** Cedar action checked before the tool executes, e.g. "tool:web_search". */
  action: string;
  /** Cedar resource (default: "*"). */
  resource?: string;
  /** The inner tool execute function. */
  execute: (args: TArgs) => Promise<TResult>;
}

/**
 * Wrap a Vercel AI `tool()` execute function with an Agentum Cedar policy guard.
 *
 * @example
 * ```ts
 * import { tool } from "ai";
 * import { agentumTool } from "@lupid/sdk/frameworks/vercel-ai";
 * import { z } from "zod";
 *
 * const searchTool = tool({
 *   description: "Web search",
 *   parameters: z.object({ query: z.string() }),
 *   execute: agentumTool({
 *     client,
 *     agentId,
 *     action: "tool:web_search",
 *     execute: async ({ query }) => fetchSearchResults(query),
 *   }),
 * });
 * ```
 */
export function agentumTool<TArgs, TResult>(
  opts: AgentumToolOptions<TArgs, TResult>,
): (args: TArgs) => Promise<TResult> {
  const { client, agentId, sessionId, action, resource = "*", execute } = opts;

  return async (args: TArgs): Promise<TResult> => {
    // Prefer the rich evaluateToolCall path so the mcp_tool_deny
    // emit carries PDP observability. Fall back to isAllowed when the
    // client is missing an apiKey (backwards compat); fail-CLOSED with
    // reason: "refresh_failed" on other transport errors.
    let evaluation: ToolCallEvaluation;
    try {
      evaluation = await client.evaluateToolCall(agentId, {
        toolName: action,
        arguments: args as unknown,
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes("apiKey is required")) {
        warnEvaluatorFallbackOnce("vercel-ai");
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
        event_type: "mcp_tool_deny",
        tool: action,
        resource,
        outcome: "deny",
        ...pdpTopLevelFields(evaluation),
        detail: {
          reason: "cedar_policy_denied",
          action,
          resource,
          framework: "vercel-ai.agentumTool",
          ...pdpObservabilityDetail(evaluation),
        },
      });
      throw new Error(
        `PermissionError: Agentum policy denied: agent=${agentId} action=${action} resource=${resource}`,
      );
    }
    return execute(args);
  };
}

// ── Telemetry object (for experimental_telemetry) ─────────────────────────────

export interface AgentumTelemetryOptions {
  /** Use a live AgentumSession as the single source of client/agentId/sessionId. */
  session?: AgentumSession;
  client?: AgentumClient;
  agentId?: string;
  sessionId?: string;
}

/**
 * Returns a `experimental_telemetry` compatible object for the Vercel AI SDK.
 *
 * @example
 * ```ts
 * const { text } = await generateText({
 *   model,
 *   prompt: "...",
 *   experimental_telemetry: createAgentumTelemetry({ session }),
 * });
 * ```
 */
export function createAgentumTelemetry(opts: AgentumTelemetryOptions) {
  const { client, agentId, sessionId } = resolveVercelOpts(opts);
  return {
    isEnabled: true,
    recordInputs: true,
    recordOutputs: false, // avoid logging sensitive output by default
    tracer: {
      startActiveSpan(name: string, fn: (span: unknown) => unknown) {
        // Map to `llm_call` (Vercel AI's tracer is invoked around LLM
        // operations) and surface the original span name in detail. Loses
        // dynamic-name filterability in the dashboard but gains correct enum
        // membership; UI can still filter on detail.span_name via the JSON
        // renderer.
        void client.ingestAuditEvent({
          agent_id: agentId,
          session_id: sessionId,
          event_type: "llm_call",
          outcome: "ok",
          detail: { span_name: name, source: "vercel-ai-tracer" },
        });
        return fn({ end: () => {} });
      },
    },
  };
}
