/**
 * Streaming tool-call accumulators shared between the explicit-wrap path
 * (`wrapOpenAIClient` at frameworks/openai.ts) and the auto-init monkeypatch
 * path (`init.ts` + `instrumentation/openai-patch.ts` /
 * `instrumentation/anthropic-patch.ts`).
 *
 * Keeping the parsers in one place guarantees that both onboarding flows
 * accumulate the same tool_calls / tool_use deltas with identical merge
 * semantics — there must be exactly one source of truth for the
 * provider-specific wire formats.
 */

// ── OpenAI ────────────────────────────────────────────────────────────────────

/** Accumulator for OpenAI streaming `choices[0].delta.tool_calls[i]` deltas. */
export interface OpenAIToolCallAcc {
  id?: string;
  type?: string;
  function: { name: string; arguments: string };
}

export interface OpenAIStreamState {
  /** Keyed by `tool_calls[].index`. */
  toolCalls: Map<number, OpenAIToolCallAcc>;
  finishReason?: string;
  usage?: Record<string, unknown>;
}

export function newOpenAIStreamState(): OpenAIStreamState {
  return { toolCalls: new Map() };
}

/**
 * Ingest a single OpenAI chat-completion stream chunk and merge tool-call
 * deltas, finish_reason and usage into `state`. Returns `state` for fluent
 * use.
 */
export function ingestOpenAIChunk(
  state: OpenAIStreamState,
  chunk: Record<string, unknown>,
): OpenAIStreamState {
  const choices = chunk["choices"] as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(choices) && choices.length > 0) {
    const choice = choices[0]!;
    const delta  = choice["delta"] as Record<string, unknown> | undefined;
    const deltaToolCalls = delta?.["tool_calls"] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(deltaToolCalls)) {
      for (const part of deltaToolCalls) {
        const idx = typeof part["index"] === "number" ? (part["index"] as number) : 0;
        const acc = state.toolCalls.get(idx) ?? { function: { name: "", arguments: "" } };
        if (typeof part["id"]   === "string") acc.id   = part["id"] as string;
        if (typeof part["type"] === "string") acc.type = part["type"] as string;
        const fn = part["function"] as Record<string, unknown> | undefined;
        if (fn) {
          if (typeof fn["name"]      === "string") acc.function.name      += fn["name"] as string;
          if (typeof fn["arguments"] === "string") acc.function.arguments += fn["arguments"] as string;
        }
        state.toolCalls.set(idx, acc);
      }
    }
    if (typeof choice["finish_reason"] === "string") {
      state.finishReason = choice["finish_reason"] as string;
    }
  }
  if (chunk["usage"] && typeof chunk["usage"] === "object") {
    state.usage = chunk["usage"] as Record<string, unknown>;
  }
  return state;
}

/** Parse OpenAI non-streaming response tool_calls (choices[0].message.tool_calls). */
export interface OpenAIToolCall {
  id: string;
  type: string;
  function: { name: string; arguments: string };
}

export function extractOpenAIToolCalls(
  resp: Record<string, unknown>,
): OpenAIToolCall[] {
  const choices = resp["choices"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(choices) || choices.length === 0) return [];
  const message = choices[0]!["message"] as Record<string, unknown> | undefined;
  const tc = message?.["tool_calls"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(tc)) return [];
  const out: OpenAIToolCall[] = [];
  for (const t of tc) {
    const fn = t["function"] as Record<string, unknown> | undefined;
    if (!fn) continue;
    out.push({
      id:   String(t["id"] ?? ""),
      type: String(t["type"] ?? "function"),
      function: {
        name:      String(fn["name"] ?? ""),
        arguments: typeof fn["arguments"] === "string" ? (fn["arguments"] as string) : "",
      },
    });
  }
  return out;
}

// ── Anthropic ─────────────────────────────────────────────────────────────────
//
// Anthropic's streaming wire format uses named SSE events:
//   message_start
//   content_block_start  { content_block: { type: "tool_use", id, name, input } }
//   content_block_delta  { delta: { type: "input_json_delta", partial_json } }
//   content_block_stop
//   message_delta        { delta: { stop_reason: "tool_use" } }
//   message_stop

/** A single in-flight tool_use content block. */
export interface AnthropicToolUseAcc {
  id: string;
  name: string;
  /** Concatenated `partial_json` strings; parsed lazily. */
  partialJson: string;
}

export interface AnthropicStreamState {
  /** Keyed by `content_block_start.index`. */
  toolUses: Map<number, AnthropicToolUseAcc>;
  stopReason?: string;
  /** Indices of blocks already finalized (content_block_stop seen). */
  stopped: Set<number>;
}

export function newAnthropicStreamState(): AnthropicStreamState {
  return { toolUses: new Map(), stopped: new Set() };
}

/**
 * Ingest one parsed Anthropic stream event. Events from the official
 * `@anthropic-ai/sdk` are already JSON-decoded; the SDK exposes them as
 * `{type, ...rest}` objects on the async iterator.
 */
export function ingestAnthropicEvent(
  state: AnthropicStreamState,
  evt: Record<string, unknown>,
): AnthropicStreamState {
  const type = evt["type"] as string | undefined;
  if (!type) return state;

  if (type === "content_block_start") {
    const idx = typeof evt["index"] === "number" ? (evt["index"] as number) : 0;
    const block = evt["content_block"] as Record<string, unknown> | undefined;
    if (block && block["type"] === "tool_use") {
      state.toolUses.set(idx, {
        id:   String(block["id"]   ?? ""),
        name: String(block["name"] ?? ""),
        partialJson: "",
      });
    }
    return state;
  }

  if (type === "content_block_delta") {
    const idx = typeof evt["index"] === "number" ? (evt["index"] as number) : 0;
    const delta = evt["delta"] as Record<string, unknown> | undefined;
    if (delta && delta["type"] === "input_json_delta") {
      const acc = state.toolUses.get(idx);
      if (acc) {
        const pj = delta["partial_json"];
        if (typeof pj === "string") acc.partialJson += pj;
      }
    }
    return state;
  }

  if (type === "content_block_stop") {
    const idx = typeof evt["index"] === "number" ? (evt["index"] as number) : 0;
    state.stopped.add(idx);
    return state;
  }

  if (type === "message_delta") {
    const delta = evt["delta"] as Record<string, unknown> | undefined;
    if (delta && typeof delta["stop_reason"] === "string") {
      state.stopReason = delta["stop_reason"] as string;
    }
    return state;
  }

  return state;
}

/** Parse Anthropic non-streaming response: `content[].type === "tool_use"`. */
export interface AnthropicToolUse {
  id: string;
  name: string;
  /** Already-parsed input object — Anthropic returns a real JSON object,
   *  not a string. */
  input: unknown;
  /** Position within the `content` array — needed to rewrite the response. */
  index: number;
}

export function extractAnthropicToolUses(
  resp: Record<string, unknown>,
): AnthropicToolUse[] {
  const content = resp["content"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(content)) return [];
  const out: AnthropicToolUse[] = [];
  content.forEach((block, i) => {
    if (block["type"] === "tool_use") {
      out.push({
        id:    String(block["id"]   ?? ""),
        name:  String(block["name"] ?? ""),
        input: block["input"],
        index: i,
      });
    }
  });
  return out;
}

/**
 * Build the human-readable block-notice text injected in place of a denied
 * tool_use / tool_call. Mirrors the gateway's `make_block_notice_sse`
 * formatting (`agentum-llm-filter/src/sse.rs:601-631`) so SDK-mode and
 * proxy-mode produce identical UX.
 *
 * H4: when the evaluator surfaces a categorical `denyCode` and/or a
 * matching policy `ruleId`, append them on a `[code=…, rule=…]` line so
 * operators can pivot directly from a user-visible error to the
 * specific rule + category. The leading `[!] Agentum blocked` line is
 * preserved verbatim for backward compatibility with consumers that
 * grep for it.
 */
export function makeBlockNoticeText(
  toolName: string,
  args: string,
  reason: string | undefined,
  meta?: { denyCode?: string | undefined; ruleId?: string | undefined },
): string {
  const reasonStr = reason ?? "policy rule matched";
  const tags: string[] = [];
  if (meta?.denyCode) tags.push(`code=${meta.denyCode}`);
  if (meta?.ruleId)   tags.push(`rule=${meta.ruleId}`);
  const trailer = tags.length > 0 ? `\n[${tags.join(", ")}]` : "";
  return `[!] Agentum blocked ${toolName} — ${reasonStr}\nArguments: ${args}${trailer}`;
}
