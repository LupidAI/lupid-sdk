/**
 * Unit tests for the Anthropic streaming patch's tool-use rewrite.
 *
 * Covers issue A2 — gateway parity for the streaming `stop_reason` rewrite.
 * The Rust gateway path (`crates/agentum-llm-filter/src/sse.rs:463, 485-501`)
 * latches `rewrote_tool_use_to_text = true` whenever ANY tool_use block is
 * replaced with a text-notice triplet, then unconditionally rewrites the
 * trailing `message_delta`'s `delta.stop_reason` from `"tool_use"` to
 * `"end_turn"`. The SDK streaming path must mirror this exactly so that
 * SDK-only deployments produce the same wire output as gateway-protected
 * deployments. (Note: this is intentionally stricter than the SDK's
 * non-streaming branch, which gates on `!stillHasTool` — see the spec at
 * `.claude/plan/issues/A2-anthropic-stop-reason-parity.md` "Risk" section.)
 *
 * `wrapAnthropicStream` accepts an `AsyncIterable<Record<string, unknown>>`
 * of already-parsed events plus a `CedarToolCallClient`. We feed inline
 * `async function*()` sources directly — no nock, no SSE bytes — and assert
 * on the drained event stream.
 */

import { wrapAnthropicStream } from "../src/instrumentation/anthropic-patch";
import type {
  CedarToolCallClient,
  ToolCallEvaluation,
} from "../src/evaluation/cedar-client";

// ── helpers ────────────────────────────────────────────────────────────────

type Event = Record<string, unknown>;

/**
 * Build a fake `CedarToolCallClient` that returns canned decisions keyed by
 * tool name. Only `evaluateToolCall` is needed by `wrapAnthropicStream`; the
 * full client surface is irrelevant here.
 */
function fakeEvaluator(
  decisions: Record<string, ToolCallEvaluation>,
): CedarToolCallClient {
  const client: Pick<CedarToolCallClient, "evaluateToolCall"> = {
    async evaluateToolCall(args: {
      toolName: string;
      arguments: unknown;
    }): Promise<ToolCallEvaluation> {
      const d = decisions[args.toolName];
      if (!d) {
        throw new Error(
          `fakeEvaluator: no canned decision for tool "${args.toolName}"`,
        );
      }
      return d;
    },
  };
  return client as CedarToolCallClient;
}

/** Drain an async iterable into an array. */
async function drain<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of it) out.push(v);
  return out;
}

/**
 * Build the canonical Anthropic streaming event sequence for a single
 * tool_use block.
 */
function streamWithSingleToolUse(opts: {
  toolName: string;
  toolInput: Record<string, unknown>;
  /** stop_reason carried on the trailing `message_delta` event. */
  stopReason?: string;
  /** Override the entire `message_delta` event (e.g. malformed shape). */
  messageDeltaOverride?: Event;
}): AsyncIterable<Event> {
  const stop = opts.stopReason ?? "tool_use";
  const messageDelta: Event = opts.messageDeltaOverride ?? {
    type: "message_delta",
    delta: { stop_reason: stop, stop_sequence: null },
    usage: { output_tokens: 5 },
  };
  return (async function* (): AsyncGenerator<Event> {
    yield { type: "message_start", message: { id: "m1", role: "assistant" } };
    yield {
      type: "content_block_start",
      index: 0,
      content_block: { type: "tool_use", id: "tu_1", name: opts.toolName, input: {} },
    };
    yield {
      type: "content_block_delta",
      index: 0,
      delta: { type: "input_json_delta", partial_json: JSON.stringify(opts.toolInput) },
    };
    yield { type: "content_block_stop", index: 0 };
    yield messageDelta;
    yield { type: "message_stop" };
  })();
}

// ── tests ──────────────────────────────────────────────────────────────────

describe("wrapAnthropicStream — gateway parity for stop_reason rewrite", () => {
  it("full_deny_stream_rewrites_message_delta_stop_reason_to_end_turn", async () => {
    const evaluator = fakeEvaluator({
      shell: { decision: "deny", reason: "blocked by policy", ttlMs: 0 },
    });
    const source = streamWithSingleToolUse({
      toolName: "shell",
      toolInput: { cmd: "rm -rf /" },
    });

    const out = await drain(wrapAnthropicStream(source, evaluator));

    // Synthetic text-notice triplet replaces the denied tool_use block.
    const noticeStart = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "text",
    );
    const noticeDelta = out.find(
      (e) =>
        e["type"] === "content_block_delta" &&
        (e["delta"] as Record<string, unknown>)?.["type"] === "text_delta",
    );
    const noticeStop = out.find(
      (e) => e["type"] === "content_block_stop" && e["index"] === 0,
    );
    expect(noticeStart).toBeDefined();
    expect(noticeDelta).toBeDefined();
    expect(noticeStop).toBeDefined();

    // The trailing message_delta has stop_reason rewritten to "end_turn".
    const messageDelta = out.find((e) => e["type"] === "message_delta");
    expect(messageDelta).toBeDefined();
    const delta = (messageDelta as Event)["delta"] as Record<string, unknown>;
    expect(delta["stop_reason"]).toBe("end_turn");
    // Other delta fields are preserved.
    expect(delta["stop_sequence"]).toBeNull();

    // The text-notice triplet precedes the message_delta.
    const idxNoticeStart = out.indexOf(noticeStart!);
    const idxNoticeStop = out.indexOf(noticeStop!);
    const idxMessageDelta = out.indexOf(messageDelta!);
    expect(idxNoticeStart).toBeLessThan(idxNoticeStop);
    expect(idxNoticeStop).toBeLessThan(idxMessageDelta);

    // No raw tool_use content_block_start should leak through.
    const leakedToolUse = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "tool_use",
    );
    expect(leakedToolUse).toBeUndefined();
  });

  it("partial_deny_stream_also_rewrites_stop_reason_to_end_turn", async () => {
    // Two tool_use blocks (indices 0, 1). Allow index 0 (search), deny
    // index 1 (shell). Mirrors the gateway latch — partial-deny still
    // rewrites stop_reason to "end_turn".
    const evaluator = fakeEvaluator({
      search: { decision: "allow", ttlMs: 0 },
      shell: { decision: "deny", reason: "blocked", ttlMs: 0 },
    });

    const source: AsyncIterable<Event> = (async function* () {
      yield { type: "message_start", message: { id: "m1", role: "assistant" } };
      // Block 0 — allowed
      yield {
        type: "content_block_start",
        index: 0,
        content_block: { type: "tool_use", id: "tu_0", name: "search", input: {} },
      };
      yield {
        type: "content_block_delta",
        index: 0,
        delta: { type: "input_json_delta", partial_json: "{\"q\":\"a\"}" },
      };
      yield { type: "content_block_stop", index: 0 };
      // Block 1 — denied
      yield {
        type: "content_block_start",
        index: 1,
        content_block: { type: "tool_use", id: "tu_1", name: "shell", input: {} },
      };
      yield {
        type: "content_block_delta",
        index: 1,
        delta: { type: "input_json_delta", partial_json: "{\"cmd\":\"x\"}" },
      };
      yield { type: "content_block_stop", index: 1 };
      yield {
        type: "message_delta",
        delta: { stop_reason: "tool_use", stop_sequence: null },
      };
      yield { type: "message_stop" };
    })();

    const out = await drain(wrapAnthropicStream(source, evaluator));

    // Surviving tool_use (index 0) is yielded unchanged: original start +
    // input_json_delta + stop are all present at index 0.
    const survivingStart = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        e["index"] === 0 &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "tool_use",
    );
    expect(survivingStart).toBeDefined();
    const survivingDelta = out.find(
      (e) =>
        e["type"] === "content_block_delta" &&
        e["index"] === 0 &&
        (e["delta"] as Record<string, unknown>)?.["type"] === "input_json_delta",
    );
    expect(survivingDelta).toBeDefined();

    // Denied block at index 1 is replaced with text-notice triplet.
    const denyNoticeStart = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        e["index"] === 1 &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "text",
    );
    expect(denyNoticeStart).toBeDefined();
    const leakedDenied = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        e["index"] === 1 &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "tool_use",
    );
    expect(leakedDenied).toBeUndefined();

    // Critical parity assertion: even though a tool_use block survives,
    // the gateway latches the flag and rewrites stop_reason. Mirror it.
    const messageDelta = out.find((e) => e["type"] === "message_delta");
    expect(messageDelta).toBeDefined();
    const delta = (messageDelta as Event)["delta"] as Record<string, unknown>;
    expect(delta["stop_reason"]).toBe("end_turn");
  });

  it("all_allow_stream_passes_message_delta_unmodified", async () => {
    const evaluator = fakeEvaluator({
      search: { decision: "allow", ttlMs: 0 },
    });
    const originalMessageDelta: Event = {
      type: "message_delta",
      delta: { stop_reason: "tool_use", stop_sequence: null },
      usage: { output_tokens: 7 },
    };
    const source = streamWithSingleToolUse({
      toolName: "search",
      toolInput: { q: "agentum" },
      messageDeltaOverride: originalMessageDelta,
    });

    const out = await drain(wrapAnthropicStream(source, evaluator));

    // Original tool_use block is preserved.
    const toolUseStart = out.find(
      (e) =>
        e["type"] === "content_block_start" &&
        (e["content_block"] as Record<string, unknown>)?.["type"] === "tool_use",
    );
    expect(toolUseStart).toBeDefined();

    // message_delta is yielded byte-identical (same reference, no rewrite
    // path taken because the flag never latched).
    const messageDelta = out.find((e) => e["type"] === "message_delta");
    expect(messageDelta).toBe(originalMessageDelta);
    const delta = (messageDelta as Event)["delta"] as Record<string, unknown>;
    expect(delta["stop_reason"]).toBe("tool_use");
  });

  it("malformed_message_delta_yields_original_event", async () => {
    // Full-deny scenario, but the message_delta has a non-object `delta`
    // field — the rewrite helper must fail-OPEN and yield the original
    // event unchanged. Mirrors the gateway `if let Ok(...)` chain.
    const evaluator = fakeEvaluator({
      shell: { decision: "deny", reason: "no", ttlMs: 0 },
    });
    const malformed: Event = {
      type: "message_delta",
      delta: "not-an-object",
      usage: { output_tokens: 1 },
    };
    const source = streamWithSingleToolUse({
      toolName: "shell",
      toolInput: { cmd: "x" },
      messageDeltaOverride: malformed,
    });

    const out = await drain(wrapAnthropicStream(source, evaluator));

    const messageDelta = out.find((e) => e["type"] === "message_delta");
    expect(messageDelta).toBe(malformed);
    expect((messageDelta as Event)["delta"]).toBe("not-an-object");
  });

  it("no_tool_use_stream_passes_through_unchanged", async () => {
    // Stream contains only text content blocks and a normal end_turn
    // message_delta — exercises the early-return path before evaluator
    // ever runs. Flag never latches; events pass untouched.
    const evaluator = fakeEvaluator({});
    const messageDelta: Event = {
      type: "message_delta",
      delta: { stop_reason: "end_turn", stop_sequence: null },
    };
    const source: AsyncIterable<Event> = (async function* () {
      yield { type: "message_start", message: { id: "m1" } };
      yield {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      };
      yield {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: "hello" },
      };
      yield { type: "content_block_stop", index: 0 };
      yield messageDelta;
      yield { type: "message_stop" };
    })();

    const out = await drain(wrapAnthropicStream(source, evaluator));

    // message_delta yielded byte-identical.
    const found = out.find((e) => e["type"] === "message_delta");
    expect(found).toBe(messageDelta);
    expect(
      (found as Event)["delta"] as Record<string, unknown>,
    ).toEqual({ stop_reason: "end_turn", stop_sequence: null });

    // Sanity: 6 events in, 6 events out.
    expect(out).toHaveLength(6);
  });
});
