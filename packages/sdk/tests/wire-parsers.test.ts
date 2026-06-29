/**
 * Unit tests for the byte-level SSE parsers (A13).
 *
 * These parsers are the contract between the streaming fetch /
 * node:http interceptors and the per-provider deny rewriter. A bug here
 * lets a tool_call slip past Cedar enforcement on streaming responses;
 * each provider has its own quirks worth pinning down in isolation:
 *
 *   - OpenAI    — unnamed `data:` frames, JSON `delta`
 *   - Anthropic — named events, `content_block_*` lifecycle
 *   - Cohere v2 — named events, `tool-call-{start,delta,end}` shape
 *   - Gemini    — unnamed `data:` frames, `functionCall` atomic
 *
 * We feed each parser the exact wire bytes a real provider emits and
 * assert the WireEvent stream. The fetch-interceptor tests cover the
 * end-to-end behaviour; here we pin the parser invariants.
 */

import {
  OpenAISSEParser,
  CohereV2SSEParser,
  GeminiSSEParser,
  BedrockConverseStreamParser,
  BedrockInvokeStreamParser,
  AnthropicSSEParser,
  encodeBedrockEventStreamMessage,
  encodeBedrockInvokeChunk,
  type WireEvent,
} from "../src/instrumentation/wire-parsers";

const enc = new TextEncoder();

function feedFrames(
  parser: { feed: (b: Uint8Array) => WireEvent[]; flush: () => WireEvent[] },
  frames: string[],
): WireEvent[] {
  const out: WireEvent[] = [];
  for (const f of frames) out.push(...parser.feed(enc.encode(f)));
  out.push(...parser.flush());
  return out;
}

// ── OpenAI ────────────────────────────────────────────────────────────────
//
// OpenAI streams unnamed `data:` frames. Each frame carries
// `{choices:[{delta:{...}, finish_reason}]}`. A tool call opens with a
// `delta.tool_calls[0]` entry bearing a `function.name` (+ `id`) at its
// `index`; subsequent frames append `function.arguments` fragments at the
// same `index`. Parallel tool calls each occupy a distinct `index` and
// arrive in their own frames. `finish_reason` carries the terminal verdict;
// the explicit `data: [DONE]` sentinel produces a `finish` with no reason.

describe("OpenAISSEParser", () => {
  /** Build one OpenAI SSE frame from a single `choices[0]` patch. */
  const frame = (choice: Record<string, unknown>): string =>
    `data: ${JSON.stringify({
      id: "chatcmpl-1",
      object: "chat.completion.chunk",
      choices: [choice],
    })}\n\n`;

  it("emits tool-call-start, arguments-deltas, finish; concatenated args parse", () => {
    const p = new OpenAISSEParser();
    const frames = [
      frame({
        index: 0,
        delta: {
          tool_calls: [
            { index: 0, id: "call_abc", type: "function", function: { name: "search", arguments: "" } },
          ],
        },
      }),
      frame({
        index: 0,
        delta: { tool_calls: [{ index: 0, function: { arguments: `{"q":` } }] },
      }),
      frame({
        index: 0,
        delta: { tool_calls: [{ index: 0, function: { arguments: `"hi"}` } }] },
      }),
      frame({ index: 0, delta: {}, finish_reason: "tool_calls" }),
    ];
    const events = feedFrames(p, frames);

    const starts = events.filter((e) => e.kind === "tool-call-start") as Array<
      Extract<WireEvent, { kind: "tool-call-start" }>
    >;
    expect(starts).toHaveLength(1);
    expect(starts[0]!.index).toBe(0);
    expect(starts[0]!.name).toBe("search");
    expect(starts[0]!.id).toBe("call_abc");

    const argFrags = events
      .filter((e) => e.kind === "tool-call-arguments")
      .map((e) => (e as Extract<WireEvent, { kind: "tool-call-arguments" }>).deltaJson);
    // Concatenated args must form valid JSON matching the original call.
    expect(JSON.parse(argFrags.join(""))).toEqual({ q: "hi" });

    const finishes = events.filter((e) => e.kind === "finish") as Array<
      Extract<WireEvent, { kind: "finish" }>
    >;
    expect(finishes).toHaveLength(1);
    expect(finishes[0]!.finishReason).toBe("tool_calls");
  });

  it("parallel tool_calls accumulate per-index across frames", () => {
    // OpenAI carries one tool_call entry per frame, keyed by `index`. Two
    // calls interleave their start/arguments frames; the parser must keep
    // each `index`'s args stream distinct so they concatenate correctly.
    const p = new OpenAISSEParser();
    const frames = [
      frame({
        index: 0,
        delta: { tool_calls: [{ index: 0, id: "a", function: { name: "fa", arguments: "" } }] },
      }),
      frame({
        index: 0,
        delta: { tool_calls: [{ index: 1, id: "b", function: { name: "fb", arguments: "" } }] },
      }),
      frame({ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: `{"x":1}` } }] } }),
      frame({ index: 0, delta: { tool_calls: [{ index: 1, function: { arguments: `{"y":2}` } }] } }),
    ];
    const events = feedFrames(p, frames);

    const starts = events.filter((e) => e.kind === "tool-call-start") as Array<
      Extract<WireEvent, { kind: "tool-call-start" }>
    >;
    expect(starts.map((s) => s.index).sort()).toEqual([0, 1]);
    expect(starts.find((s) => s.index === 0)?.name).toBe("fa");
    expect(starts.find((s) => s.index === 1)?.name).toBe("fb");

    const argsByIndex = new Map<number, string>();
    for (const e of events) {
      if (e.kind === "tool-call-arguments") {
        argsByIndex.set(e.index, (argsByIndex.get(e.index) ?? "") + e.deltaJson);
      }
    }
    expect(JSON.parse(argsByIndex.get(0) ?? "")).toEqual({ x: 1 });
    expect(JSON.parse(argsByIndex.get(1) ?? "")).toEqual({ y: 2 });
  });

  it("a tool_calls arguments delta split across feed() boundaries reassembles", () => {
    // SSE framing is on `\n\n`; a single frame's bytes can arrive in two
    // chunks. The arguments fragment must survive split-frame reassembly.
    const p = new OpenAISSEParser();
    const startFrame = frame({
      index: 0,
      delta: { tool_calls: [{ index: 0, id: "c", function: { name: "f", arguments: "" } }] },
    });
    const argFrame = frame({
      index: 0,
      delta: { tool_calls: [{ index: 0, function: { arguments: `{"k":"v"}` } }] },
    });
    const out: WireEvent[] = [];
    out.push(...p.feed(enc.encode(startFrame)));
    // Split the argument frame mid-bytes across two feed() calls.
    const half = argFrame.length >> 1;
    out.push(...p.feed(enc.encode(argFrame.slice(0, half))));
    out.push(...p.feed(enc.encode(argFrame.slice(half))));
    out.push(...p.flush());

    const args = out.filter((e) => e.kind === "tool-call-arguments") as Array<
      Extract<WireEvent, { kind: "tool-call-arguments" }>
    >;
    expect(args).toHaveLength(1);
    expect(args[0]!.index).toBe(0);
    expect(JSON.parse(args[0]!.deltaJson)).toEqual({ k: "v" });
  });

  it("content delta produces a text-delta event", () => {
    const p = new OpenAISSEParser();
    const events = feedFrames(p, [frame({ index: 0, delta: { content: "hello world" } })]);
    const text = events.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect((text as Extract<WireEvent, { kind: "text-delta" }>).text).toBe("hello world");
  });

  it("data: [DONE] sentinel produces a finish with no finishReason", () => {
    const p = new OpenAISSEParser();
    const events = feedFrames(p, [`data: [DONE]\n\n`]);
    const finishes = events.filter((e) => e.kind === "finish") as Array<
      Extract<WireEvent, { kind: "finish" }>
    >;
    expect(finishes).toHaveLength(1);
    expect(finishes[0]!.finishReason).toBeUndefined();
  });

  it("finish_reason maps onto the finish event (stop)", () => {
    const p = new OpenAISSEParser();
    const events = feedFrames(p, [frame({ index: 0, delta: { content: "bye" } }), frame({ index: 0, delta: {}, finish_reason: "stop" })]);
    const finish = events.find((e) => e.kind === "finish");
    expect(finish).toBeDefined();
    expect((finish as Extract<WireEvent, { kind: "finish" }>).finishReason).toBe("stop");
  });
});

// ── Cohere v2 ─────────────────────────────────────────────────────────────

describe("CohereV2SSEParser", () => {
  it("emits tool-call-start, arguments-deltas, tool-call-end, finish", () => {
    const p = new CohereV2SSEParser();
    const frames = [
      `event: tool-call-start\ndata: ${JSON.stringify({
        index: 0,
        delta: {
          message: {
            tool_calls: {
              id: "call_abc",
              type: "function",
              function: { name: "search", arguments: "" },
            },
          },
        },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: {
          message: {
            tool_calls: { function: { arguments: `{"q":` } },
          },
        },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: {
          message: {
            tool_calls: { function: { arguments: `"hi"}` } },
          },
        },
      })}\n\n`,
      `event: tool-call-end\ndata: ${JSON.stringify({ index: 0 })}\n\n`,
      `event: message-end\ndata: ${JSON.stringify({
        delta: { finish_reason: "TOOL_CALL" },
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);

    const starts = events.filter((e) => e.kind === "tool-call-start");
    expect(starts).toHaveLength(1);
    const start = starts[0] as Extract<WireEvent, { kind: "tool-call-start" }>;
    expect(start.index).toBe(0);
    expect(start.name).toBe("search");
    expect(start.id).toBe("call_abc");

    const argFrags = events
      .filter((e) => e.kind === "tool-call-arguments")
      .map((e) => (e as Extract<WireEvent, { kind: "tool-call-arguments" }>).deltaJson);
    // Concatenated args must form valid JSON matching the original call.
    const concat = argFrags.join("");
    expect(JSON.parse(concat)).toEqual({ q: "hi" });

    const ends = events.filter((e) => e.kind === "tool-call-end");
    expect(ends).toHaveLength(1);

    const finishes = events.filter((e) => e.kind === "finish");
    expect(finishes).toHaveLength(1);
    expect(
      (finishes[0] as Extract<WireEvent, { kind: "finish" }>).finishReason,
    ).toBe("TOOL_CALL");
  });

  it("text content-delta produces a text-delta event", () => {
    const p = new CohereV2SSEParser();
    const frames = [
      `event: content-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { content: { text: "hello world" } } },
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const text = events.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect(
      (text as Extract<WireEvent, { kind: "text-delta" }>).text,
    ).toBe("hello world");
  });

  it("parallel tool_calls at distinct indices preserve per-index args", () => {
    // Cohere v2's wire shape uses a numeric `index` per tool call. Two
    // calls interleave start/delta frames; the parser must keep them
    // distinct so each call's args stream concatenates correctly.
    const p = new CohereV2SSEParser();
    const frames = [
      `event: tool-call-start\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { id: "a", function: { name: "fa", arguments: "" } } } },
      })}\n\n`,
      `event: tool-call-start\ndata: ${JSON.stringify({
        index: 1,
        delta: { message: { tool_calls: { id: "b", function: { name: "fb", arguments: "" } } } },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { function: { arguments: `{"x":1}` } } } },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 1,
        delta: { message: { tool_calls: { function: { arguments: `{"y":2}` } } } },
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const starts = events.filter((e) => e.kind === "tool-call-start") as Array<
      Extract<WireEvent, { kind: "tool-call-start" }>
    >;
    expect(starts.map((s) => s.index).sort()).toEqual([0, 1]);
    expect(starts.find((s) => s.index === 0)?.name).toBe("fa");
    expect(starts.find((s) => s.index === 1)?.name).toBe("fb");

    const argsByIndex = new Map<number, string>();
    for (const e of events) {
      if (e.kind === "tool-call-arguments") {
        argsByIndex.set(e.index, (argsByIndex.get(e.index) ?? "") + e.deltaJson);
      }
    }
    expect(JSON.parse(argsByIndex.get(0) ?? "")).toEqual({ x: 1 });
    expect(JSON.parse(argsByIndex.get(1) ?? "")).toEqual({ y: 2 });
  });

  it("unrecognised event emits passthrough (forward verbatim)", () => {
    const p = new CohereV2SSEParser();
    const frames = [
      `event: heartbeat\ndata: ${JSON.stringify({ ping: 1 })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    expect(events.map((e) => e.kind)).toEqual(["passthrough"]);
  });
});

// ── Gemini ────────────────────────────────────────────────────────────────

describe("GeminiSSEParser", () => {
  it("functionCall produces tool-call-start + arguments with full JSON string", () => {
    const p = new GeminiSSEParser();
    const frames = [
      `data: ${JSON.stringify({
        candidates: [
          {
            content: {
              role: "model",
              parts: [
                { functionCall: { name: "search", args: { q: "weather" } } },
              ],
            },
          },
        ],
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const starts = events.filter((e) => e.kind === "tool-call-start") as Array<
      Extract<WireEvent, { kind: "tool-call-start" }>
    >;
    expect(starts).toHaveLength(1);
    expect(starts[0]!.name).toBe("search");
    const args = events.filter((e) => e.kind === "tool-call-arguments") as Array<
      Extract<WireEvent, { kind: "tool-call-arguments" }>
    >;
    expect(args).toHaveLength(1);
    // The accumulator concatenates deltas; a single emission of the
    // full args JSON must produce the original object.
    expect(JSON.parse(args[0]!.deltaJson)).toEqual({ q: "weather" });
  });

  it("text part produces text-delta", () => {
    const p = new GeminiSSEParser();
    const frames = [
      `data: ${JSON.stringify({
        candidates: [
          {
            content: { role: "model", parts: [{ text: "hello" }] },
          },
        ],
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const text = events.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect(
      (text as Extract<WireEvent, { kind: "text-delta" }>).text,
    ).toBe("hello");
  });

  it("finishReason produces a finish event", () => {
    const p = new GeminiSSEParser();
    const frames = [
      `data: ${JSON.stringify({
        candidates: [
          {
            content: { role: "model", parts: [{ text: "bye" }] },
            finishReason: "STOP",
          },
        ],
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const finish = events.find((e) => e.kind === "finish");
    expect(finish).toBeDefined();
    expect(
      (finish as Extract<WireEvent, { kind: "finish" }>).finishReason,
    ).toBe("STOP");
  });

  it("functionCall.args carried as a string (rare) is passed through verbatim", () => {
    // Some upstreams emit args as a stringified JSON rather than an
    // object. The parser must NOT double-stringify in that case; the
    // accumulator's concatenated args must still parse correctly.
    const p = new GeminiSSEParser();
    const frames = [
      `data: ${JSON.stringify({
        candidates: [
          {
            content: {
              role: "model",
              parts: [
                { functionCall: { name: "f", args: `{"k":"v"}` } },
              ],
            },
          },
        ],
      })}\n\n`,
    ];
    const events = feedFrames(p, frames);
    const args = events.filter((e) => e.kind === "tool-call-arguments") as Array<
      Extract<WireEvent, { kind: "tool-call-arguments" }>
    >;
    expect(args).toHaveLength(1);
    expect(JSON.parse(args[0]!.deltaJson)).toEqual({ k: "v" });
  });

  it("frames split across feed() boundaries reassemble correctly", () => {
    // SSE framing is on `\n\n`; chunks may arrive mid-frame.
    const p = new GeminiSSEParser();
    const full = `data: ${JSON.stringify({
      candidates: [
        { content: { role: "model", parts: [{ text: "split" }] } },
      ],
    })}\n\n`;
    const half = full.length >> 1;
    const out: WireEvent[] = [];
    out.push(...p.feed(enc.encode(full.slice(0, half))));
    out.push(...p.feed(enc.encode(full.slice(half))));
    out.push(...p.flush());
    const text = out.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect(
      (text as Extract<WireEvent, { kind: "text-delta" }>).text,
    ).toBe("split");
  });
});

// ── Bedrock binary event-stream (GR-18) ─────────────────────────────────────
//
// Bedrock streams are NOT SSE — they're the binary AWS event-stream framing
// (`application/vnd.amazon.eventstream`). We can't hand-write the frames with
// correct CRCs, so we use the module's own encoders to produce the fixture
// bytes and assert the parser decodes them. The encoder/parser round-trip is
// the contract that the deny-splice frames the AWS SDK checksums are valid.

/** Concatenate Uint8Arrays into one buffer. */
function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Independent table-free CRC32 (distinct impl from the source under test). */
function independentCrc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i]!;
    for (let k = 0; k < 8; k++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

describe("BedrockConverseStreamParser", () => {
  it("full tool sequence emits start/arguments/end/finish with per-index integrity", () => {
    const p = new BedrockConverseStreamParser();
    const bytes = concatBytes([
      encodeBedrockEventStreamMessage("contentBlockStart", {
        contentBlockIndex: 0,
        start: { toolUse: { toolUseId: "tu_1", name: "search" } },
      }),
      encodeBedrockEventStreamMessage("contentBlockDelta", {
        contentBlockIndex: 0,
        delta: { toolUse: { input: `{"q":` } },
      }),
      encodeBedrockEventStreamMessage("contentBlockDelta", {
        contentBlockIndex: 0,
        delta: { toolUse: { input: `"weather"}` } },
      }),
      encodeBedrockEventStreamMessage("contentBlockStop", { contentBlockIndex: 0 }),
      encodeBedrockEventStreamMessage("messageStop", { stopReason: "tool_use" }),
    ]);
    const events = [...p.feed(bytes), ...p.flush()];
    expect(events.map((e) => e.kind)).toEqual([
      "tool-call-start",
      "tool-call-arguments",
      "tool-call-arguments",
      "tool-call-end",
      "finish",
    ]);
    const start = events[0] as Extract<WireEvent, { kind: "tool-call-start" }>;
    expect(start.index).toBe(0);
    expect(start.name).toBe("search");
    expect(start.id).toBe("tu_1");
    const args = events.filter(
      (e) => e.kind === "tool-call-arguments",
    ) as Array<Extract<WireEvent, { kind: "tool-call-arguments" }>>;
    expect(JSON.parse(args.map((a) => a.deltaJson).join(""))).toEqual({ q: "weather" });
    const finish = events[4] as Extract<WireEvent, { kind: "finish" }>;
    expect(finish.finishReason).toBe("tool_use");
  });

  it("contentBlockDelta text produces text-delta", () => {
    const p = new BedrockConverseStreamParser();
    const bytes = encodeBedrockEventStreamMessage("contentBlockDelta", {
      contentBlockIndex: 0,
      delta: { text: "hello" },
    });
    const events = [...p.feed(bytes), ...p.flush()];
    const text = events.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect((text as Extract<WireEvent, { kind: "text-delta" }>).text).toBe("hello");
  });

  it("messageStart / metadata frames pass through", () => {
    const p = new BedrockConverseStreamParser();
    const bytes = concatBytes([
      encodeBedrockEventStreamMessage("messageStart", { role: "assistant" }),
      encodeBedrockEventStreamMessage("metadata", { usage: { inputTokens: 1 } }),
    ]);
    const events = [...p.feed(bytes), ...p.flush()];
    expect(events.map((e) => e.kind)).toEqual(["passthrough", "passthrough"]);
  });

  it("frames split across feed() boundaries reassemble", () => {
    const p = new BedrockConverseStreamParser();
    const bytes = concatBytes([
      encodeBedrockEventStreamMessage("contentBlockStart", {
        contentBlockIndex: 0,
        start: { toolUse: { toolUseId: "tu_1", name: "search" } },
      }),
      encodeBedrockEventStreamMessage("messageStop", { stopReason: "end_turn" }),
    ]);
    const half = bytes.length >> 1;
    const events = [
      ...p.feed(bytes.subarray(0, half)),
      ...p.feed(bytes.subarray(half)),
      ...p.flush(),
    ];
    expect(events.map((e) => e.kind)).toEqual(["tool-call-start", "finish"]);
  });

  it("corrupt frame degrades to passthrough", () => {
    const p = new BedrockConverseStreamParser();
    // First two bytes claim a giant total_length → decoder rejects.
    const corrupt = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0]);
    const events = [...p.feed(corrupt), ...p.flush()];
    expect(events.every((e) => e.kind === "passthrough")).toBe(true);
    expect(events.length).toBeGreaterThan(0);
  });
});

describe("BedrockInvokeStreamParser (anthropic-on-bedrock)", () => {
  it("base64 chunk events map to the same WireEvents as AnthropicSSEParser", () => {
    const chunkObjs: Array<Record<string, unknown>> = [
      { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_1", name: "lookup" } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: `{"id":1}` } },
      { type: "content_block_stop", index: 0 },
      { type: "message_stop" },
    ];
    const bedrock = new BedrockInvokeStreamParser();
    const bedrockEvents = [
      ...bedrock.feed(concatBytes(chunkObjs.map((c) => encodeBedrockInvokeChunk(c)))),
      ...bedrock.flush(),
    ];

    // Feed the same chunk objects to AnthropicSSEParser via SSE framing.
    const sse = new AnthropicSSEParser();
    const sseBytes = enc.encode(
      chunkObjs
        .map((c) => `event: ${c["type"] as string}\ndata: ${JSON.stringify(c)}\n\n`)
        .join(""),
    );
    const sseEvents = [...sse.feed(sseBytes), ...sse.flush()];

    expect(bedrockEvents.map((e) => e.kind)).toEqual(sseEvents.map((e) => e.kind));
    expect(bedrockEvents.map((e) => e.kind)).toEqual([
      "tool-call-start",
      "tool-call-arguments",
      "tool-call-end",
      "finish",
    ]);
    const start = bedrockEvents[0] as Extract<WireEvent, { kind: "tool-call-start" }>;
    expect(start.name).toBe("lookup");
    expect(start.id).toBe("toolu_1");
  });

  it("non-chunk events pass through", () => {
    const p = new BedrockInvokeStreamParser();
    const bytes = encodeBedrockEventStreamMessage("metadata", { foo: 1 });
    const events = [...p.feed(bytes), ...p.flush()];
    expect(events.map((e) => e.kind)).toEqual(["passthrough"]);
  });
});

describe("Bedrock event-stream codec", () => {
  it("encoder output decodes back through the parser (round-trip)", () => {
    const p = new BedrockConverseStreamParser();
    const frame = encodeBedrockEventStreamMessage("messageStop", { stopReason: "end_turn" });
    const events = [...p.feed(frame), ...p.flush()];
    expect(events).toHaveLength(1);
    expect(events[0]!.kind).toBe("finish");
  });

  it("prelude + message CRC32 fields verify against an independent CRC", () => {
    const frame = encodeBedrockEventStreamMessage("contentBlockStop", { contentBlockIndex: 0 });
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const totalLength = view.getUint32(0, false);
    expect(totalLength).toBe(frame.byteLength);
    // prelude_crc = CRC32(bytes 0..8)
    const preludeCrc = view.getUint32(8, false);
    expect(preludeCrc).toBe(independentCrc32(frame.subarray(0, 8)));
    // message_crc = CRC32(bytes 0..end-4)
    const messageCrc = view.getUint32(frame.byteLength - 4, false);
    expect(messageCrc).toBe(independentCrc32(frame.subarray(0, frame.byteLength - 4)));
  });

  it("encodeBedrockInvokeChunk wraps the payload as base64 under {bytes}", () => {
    const p = new BedrockInvokeStreamParser();
    const frame = encodeBedrockInvokeChunk({
      type: "content_block_delta",
      index: 0,
      delta: { type: "text_delta", text: "blocked" },
    });
    const events = [...p.feed(frame), ...p.flush()];
    const text = events.find((e) => e.kind === "text-delta");
    expect(text).toBeDefined();
    expect((text as Extract<WireEvent, { kind: "text-delta" }>).text).toBe("blocked");
  });
});
