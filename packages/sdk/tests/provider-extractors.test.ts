/**
 * Unit tests for the shared provider-shaped extraction + deny rewrite module
 * (GR-18). This module is the single source of truth shared by the fetch,
 * node:http and undici interceptors; pinning per-shape behaviour here proves
 * the three interceptors all enforce identically (no drift).
 *
 * Matrix: for each wire shape we assert
 *   1. request-side tool-call extraction
 *   2. response-side tool-call extraction
 *   3. deny rewrite (drop/replace the tool call, append the block notice)
 *
 * Bedrock has two shapes: Converse (plain JSON, model-agnostic) and Invoke
 * (provider-native — we cover anthropic-on-bedrock, sniffed via
 * `anthropic_version`). Non-anthropic invoke payloads must be observe-only.
 */

import {
  extractRequestToolCalls,
  extractResponseToolCalls,
  rewriteResponseBody,
} from "../src/instrumentation/provider-extractors";
import type { HostMatch } from "../src/instrumentation/host-registry";
import type { ToolCallEvaluation } from "../src/evaluation/cedar-client";

function deny(reason = "policy denied"): ToolCallEvaluation {
  return { decision: "deny", ttlMs: 0, reason };
}
function allow(): ToolCallEvaluation {
  return { decision: "allow", ttlMs: 0 };
}

const m = (shape: HostMatch["shape"], provider: HostMatch["provider"]): HostMatch => ({
  provider,
  shape,
});

// ── OpenAI chat ─────────────────────────────────────────────────────────────

describe("openai-chat", () => {
  const match = m("openai-chat", "openai");

  it("extracts request tool_calls", () => {
    const body = {
      messages: [
        {
          role: "assistant",
          tool_calls: [{ function: { name: "search", arguments: `{"q":"x"}` } }],
        },
      ],
    };
    const calls = extractRequestToolCalls(match, body);
    expect(calls).toEqual([{ name: "search", args: { q: "x" } }]);
  });

  it("extracts response tool_calls and deny rewrite drops them + resets finish_reason", () => {
    const json = {
      choices: [
        {
          message: {
            content: "",
            tool_calls: [{ function: { name: "search", arguments: `{"q":"x"}` } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    };
    const calls = extractResponseToolCalls(match, json);
    expect(calls).toHaveLength(1);
    const rewritten = rewriteResponseBody(match, json, [deny("nope")], calls) as typeof json;
    const msg = rewritten.choices[0]!.message as Record<string, unknown>;
    expect(msg["tool_calls"]).toBeUndefined();
    expect(rewritten.choices[0]!.finish_reason).toBe("stop");
    expect(msg["content"]).toContain("Agentum blocked search");
  });
});

// ── Anthropic messages ──────────────────────────────────────────────────────

describe("anthropic-messages", () => {
  const match = m("anthropic-messages", "anthropic");

  it("extracts request tool_use blocks", () => {
    const body = {
      messages: [
        { role: "assistant", content: [{ type: "tool_use", name: "lookup", input: { id: 1 } }] },
      ],
    };
    expect(extractRequestToolCalls(match, body)).toEqual([{ name: "lookup", args: { id: 1 } }]);
  });

  it("deny rewrite replaces tool_use with text and normalises stop_reason", () => {
    const json: Record<string, unknown> = {
      content: [{ type: "tool_use", name: "lookup", input: { id: 1 } }],
      stop_reason: "tool_use",
    };
    const calls = extractResponseToolCalls(match, json);
    const rewritten = rewriteResponseBody(match, json, [deny()], calls);
    const content = rewritten["content"] as Array<Record<string, unknown>>;
    expect(content[0]!["type"]).toBe("text");
    expect(content[0]!["text"]).toContain("Agentum blocked lookup");
    expect(rewritten["stop_reason"]).toBe("end_turn");
  });
});

// ── Cohere chat ─────────────────────────────────────────────────────────────

describe("cohere-chat", () => {
  const match = m("cohere-chat", "cohere");

  it("extracts request tool_calls (top-level + per-message)", () => {
    const body = {
      tool_calls: [{ name: "a", parameters: { x: 1 } }],
      messages: [{ role: "assistant", tool_calls: [{ name: "b", parameters: { y: 2 } }] }],
    };
    expect(extractRequestToolCalls(match, body)).toEqual([
      { name: "a", args: { x: 1 } },
      { name: "b", args: { y: 2 } },
    ]);
  });

  it("deny rewrite drops tool_calls + appends notice", () => {
    const json: Record<string, unknown> = {
      tool_calls: [{ name: "search", parameters: { q: "x" } }],
      finish_reason: "TOOL_CALL",
      message: { content: [{ type: "text", text: "" }] },
    };
    const calls = extractResponseToolCalls(match, json);
    const rewritten = rewriteResponseBody(match, json, [deny()], calls) as Record<string, unknown>;
    expect(rewritten["tool_calls"]).toBeUndefined();
    expect(rewritten["finish_reason"]).toBe("COMPLETE");
  });
});

// ── Gemini generate ─────────────────────────────────────────────────────────

describe("gemini-generate", () => {
  const match = m("gemini-generate", "gemini");

  it("extracts request functionCall parts", () => {
    const body = {
      contents: [{ role: "model", parts: [{ functionCall: { name: "f", args: { a: 1 } } }] }],
    };
    expect(extractRequestToolCalls(match, body)).toEqual([{ name: "f", args: { a: 1 } }]);
  });

  it("deny rewrite replaces functionCall part with text + normalises finishReason", () => {
    const json: Record<string, unknown> = {
      candidates: [
        {
          content: { role: "model", parts: [{ functionCall: { name: "f", args: { a: 1 } } }] },
          finishReason: "TOOL_USE",
        },
      ],
    };
    const calls = extractResponseToolCalls(match, json);
    const rewritten = rewriteResponseBody(match, json, [deny()], calls);
    const cand = (rewritten["candidates"] as Array<Record<string, unknown>>)[0]!;
    const parts = (cand["content"] as Record<string, unknown>)["parts"] as Array<Record<string, unknown>>;
    expect(parts[0]!["functionCall"]).toBeUndefined();
    expect(parts[0]!["text"]).toContain("Agentum blocked f");
    expect(cand["finishReason"]).toBe("STOP");
  });
});

// ── Bedrock Converse ────────────────────────────────────────────────────────

describe("bedrock-converse", () => {
  const match = m("bedrock-converse", "bedrock");

  it("extracts request toolUse blocks", () => {
    const body = {
      messages: [
        {
          role: "assistant",
          content: [{ toolUse: { toolUseId: "tu_1", name: "search", input: { q: "x" } } }],
        },
      ],
    };
    expect(extractRequestToolCalls(match, body)).toEqual([{ name: "search", args: { q: "x" } }]);
  });

  it("extracts response toolUse blocks", () => {
    const json = {
      output: {
        message: {
          role: "assistant",
          content: [{ toolUse: { toolUseId: "tu_1", name: "search", input: { q: "x" } } }],
        },
      },
      stopReason: "tool_use",
    };
    const calls = extractResponseToolCalls(match, json);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.name).toBe("search");
  });

  const converseBody = (): Record<string, unknown> => ({
    output: {
      message: {
        role: "assistant",
        content: [{ toolUse: { toolUseId: "tu_1", name: "search", input: { q: "x" } } }],
      },
    },
    stopReason: "tool_use",
  });

  const converseBlocks = (j: Record<string, unknown>): Array<Record<string, unknown>> =>
    ((j["output"] as Record<string, unknown>)["message"] as Record<string, unknown>)[
      "content"
    ] as Array<Record<string, unknown>>;

  it("deny rewrite replaces toolUse with text block + normalises stopReason", () => {
    const json = converseBody();
    const calls = extractResponseToolCalls(match, json);
    const rewritten = rewriteResponseBody(match, json, [deny()], calls);
    const blocks = converseBlocks(rewritten);
    expect(blocks[0]!["toolUse"]).toBeUndefined();
    expect(blocks[0]!["text"]).toContain("Agentum blocked search");
    expect(rewritten["stopReason"]).toBe("end_turn");
  });

  it("allow path leaves the body unchanged", () => {
    const json = converseBody();
    const calls = extractResponseToolCalls(match, json);
    const rewritten = rewriteResponseBody(match, json, [allow()], calls);
    const blocks = converseBlocks(rewritten);
    expect(blocks[0]!["toolUse"]).toBeDefined();
    expect(rewritten["stopReason"]).toBe("tool_use");
  });
});

// ── Bedrock Invoke (anthropic-on-bedrock) ───────────────────────────────────

describe("bedrock-invoke (anthropic body)", () => {
  const match = m("bedrock-invoke", "bedrock");

  it("extracts request tool_use when anthropic_version present", () => {
    const body = {
      anthropic_version: "bedrock-2023-05-31",
      messages: [
        { role: "assistant", content: [{ type: "tool_use", name: "lookup", input: { id: 1 } }] },
      ],
    };
    expect(extractRequestToolCalls(match, body)).toEqual([{ name: "lookup", args: { id: 1 } }]);
  });

  it("response = anthropic message JSON; deny rewrite normalises stop_reason", () => {
    const json: Record<string, unknown> = {
      type: "message",
      content: [{ type: "tool_use", name: "lookup", input: { id: 1 } }],
      stop_reason: "tool_use",
    };
    const calls = extractResponseToolCalls(match, json);
    expect(calls).toHaveLength(1);
    const rewritten = rewriteResponseBody(match, json, [deny()], calls);
    const content = rewritten["content"] as Array<Record<string, unknown>>;
    expect(content[0]!["type"]).toBe("text");
    expect(rewritten["stop_reason"]).toBe("end_turn");
  });

  it("non-anthropic invoke body (Titan) extracts [] and rewrite is identity", () => {
    const titanReq = { inputText: "hello", textGenerationConfig: { maxTokenCount: 10 } };
    expect(extractRequestToolCalls(match, titanReq)).toEqual([]);
    const titanResp = { inputTextTokenCount: 2, results: [{ outputText: "hi" }] };
    expect(extractResponseToolCalls(match, titanResp)).toEqual([]);
    const out = rewriteResponseBody(match, titanResp, [], []);
    expect(out).toEqual(titanResp);
  });
});

// ── fail-CLOSED-first: a deny decision must always suppress the tool ─────────
//
// (The evaluator-throws→deny path lives in the interceptors; here we assert
// the rewrite half of the contract — given a deny, the tool call never
// survives into the rewritten body, for every shape.)

describe("deny always removes the tool call (every shape)", () => {
  it("openai/anthropic/cohere/gemini/bedrock-converse/bedrock-invoke all drop on deny", () => {
    const cases: Array<{ match: HostMatch; json: Record<string, unknown>; survives: (j: unknown) => boolean }> = [
      {
        match: m("openai-chat", "openai"),
        json: { choices: [{ message: { content: "", tool_calls: [{ function: { name: "t", arguments: "{}" } }] }, finish_reason: "tool_calls" }] },
        survives: (j) => {
          const c = (j as { choices: Array<{ message: Record<string, unknown> }> }).choices[0]!;
          return c.message["tool_calls"] !== undefined;
        },
      },
      {
        match: m("anthropic-messages", "anthropic"),
        json: { content: [{ type: "tool_use", name: "t", input: {} }], stop_reason: "tool_use" },
        survives: (j) => (j as { content: Array<Record<string, unknown>> }).content.some((b) => b["type"] === "tool_use"),
      },
      {
        match: m("cohere-chat", "cohere"),
        json: { tool_calls: [{ name: "t", parameters: {} }], finish_reason: "TOOL_CALL" },
        survives: (j) => (j as Record<string, unknown>)["tool_calls"] !== undefined,
      },
      {
        match: m("gemini-generate", "gemini"),
        json: { candidates: [{ content: { parts: [{ functionCall: { name: "t", args: {} } }] }, finishReason: "TOOL_USE" }] },
        survives: (j) => {
          const parts = (j as { candidates: Array<{ content: { parts: Array<Record<string, unknown>> } }> }).candidates[0]!.content.parts;
          return parts.some((p) => p["functionCall"] !== undefined);
        },
      },
      {
        match: m("bedrock-converse", "bedrock"),
        json: { output: { message: { content: [{ toolUse: { name: "t", input: {} } }] } }, stopReason: "tool_use" },
        survives: (j) => {
          const blocks = (j as { output: { message: { content: Array<Record<string, unknown>> } } }).output.message.content;
          return blocks.some((b) => b["toolUse"] !== undefined);
        },
      },
      {
        // bedrock-invoke (anthropic-on-bedrock): response is an anthropic
        // message JSON, so the tool_use block must drop just like the
        // anthropic-messages shape — proves the invariant is all-shapes.
        match: m("bedrock-invoke", "bedrock"),
        json: { type: "message", content: [{ type: "tool_use", name: "t", input: {} }], stop_reason: "tool_use" },
        survives: (j) => (j as { content: Array<Record<string, unknown>> }).content.some((b) => b["type"] === "tool_use"),
      },
    ];
    for (const c of cases) {
      const calls = extractResponseToolCalls(c.match, c.json);
      const decisions = calls.map(() => deny());
      const rewritten = rewriteResponseBody(c.match, c.json, decisions, calls);
      expect(c.survives(rewritten)).toBe(false);
    }
  });
});
