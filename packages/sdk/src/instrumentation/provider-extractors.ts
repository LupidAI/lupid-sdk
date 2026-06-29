/**
 * Shared provider-shaped request/response tool-call extraction + deny
 * rewrite for ALL wire shapes.
 *
 * Why this module exists (GR-18): three interceptors — `fetch-interceptor.ts`,
 * `node-http-interceptor.ts`, `undici-dispatcher-interceptor.ts` — each
 * hand-copied the same extract/rewrite logic. The copies drifted: fetch was
 * the most complete (all four shapes + `{denyCode, ruleId}` meta on the block
 * notice), while node:http and undici were stale forks missing Cohere/Gemini
 * and Bedrock. This module is the single source of truth so the *class* of
 * drift bug cannot recur.
 *
 * Edge-safe: NO `Buffer`, NO `node:*` imports. This file is reachable from
 * `index.ts` via the fetch interceptor, so it ships in the universal edge
 * bundle (`dist/index.mjs`). `tests/edge-entry.test.ts` greps the built bundle
 * for any leaked Node built-in import — keep this file pure.
 */

import type { HostMatch } from "./host-registry.js";
import { makeBlockNoticeText } from "./_parsers.js";
import type { ToolCallEvaluation } from "../evaluation/cedar-client.js"; // type-only — allowed

export interface RequestToolCall {
  name: string;
  args: unknown;
}

export interface ResponseToolCall {
  name: string;
  args: unknown;
  raw: string;
}

// ── small helpers (edge-safe) ───────────────────────────────────────────────

export function safeJsonParse(s: string): unknown {
  if (!s) return {};
  try {
    return JSON.parse(s);
  } catch {
    return { _raw: s };
  }
}

export function safeStringify(v: unknown): string {
  try {
    return typeof v === "string" ? v : JSON.stringify(v ?? {});
  } catch {
    return String(v);
  }
}

// ── per-shape internal extractors (named so bedrock-invoke can delegate) ─────

function openAIRequestToolCalls(body: Record<string, unknown>): RequestToolCall[] {
  const messages = body["messages"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(messages)) return [];
  const out: RequestToolCall[] = [];
  for (const msg of messages) {
    const tcs = msg["tool_calls"] as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(tcs)) continue;
    for (const tc of tcs) {
      const fn = tc["function"] as Record<string, unknown> | undefined;
      if (!fn || typeof fn["name"] !== "string") continue;
      const args =
        typeof fn["arguments"] === "string"
          ? safeJsonParse(fn["arguments"] as string)
          : fn["arguments"];
      out.push({ name: fn["name"] as string, args });
    }
  }
  return out;
}

function anthropicRequestToolCalls(body: Record<string, unknown>): RequestToolCall[] {
  const messages = body["messages"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(messages)) return [];
  const out: RequestToolCall[] = [];
  for (const msg of messages) {
    const content = msg["content"];
    if (!Array.isArray(content)) continue;
    for (const block of content as Array<Record<string, unknown>>) {
      if (block["type"] === "tool_use" && typeof block["name"] === "string") {
        out.push({ name: block["name"] as string, args: block["input"] });
      }
    }
  }
  return out;
}

function cohereRequestToolCalls(body: Record<string, unknown>): RequestToolCall[] {
  // Cohere v1/v2 chat: prior assistant turns may include `tool_calls`
  // entries either at the top level (`body.tool_calls`) or per-message
  // (`messages[].tool_calls`). The shape is `{ name, parameters }` —
  // `parameters` is already an object, no string-decode needed.
  const out: RequestToolCall[] = [];
  const collect = (tcs: unknown): void => {
    if (!Array.isArray(tcs)) return;
    for (const tc of tcs as Array<Record<string, unknown>>) {
      if (typeof tc["name"] !== "string") continue;
      out.push({ name: tc["name"] as string, args: tc["parameters"] });
    }
  };
  collect(body["tool_calls"]);
  const messages = body["messages"];
  if (Array.isArray(messages)) {
    for (const msg of messages as Array<Record<string, unknown>>) {
      collect(msg["tool_calls"]);
    }
  }
  return out;
}

function geminiRequestToolCalls(body: Record<string, unknown>): RequestToolCall[] {
  // Gemini :generateContent — historical model turns appear under
  // `contents[].parts[].functionCall = { name, args }`.
  const contents = body["contents"];
  if (!Array.isArray(contents)) return [];
  const out: RequestToolCall[] = [];
  for (const c of contents as Array<Record<string, unknown>>) {
    const parts = c["parts"];
    if (!Array.isArray(parts)) continue;
    for (const p of parts as Array<Record<string, unknown>>) {
      const fc = p["functionCall"] as Record<string, unknown> | undefined;
      if (fc && typeof fc["name"] === "string") {
        out.push({ name: fc["name"] as string, args: fc["args"] });
      }
    }
  }
  return out;
}

function bedrockConverseRequestToolCalls(body: Record<string, unknown>): RequestToolCall[] {
  // Converse API is plain JSON, model-agnostic:
  //   messages[].content[].toolUse = { toolUseId, name, input }
  const messages = body["messages"];
  if (!Array.isArray(messages)) return [];
  const out: RequestToolCall[] = [];
  for (const msg of messages as Array<Record<string, unknown>>) {
    const content = msg["content"];
    if (!Array.isArray(content)) continue;
    for (const block of content as Array<Record<string, unknown>>) {
      const tu = block["toolUse"] as Record<string, unknown> | undefined;
      if (tu && typeof tu["name"] === "string") {
        out.push({ name: tu["name"] as string, args: tu["input"] });
      }
    }
  }
  return out;
}

function openAIResponseToolCalls(json: Record<string, unknown>): ResponseToolCall[] {
  const choices = json["choices"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(choices) || choices.length === 0) return [];
  const message = choices[0]!["message"] as Record<string, unknown> | undefined;
  const tcs = message?.["tool_calls"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(tcs)) return [];
  return tcs.map((tc) => {
    const fn = (tc["function"] as Record<string, unknown>) ?? {};
    const raw = typeof fn["arguments"] === "string" ? (fn["arguments"] as string) : "";
    return {
      name: String(fn["name"] ?? ""),
      args: safeJsonParse(raw),
      raw,
    };
  });
}

function anthropicResponseToolCalls(json: Record<string, unknown>): ResponseToolCall[] {
  const content = json["content"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(content)) return [];
  const out: ResponseToolCall[] = [];
  for (const b of content) {
    if (b["type"] === "tool_use" && typeof b["name"] === "string") {
      out.push({
        name: b["name"] as string,
        args: b["input"],
        raw: safeStringify(b["input"]),
      });
    }
  }
  return out;
}

function cohereResponseToolCalls(json: Record<string, unknown>): ResponseToolCall[] {
  // Cohere puts denied-or-allowed tool calls at the top level:
  //   { tool_calls: [ { name, parameters } ], message: { content: ... } }
  const tcs = json["tool_calls"];
  if (!Array.isArray(tcs)) return [];
  const out: ResponseToolCall[] = [];
  for (const tc of tcs as Array<Record<string, unknown>>) {
    if (typeof tc["name"] !== "string") continue;
    const params = tc["parameters"];
    out.push({
      name: tc["name"] as string,
      args: params,
      raw: safeStringify(params),
    });
  }
  return out;
}

function geminiResponseToolCalls(json: Record<string, unknown>): ResponseToolCall[] {
  // Gemini: candidates[0].content.parts[].functionCall = { name, args }
  const candidates = json["candidates"];
  if (!Array.isArray(candidates) || candidates.length === 0) return [];
  const cand = candidates[0] as Record<string, unknown>;
  const cont = cand["content"] as Record<string, unknown> | undefined;
  const parts = cont?.["parts"];
  if (!Array.isArray(parts)) return [];
  const out: ResponseToolCall[] = [];
  for (const p of parts as Array<Record<string, unknown>>) {
    const fc = p["functionCall"] as Record<string, unknown> | undefined;
    if (!fc || typeof fc["name"] !== "string") continue;
    const args = fc["args"];
    out.push({
      name: fc["name"] as string,
      args,
      raw: safeStringify(args),
    });
  }
  return out;
}

function bedrockConverseResponseToolCalls(json: Record<string, unknown>): ResponseToolCall[] {
  // response: output.message.content[].toolUse = { toolUseId, name, input }
  const output = json["output"] as Record<string, unknown> | undefined;
  const message = output?.["message"] as Record<string, unknown> | undefined;
  const content = message?.["content"];
  if (!Array.isArray(content)) return [];
  const out: ResponseToolCall[] = [];
  for (const block of content as Array<Record<string, unknown>>) {
    const tu = block["toolUse"] as Record<string, unknown> | undefined;
    if (tu && typeof tu["name"] === "string") {
      out.push({
        name: tu["name"] as string,
        args: tu["input"],
        raw: safeStringify(tu["input"]),
      });
    }
  }
  return out;
}

// ── per-shape internal rewriters ─────────────────────────────────────────────

function openAIRewrite(
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  const choices = json["choices"] as Array<Record<string, unknown>>;
  const message = choices[0]!["message"] as Record<string, unknown>;
  const original = message["tool_calls"] as Array<Record<string, unknown>>;
  const remaining: Array<Record<string, unknown>> = [];
  const notices: string[] = [];
  original.forEach((tc, i) => {
    const d = decisions[i]!;
    if (d.decision === "deny") {
      const c = calls[i]!;
      notices.push(
        makeBlockNoticeText(c.name, c.raw, d.reason, {
          denyCode: d.denyCode,
          ruleId: d.ruleId,
        }),
      );
    } else {
      remaining.push(tc);
    }
  });
  if (remaining.length > 0) {
    message["tool_calls"] = remaining;
  } else {
    delete message["tool_calls"];
    choices[0]!["finish_reason"] = "stop";
  }
  const content = typeof message["content"] === "string" ? (message["content"] as string) : "";
  message["content"] = [content, ...notices].filter(Boolean).join("\n");
  return json;
}

function anthropicRewrite(
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  const content = json["content"] as Array<Record<string, unknown>>;
  let callCursor = 0;
  for (let i = 0; i < content.length; i++) {
    const b = content[i]!;
    if (b["type"] !== "tool_use") continue;
    const d = decisions[callCursor]!;
    if (d.decision === "deny") {
      const c = calls[callCursor]!;
      content[i] = {
        type: "text",
        text: makeBlockNoticeText(c.name, c.raw, d.reason, {
          denyCode: d.denyCode,
          ruleId: d.ruleId,
        }),
      };
    }
    callCursor++;
  }
  const stillTool = content.some((b) => b["type"] === "tool_use");
  if (!stillTool && json["stop_reason"] === "tool_use") {
    json["stop_reason"] = "end_turn";
  }
  return json;
}

function cohereRewrite(
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  const original = json["tool_calls"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(original)) return json;
  const remaining: Array<Record<string, unknown>> = [];
  const notices: string[] = [];
  original.forEach((tc, i) => {
    const d = decisions[i];
    const c = calls[i];
    if (d && c && d.decision === "deny") {
      notices.push(
        makeBlockNoticeText(c.name, c.raw, d.reason, {
          denyCode: d.denyCode,
          ruleId: d.ruleId,
        }),
      );
    } else {
      remaining.push(tc);
    }
  });
  if (remaining.length > 0) {
    json["tool_calls"] = remaining;
  } else {
    delete json["tool_calls"];
    // Cohere uses `finish_reason: "TOOL_CALL"` (uppercase) when emitting
    // tool calls. Mirror the OpenAI rewrite behaviour and reset to
    // "COMPLETE" when no tool calls remain.
    if (typeof json["finish_reason"] === "string" && json["finish_reason"] === "TOOL_CALL") {
      json["finish_reason"] = "COMPLETE";
    }
  }
  if (notices.length > 0) {
    // Append the deny notices to the assistant text. Cohere v2 places the
    // assistant text under `message.content[0].text`; v1 uses top-level
    // `text`. Cover both.
    const message = json["message"] as Record<string, unknown> | undefined;
    if (message && Array.isArray(message["content"])) {
      const arr = message["content"] as Array<Record<string, unknown>>;
      arr.push({ type: "text", text: notices.join("\n") });
    } else if (typeof json["text"] === "string") {
      json["text"] = [json["text"] as string, ...notices].filter(Boolean).join("\n");
    } else {
      json["text"] = notices.join("\n");
    }
  }
  return json;
}

function geminiRewrite(
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  const candidates = json["candidates"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(candidates) || candidates.length === 0) return json;
  const cand = candidates[0]!;
  const content = cand["content"] as Record<string, unknown> | undefined;
  const parts = content?.["parts"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(parts)) return json;
  let callCursor = 0;
  let stillFunctionCall = false;
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    const fc = p["functionCall"] as Record<string, unknown> | undefined;
    if (!fc) continue;
    const d = decisions[callCursor];
    const c = calls[callCursor];
    callCursor++;
    if (d && c && d.decision === "deny") {
      // Replace the denied functionCall part with a plain text part.
      parts[i] = {
        text: makeBlockNoticeText(c.name, c.raw, d.reason, {
          denyCode: d.denyCode,
          ruleId: d.ruleId,
        }),
      };
    } else {
      stillFunctionCall = true;
    }
  }
  // Gemini sets `finishReason: "STOP"` after a normal turn and may set
  // tool-related reasons such as "TOOL_USE" / "FUNCTION_CALL" when a
  // call is emitted. If every functionCall was denied, normalise to
  // "STOP" so downstream consumers don't await a non-existent tool turn.
  if (!stillFunctionCall) {
    const fr = cand["finishReason"];
    if (typeof fr === "string" && fr !== "STOP" && fr !== "MAX_TOKENS" && fr !== "SAFETY") {
      cand["finishReason"] = "STOP";
    }
  }
  return json;
}

function bedrockConverseRewrite(
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  // response: output.message.content[].toolUse; top-level stopReason.
  // Mirror the anthropic-messages rewrite contract: replace each DENIED
  // toolUse block in-place with a { text: <notice> } block, and if no
  // toolUse blocks remain && stopReason === "tool_use" → "end_turn".
  const output = json["output"] as Record<string, unknown> | undefined;
  const message = output?.["message"] as Record<string, unknown> | undefined;
  const content = message?.["content"];
  if (!Array.isArray(content)) return json;
  const blocks = content as Array<Record<string, unknown>>;
  let callCursor = 0;
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i]!;
    const tu = block["toolUse"] as Record<string, unknown> | undefined;
    if (!tu || typeof tu["name"] !== "string") continue;
    const d = decisions[callCursor];
    const c = calls[callCursor];
    callCursor++;
    if (d && c && d.decision === "deny") {
      blocks[i] = {
        text: makeBlockNoticeText(c.name, c.raw, d.reason, {
          denyCode: d.denyCode,
          ruleId: d.ruleId,
        }),
      };
    }
  }
  const stillTool = blocks.some((b) => {
    const tu = b["toolUse"] as Record<string, unknown> | undefined;
    return tu && typeof tu["name"] === "string";
  });
  if (!stillTool && json["stopReason"] === "tool_use") {
    json["stopReason"] = "end_turn";
  }
  return json;
}

// ── bedrock-invoke discriminators (anthropic-on-bedrock) ─────────────────────

function isAnthropicInvokeRequest(body: Record<string, unknown>): boolean {
  // Bedrock requires `anthropic_version` on every Anthropic InvokeModel call,
  // so this is a reliable discriminator. Non-Anthropic invoke payloads
  // (Titan/Llama/Mistral) lack it and remain observe-only — fail-open at the
  // *coverage* level (Bedrock rejects malformed Anthropic requests anyway),
  // not at the decision level.
  return typeof body["anthropic_version"] === "string";
}

function isAnthropicInvokeResponse(json: Record<string, unknown>): boolean {
  return json["type"] === "message" && Array.isArray(json["content"]);
}

// ── public API (keyed by HostMatch.shape) ────────────────────────────────────

export function extractRequestToolCalls(
  match: HostMatch,
  body: Record<string, unknown>,
): RequestToolCall[] {
  switch (match.shape) {
    case "openai-chat":
    case "openai-responses":
      return openAIRequestToolCalls(body);
    case "anthropic-messages":
      return anthropicRequestToolCalls(body);
    case "cohere-chat":
      return cohereRequestToolCalls(body);
    case "gemini-generate":
      return geminiRequestToolCalls(body);
    case "bedrock-converse":
      return bedrockConverseRequestToolCalls(body);
    case "bedrock-invoke":
      // modelId lives in the URL (not visible here); sniff the payload.
      return isAnthropicInvokeRequest(body) ? anthropicRequestToolCalls(body) : [];
    default:
      return [];
  }
}

export function extractResponseToolCalls(
  match: HostMatch,
  json: Record<string, unknown>,
): ResponseToolCall[] {
  switch (match.shape) {
    case "openai-chat":
    case "openai-responses":
      return openAIResponseToolCalls(json);
    case "anthropic-messages":
      return anthropicResponseToolCalls(json);
    case "cohere-chat":
      return cohereResponseToolCalls(json);
    case "gemini-generate":
      return geminiResponseToolCalls(json);
    case "bedrock-converse":
      return bedrockConverseResponseToolCalls(json);
    case "bedrock-invoke":
      return isAnthropicInvokeResponse(json) ? anthropicResponseToolCalls(json) : [];
    default:
      return [];
  }
}

export function rewriteResponseBody(
  match: HostMatch,
  json: Record<string, unknown>,
  decisions: ToolCallEvaluation[],
  calls: ResponseToolCall[],
): Record<string, unknown> {
  switch (match.shape) {
    case "openai-chat":
    case "openai-responses":
      return openAIRewrite(json, decisions, calls);
    case "anthropic-messages":
      return anthropicRewrite(json, decisions, calls);
    case "cohere-chat":
      return cohereRewrite(json, decisions, calls);
    case "gemini-generate":
      return geminiRewrite(json, decisions, calls);
    case "bedrock-converse":
      return bedrockConverseRewrite(json, decisions, calls);
    case "bedrock-invoke":
      // anthropic-on-bedrock invoke responses are Anthropic message JSON
      // (incl. `stop_reason: "tool_use"` → `"end_turn"` normalisation).
      return isAnthropicInvokeResponse(json)
        ? anthropicRewrite(json, decisions, calls)
        : json;
    default:
      return json;
  }
}
