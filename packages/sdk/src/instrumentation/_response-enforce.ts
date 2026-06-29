/**
 * Transport-agnostic RESPONSE-side (model-emitted) tool-call enforcement core.
 *
 * Why this module exists
 * ----------------------
 * The fetch interceptor enforces response bodies via a `ReadableStream`
 * pull model; the `node:http` interceptor and the undici dispatcher plane are
 * push-based (callbacks/events). The undici plane historically did
 * request-side pre-flight only — undici-only traffic (the Next.js route-handler
 * case where `globalThis.fetch` is UNPATCHED but the shared undici global
 * dispatcher IS wrapped) never got the deny-rewrite the fetch + node:http
 * planes apply to model-emitted tool calls.
 *
 * This core lifts the push-based response-enforce logic (modelled on
 * `node-http-interceptor.ts::wrapStreaming` / `wrapJsonResponse`) into a
 * transport-neutral driver. It carries NO transport dependency: callers feed it
 * bytes and it emits bytes through an abstract sink. The undici dispatcher
 * drives it via a wrapped handler; fetch + node:http keep their own copies for
 * now (parity is behavioural — same building blocks, same wire output — not a
 * refactor, to keep this change's blast radius small).
 *
 * Edge-safe: NO `Buffer`, NO `node:*` imports. This file imports only the
 * already-edge-safe `wire-parsers.ts` / `provider-extractors.ts` / `_parsers.ts`
 * primitives, so it stays out of the universal bundle's Node-builtin denylist
 * (`tests/edge-entry.test.ts`). Bytes are `Uint8Array`; JSON is encoded with
 * `TextEncoder`/`TextDecoder`.
 */

import type { HostMatch } from "./host-registry.js";
import {
  OpenAISSEParser,
  AnthropicSSEParser,
  CohereV2SSEParser,
  GeminiSSEParser,
  BedrockConverseStreamParser,
  BedrockInvokeStreamParser,
  encodeOpenAIDataFrame,
  encodeAnthropicEventFrame,
  encodeCohereEventFrame,
  encodeGeminiDataFrame,
  encodeBedrockEventStreamMessage,
  encodeBedrockInvokeChunk,
  OPENAI_DONE_FRAME,
  type WireEvent,
} from "./wire-parsers.js";
import { makeBlockNoticeText } from "./_parsers.js";
import {
  extractResponseToolCalls,
  rewriteResponseBody,
  safeJsonParse,
  type ResponseToolCall,
} from "./provider-extractors.js";
import type { ToolCallEvaluation } from "../evaluation/cedar-client.js"; // type-only — allowed

// ── streaming provider taxonomy (mirrors node-http-interceptor.ts) ───────────

type StreamProvider =
  | "openai"
  | "anthropic"
  | "cohere"
  | "gemini"
  | "bedrock-converse"
  | "bedrock-invoke";

/**
 * Map a classified `HostMatch.shape` to a streaming wire provider. Returns
 * `null` for shapes we have no streaming parser for — callers degrade to
 * verbatim passthrough rather than risk corrupting an unfamiliar wire format.
 */
export function streamProviderForShape(
  shape: string | null | undefined,
): StreamProvider | null {
  switch (shape) {
    case "openai-chat":
    case "openai-responses":
      return "openai";
    case "anthropic-messages":
      return "anthropic";
    case "cohere-chat":
      return "cohere";
    case "gemini-generate":
      return "gemini";
    case "bedrock-converse":
      return "bedrock-converse";
    case "bedrock-invoke":
      return "bedrock-invoke";
    default:
      return null;
  }
}

// The SSE parsers and the binary event-stream parsers share the structural
// `feed`/`flush`→WireEvent[] interface, so the streaming pipeline treats them
// uniformly.
type StreamWireParser = { feed(b: Uint8Array): WireEvent[]; flush(): WireEvent[] };

function newParserFor(provider: StreamProvider): StreamWireParser {
  switch (provider) {
    case "anthropic":
      return new AnthropicSSEParser();
    case "cohere":
      return new CohereV2SSEParser();
    case "gemini":
      return new GeminiSSEParser();
    case "bedrock-converse":
      return new BedrockConverseStreamParser();
    case "bedrock-invoke":
      return new BedrockInvokeStreamParser();
    case "openai":
    default:
      return new OpenAISSEParser();
  }
}

// ── evaluator contract (only the method this core needs) ─────────────────────

export interface ResponseEnforceEvaluator {
  evaluateToolCall(input: {
    toolName: string;
    arguments: unknown;
  }): Promise<ToolCallEvaluation>;
}

export interface ResponseEnforceConfig {
  match: HostMatch;
  evaluator: ResponseEnforceEvaluator;
  failMode: "allow" | "deny";
  logger: Pick<Console, "log" | "warn" | "error">;
}

// ── small edge-safe helpers ──────────────────────────────────────────────────

function safeParse(raw: string): unknown {
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return { _raw: raw };
  }
}

/**
 * Detect the deny-default sentinel emitted by `safeParse` when the argument
 * string couldn't be parsed (`{_raw: "<half>"}`), or an empty-string input.
 * Mirrors fetch-interceptor.ts / node-http-interceptor.ts `isPartialJson`:
 * a streaming tool call that finished with unparseable or zero argument bytes
 * is treated as a truncated stream → deny-by-default (we'd rather refuse a
 * call we couldn't fully observe than let it through unobserved).
 */
function isPartialJson(parsed: unknown, raw: string): boolean {
  if (raw.length === 0) return true;
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 1 && keys[0] === "_raw" && typeof obj["_raw"] === "string") {
      return true;
    }
  }
  return false;
}

async function safeEvalStream(
  cfg: ResponseEnforceConfig,
  name: string,
  rawArgs: string,
): Promise<ToolCallEvaluation> {
  const parsed = safeParse(rawArgs);
  if (isPartialJson(parsed, rawArgs)) {
    return { decision: "deny", ttlMs: 0, reason: "agentum-partial-tool-args" };
  }
  try {
    return await cfg.evaluator.evaluateToolCall({ toolName: name, arguments: parsed });
  } catch (err) {
    cfg.logger.warn(`[agentum] response-enforce stream eval: ${(err as Error).message}`);
    if (cfg.failMode === "deny") {
      return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" };
    }
    return { decision: "allow", ttlMs: 0 };
  }
}

// ── (a) streaming response enforcement ───────────────────────────────────────

/**
 * A push-based streaming response enforcer. The caller feeds upstream bytes via
 * `feed(chunk)` and signals EOF via `end()`; both are async (evaluation is
 * async). The enforcer emits bytes (verbatim text, or a synthetic deny
 * sequence) through the `emit` sink. The deny-rewrite + finish/stop-reason
 * normalization for every provider shape mirrors
 * `node-http-interceptor.ts::wrapStreaming` / `fetch-interceptor.ts::
 * wrapStreamingResponse` exactly (same encoders, same suppression logic).
 *
 * Returns `null` when the shape has no streaming parser — the caller MUST then
 * forward the upstream stream verbatim (fail-OPEN on shape-unrecognized).
 */
export function createStreamingEnforcer(
  cfg: ResponseEnforceConfig,
  emit: (bytes: Uint8Array) => void,
): { feed(chunk: Uint8Array): Promise<void>; end(): Promise<void> } | null {
  const provider = streamProviderForShape(cfg.match.shape);
  if (!provider) return null;
  const parser = newParserFor(provider);

  interface ToolAcc {
    name: string;
    args: string;
    bufferedFrames: Uint8Array[];
  }
  const accs = new Map<number, ToolAcc>();
  const inFlight = new Set<number>();
  // Latches true the first time flushTool emits a synthetic terminal sequence.
  // Once set, ALL subsequent upstream terminal frames are suppressed so we
  // never double-emit after the synthetic close.
  let syntheticTerminalEmitted = false;

  const flushTool = (index: number, acc: ToolAcc, verdict: ToolCallEvaluation): void => {
    if (verdict.decision === "allow") {
      for (const f of acc.bufferedFrames) emit(f);
      return;
    }
    const notice = makeBlockNoticeText(acc.name, acc.args, verdict.reason, {
      denyCode: verdict.denyCode,
      ruleId: verdict.ruleId,
    });
    if (provider === "anthropic") {
      emit(encodeAnthropicEventFrame("content_block_start", {
        type: "content_block_start", index, content_block: { type: "text", text: "" },
      }));
      emit(encodeAnthropicEventFrame("content_block_delta", {
        type: "content_block_delta", index, delta: { type: "text_delta", text: notice },
      }));
      emit(encodeAnthropicEventFrame("content_block_stop", { type: "content_block_stop", index }));
      return;
    }
    if (provider === "cohere") {
      emit(encodeCohereEventFrame("content-start", {
        index, delta: { message: { content: { type: "text", text: "" } } },
      }));
      emit(encodeCohereEventFrame("content-delta", {
        index, delta: { message: { content: { text: notice } } },
      }));
      emit(encodeCohereEventFrame("content-end", { index }));
      emit(encodeCohereEventFrame("message-end", { delta: { finish_reason: "COMPLETE" } }));
      return;
    }
    if (provider === "gemini") {
      emit(encodeGeminiDataFrame({
        candidates: [{
          content: { role: "model", parts: [{ text: notice }] },
          finishReason: "STOP",
          index: 0,
        }],
      }));
      return;
    }
    if (provider === "bedrock-converse") {
      emit(encodeBedrockEventStreamMessage("contentBlockDelta", {
        contentBlockIndex: index, delta: { text: notice },
      }));
      emit(encodeBedrockEventStreamMessage("contentBlockStop", { contentBlockIndex: index }));
      emit(encodeBedrockEventStreamMessage("messageStop", { stopReason: "end_turn" }));
      return;
    }
    if (provider === "bedrock-invoke") {
      emit(encodeBedrockInvokeChunk({
        type: "content_block_start", index, content_block: { type: "text", text: "" },
      }));
      emit(encodeBedrockInvokeChunk({
        type: "content_block_delta", index, delta: { type: "text_delta", text: notice },
      }));
      emit(encodeBedrockInvokeChunk({ type: "content_block_stop", index }));
      return;
    }
    // Default: OpenAI / OpenAI-compatible.
    emit(encodeOpenAIDataFrame({
      choices: [{ index: 0, delta: { role: "assistant", content: notice }, finish_reason: null }],
    }));
    emit(encodeOpenAIDataFrame({
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    }));
    emit(OPENAI_DONE_FRAME);
  };

  const onEvent = async (ev: WireEvent): Promise<void> => {
    if (ev.kind === "text-delta" || ev.kind === "passthrough") {
      if (ev.rawFrame.byteLength > 0) emit(ev.rawFrame);
      return;
    }
    if (ev.kind === "tool-call-start") {
      accs.set(ev.index, {
        name: ev.name ?? "",
        args: "",
        bufferedFrames: ev.rawFrame.byteLength > 0 ? [ev.rawFrame] : [],
      });
      inFlight.add(ev.index);
      return;
    }
    if (ev.kind === "tool-call-arguments") {
      const acc = accs.get(ev.index);
      if (!acc) {
        if (ev.rawFrame.byteLength > 0) emit(ev.rawFrame);
        return;
      }
      acc.args += ev.deltaJson;
      if (ev.rawFrame.byteLength > 0) acc.bufferedFrames.push(ev.rawFrame);
      return;
    }
    if (ev.kind === "tool-call-end") {
      // Buffer the closing frame alongside its matching start/arguments so a
      // deny rewrites the entire block atomically.
      const acc = accs.get(ev.index);
      if (acc) {
        if (ev.rawFrame.byteLength > 0) acc.bufferedFrames.push(ev.rawFrame);
        return;
      }
      if (ev.rawFrame.byteLength > 0) emit(ev.rawFrame);
      return;
    }
    if (ev.kind === "finish") {
      let anyDenyFlushed = false;
      for (const idx of inFlight) {
        const acc = accs.get(idx);
        if (!acc) continue;
        const verdict = await safeEvalStream(cfg, acc.name, acc.args);
        if (verdict.decision !== "allow") anyDenyFlushed = true;
        flushTool(idx, acc, verdict);
      }
      inFlight.clear();
      // When flushTool took the deny branch it already emitted a synthetic
      // terminator; re-emitting the upstream raw finish frame after it would
      // leave streaming consumers waiting forever for tool output that will
      // never come. Only emit the raw frame when no deny was flushed.
      if (anyDenyFlushed) {
        syntheticTerminalEmitted = true;
        return;
      }
      if (syntheticTerminalEmitted) return;
      if (ev.rawFrame.byteLength > 0) emit(ev.rawFrame);
    }
  };

  return {
    async feed(chunk: Uint8Array): Promise<void> {
      const events = parser.feed(chunk);
      for (const ev of events) await onEvent(ev);
    },
    async end(): Promise<void> {
      const events = parser.flush();
      for (const ev of events) await onEvent(ev);
      // Resolve any still-buffered tool calls (no finish frame seen).
      for (const idx of inFlight) {
        const acc = accs.get(idx);
        if (!acc) continue;
        const verdict = await safeEvalStream(cfg, acc.name, acc.args);
        flushTool(idx, acc, verdict);
      }
      inFlight.clear();
    },
  };
}

// ── (b) non-streaming (buffered JSON) response enforcement ───────────────────

export interface NonStreamingEnforceResult {
  /** UTF-8 bytes of the (possibly rewritten) response body. */
  body: Uint8Array;
  /** True when at least one tool call was denied and the body was rewritten. */
  rewritten: boolean;
}

/**
 * Buffer-mode response enforcement for non-streaming JSON. Parses the full body,
 * extracts model-emitted tool calls, evaluates each, and on any deny rewrites
 * the body via the provider-shape rewriter (drop/replace the denied tool call +
 * append a notice + normalize finish/stop_reason). Mirrors
 * `node-http-interceptor.ts::wrapJsonResponse` / `fetch-interceptor.ts::
 * wrapNonStreamingResponse`.
 *
 * On unparseable JSON or zero tool calls the original bytes are returned with
 * `rewritten: false` (fail-OPEN on shape-unrecognized — only an actual deny
 * rewrites). The caller is responsible for setting `content-length` on the
 * returned bytes.
 */
export async function enforceNonStreamingBody(
  cfg: ResponseEnforceConfig,
  rawBody: Uint8Array,
): Promise<NonStreamingEnforceResult> {
  const text = new TextDecoder().decode(rawBody);
  let json: Record<string, unknown>;
  try {
    const v = JSON.parse(text);
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      return { body: rawBody, rewritten: false };
    }
    json = v as Record<string, unknown>;
  } catch {
    return { body: rawBody, rewritten: false };
  }

  const calls = extractResponseToolCalls(cfg.match, json);
  if (calls.length === 0) {
    return { body: rawBody, rewritten: false };
  }

  const decisions: ToolCallEvaluation[] = await Promise.all(
    calls.map((c: ResponseToolCall) => evalResponseCall(cfg, c)),
  );
  const denied = decisions.some((d) => d.decision === "deny");
  if (!denied) {
    return { body: rawBody, rewritten: false };
  }

  const rewritten = rewriteResponseBody(cfg.match, json, decisions, calls);
  const out = JSON.stringify(rewritten);
  return { body: new TextEncoder().encode(out), rewritten: true };
}

async function evalResponseCall(
  cfg: ResponseEnforceConfig,
  c: ResponseToolCall,
): Promise<ToolCallEvaluation> {
  try {
    return await cfg.evaluator.evaluateToolCall({ toolName: c.name, arguments: c.args });
  } catch (err) {
    cfg.logger.warn(`[agentum] response-enforce json eval: ${(err as Error).message}`);
    if (cfg.failMode === "deny") {
      return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" };
    }
    return { decision: "allow", ttlMs: 0 };
  }
}

// Re-export so the undici plane can reuse the shared JSON parser if needed.
export { safeJsonParse };
