/**
 * Incremental, byte-level SSE parsers for the Layer-1 fetch interceptor.
 *
 * The object-level parsers in `_parsers.ts` operate on already-decoded
 * provider chunks (the official SDKs do that work for us). When we own the
 * wire — as the fetch interceptor does — we receive raw bytes. These
 * helpers buffer partial frames, decode each `data: {...}\n\n` block, and
 * produce a small typed event stream the interceptor can react to:
 *
 *   - `text-delta`           — pass through downstream immediately
 *   - `tool-call-start`      — begin accumulating arguments for an index
 *   - `tool-call-arguments`  — append a delta JSON fragment
 *   - `tool-call-end`        — terminal frame for a single tool call; the
 *                              interceptor uses this to buffer the closing
 *                              frame alongside its matching start/args,
 *                              so a deny rewrites the entire block atomically
 *   - `finish`               — terminal frame (`finish_reason` / `message_stop`)
 *   - `passthrough`          — unrecognized event; forward bytes as-is
 *
 * The parser is pull-based (`feed(bytes)` yields events synchronously) so
 * the interceptor stays in control of when to splice notices and when to
 * close the downstream stream.
 *
 * One frame can produce zero, one or many WireEvents — Gemini's chunked
 * JSON, for example, can carry both a text part and a functionCall part
 * in the same SSE frame.
 */

export type WireEvent =
  | { kind: "text-delta"; text: string; rawFrame: Uint8Array }
  | { kind: "tool-call-start"; index: number; id?: string; name?: string; rawFrame: Uint8Array }
  | { kind: "tool-call-arguments"; index: number; deltaJson: string; rawFrame: Uint8Array }
  | { kind: "tool-call-end"; index: number; rawFrame: Uint8Array }
  | { kind: "finish"; finishReason?: string; rawFrame: Uint8Array }
  | { kind: "passthrough"; rawFrame: Uint8Array };

const FRAME_DELIM = /\r?\n\r?\n/;
const decoder = new TextDecoder("utf-8", { fatal: false });
const EMPTY_FRAME = new Uint8Array(0);

abstract class StreamParser {
  protected buf = "";
  /** Feed raw bytes; return events parsed from any complete frames. */
  feed(bytes: Uint8Array): WireEvent[] {
    this.buf += decoder.decode(bytes, { stream: true });
    return this.drain(false);
  }
  /** Flush any final pending frame (called once at upstream EOF). */
  flush(): WireEvent[] {
    this.buf += decoder.decode();
    return this.drain(true);
  }

  private drain(final: boolean): WireEvent[] {
    const out: WireEvent[] = [];
    // SSE separates frames by a blank line. Split, leaving the final
    // (possibly partial) chunk in `buf` unless this is a flush.
    let m: RegExpExecArray | null;
    while ((m = FRAME_DELIM.exec(this.buf)) !== null) {
      const raw = this.buf.slice(0, m.index + m[0].length);
      this.buf = this.buf.slice(m.index + m[0].length);
      const evs = this.parseFrame(raw);
      if (evs.length > 0) out.push(...evs);
    }
    if (final && this.buf.length > 0) {
      const evs = this.parseFrame(this.buf);
      this.buf = "";
      if (evs.length > 0) out.push(...evs);
    }
    return out;
  }

  /**
   * Parse one complete SSE frame and emit zero or more wire events.
   * Subclasses return an empty array to indicate the frame had no
   * downstream-actionable content; use a `passthrough` event when the
   * frame should still be forwarded byte-for-byte.
   */
  protected abstract parseFrame(rawFrame: string): WireEvent[];
}

// ── OpenAI SSE ──────────────────────────────────────────────────────────────

export class OpenAISSEParser extends StreamParser {
  protected parseFrame(rawFrame: string): WireEvent[] {
    const rawBytes = new TextEncoder().encode(rawFrame);
    const lines = rawFrame.split(/\r?\n/);
    let dataLine: string | null = null;
    for (const line of lines) {
      if (line.startsWith("data:")) {
        const v = line.slice(5).trim();
        dataLine = dataLine === null ? v : dataLine + v;
      }
    }
    if (dataLine === null) return [{ kind: "passthrough", rawFrame: rawBytes }];
    if (dataLine === "[DONE]") return [{ kind: "finish", rawFrame: rawBytes }];

    let json: Record<string, unknown>;
    try {
      json = JSON.parse(dataLine) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    const choices = json["choices"] as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(choices) || choices.length === 0) {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    const choice = choices[0]!;
    const delta = choice["delta"] as Record<string, unknown> | undefined;
    const finishReason = typeof choice["finish_reason"] === "string"
      ? (choice["finish_reason"] as string)
      : undefined;

    const tcs = delta?.["tool_calls"] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(tcs) && tcs.length > 0) {
      const part = tcs[0]!;
      const idx = typeof part["index"] === "number" ? (part["index"] as number) : 0;
      const fn = part["function"] as Record<string, unknown> | undefined;
      const hasName = typeof fn?.["name"] === "string" && (fn!["name"] as string).length > 0;
      const hasId = typeof part["id"] === "string" && (part["id"] as string).length > 0;
      if (hasName || hasId) {
        const ev: WireEvent = {
          kind: "tool-call-start",
          index: idx,
          rawFrame: rawBytes,
        };
        if (hasId) ev.id = part["id"] as string;
        if (hasName) ev.name = fn!["name"] as string;
        return [ev];
      }
      if (typeof fn?.["arguments"] === "string") {
        return [{
          kind: "tool-call-arguments",
          index: idx,
          deltaJson: fn!["arguments"] as string,
          rawFrame: rawBytes,
        }];
      }
    }

    if (typeof delta?.["content"] === "string" && (delta!["content"] as string).length > 0) {
      return [{
        kind: "text-delta",
        text: delta!["content"] as string,
        rawFrame: rawBytes,
      }];
    }

    if (finishReason) {
      const ev: WireEvent = { kind: "finish", rawFrame: rawBytes };
      ev.finishReason = finishReason;
      return [ev];
    }

    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }
}

// ── Anthropic SSE ───────────────────────────────────────────────────────────

/**
 * The Anthropic parser tracks which `content_block_*` indices opened as
 * `tool_use` blocks so the matching `content_block_stop` can be emitted as
 * `tool-call-end` (and buffered alongside its start/delta frames). Without
 * this, a deny would drop the start/delta frames but leak the `stop` frame,
 * leaving streaming consumers with a half-deleted tool_use block.
 */
/**
 * Map an already-decoded Anthropic stream chunk object to WireEvents. Shared
 * between `AnthropicSSEParser` (SSE framing on top) and
 * `BedrockInvokeStreamParser` (base64 `chunk` events carrying the same chunk
 * objects, decoded from the binary AWS event-stream). `toolUseIndices` tracks
 * which `content_block_*` indices opened as `tool_use` so the matching
 * `content_block_stop` emits `tool-call-end`.
 *
 * `explicitType` lets the SSE parser pass the `event:` name (which Anthropic
 * sets even when the JSON `type` is absent); Bedrock invoke chunks always
 * carry `type` inline so callers can omit it.
 */
export function mapAnthropicChunkObject(
  json: Record<string, unknown>,
  rawBytes: Uint8Array,
  toolUseIndices: Set<number>,
  explicitType?: string | null,
): WireEvent[] {
  const type = (explicitType ?? (json["type"] as string | undefined)) ?? "";

  if (type === "content_block_start") {
    const idx = typeof json["index"] === "number" ? (json["index"] as number) : 0;
    const block = json["content_block"] as Record<string, unknown> | undefined;
    if (block?.["type"] === "tool_use") {
      toolUseIndices.add(idx);
      const ev: WireEvent = {
        kind: "tool-call-start",
        index: idx,
        rawFrame: rawBytes,
      };
      if (typeof block["id"] === "string") ev.id = block["id"] as string;
      if (typeof block["name"] === "string") ev.name = block["name"] as string;
      return [ev];
    }
    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }

  if (type === "content_block_delta") {
    const idx = typeof json["index"] === "number" ? (json["index"] as number) : 0;
    const delta = json["delta"] as Record<string, unknown> | undefined;
    if (delta?.["type"] === "input_json_delta" && typeof delta["partial_json"] === "string") {
      return [{
        kind: "tool-call-arguments",
        index: idx,
        deltaJson: delta["partial_json"] as string,
        rawFrame: rawBytes,
      }];
    }
    if (delta?.["type"] === "text_delta" && typeof delta["text"] === "string") {
      return [{
        kind: "text-delta",
        text: delta["text"] as string,
        rawFrame: rawBytes,
      }];
    }
    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }

  if (type === "content_block_stop") {
    const idx = typeof json["index"] === "number" ? (json["index"] as number) : 0;
    if (toolUseIndices.has(idx)) {
      toolUseIndices.delete(idx);
      return [{ kind: "tool-call-end", index: idx, rawFrame: rawBytes }];
    }
    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }

  if (type === "message_stop" || type === "message_delta") {
    const delta = json["delta"] as Record<string, unknown> | undefined;
    const stop = typeof delta?.["stop_reason"] === "string"
      ? (delta!["stop_reason"] as string)
      : undefined;
    const ev: WireEvent = { kind: type === "message_stop" ? "finish" : "passthrough", rawFrame: rawBytes };
    if (ev.kind === "finish" && stop) ev.finishReason = stop;
    return [ev];
  }

  return [{ kind: "passthrough", rawFrame: rawBytes }];
}

export class AnthropicSSEParser extends StreamParser {
  private toolUseIndices = new Set<number>();

  protected parseFrame(rawFrame: string): WireEvent[] {
    const rawBytes = new TextEncoder().encode(rawFrame);
    const lines = rawFrame.split(/\r?\n/);
    let evtName: string | null = null;
    let dataLine: string | null = null;
    for (const line of lines) {
      if (line.startsWith("event:")) {
        evtName = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        const v = line.slice(5).trim();
        dataLine = dataLine === null ? v : dataLine + v;
      }
    }
    if (!dataLine) return [{ kind: "passthrough", rawFrame: rawBytes }];

    let json: Record<string, unknown>;
    try {
      json = JSON.parse(dataLine) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    return mapAnthropicChunkObject(json, rawBytes, this.toolUseIndices, evtName);
  }
}

// ── Cohere v2 SSE ───────────────────────────────────────────────────────────
//
// Cohere v2 chat stream events (https://docs.cohere.com/v2/docs/streaming):
//
//   event: message-start    { id, delta: { ... } }
//   event: content-start    { index, delta: { message: { content: { type:"text", text:"" } } } }
//   event: content-delta    { index, delta: { message: { content: { text } } } }
//   event: content-end      { index }
//   event: tool-call-start  { index, delta: { message: { tool_calls: { id, type, function: { name, arguments:"" } } } } }
//   event: tool-call-delta  { index, delta: { message: { tool_calls: { function: { arguments } } } } }
//   event: tool-call-end    { index }
//   event: message-end      { delta: { finish_reason: "COMPLETE" | "TOOL_CALL", usage } }
//
// We emit `tool-call-end` so the interceptor can buffer the closing frame
// alongside the start/delta frames — a deny rewrites the entire block.

export class CohereV2SSEParser extends StreamParser {
  protected parseFrame(rawFrame: string): WireEvent[] {
    const rawBytes = new TextEncoder().encode(rawFrame);
    const lines = rawFrame.split(/\r?\n/);
    let evtName: string | null = null;
    let dataLine: string | null = null;
    for (const line of lines) {
      if (line.startsWith("event:")) {
        evtName = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        const v = line.slice(5).trim();
        dataLine = dataLine === null ? v : dataLine + v;
      }
    }
    if (!evtName) return [{ kind: "passthrough", rawFrame: rawBytes }];
    if (!dataLine) return [{ kind: "passthrough", rawFrame: rawBytes }];

    let json: Record<string, unknown>;
    try {
      json = JSON.parse(dataLine) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    const idx = typeof json["index"] === "number" ? (json["index"] as number) : 0;
    const delta = json["delta"] as Record<string, unknown> | undefined;
    const message = delta?.["message"] as Record<string, unknown> | undefined;

    if (evtName === "content-delta") {
      const content = message?.["content"] as Record<string, unknown> | undefined;
      const text = content?.["text"];
      if (typeof text === "string" && text.length > 0) {
        return [{ kind: "text-delta", text, rawFrame: rawBytes }];
      }
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    if (evtName === "tool-call-start") {
      // Cohere v2's wire shape places `tool_calls` as either a single
      // object or a one-element array; tolerate both. The function name
      // arrives in this frame; arguments may be empty here and arrive in
      // subsequent tool-call-delta frames.
      const tcRaw = message?.["tool_calls"];
      const tc = Array.isArray(tcRaw)
        ? (tcRaw[0] as Record<string, unknown> | undefined)
        : (tcRaw as Record<string, unknown> | undefined);
      const fn = tc?.["function"] as Record<string, unknown> | undefined;
      const ev: WireEvent = { kind: "tool-call-start", index: idx, rawFrame: rawBytes };
      if (typeof tc?.["id"] === "string") ev.id = tc["id"] as string;
      if (typeof fn?.["name"] === "string") ev.name = fn["name"] as string;
      // Cohere occasionally carries `arguments: ""` in the start frame; if it
      // arrives non-empty we still want to capture it. Emit a follow-on
      // tool-call-arguments event so the accumulator picks it up.
      const args0 = typeof fn?.["arguments"] === "string" ? (fn["arguments"] as string) : "";
      const out: WireEvent[] = [ev];
      if (args0.length > 0) {
        out.push({
          kind: "tool-call-arguments",
          index: idx,
          deltaJson: args0,
          rawFrame: EMPTY_FRAME,
        });
      }
      return out;
    }

    if (evtName === "tool-call-delta") {
      const tcRaw = message?.["tool_calls"];
      const tc = Array.isArray(tcRaw)
        ? (tcRaw[0] as Record<string, unknown> | undefined)
        : (tcRaw as Record<string, unknown> | undefined);
      const fn = tc?.["function"] as Record<string, unknown> | undefined;
      const args = typeof fn?.["arguments"] === "string" ? (fn["arguments"] as string) : "";
      if (args.length > 0) {
        return [{
          kind: "tool-call-arguments",
          index: idx,
          deltaJson: args,
          rawFrame: rawBytes,
        }];
      }
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    if (evtName === "tool-call-end") {
      return [{ kind: "tool-call-end", index: idx, rawFrame: rawBytes }];
    }

    if (evtName === "message-end") {
      const finishReason = typeof delta?.["finish_reason"] === "string"
        ? (delta!["finish_reason"] as string)
        : undefined;
      const ev: WireEvent = { kind: "finish", rawFrame: rawBytes };
      if (finishReason) ev.finishReason = finishReason;
      return [ev];
    }

    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }
}

// ── Gemini SSE ──────────────────────────────────────────────────────────────
//
// Gemini's streaming SSE (`?alt=sse` on `:generateContent` /
// `:streamGenerateContent`) emits a `data:` frame per partial Candidate.
//
//   data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]},"index":0}]}
//   data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":{...}}}]},"finishReason":"STOP"}]}
//
// Unlike OpenAI/Anthropic/Cohere where tool arguments are streamed across
// many small deltas, Gemini emits each `functionCall` atomically inside a
// single frame. We therefore emit `tool-call-start` and
// `tool-call-arguments` (carrying the full args JSON) from one parseFrame
// call so the accumulator has the complete argument string immediately.
//
// Tool indexing: Gemini's `parts[]` array position is not stable across
// frames (the same call may move). We use a monotonic counter so each
// `functionCall` gets its own stable index across the stream.

export class GeminiSSEParser extends StreamParser {
  private nextToolIndex = 0;

  protected parseFrame(rawFrame: string): WireEvent[] {
    const rawBytes = new TextEncoder().encode(rawFrame);
    const lines = rawFrame.split(/\r?\n/);
    let dataLine: string | null = null;
    for (const line of lines) {
      if (line.startsWith("data:")) {
        const v = line.slice(5).trim();
        dataLine = dataLine === null ? v : dataLine + v;
      }
    }
    if (!dataLine) return [{ kind: "passthrough", rawFrame: rawBytes }];

    let json: Record<string, unknown>;
    try {
      json = JSON.parse(dataLine) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    const candidates = json["candidates"] as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(candidates) || candidates.length === 0) {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    const cand = candidates[0]!;
    const content = cand["content"] as Record<string, unknown> | undefined;
    const parts = content?.["parts"] as Array<Record<string, unknown>> | undefined;
    const finishReason = typeof cand["finishReason"] === "string"
      ? (cand["finishReason"] as string)
      : undefined;

    const out: WireEvent[] = [];
    let emittedAnything = false;
    if (Array.isArray(parts)) {
      for (const p of parts) {
        const fc = p["functionCall"] as Record<string, unknown> | undefined;
        if (fc && typeof fc["name"] === "string") {
          const myIdx = this.nextToolIndex++;
          const start: WireEvent = {
            kind: "tool-call-start",
            index: myIdx,
            rawFrame: rawBytes,
          };
          start.name = fc["name"] as string;
          out.push(start);
          // Carry the full args as one arguments event so the
          // accumulator has a complete JSON string by the time `finish`
          // fires. The raw bytes are attached to `tool-call-start` (so
          // a deny drops them) and we attach an EMPTY_FRAME here
          // because the underlying chunk is already accounted for.
          const args = fc["args"];
          const argsStr = typeof args === "string"
            ? (args as string)
            : JSON.stringify(args ?? {});
          out.push({
            kind: "tool-call-arguments",
            index: myIdx,
            deltaJson: argsStr,
            rawFrame: EMPTY_FRAME,
          });
          out.push({
            kind: "tool-call-end",
            index: myIdx,
            rawFrame: EMPTY_FRAME,
          });
          emittedAnything = true;
          continue;
        }
        const txt = p["text"];
        if (typeof txt === "string" && txt.length > 0) {
          // Text part — emit as text-delta but with EMPTY_FRAME so the
          // raw frame (which carries the whole chunk including potential
          // functionCalls below) is enqueued exactly once via the
          // tool-call-start path or via this fallback at frame end.
          out.push({
            kind: "text-delta",
            text: txt,
            rawFrame: EMPTY_FRAME,
          });
          emittedAnything = true;
        }
      }
    }

    if (!emittedAnything) {
      // No tool / text content extracted — forward verbatim.
      out.push({ kind: "passthrough", rawFrame: rawBytes });
    } else if (out.every((e) => e.rawFrame.byteLength === 0)) {
      // We extracted only EMPTY_FRAME events from this chunk. Forward
      // the original chunk once so allowed text reaches the consumer.
      // (Denied tool calls' rawFrame is dropped by flushToolBuffer; the
      // tool-call-start event carries `rawBytes` for the allow branch.)
      out.unshift({ kind: "passthrough", rawFrame: rawBytes });
    }

    if (finishReason) {
      const ev: WireEvent = { kind: "finish", rawFrame: EMPTY_FRAME };
      ev.finishReason = finishReason;
      out.push(ev);
    }

    return out;
  }
}

/**
 * Build a `data: {...}\n\n` SSE frame for OpenAI-format streams.
 * Used to splice synthetic notice/finish frames after a deny verdict.
 */
export function encodeOpenAIDataFrame(payload: unknown): Uint8Array {
  return new TextEncoder().encode(`data: ${JSON.stringify(payload)}\n\n`);
}

/** Encode an Anthropic-style named SSE frame. */
export function encodeAnthropicEventFrame(name: string, payload: unknown): Uint8Array {
  return new TextEncoder().encode(
    `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`,
  );
}

/**
 * Encode a Cohere v2-style named SSE frame. Cohere uses the same
 * `event:`/`data:` convention as Anthropic but its event names live in a
 * separate namespace (`content-start`, `message-end`, etc.).
 */
export function encodeCohereEventFrame(name: string, payload: unknown): Uint8Array {
  return new TextEncoder().encode(
    `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`,
  );
}

/** Encode a Gemini SSE frame. Identical to OpenAI's `data: ...` envelope. */
export function encodeGeminiDataFrame(payload: unknown): Uint8Array {
  return new TextEncoder().encode(`data: ${JSON.stringify(payload)}\n\n`);
}

export const OPENAI_DONE_FRAME: Uint8Array = new TextEncoder().encode("data: [DONE]\n\n");

// ── AWS Bedrock binary event-stream (application/vnd.amazon.eventstream) ─────
//
// Bedrock streaming responses (`/invoke-with-response-stream`,
// `/converse-stream`) are NOT SSE. Each message is a length-prefixed binary
// frame with CRC32-checked prelude + body (all big-endian):
//
//   [ total_length:4 ][ headers_length:4 ][ prelude_crc:4 = CRC32(bytes 0..8) ]
//   [ headers: { name_len:1, name:utf8, value_type:1, value_len:2, value }* ]
//   [ payload (JSON) ]
//   [ message_crc:4 = CRC32(bytes 0..end-4) ]
//
// Header value types we emit/read: 7 = string. We only decode the headers we
// care about (:message-type, :event-type, :content-type) and tolerate the
// rest. A frame that fails to parse degrades to a single `passthrough`
// WireEvent carrying the raw bytes (same posture as the SSE parsers).
//
// Encode MUST produce correct CRCs — the AWS SDK client hard-errors on a bad
// checksum, so a bad synthetic deny frame would brick the stream. The CRC32
// here is a pure-JS table implementation (edge-safe — no `node:zlib`).

const CRC32_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Encode a Uint8Array to base64 without `Buffer` (edge-safe). */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000; // chunk to avoid call-stack limits on String.fromCharCode
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, i + chunk);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

/** Decode a base64 string to a Uint8Array without `Buffer` (edge-safe). */
function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

interface DecodedEventStreamMessage {
  headers: Record<string, string>;
  payload: Uint8Array;
  /** The complete original message bytes (re-emit verbatim on allow). */
  rawBytes: Uint8Array;
}

/**
 * Decode one complete binary event-stream message starting at `offset`.
 * Returns the decoded message + the byte index just past it, or `null` if
 * there aren't enough buffered bytes for a complete message yet. Throws on a
 * structurally-corrupt frame (caller maps that to a passthrough of the
 * available bytes).
 */
function decodeEventStreamMessageAt(
  buf: Uint8Array,
  offset: number,
): { message: DecodedEventStreamMessage; next: number } | null {
  if (buf.length - offset < 12) return null; // need at least the prelude + crcs
  const view = new DataView(buf.buffer, buf.byteOffset + offset, buf.length - offset);
  const totalLength = view.getUint32(0, false);
  if (totalLength < 16 || totalLength > 16 * 1024 * 1024) {
    throw new Error("event-stream: implausible total_length");
  }
  if (buf.length - offset < totalLength) return null; // message not fully buffered
  const headersLength = view.getUint32(4, false);
  const rawBytes = buf.subarray(offset, offset + totalLength);

  // headers occupy bytes [12, 12 + headersLength)
  const headers: Record<string, string> = {};
  let p = 12;
  const headersEnd = 12 + headersLength;
  const dec = new TextDecoder("utf-8", { fatal: false });
  while (p < headersEnd) {
    const nameLen = view.getUint8(p);
    p += 1;
    const name = dec.decode(rawBytes.subarray(p, p + nameLen));
    p += nameLen;
    const valueType = view.getUint8(p);
    p += 1;
    if (valueType === 7) {
      const valueLen = view.getUint16(p, false);
      p += 2;
      headers[name] = dec.decode(rawBytes.subarray(p, p + valueLen));
      p += valueLen;
    } else {
      // We only round-trip string (7) headers; bail on anything else so we
      // don't mis-parse and corrupt subsequent header offsets.
      throw new Error(`event-stream: unsupported header value type ${valueType}`);
    }
  }

  const payload = rawBytes.subarray(headersEnd, totalLength - 4);
  return {
    message: { headers, payload, rawBytes: rawBytes.slice() },
    next: offset + totalLength,
  };
}

/**
 * Structural twin of the SSE `StreamParser` (`feed`/`flush` returning
 * WireEvents) but operates on the binary event-stream framing.
 */
export interface ByteStreamParser {
  feed(bytes: Uint8Array): WireEvent[];
  flush(): WireEvent[];
}

abstract class EventStreamParserBase implements ByteStreamParser {
  protected acc = new Uint8Array(0);

  feed(bytes: Uint8Array): WireEvent[] {
    if (bytes.byteLength > 0) {
      const merged = new Uint8Array(this.acc.length + bytes.length);
      merged.set(this.acc, 0);
      merged.set(bytes, this.acc.length);
      this.acc = merged;
    }
    return this.drain(false);
  }

  flush(): WireEvent[] {
    return this.drain(true);
  }

  private drain(final: boolean): WireEvent[] {
    const out: WireEvent[] = [];
    let offset = 0;
    for (;;) {
      let decoded: { message: DecodedEventStreamMessage; next: number } | null;
      try {
        decoded = decodeEventStreamMessageAt(this.acc, offset);
      } catch {
        // Corrupt frame: forward whatever bytes remain verbatim and stop.
        const rest = this.acc.subarray(offset);
        if (rest.byteLength > 0) out.push({ kind: "passthrough", rawFrame: rest.slice() });
        this.acc = new Uint8Array(0);
        return out;
      }
      if (!decoded) break; // need more bytes for the next message
      out.push(...this.mapMessage(decoded.message));
      offset = decoded.next;
    }
    // Retain the unconsumed tail for the next feed.
    this.acc = offset > 0 ? this.acc.subarray(offset).slice() : this.acc;
    if (final && this.acc.byteLength > 0) {
      // Trailing partial bytes at EOF — forward verbatim rather than drop.
      out.push({ kind: "passthrough", rawFrame: this.acc.slice() });
      this.acc = new Uint8Array(0);
    }
    return out;
  }

  protected abstract mapMessage(msg: DecodedEventStreamMessage): WireEvent[];
}

/**
 * Bedrock Converse-stream parser. The Converse streaming API emits JSON
 * payloads keyed by the `:event-type` header. Tool calls arrive as a
 * `contentBlockStart` carrying `start.toolUse {toolUseId, name}`, then
 * `contentBlockDelta` frames carrying `delta.toolUse.input` string fragments,
 * then `contentBlockStop`; `messageStop` carries `{stopReason}`.
 */
export class BedrockConverseStreamParser extends EventStreamParserBase {
  private toolUseIndices = new Set<number>();

  protected mapMessage(msg: DecodedEventStreamMessage): WireEvent[] {
    const rawBytes = msg.rawBytes;
    const eventType = msg.headers[":event-type"];
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(new TextDecoder("utf-8", { fatal: false }).decode(msg.payload)) as Record<
        string,
        unknown
      >;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    const blockIndex =
      typeof json["contentBlockIndex"] === "number" ? (json["contentBlockIndex"] as number) : 0;

    if (eventType === "contentBlockStart") {
      const start = json["start"] as Record<string, unknown> | undefined;
      const tu = start?.["toolUse"] as Record<string, unknown> | undefined;
      if (tu && typeof tu["name"] === "string") {
        this.toolUseIndices.add(blockIndex);
        const ev: WireEvent = { kind: "tool-call-start", index: blockIndex, rawFrame: rawBytes };
        if (typeof tu["toolUseId"] === "string") ev.id = tu["toolUseId"] as string;
        ev.name = tu["name"] as string;
        return [ev];
      }
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    if (eventType === "contentBlockDelta") {
      const delta = json["delta"] as Record<string, unknown> | undefined;
      const tu = delta?.["toolUse"] as Record<string, unknown> | undefined;
      if (tu && typeof tu["input"] === "string") {
        return [
          {
            kind: "tool-call-arguments",
            index: blockIndex,
            deltaJson: tu["input"] as string,
            rawFrame: rawBytes,
          },
        ];
      }
      if (typeof delta?.["text"] === "string") {
        return [{ kind: "text-delta", text: delta["text"] as string, rawFrame: rawBytes }];
      }
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    if (eventType === "contentBlockStop") {
      if (this.toolUseIndices.has(blockIndex)) {
        this.toolUseIndices.delete(blockIndex);
        return [{ kind: "tool-call-end", index: blockIndex, rawFrame: rawBytes }];
      }
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }

    if (eventType === "messageStop") {
      const ev: WireEvent = { kind: "finish", rawFrame: rawBytes };
      if (typeof json["stopReason"] === "string") ev.finishReason = json["stopReason"] as string;
      return [ev];
    }

    // messageStart, metadata, anything else.
    return [{ kind: "passthrough", rawFrame: rawBytes }];
  }
}

/**
 * Bedrock InvokeModel-with-response-stream parser for anthropic-on-bedrock.
 * Each `:event-type: chunk` payload is `{"bytes":"<base64>"}` where the
 * decoded bytes are exactly an Anthropic stream event JSON object. We feed
 * those decoded chunk objects into the shared `mapAnthropicChunkObject` so the
 * mapping matches `AnthropicSSEParser` exactly. Non-anthropic chunks (no
 * recognisable `type`) degrade to passthrough.
 */
export class BedrockInvokeStreamParser extends EventStreamParserBase {
  private toolUseIndices = new Set<number>();

  protected mapMessage(msg: DecodedEventStreamMessage): WireEvent[] {
    const rawBytes = msg.rawBytes;
    const eventType = msg.headers[":event-type"];
    if (eventType !== "chunk") {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    let envelope: Record<string, unknown>;
    try {
      envelope = JSON.parse(
        new TextDecoder("utf-8", { fatal: false }).decode(msg.payload),
      ) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    const b64 = envelope["bytes"];
    if (typeof b64 !== "string") return [{ kind: "passthrough", rawFrame: rawBytes }];
    let chunkObj: Record<string, unknown>;
    try {
      chunkObj = JSON.parse(
        new TextDecoder("utf-8", { fatal: false }).decode(base64ToBytes(b64)),
      ) as Record<string, unknown>;
    } catch {
      return [{ kind: "passthrough", rawFrame: rawBytes }];
    }
    return mapAnthropicChunkObject(chunkObj, rawBytes, this.toolUseIndices);
  }
}

/**
 * Encode a binary AWS event-stream message with `:message-type=event`,
 * `:event-type=<eventType>`, `:content-type=application/json` headers and a
 * JSON payload. Computes correct prelude + message CRC32s (the AWS SDK
 * validates them).
 */
export function encodeBedrockEventStreamMessage(eventType: string, payload: unknown): Uint8Array {
  const enc = new TextEncoder();
  const headerEntries: Array<[string, string]> = [
    [":message-type", "event"],
    [":event-type", eventType],
    [":content-type", "application/json"],
  ];

  // Serialize headers: { name_len:1, name, value_type:1=7(string), value_len:2, value }
  const headerParts: Uint8Array[] = [];
  for (const [name, value] of headerEntries) {
    const nameBytes = enc.encode(name);
    const valueBytes = enc.encode(value);
    const part = new Uint8Array(1 + nameBytes.length + 1 + 2 + valueBytes.length);
    const dv = new DataView(part.buffer);
    let o = 0;
    dv.setUint8(o, nameBytes.length);
    o += 1;
    part.set(nameBytes, o);
    o += nameBytes.length;
    dv.setUint8(o, 7); // string
    o += 1;
    dv.setUint16(o, valueBytes.length, false);
    o += 2;
    part.set(valueBytes, o);
    headerParts.push(part);
  }
  const headersLength = headerParts.reduce((n, h) => n + h.length, 0);

  const payloadBytes = enc.encode(JSON.stringify(payload));
  const totalLength = 4 + 4 + 4 + headersLength + payloadBytes.length + 4;

  const out = new Uint8Array(totalLength);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, totalLength, false);
  dv.setUint32(4, headersLength, false);
  // prelude_crc = CRC32(bytes 0..8)
  dv.setUint32(8, crc32(out.subarray(0, 8)), false);
  let off = 12;
  for (const h of headerParts) {
    out.set(h, off);
    off += h.length;
  }
  out.set(payloadBytes, off);
  off += payloadBytes.length;
  // message_crc = CRC32(bytes 0..end-4)
  dv.setUint32(off, crc32(out.subarray(0, off)), false);
  return out;
}

/**
 * Encode a Bedrock InvokeModel-with-response-stream `chunk` message wrapping an
 * Anthropic stream-event payload (base64 under `{ bytes }`).
 */
export function encodeBedrockInvokeChunk(payload: unknown): Uint8Array {
  const inner = new TextEncoder().encode(JSON.stringify(payload));
  return encodeBedrockEventStreamMessage("chunk", { bytes: bytesToBase64(inner) });
}
