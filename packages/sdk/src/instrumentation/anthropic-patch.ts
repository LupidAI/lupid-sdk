/**
 * Auto-monkeypatch for `@anthropic-ai/sdk`.
 *
 * Patch site: `Messages.prototype.create`. Like the OpenAI patch we
 * locate the prototype both via the static export tree (`Anthropic.Messages`
 * on some builds) and via a probe instance, so the patch survives minor
 * version churn.
 *
 * Streaming wire format (named SSE events):
 *   message_start
 *   content_block_start  { content_block: { type: "tool_use", id, name, input } }
 *   content_block_delta  { delta: { type: "input_json_delta", partial_json } }
 *   content_block_stop
 *   message_delta        { delta: { stop_reason: "tool_use" | "end_turn" } }
 *   message_stop
 *
 * The official SDK exposes these events as already-parsed objects on the
 * async iterator returned by `messages.create({ stream: true })` (and on
 * `messages.stream(...).iterator`); we don't need to parse SSE bytes.
 */

import {
  newAnthropicStreamState,
  ingestAnthropicEvent,
  extractAnthropicToolUses,
  makeBlockNoticeText,
} from "./_parsers.js";
import type { CedarToolCallClient, ToolCallEvaluation } from "../evaluation/cedar-client.js";
import { loadOptional } from "./_optional.js";
import { warnHitlUnsupportedOnce } from "./hitl-unsupported.js";

const PATCHED = Symbol.for("agentum.anthropic.patched");
const ORIGINAL = Symbol.for("agentum.anthropic.original");
const EVALUATOR_REF = Symbol.for("agentum.anthropic.evaluator");

interface PatchableMessagesProto {
  create: (...args: unknown[]) => Promise<unknown>;
  [PATCHED]?: boolean;
  [ORIGINAL]?: (...args: unknown[]) => Promise<unknown>;
  [EVALUATOR_REF]?: () => CedarToolCallClient | undefined;
}

export async function installAnthropicPatch(
  getEvaluator: () => CedarToolCallClient | undefined,
): Promise<boolean> {
  let mod: unknown;
  try {
    mod = await loadOptional("@anthropic-ai/sdk");
  } catch {
    return false;
  }
  if (!mod) return false;

  const located = locateMessagesPrototype(mod);
  if (!located) return false;
  const { proto, ctor } = located;

  const target = proto as PatchableMessagesProto;
  if (target[PATCHED]) {
    target[EVALUATOR_REF] = getEvaluator;
    return true;
  }

  const original = target.create;
  if (typeof original !== "function") return false;
  target[ORIGINAL] = original;
  target[EVALUATOR_REF] = getEvaluator;

  const patched = async function (
    this: unknown,
    ...args: unknown[]
  ): Promise<unknown> {
    const evaluator = target[EVALUATOR_REF]?.();
    if (!evaluator) return original.apply(this, args);
    const req = (args[0] ?? {}) as Record<string, unknown>;
    const isStream = Boolean(req["stream"]);
    if (!isStream) {
      const resp = await original.apply(this, args) as Record<string, unknown>;
      return enforceNonStreamingAnthropic(resp, evaluator);
    }
    const stream = await original.apply(this, args);
    return wrapAnthropicStream(
      stream as AsyncIterable<Record<string, unknown>>,
      evaluator,
    );
  };
  Object.defineProperty(patched, "name", { value: "create" });

  target.create = patched;
  target[PATCHED] = true;

  // Post-flight verification: confirm the patched `create` is the one a
  // freshly constructed instance method-resolves through. If a constructor
  // is available, build a probe and assert `probe.messages.create === patched`
  // (the patch sits on the prototype the instance actually uses). If the
  // marker did not stick — e.g. a build where the static export tree and the
  // instance chain diverge and we patched the wrong object — roll the patch
  // back and report failure rather than a false success.
  if (ctor && !verifyPatchReachable(ctor, patched)) {
    target.create = original;
    delete target[PATCHED];
    delete target[ORIGINAL];
    delete target[EVALUATOR_REF];
    return false;
  }

  return true;
}

/**
 * Construct a fresh probe instance and confirm that the function reachable
 * via `probe.messages.create` is the patched function we installed. Returns
 * `false` (do not claim success) if the instance resolves a different
 * function, or if probe construction throws (in which case we cannot prove
 * reachability and refuse to report success on an unverifiable patch).
 */
function verifyPatchReachable(
  ctor: new (...a: unknown[]) => unknown,
  patched: (...args: unknown[]) => Promise<unknown>,
): boolean {
  try {
    const probe = new ctor({ apiKey: "agentum-patch-verify" }) as Record<string, unknown>;
    const messages = probe["messages"];
    if (!messages || typeof messages !== "object") return false;
    return (messages as Record<string, unknown>)["create"] === patched;
  } catch {
    return false;
  }
}

export async function uninstallAnthropicPatch(): Promise<void> {
  let mod: unknown;
  try { mod = await loadOptional("@anthropic-ai/sdk"); } catch { return; }
  if (!mod) return;
  const located = locateMessagesPrototype(mod);
  if (!located) return;
  const target = located.proto as PatchableMessagesProto;
  const original = target[ORIGINAL];
  if (target[PATCHED] && typeof original === "function") {
    target.create = original;
    delete target[PATCHED];
    delete target[ORIGINAL];
    delete target[EVALUATOR_REF];
  }
}

interface LocatedMessagesProto {
  /** The prototype object that owns the `create` method we patch. */
  proto: object;
  /**
   * The Anthropic constructor, when discoverable, so the installer can build
   * a probe instance and verify the patch is reachable from the live
   * instance method-resolution path.
   */
  ctor?: new (...a: unknown[]) => unknown;
}

/**
 * Locate the prototype object whose **own** `create` property is the method a
 * freshly constructed `new Anthropic().messages` instance resolves through.
 *
 * Newer `@anthropic-ai/sdk` builds (≥0.30, incl. 0.73.x) restructured the
 * resource classes so that the static export tree (`Anthropic.Messages`) and
 * the prototype the live instance method-resolves through no longer coincide,
 * and `create` may live further up the chain than the immediate prototype.
 * Patching a statically-guessed prototype stamps the marker on an object the
 * instance never touches — the patch is dead while reporting success (G18b).
 *
 * The instance-walk below is strictly more general than the old static path:
 * it constructs a probe, then walks `Object.getPrototypeOf(...)` up the live
 * `messages` chain until it finds the object with an **own** `create`
 * descriptor, and patches THAT object. We fall back to the static export
 * candidates only when probe construction is impossible (constructor throws).
 */
function locateMessagesPrototype(mod: unknown): LocatedMessagesProto | null {
  const m = mod as Record<string, unknown>;
  const Ctor = (m["default"] ?? m["Anthropic"]) as
    | (new (...a: unknown[]) => unknown)
    | undefined;

  // Preferred path: walk the live instance chain to the own-`create` owner.
  if (Ctor) {
    try {
      const inst = new Ctor({ apiKey: "agentum-patch-probe" }) as Record<string, unknown>;
      const messages = inst["messages"];
      if (messages && typeof messages === "object") {
        const owner = findOwnCreateOwner(messages as object);
        if (owner) return { proto: owner, ctor: Ctor };
      }
    } catch {
      // Constructor validated env or otherwise threw — fall through to the
      // static export candidates below and warn (return without ctor so the
      // installer skips probe verification it cannot run).
    }
  }

  // Fallback: static export tree (older builds the instance-walk can't reach
  // because the constructor refused to build). Use own-`create` resolution
  // here too so we never latch onto an inherited method on the wrong object.
  const staticCandidates: unknown[] = [];
  if (Ctor) {
    const staticMessages = (Ctor as unknown as Record<string, unknown>)["Messages"];
    if (staticMessages && typeof staticMessages === "function") {
      staticCandidates.push((staticMessages as { prototype?: unknown }).prototype);
    }
  }
  if (m["Messages"]) {
    staticCandidates.push((m["Messages"] as { prototype?: unknown }).prototype);
  }
  for (const cand of staticCandidates) {
    if (cand && typeof cand === "object") {
      const owner = findOwnCreateOwner(cand as object);
      if (owner) return Ctor ? { proto: owner, ctor: Ctor } : { proto: owner };
    }
  }
  return null;
}

/**
 * Walk an object's prototype chain (starting at the object itself) and return
 * the first object that has an **own** `create` property which is a function.
 * Using `getOwnPropertyDescriptor` (not `typeof obj.create`) is what makes
 * this correct: we patch the exact object the method lives on, not a
 * descendant that merely inherits it.
 */
function findOwnCreateOwner(start: object): object | null {
  let cur: object | null = start;
  // Bound the walk defensively; the resource chain is shallow in practice.
  for (let depth = 0; cur && depth < 16; depth++) {
    const desc = Object.getOwnPropertyDescriptor(cur, "create");
    if (desc && typeof desc.value === "function") return cur;
    cur = Object.getPrototypeOf(cur);
  }
  return null;
}

// ── enforcement ──────────────────────────────────────────────────────────────

async function enforceNonStreamingAnthropic(
  resp: Record<string, unknown>,
  evaluator: CedarToolCallClient,
): Promise<Record<string, unknown>> {
  const tools = extractAnthropicToolUses(resp);
  if (tools.length === 0) return resp;

  const decisions = await Promise.all(
    tools.map((t) => evaluator.evaluateToolCall({
      toolName:  t.name,
      arguments: t.input,
    })),
  );

  const content = resp["content"] as Array<Record<string, unknown>>;
  let mutated = false;
  // Walk in reverse so splicing doesn't invalidate stored indices.
  for (let i = tools.length - 1; i >= 0; i--) {
    const d = decisions[i]!;
    if (d.decision === "deny") {
      // HITL-8: require_hitl deny has no session to suspend here; warn once.
      warnHitlUnsupportedOnce("anthropic", d);
      mutated = true;
      const t = tools[i]!;
      const notice = makeBlockNoticeText(
        t.name,
        safeStringify(t.input),
        d.reason,
      );
      content.splice(t.index, 1, { type: "text", text: notice });
    }
  }
  if (mutated) {
    // If no tool_use blocks remain, downgrade stop_reason for cleanliness.
    const stillHasTool = content.some((b) => b["type"] === "tool_use");
    if (!stillHasTool && resp["stop_reason"] === "tool_use") {
      resp["stop_reason"] = "end_turn";
    }
  }
  return resp;
}

interface BufferedEvent {
  evt: Record<string, unknown>;
  blockIndex?: number;
}

export function wrapAnthropicStream(
  source: AsyncIterable<Record<string, unknown>>,
  evaluator: CedarToolCallClient,
): AsyncIterable<Record<string, unknown>> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<Record<string, unknown>> {
      const state = newAnthropicStreamState();
      // We buffer ALL events tied to tool_use blocks until we know the
      // verdict; non-tool_use blocks (text deltas) pass through live.
      const buffered: BufferedEvent[] = [];
      const toolBlockIndices = new Set<number>();
      // Mirrors the gateway's `rewrote_tool_use_to_text` flag
      // (`crates/agentum-llm-filter/src/sse.rs:463`). Latches to true the
      // first time ANY tool_use block is replaced with a text-notice triplet.
      // Once latched, the trailing `message_delta` event has its
      // `delta.stop_reason` rewritten from `"tool_use"` → `"end_turn"` so
      // strict-parsing clients (Claude Code, MCP) don't see a `tool_use`
      // stop reason without a corresponding tool_use content block. Note:
      // the gateway sets this flag whenever ANY tool_use block is replaced,
      // with no `stillHasTool` guard — partial-deny streams therefore also
      // emit `end_turn`. We mirror that exactly for two-plane parity.
      let rewroteToolUseToText = false;

      for await (const evt of source) {
        ingestAnthropicEvent(state, evt);

        const type = evt["type"] as string | undefined;
        const idx  = typeof evt["index"] === "number" ? (evt["index"] as number) : undefined;

        if (type === "content_block_start" && idx !== undefined) {
          const block = evt["content_block"] as Record<string, unknown> | undefined;
          if (block?.["type"] === "tool_use") {
            toolBlockIndices.add(idx);
            buffered.push({ evt, blockIndex: idx });
            continue;
          }
        }

        if ((type === "content_block_delta" || type === "content_block_stop") &&
            idx !== undefined && toolBlockIndices.has(idx)) {
          buffered.push({ evt, blockIndex: idx });
          continue;
        }

        if (type === "message_delta" || type === "message_stop") {
          // Hold trailing message-level events until tool verdicts settle.
          buffered.push({ evt });
          continue;
        }

        // Text blocks / message_start pass through live.
        yield evt;
      }

      if (toolBlockIndices.size === 0) {
        for (const b of buffered) yield b.evt;
        return;
      }

      // Resolve verdicts.
      const indices = [...state.toolUses.keys()];
      const decisions = await Promise.all(
        indices.map((i) => {
          const acc = state.toolUses.get(i)!;
          let parsed: unknown = {};
          try { parsed = acc.partialJson ? JSON.parse(acc.partialJson) : {}; }
          catch { parsed = { _raw: acc.partialJson }; }
          return evaluator.evaluateToolCall({ toolName: acc.name, arguments: parsed });
        }),
      );
      const denyByIndex = new Map<number, ToolCallEvaluation>();
      indices.forEach((i, k) => {
        const d = decisions[k]!;
        if (d.decision === "deny") {
          // HITL-8: warn once on a require_hitl deny; deny still stands.
          warnHitlUnsupportedOnce("anthropic", d);
          denyByIndex.set(i, d);
        }
      });

      // Emit buffered events: replace denied blocks with a notice triplet.
      const handledDenials = new Set<number>();
      for (const b of buffered) {
        if (b.blockIndex !== undefined && denyByIndex.has(b.blockIndex)) {
          if (handledDenials.has(b.blockIndex)) continue; // skip rest of denied block
          const decision = denyByIndex.get(b.blockIndex)!;
          const acc = state.toolUses.get(b.blockIndex)!;
          const notice = makeBlockNoticeText(
            acc.name,
            acc.partialJson,
            decision.reason,
          );
          // Synthetic notice triplet at the same index — matches the
          // gateway's `make_block_notice_sse` shape.
          yield {
            type: "content_block_start",
            index: b.blockIndex,
            content_block: { type: "text", text: "" },
          };
          yield {
            type: "content_block_delta",
            index: b.blockIndex,
            delta: { type: "text_delta", text: notice },
          };
          yield {
            type: "content_block_stop",
            index: b.blockIndex,
          };
          handledDenials.add(b.blockIndex);
          rewroteToolUseToText = true;
          continue;
        }
        const evt = b.evt;
        if (rewroteToolUseToText && evt["type"] === "message_delta") {
          yield rewriteMessageDeltaStopReason(evt);
        } else {
          yield evt;
        }
      }
    },
  };
}

/**
 * Mirrors the gateway's `message_delta` rewrite at
 * `crates/agentum-llm-filter/src/sse.rs:486-500`. When we have replaced any
 * tool_use block in this stream with a text notice, the upstream
 * `message_delta` still carries `delta.stop_reason: "tool_use"` — strict
 * clients then see a tool_use stop reason with no surviving tool_use content
 * block and either error ("tool call could not be parsed") or retry in ways
 * that can bypass the deny. Rewrite to `"end_turn"` so the response reads as
 * a normal text turn.
 *
 * Defensive: on any unexpected shape (missing/non-object delta, non-tool_use
 * stop_reason, non-string stop_reason), the original event is returned
 * unchanged. Mirrors the `if let Ok(...)` chain in the gateway — fail-OPEN
 * on unknown shapes, never throw.
 */
function rewriteMessageDeltaStopReason(
  evt: Record<string, unknown>,
): Record<string, unknown> {
  const delta = evt["delta"];
  if (!delta || typeof delta !== "object") return evt;
  const d = delta as Record<string, unknown>;
  if (d["stop_reason"] !== "tool_use") return evt;
  return { ...evt, delta: { ...d, stop_reason: "end_turn" } };
}

function safeStringify(v: unknown): string {
  try { return typeof v === "string" ? v : JSON.stringify(v ?? {}); }
  catch { return String(v); }
}
