/**
 * Auto-monkeypatch for the official `openai` v4+ SDK.
 *
 * Strategy: in v4 the `openai` package exports a `Completions` class; an
 * `OpenAI` instance has a `chat.completions` getter that returns a fresh
 * `Completions` resource. We patch `Completions.prototype.create` so every
 * existing AND future `OpenAI` instance is covered without per-instance
 * wrapping. This is exactly the pattern OpenTelemetry's instrumentation
 * uses.
 *
 * The patch is idempotent: a tag symbol is set on the patched function so
 * repeat `init()` calls are no-ops, and the original is preserved on the
 * symbol for clean uninstall in tests.
 */

import {
  newOpenAIStreamState,
  ingestOpenAIChunk,
  extractOpenAIToolCalls,
  makeBlockNoticeText,
  type OpenAIStreamState,
} from "./_parsers.js";
import type { CedarToolCallClient, ToolCallEvaluation } from "../evaluation/cedar-client.js";
import { loadOptional } from "./_optional.js";
import { warnHitlUnsupportedOnce } from "./hitl-unsupported.js";

const PATCHED = Symbol.for("agentum.openai.patched");
const ORIGINAL = Symbol.for("agentum.openai.original");
const EVALUATOR_REF = Symbol.for("agentum.openai.evaluator");

interface PatchableCompletionsProto {
  create: (...args: unknown[]) => Promise<unknown>;
  [PATCHED]?: boolean;
  [ORIGINAL]?: (...args: unknown[]) => Promise<unknown>;
  [EVALUATOR_REF]?: () => CedarToolCallClient | undefined;
}

/**
 * Try to load the customer's installed `openai` package and patch its
 * `Completions.prototype.create`. Returns `true` if the patch was applied
 * (or was already applied), `false` if `openai` is not installed.
 *
 * `getEvaluator` is a thunk so the patch site can pick up the live
 * evaluator after `agentum.init()` finishes; calls before init resolve to
 * `undefined` and pass through unchanged (fail-open by design — we don't
 * want to break apps whose patch fired before init for any reason).
 */
export async function installOpenAIPatch(
  getEvaluator: () => CedarToolCallClient | undefined,
): Promise<boolean> {
  let mod: unknown;
  try {
    // Indirect dynamic import keeps `openai` an optional peer dep AND
    // hides the literal specifier from TypeScript so its absence at
    // typecheck time isn't a hard error.
    mod = await loadOptional("openai");
  } catch {
    return false;
  }
  if (!mod) return false;

  const located = locateCompletionsPrototype(mod);
  if (!located) return false;
  const { proto, ctor } = located;

  const target = proto as PatchableCompletionsProto;
  if (target[PATCHED]) {
    // Already patched in this process — refresh the evaluator thunk.
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
    if (!evaluator) {
      // Init hasn't finished — fall through unchanged.
      return original.apply(this, args);
    }
    const req = (args[0] ?? {}) as Record<string, unknown>;
    const isStream = Boolean(req["stream"]);

    if (!isStream) {
      const resp = await original.apply(this, args) as Record<string, unknown>;
      const reqModel = typeof req["model"] === "string" ? (req["model"] as string) : undefined;
      return enforceNonStreamingOpenAI(resp, evaluator, reqModel);
    }

    const stream = await original.apply(this, args);
    return wrapOpenAIStream(
      stream as AsyncIterable<Record<string, unknown>>,
      evaluator,
    );
  };
  Object.defineProperty(patched, "name", { value: "create" });
  (patched as PatchableCompletionsProto["create"] & { [k: symbol]: unknown })[PATCHED] = true;

  target.create = patched;
  target[PATCHED] = true;

  // Post-flight verification: confirm the patched `create` is the one a
  // freshly constructed `new OpenAI().chat.completions` resolves through.
  // Same SDK-restructuring class of bug as the Anthropic patch (G18b/G19) —
  // if the static export tree and the live instance chain diverge and we
  // patched the wrong object, roll back and report failure rather than a
  // false success.
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
 * via `probe.chat.completions.create` is the patched function we installed.
 * Returns `false` (do not claim success) if the instance resolves a different
 * function, or if probe construction throws (an unverifiable patch must not
 * report success).
 */
function verifyPatchReachable(
  ctor: new (...a: unknown[]) => unknown,
  patched: (...args: unknown[]) => Promise<unknown>,
): boolean {
  try {
    const probe = new ctor({ apiKey: "agentum-patch-verify" }) as Record<string, unknown>;
    const chat = probe["chat"] as Record<string, unknown> | undefined;
    const comps = chat?.["completions"];
    if (!comps || typeof comps !== "object") return false;
    return (comps as Record<string, unknown>)["create"] === patched;
  } catch {
    return false;
  }
}

/** Test-only: undo a previously applied patch. */
export async function uninstallOpenAIPatch(): Promise<void> {
  let mod: unknown;
  try { mod = await loadOptional("openai"); } catch { return; }
  if (!mod) return;
  const located = locateCompletionsPrototype(mod);
  if (!located) return;
  const target = located.proto as PatchableCompletionsProto;
  const original = target[ORIGINAL];
  if (target[PATCHED] && typeof original === "function") {
    target.create = original;
    delete target[PATCHED];
    delete target[ORIGINAL];
    delete target[EVALUATOR_REF];
  }
}

interface LocatedCompletionsProto {
  /** The prototype object that owns the `create` method we patch. */
  proto: object;
  /**
   * The OpenAI constructor, when discoverable, so the installer can build a
   * probe instance and verify the patch is reachable from the live instance
   * method-resolution path.
   */
  ctor?: new (...a: unknown[]) => unknown;
}

/**
 * Find the prototype object whose **own** `create` property is the method a
 * freshly constructed `new OpenAI().chat.completions` resolves through.
 *
 * Like the Anthropic patch (G18b/G19), newer `openai` builds restructure the
 * resource classes so the static export tree (`OpenAI.Chat.Completions`) and
 * the prototype the live instance method-resolves through can diverge, and
 * `create` may live further up the chain than the immediate prototype.
 * Patching a statically-guessed prototype stamps the marker on an object the
 * instance never touches — the patch reports success but is dead.
 *
 * We construct a probe and walk `Object.getPrototypeOf(...)` up the live
 * `chat.completions` chain to the object with an **own** `create` descriptor
 * (strictly more general than the old static path), falling back to the
 * static export candidates only when the constructor refuses to build.
 */
function locateCompletionsPrototype(mod: unknown): LocatedCompletionsProto | null {
  const m = mod as Record<string, unknown>;
  const OpenAICtor = (m["default"] ?? m["OpenAI"]) as
    | (new (...a: unknown[]) => unknown)
    | undefined;

  // Preferred path: walk the live instance chain to the own-`create` owner.
  if (OpenAICtor) {
    try {
      const inst = new OpenAICtor({ apiKey: "agentum-patch-probe" }) as Record<string, unknown>;
      const chat = inst["chat"] as Record<string, unknown> | undefined;
      const comps = chat?.["completions"];
      if (comps && typeof comps === "object") {
        const owner = findOwnCreateOwner(comps as object);
        if (owner) return { proto: owner, ctor: OpenAICtor };
      }
    } catch {
      // Some bundlers / minor versions throw without an apiKey env var —
      // fall through to the static export candidates below.
    }
  }

  // Fallback: static export tree, own-`create` resolved so we never latch
  // onto an inherited method on the wrong object.
  const staticCandidates: unknown[] = [];
  if (OpenAICtor) {
    const staticChat = (OpenAICtor as unknown as Record<string, unknown>)["Chat"];
    if (staticChat && typeof staticChat === "object") {
      const sc = staticChat as Record<string, unknown>;
      if (sc["Completions"]) {
        staticCandidates.push((sc["Completions"] as { prototype?: unknown }).prototype);
      }
    }
  }
  if (m["Completions"]) {
    staticCandidates.push((m["Completions"] as { prototype?: unknown }).prototype);
  }
  for (const cand of staticCandidates) {
    if (cand && typeof cand === "object") {
      const owner = findOwnCreateOwner(cand as object);
      if (owner) return OpenAICtor ? { proto: owner, ctor: OpenAICtor } : { proto: owner };
    }
  }
  return null;
}

/**
 * Walk an object's prototype chain (starting at the object itself) and return
 * the first object that has an **own** `create` property which is a function.
 * Using `getOwnPropertyDescriptor` (not `typeof obj.create`) patches the exact
 * object the method lives on, not a descendant that merely inherits it.
 */
function findOwnCreateOwner(start: object): object | null {
  let cur: object | null = start;
  for (let depth = 0; cur && depth < 16; depth++) {
    const desc = Object.getOwnPropertyDescriptor(cur, "create");
    if (desc && typeof desc.value === "function") return cur;
    cur = Object.getPrototypeOf(cur);
  }
  return null;
}

// ── enforcement ──────────────────────────────────────────────────────────────

/**
 * Evaluate every tool_call in a non-streaming response and rewrite the
 * response so denied calls are dropped and replaced with a human-readable
 * assistant text message — same UX as the gateway's deny path.
 */
async function enforceNonStreamingOpenAI(
  resp: Record<string, unknown>,
  evaluator: CedarToolCallClient,
  requestModel?: string,
): Promise<Record<string, unknown>> {
  const toolCalls = extractOpenAIToolCalls(resp);
  if (toolCalls.length === 0) {
    // Emit a post-flight audit event for plain-text completions.
    // Fire-and-forget: the response is returned unmodified regardless of
    // whether the audit write succeeds.
    emitPlaintextAuditBestEffort(resp, evaluator, requestModel);
    return resp;
  }

  const decisions = await Promise.all(
    toolCalls.map((tc) =>
      evaluator.evaluateToolCall({
        toolName:  tc.function.name,
        arguments: safeJsonParse(tc.function.arguments),
      }),
    ),
  );

  let mutated = false;
  const noticeChunks: string[] = [];
  const choices = resp["choices"] as Array<Record<string, unknown>>;
  const message = choices[0]!["message"] as Record<string, unknown>;
  const remaining = (message["tool_calls"] as Array<Record<string, unknown>>).filter(
    (tc, i) => {
      const d = decisions[i]!;
      if (d.decision === "deny") {
        // HITL-8: a require_hitl deny has no session to suspend on this plane.
        // Warn once, then stand by the fail-CLOSED deny (no LLM re-invoke).
        warnHitlUnsupportedOnce("openai", d);
        mutated = true;
        const fn = (tc["function"] as Record<string, unknown>) ?? {};
        noticeChunks.push(
          makeBlockNoticeText(
            String(fn["name"] ?? ""),
            String(fn["arguments"] ?? ""),
            d.reason,
          ),
        );
        return false;
      }
      return true;
    },
  );

  if (!mutated) return resp;

  if (remaining.length > 0) {
    message["tool_calls"] = remaining;
  } else {
    delete message["tool_calls"];
    choices[0]!["finish_reason"] = "stop";
  }
  const existingContent = typeof message["content"] === "string"
    ? (message["content"] as string)
    : "";
  message["content"] = [existingContent, ...noticeChunks].filter(Boolean).join("\n");
  return resp;
}

/**
 * Wrap an OpenAI streaming response so chunks are buffered until the run
 * finishes its tool_calls phase, then evaluated. On allow we replay the
 * buffered chunks unchanged. On deny we replay only the non-tool-call
 * chunks and append a synthetic content chunk with the block notice.
 *
 * NOTE: This intentionally buffers. OpenAI tool_calls finish on
 * `finish_reason: "tool_calls"`, which only arrives in the final chunk —
 * any earlier emission would risk leaking arguments before the policy
 * verdict is known. The buffered window is bounded by tool-call latency,
 * not by total response length, because a tool-call run produces no text
 * output.
 */
function wrapOpenAIStream(
  source: AsyncIterable<Record<string, unknown>>,
  evaluator: CedarToolCallClient,
): AsyncIterable<Record<string, unknown>> {
  return {
    async *[Symbol.asyncIterator](): AsyncGenerator<Record<string, unknown>> {
      const state: OpenAIStreamState = newOpenAIStreamState();
      const buffered: Array<Record<string, unknown>> = [];
      let hasToolCalls = false;

      for await (const chunk of source) {
        ingestOpenAIChunk(state, chunk);
        if (state.toolCalls.size > 0) hasToolCalls = true;
        if (hasToolCalls || state.finishReason === undefined) {
          buffered.push(chunk);
          if (state.finishReason === "tool_calls") break;
          continue;
        }
        // Plain text completion — pass through immediately.
        yield chunk;
      }

      if (!hasToolCalls) {
        for (const c of buffered) yield c;
        return;
      }

      // Evaluate every aggregated tool call.
      const entries = [...state.toolCalls.entries()];
      const decisions = await Promise.all(
        entries.map(([, tc]) =>
          evaluator.evaluateToolCall({
            toolName:  tc.function.name,
            arguments: safeJsonParse(tc.function.arguments),
          }),
        ),
      );
      const denyByIndex = new Map<number, ToolCallEvaluation>();
      entries.forEach(([idx, _], i) => {
        const d = decisions[i]!;
        if (d.decision === "deny") {
          // HITL-8: warn once on a require_hitl deny; the deny still stands.
          warnHitlUnsupportedOnce("openai", d);
          denyByIndex.set(idx, d);
        }
      });

      if (denyByIndex.size === 0) {
        for (const c of buffered) yield c;
        return;
      }

      // Replay buffered chunks with denied tool_calls dropped.
      for (const chunk of buffered) {
        const rewritten = rewriteChunkDroppingDenied(chunk, denyByIndex);
        if (rewritten) yield rewritten;
      }

      // Emit one notice chunk per denied call so the assistant message
      // renders the block reason inline.
      for (const [idx, decision] of denyByIndex) {
        const acc = state.toolCalls.get(idx)!;
        const notice = makeBlockNoticeText(
          acc.function.name,
          acc.function.arguments,
          decision.reason,
        );
        yield {
          choices: [{
            index: 0,
            delta: { role: "assistant", content: notice },
            finish_reason: null,
          }],
        };
      }
      // Final stop chunk so the consumer's stream cleanly terminates.
      yield {
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      };
    },
  };
}

/**
 * Rewrite a buffered chunk to drop any deltas referencing a denied
 * tool-call index. Returns `null` if the rewritten chunk has nothing
 * meaningful left.
 */
function rewriteChunkDroppingDenied(
  chunk: Record<string, unknown>,
  denied: Map<number, ToolCallEvaluation>,
): Record<string, unknown> | null {
  const choices = chunk["choices"] as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(choices) || choices.length === 0) return chunk;
  const choice = { ...choices[0]! };
  const delta  = choice["delta"] as Record<string, unknown> | undefined;
  if (delta) {
    const tcs = delta["tool_calls"] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(tcs)) {
      const filtered = tcs.filter((part) => {
        const idx = typeof part["index"] === "number" ? (part["index"] as number) : 0;
        return !denied.has(idx);
      });
      if (filtered.length === 0) {
        const newDelta = { ...delta };
        delete newDelta["tool_calls"];
        choice["delta"] = newDelta;
      } else {
        choice["delta"] = { ...delta, tool_calls: filtered };
      }
    }
  }
  if (choice["finish_reason"] === "tool_calls") {
    // Re-route the finish reason: `stop` if everything was denied,
    // `tool_calls` if some calls survived.
    const surviving = (choice["delta"] as Record<string, unknown> | undefined)?.["tool_calls"];
    choice["finish_reason"] = Array.isArray(surviving) && surviving.length > 0 ? "tool_calls" : "stop";
  }
  return { ...chunk, choices: [choice, ...choices.slice(1)] };
}

function safeJsonParse(s: string): unknown {
  if (!s) return {};
  try { return JSON.parse(s); } catch { return { _raw: s }; }
}

/**
 * Every plain-text non-streaming OpenAI completion produces one
 * observe-prompt audit row keyed by `kind: "plaintext_completion"`.
 * Emission is fire-and-forget — wrapped in try/catch so an audit failure
 * never propagates back to the LLM caller.
 */
function emitPlaintextAuditBestEffort(
  resp: Record<string, unknown>,
  evaluator: CedarToolCallClient,
  requestModel?: string,
): void {
  try {
    const choices = resp["choices"];
    const firstChoice =
      Array.isArray(choices) && choices.length > 0
        ? (choices[0] as Record<string, unknown>)
        : undefined;
    const message = firstChoice?.["message"] as
      | Record<string, unknown>
      | undefined;
    const finishReasonRaw = firstChoice?.["finish_reason"];
    const roleRaw = message?.["role"];
    const idRaw = resp["id"];
    const modelRaw = resp["model"];
    const usageRaw = resp["usage"];
    const content = message?.["content"];
    const contentByteCount =
      typeof content === "string"
        ? new TextEncoder().encode(content).byteLength
        : null;

    evaluator.recordPlaintextCompletion({
      provider: "openai",
      model:
        typeof modelRaw === "string"
          ? modelRaw
          : (requestModel ?? "unknown"),
      finishReason:
        typeof finishReasonRaw === "string" ? finishReasonRaw : null,
      role: typeof roleRaw === "string" ? roleRaw : null,
      completionId: typeof idRaw === "string" ? idRaw : null,
      usage:
        usageRaw && typeof usageRaw === "object"
          ? (usageRaw as Record<string, unknown>)
          : null,
      contentByteCount,
    });
  } catch {
    /* fail-OPEN — audit emission must never break the response path */
  }
}
