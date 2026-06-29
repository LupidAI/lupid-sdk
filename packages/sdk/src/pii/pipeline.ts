/**
 * Y05 — PII pipeline orchestrator. The load-bearing change that flips the
 * SDK from "PII infrastructure exists but unused" to "PII infrastructure
 * runs on every audit emit". Composes Y03 (Layer 1 / field-rule trie) and
 * Y04 (Layer 2 / text scanner + self-check) into a single async helper
 * the three audit-emit call sites consume:
 *
 *   - `client.ts::ingestAuditEvent`            (single-event emit)
 *   - `client.ts` batched flusher (per-event)  (drain path)
 *   - `evaluation/cedar-client.ts::postAuditEvent` (PDP-decision fire-and-forget)
 *
 * # Stage order (fixed — see `.claude/rules/pii.md` invariant #4)
 *
 *   Stage 1 (Layer 1) — `applyTrie` against `detail`. The trie is precise:
 *                       JSONPath-targeted fields are replaced with the
 *                       rule's `mode` (drop / mask / hash / tokenize).
 *   Stage 2 (Layer 2) — walk every remaining string and run `scanAndMask`.
 *                       The scanner is the safety net for unstructured
 *                       text the trie did not reach.
 *   Stage D (verify)  — re-scan every masked string with `selfCheck`. If a
 *                       pattern still matches we throw
 *                       `PiiSelfCheckFailedError` and the orchestrator's
 *                       caller drops the event entirely.
 *
 * Reversing 1 and 2 would double-mask deterministically-targeted fields
 * (technically safe but harder to debug). The order is documented and not
 * negotiable.
 *
 * # Failure semantics — fail-CLOSED
 *
 * `PiiSelfCheckFailedError` is the signal that masking is incomplete. The
 * caller MUST drop the event rather than emit unmasked-with-warning (per
 * the rules file invariant #11). Non-PII errors (programmer bugs, e.g.
 * `applyTrie` throwing on an unexpected shape) propagate — they are not
 * leaks, they are bugs, and silently swallowing them would hide real
 * issues.
 *
 * # Edge safety
 *
 * Pure module — no `node:*` imports, no top-level I/O. `applyTrie` is
 * async because Y03's hash / tokenize modes lazy-import `node:crypto`;
 * the scanner is sync. `runPiiPipeline` is async to track that.
 */

import { applyTrie, type ApplyTrieTracker } from "./field-rule-trie.js";
import { getActiveFieldRuleTrie } from "./trie-state.js";
import { scanAndMask, selfCheck, type Scanner } from "./text-scanner.js";
import { getActiveTextScanner } from "./scanner-state.js";
import { getActiveKeyFingerprint } from "./pii-key-fingerprint.js";

/**
 * Synchronous fast-path check — `true` when both Layer 1 (trie) and
 * Layer 2 (scanner) are no-ops in the current process. Lets call sites
 * skip the `await runPiiPipeline(...)` entirely on the audit hot path.
 *
 * The "no PII config configured at init" case is the dominant one in
 * pre-Y02 deployments (and the common case in tests that don't set a
 * scanner or trie). Adding a microtask boundary for a guaranteed no-op
 * regresses fire-and-forget audit observability where the caller
 * inspects the fetch mock immediately after invoking the wrapper (the
 * mock `fetch` is invoked synchronously from inside `this.post`, so the
 * call site assertions happen before any awaits in the same task).
 *
 * Returns `false` the moment either side has anything to do — the
 * pipeline must run.
 */
export function isPiiPipelineNoOp(): boolean {
  const trie = getActiveFieldRuleTrie();
  if (!trie.empty) return false;
  const scanner = getActiveTextScanner();
  return scanner.patterns.length === 0;
}

/**
 * Result shape from `runPiiPipeline`. `detail` is the scrubbed value
 * the caller writes back onto the audit request. `pii_key_id` carries
 * the active hash/tokenize secret fingerprint (Y06) when — and only
 * when — Stage 1 actually dispatched `mode: hash` or `mode: tokenize`
 * on at least one matched path. Absent (not empty string) on every
 * other path, including the no-op fast path, drop-only / mask-only
 * pipelines, and scanner-only pipelines (the scanner does not use
 * key material).
 */
export interface PiiPipelineResult {
  detail: unknown;
  pii_key_id?: string;
}

/**
 * Compose Stage 1 + Stage 2 + Stage D on `detail`, returning the
 * fully-masked value. The original `detail` is never mutated — Y03 +
 * `walkStrings` both return structurally-shared copies.
 *
 * `tool` is the audit event's `tool` field (e.g. `"send_email"`) and is
 * used by the trie to select tool-specific rules. Pass `"*"` when the
 * caller has no tool context — the wildcard rules still apply.
 *
 * Returns `detail` unchanged when both the active trie is empty AND the
 * active scanner has zero patterns. The shortest-path no-op is
 * essentially free.
 *
 * Y06 — when Stage 1 dispatches `mode: hash` or `mode: tokenize` on at
 * least one path, the returned object includes `pii_key_id` (the
 * truncated SHA-256 fingerprint of the active hash/tokenize secret) so
 * the caller can stamp the outbound audit event. The fingerprint is
 * NOT computed when no hash/tokenize fired, even if secrets are
 * configured — the column on the wire stays absent for drop-only /
 * mask-only / scanner-only events.
 *
 * Throws `PiiSelfCheckFailedError` when Stage D detects a residual
 * match. Re-throws any other error from Stage 1 / Stage 2 unchanged.
 */
export async function runPiiPipeline(
  detail: unknown,
  tool: string,
): Promise<PiiPipelineResult> {
  // Stage 1 — field-rule trie (Y03). `applyTrie` short-circuits when the
  // trie is empty, so the no-op fast path lives inside the callee. The
  // tracker captures whether any hash/tokenize mode actually fired so
  // we only stamp `pii_key_id` on events that legitimately recorded
  // hashed/tokenized material under the active secret epoch.
  const trie = getActiveFieldRuleTrie();
  const tracker: ApplyTrieTracker = { hashOrTokenizeFired: false };
  let masked = await applyTrie(detail, trie, tool, tracker);

  // Stage 2 — text scanner (Y04 Layer 2). Skip the walk entirely when no
  // patterns are configured; the recursive walk is O(detail size) so the
  // guard matters for the common "scanner disabled" case.
  const scanner = getActiveTextScanner();
  if (scanner.patterns.length > 0) {
    masked = walkStrings(masked, (s) => scanAndMask(s, scanner));

    // Stage D — self-check the masked output. Throws on the first
    // pattern that still matches.
    walkStringsReadOnly(masked, scanner);
  }

  // Y06 — only stamp `pii_key_id` when hash/tokenize actually fired.
  // `getActiveKeyFingerprint` may still return undefined when the
  // process resolved a fingerprint earlier but the secrets holder has
  // since been cleared (test resets), or when the runtime cannot reach
  // `node:crypto` (edge bundlers). In either case we leave the field
  // absent rather than emit a placeholder.
  if (tracker.hashOrTokenizeFired) {
    const fp = getActiveKeyFingerprint();
    if (fp !== undefined) {
      return { detail: masked, pii_key_id: fp };
    }
  }
  return { detail: masked };
}

/**
 * Recursive immutable walk. Replaces every string leaf via `fn`,
 * preserves arrays / plain objects, and passes through everything else
 * (numbers, booleans, null, undefined, bigint, symbols) unchanged.
 *
 * Returns a new container only when at least one child changed —
 * matches Y03's structurally-shared discipline so unchanged subtrees
 * keep their identity.
 *
 * Cycle handling: a `WeakSet` of visited objects prevents infinite
 * recursion if a caller hands us a self-referential structure. The
 * detected cycle is replaced with the original reference (we do not
 * attempt to clone the cycle).
 */
function walkStrings(
  value: unknown,
  fn: (s: string) => string,
): unknown {
  const seen = new WeakSet<object>();
  return walkStringsImpl(value, fn, seen);
}

function walkStringsImpl(
  value: unknown,
  fn: (s: string) => string,
  seen: WeakSet<object>,
): unknown {
  if (typeof value === "string") return fn(value);
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return value;
  seen.add(value);

  if (Array.isArray(value)) {
    let changed = false;
    const next: unknown[] = new Array(value.length);
    for (let i = 0; i < value.length; i += 1) {
      const replaced = walkStringsImpl(value[i], fn, seen);
      next[i] = replaced;
      if (replaced !== value[i]) changed = true;
    }
    return changed ? next : value;
  }

  // Plain object (including `Object.create(null)` records). We intentionally
  // do NOT walk class instances with custom prototypes — the audit
  // `detail` is a plain JSON-shaped record per `AuditIngestRequest.detail`.
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return value;

  const obj = value as Record<string, unknown>;
  let changed = false;
  const next: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const original = obj[key];
    const replaced = walkStringsImpl(original, fn, seen);
    next[key] = replaced;
    if (replaced !== original) changed = true;
  }
  return changed ? next : value;
}

/**
 * Read-only walk that hands every string leaf to `selfCheck`. Throws
 * `PiiSelfCheckFailedError` on the first residual match; the caller is
 * expected to drop the event.
 *
 * Mirrors `walkStrings`'s cycle guard and prototype discipline so the
 * verification pass visits exactly the same leaves the masking pass
 * visited. Numbers / booleans / null / undefined are skipped — the
 * scanner only matches strings.
 */
function walkStringsReadOnly(value: unknown, scanner: Scanner): void {
  const seen = new WeakSet<object>();
  walkStringsReadOnlyImpl(value, scanner, seen);
}

function walkStringsReadOnlyImpl(
  value: unknown,
  scanner: Scanner,
  seen: WeakSet<object>,
): void {
  if (typeof value === "string") {
    selfCheck(value, scanner);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);

  if (Array.isArray(value)) {
    for (const child of value) {
      walkStringsReadOnlyImpl(child, scanner, seen);
    }
    return;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return;

  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    walkStringsReadOnlyImpl(obj[key], scanner, seen);
  }
}

// Re-export the error so callers can `instanceof` it without reaching
// into the scanner module directly.
export { PiiSelfCheckFailedError } from "./text-scanner.js";
