/**
 * Y03 Sub-B — JSONPath field-rule trie (Layer 1 of the PII pipeline).
 *
 * Compiles `PiiFieldRule[]` from the validated manifest (Y02) into a
 * compact representation keyed by tool name + JSONPath segments. At
 * audit-emit time the orchestrator (Y05) calls `applyTrie(value, trie,
 * toolName)` which returns a structurally-shared copy of the value with
 * every matching path masked according to the rule's `mode`.
 *
 * # Supported JSONPath subset
 *
 * Y03 deliberately implements a small, well-defined subset of JSONPath.
 * Anything outside this list is rejected at compile time with a clear
 * error (the manifest is wire-validated against the same subset).
 *
 *   - `$.` root prefix (mandatory)
 *   - `.<key>` dot-notation key
 *   - `["<key>"]` bracket-notation key (single or double quote)
 *   - `*` and `[*]` wildcard — match any single segment / array element
 *   - `..` recursive descent — match the next segment at any depth
 *   - `[N]` non-negative integer array index (e.g. `[0]`, `[3]`)
 *
 * Out of scope for Y03 (rejected at compile time, may land in Y04+):
 *   - Slices: `[1:5]`, `[::-1]`
 *   - Filters: `[?(@.foo > 1)]`
 *   - Unions: `["a","b"]`
 *   - Negative indices: `[-1]`
 *   - Script expressions
 *
 * # Tool wildcard semantics
 *
 * A rule with `tool: "*"` applies to every tool. When both a wildcard
 * rule and a tool-specific rule match the same tool, both are applied in
 * sequence — the wildcard rule first, then the tool-specific rule. This
 * is the spec's "union both" decision (see Y03 § Risk).
 *
 * # Edge safety
 *
 * Pure file — no I/O, no `node:*` imports, no globals beyond what the
 * trie's mode functions reach for. Reachable from `index.ts` indirectly
 * (via `init.ts`), so the no-top-level-`node:*` rule applies. Mode
 * application calls into `./mask.ts::applyPii`, which lazy-imports
 * `node:crypto` inside `hash` / `tokenize`. Consequently `applyTrie` is
 * `async` — Y05's orchestrator awaits it once per emit.
 */

import type { PiiFieldRule } from "../types.js";
import { REDACTED_LITERAL } from "./modes/drop.js";
import { hash } from "./modes/hash.js";
import { tokenize } from "./modes/tokenize.js";
import { getPiiSecrets } from "./secrets.js";

/**
 * Literal used by `mode: "mask"`. Distinct from `<redacted>` (drop) so
 * downstream operators can tell at a glance which Layer produced the
 * masking. Mask is intentionally a fixed sentinel — Y04's text-scanner
 * branch may emit `<masked:kind>` enriched forms later, but Y03 itself
 * has no `kind` to enrich with.
 */
export const MASK_LITERAL = "***";

/** One parsed JSONPath segment. */
type Segment =
  | { kind: "key"; name: string }
  | { kind: "wildcard" }
  | { kind: "index"; value: number }
  | { kind: "recursive_descent" };

interface CompiledRule {
  readonly segments: readonly Segment[];
  readonly mode: PiiFieldRule["mode"];
  /** The original rule object for diagnostic strings; never mutated. */
  readonly source: PiiFieldRule;
}

/**
 * Compiled field-rule trie. The public shape is intentionally opaque —
 * callers receive a `FieldRuleTrie` and pass it back to `applyTrie`.
 * Y05's orchestrator is the only intended consumer.
 */
export interface FieldRuleTrie {
  readonly byTool: ReadonlyMap<string, readonly CompiledRule[]>;
  readonly wildcardTool: readonly CompiledRule[];
  /** `true` when there are zero rules across all tools — fast-path. */
  readonly empty: boolean;
}

/**
 * Thrown by `compileFieldRuleTrie` when a rule's path uses syntax outside
 * the Y03 subset. Includes the rule's tool + path so operators can locate
 * the offending entry in their manifest.
 */
export class FieldRuleCompileError extends Error {
  constructor(
    public readonly rule: PiiFieldRule,
    public readonly detail: string,
  ) {
    super(
      `agentum.pii: field rule for tool '${rule.tool}' has unsupported ` +
        `JSONPath syntax in '${rule.path}': ${detail}`,
    );
    this.name = "FieldRuleCompileError";
  }
}

/**
 * Compile a list of validated `PiiFieldRule`s into the runtime trie.
 *
 * Pure: deterministic for a given input, no side effects, no I/O. Safe
 * to call at init time (the typical caller) or in unit tests. The empty
 * input yields the empty trie which `applyTrie` short-circuits on.
 */
export function compileFieldRuleTrie(
  rules: readonly PiiFieldRule[],
): FieldRuleTrie {
  const byTool = new Map<string, CompiledRule[]>();
  const wildcardTool: CompiledRule[] = [];

  for (const rule of rules) {
    const compiled: CompiledRule = {
      segments: parsePath(rule),
      mode: rule.mode,
      source: rule,
    };
    if (rule.tool === "*") {
      wildcardTool.push(compiled);
    } else {
      const bucket = byTool.get(rule.tool);
      if (bucket === undefined) {
        byTool.set(rule.tool, [compiled]);
      } else {
        bucket.push(compiled);
      }
    }
  }

  return {
    byTool,
    wildcardTool,
    empty: byTool.size === 0 && wildcardTool.length === 0,
  };
}

/**
 * Tracker passed by Y05's pipeline orchestrator so it can stamp the
 * resulting event with `pii_key_id` only when a hash or tokenize mode
 * actually fired. `applyTrie` mutates `hashOrTokenizeFired` to `true`
 * the moment it dispatches `mode: "hash"` or `mode: "tokenize"` on a
 * matched path. Existing callers that don't care about the signal omit
 * the argument entirely (back-compat).
 */
export interface ApplyTrieTracker {
  hashOrTokenizeFired: boolean;
}

/**
 * Apply every rule in `trie` matching `tool` to `value`, returning a
 * new value with masked fields. Original input is never mutated.
 *
 * Order of application:
 *   1. Every rule with `tool: "*"` (in declared order)
 *   2. Every rule with `tool === <tool>` (in declared order)
 *
 * Both buckets are applied sequentially — the spec's union semantics —
 * so a wildcard hash followed by a tool-specific drop on the same field
 * deterministically yields the drop sentinel.
 *
 * Returns the input unchanged when `trie.empty` is `true` or no bucket
 * targets the named tool.
 *
 * The optional `tracker` is set to `{ hashOrTokenizeFired: true }` the
 * moment a matched path dispatches `mode: hash` or `mode: tokenize`.
 * Callers (Y05's `runPiiPipeline`) use it to decide whether to populate
 * `pii_key_id` on the outbound audit event.
 */
export async function applyTrie(
  value: unknown,
  trie: FieldRuleTrie,
  tool: string,
  tracker?: ApplyTrieTracker,
): Promise<unknown> {
  if (trie.empty) return value;
  const toolSpecific = trie.byTool.get(tool) ?? [];
  if (trie.wildcardTool.length === 0 && toolSpecific.length === 0) {
    return value;
  }
  let current = value;
  for (const rule of trie.wildcardTool) {
    current = await applyRule(current, rule, tracker);
  }
  for (const rule of toolSpecific) {
    current = await applyRule(current, rule, tracker);
  }
  return current;
}

// ── path parsing ──────────────────────────────────────────────────────────

function parsePath(rule: PiiFieldRule): Segment[] {
  const expr = rule.path;
  if (!expr.startsWith("$")) {
    throw new FieldRuleCompileError(rule, `must start with "$"`);
  }
  // After the `$`, the first character must be `.` (dot-root) or `[`
  // (bracket-root). Bare `$` is allowed only when the rule is the whole
  // path (i.e. `expr === "$"`); but a rule that masks the entire input
  // is degenerate and we reject it to surface manifest typos.
  if (expr.length === 1) {
    throw new FieldRuleCompileError(
      rule,
      `path "$" alone matches the entire value — add at least one segment`,
    );
  }

  const segments: Segment[] = [];
  let i = 1; // skip the `$`
  while (i < expr.length) {
    const c = expr[i];
    if (c === ".") {
      // Either `..` (recursive descent + bare key/wildcard/bracket) or
      // `.<key>` / `.*`.
      if (expr[i + 1] === ".") {
        segments.push({ kind: "recursive_descent" });
        i += 2;
        // A `..` must be followed by another segment (key/wildcard/bracket).
        if (i >= expr.length) {
          throw new FieldRuleCompileError(
            rule,
            `trailing ".." without a following segment`,
          );
        }
        // Wildcard, bracket or bare key may follow `..` directly (no
        // leading `.`). Bracket form falls through to the `[` branch
        // below on the next loop iteration; wildcard and key are
        // consumed here so we don't double-advance.
        const next = expr[i];
        if (next === "*") {
          segments.push({ kind: "wildcard" });
          i += 1;
          continue;
        }
        if (next === "[") {
          // Let the `[` branch on the next iteration handle it.
          continue;
        }
        // Bare key form: walk until the next segment boundary.
        const start = i;
        while (
          i < expr.length &&
          expr[i] !== "." &&
          expr[i] !== "["
        ) {
          i += 1;
        }
        const key = expr.slice(start, i);
        if (key.length === 0) {
          throw new FieldRuleCompileError(
            rule,
            `empty key after ".."`,
          );
        }
        segments.push({ kind: "key", name: key });
        continue;
      }
      // `.<key>` or `.*`. Walk until the next segment boundary.
      i += 1;
      if (i >= expr.length) {
        throw new FieldRuleCompileError(rule, `trailing "."`);
      }
      if (expr[i] === "*") {
        segments.push({ kind: "wildcard" });
        i += 1;
        continue;
      }
      const start = i;
      while (
        i < expr.length &&
        expr[i] !== "." &&
        expr[i] !== "["
      ) {
        i += 1;
      }
      const key = expr.slice(start, i);
      if (key.length === 0) {
        throw new FieldRuleCompileError(rule, `empty key after "."`);
      }
      segments.push({ kind: "key", name: key });
      continue;
    }
    if (c === "[") {
      const end = expr.indexOf("]", i);
      if (end < 0) {
        throw new FieldRuleCompileError(rule, `unbalanced "["`);
      }
      const inner = expr.slice(i + 1, end);
      segments.push(parseBracket(rule, inner));
      i = end + 1;
      continue;
    }
    throw new FieldRuleCompileError(
      rule,
      `unexpected character "${c}" at offset ${i}`,
    );
  }
  if (segments.length === 0) {
    throw new FieldRuleCompileError(
      rule,
      `no segments after "$" — path matches nothing`,
    );
  }
  return segments;
}

function parseBracket(rule: PiiFieldRule, inner: string): Segment {
  if (inner === "*") {
    return { kind: "wildcard" };
  }
  // Unions and slices are out-of-subset; check before the quoted-key
  // branch so e.g. `["a","b"]` is rejected as a union rather than
  // mis-parsed as a key literally named `a","b`.
  if (inner.includes(",")) {
    throw new FieldRuleCompileError(
      rule,
      `bracket unions are not supported in Y03 (got "[${inner}]")`,
    );
  }
  if (inner.includes(":")) {
    throw new FieldRuleCompileError(
      rule,
      `array slices are not supported in Y03 (got "[${inner}]")`,
    );
  }
  if (inner.startsWith("?")) {
    throw new FieldRuleCompileError(
      rule,
      `filter expressions are not supported in Y03 (got "[${inner}]")`,
    );
  }
  // `["key"]` or `['key']` — quoted string.
  if (
    inner.length >= 2 &&
    ((inner[0] === '"' && inner[inner.length - 1] === '"') ||
      (inner[0] === "'" && inner[inner.length - 1] === "'"))
  ) {
    const name = inner.slice(1, inner.length - 1);
    if (name.length === 0) {
      throw new FieldRuleCompileError(rule, `empty bracketed key`);
    }
    // Embedded quotes / escapes are not supported in Y03 — reject so a
    // typo surfaces rather than silently mis-matching.
    if (name.includes("\\")) {
      throw new FieldRuleCompileError(
        rule,
        `escape sequences in bracketed keys are not supported`,
      );
    }
    return { kind: "key", name };
  }
  // Numeric index — non-negative integer only.
  if (/^\d+$/.test(inner)) {
    const value = Number.parseInt(inner, 10);
    if (!Number.isSafeInteger(value)) {
      throw new FieldRuleCompileError(rule, `array index out of range: ${inner}`);
    }
    return { kind: "index", value };
  }
  // Anything else (negative index, identifier-without-quotes, ...) — reject.
  throw new FieldRuleCompileError(
    rule,
    `unrecognised bracket contents "[${inner}]"`,
  );
}

// ── rule application ──────────────────────────────────────────────────────

/**
 * Apply one compiled rule to `value`. Returns a structurally-shared
 * copy with every matching path masked. The walk threads an
 * `(value, segmentIndex)` cursor through `applyAtSegment`, only cloning
 * sub-objects on the spine of the match.
 */
async function applyRule(
  value: unknown,
  rule: CompiledRule,
  tracker?: ApplyTrieTracker,
): Promise<unknown> {
  return applyAtSegment(value, rule, 0, tracker);
}

/**
 * Walk `value` against `rule.segments[segIndex...]`. Returns the
 * possibly-modified `value`.
 *
 * Invariants:
 *   - Never mutates `value` or any nested object — clones on the spine
 *     of every match before applying the mode.
 *   - Returns the input unchanged when no match exists in this subtree.
 */
async function applyAtSegment(
  value: unknown,
  rule: CompiledRule,
  segIndex: number,
  tracker?: ApplyTrieTracker,
): Promise<unknown> {
  // Reached the end of the segments — `value` is the match site.
  if (segIndex >= rule.segments.length) {
    return applyMode(value, rule.mode, tracker);
  }
  const seg = rule.segments[segIndex];
  if (seg === undefined) return value;

  if (seg.kind === "recursive_descent") {
    // `..<next>` — try matching the remainder at the current node AND
    // recurse into every child. Recursive descent does NOT consume an
    // input segment by itself; it lets the next segment match at any
    // depth.
    let current = value;
    // Attempt match at this depth first (allows e.g. `$..email` to hit
    // top-level `email`).
    current = await applyAtSegment(current, rule, segIndex + 1, tracker);
    // Then recurse into children of the (possibly already-updated)
    // value, still trying to match `..<next>` (i.e. keep segIndex on the
    // recursive_descent so deeper levels also test the next segment).
    current = await walkChildren(current, async (child) =>
      applyAtSegment(child, rule, segIndex, tracker),
    );
    return current;
  }

  if (seg.kind === "wildcard") {
    // Wildcard consumes one segment — try every child.
    return walkChildren(value, async (child) =>
      applyAtSegment(child, rule, segIndex + 1, tracker),
    );
  }

  if (seg.kind === "key") {
    if (!isPlainObject(value)) return value;
    const obj = value as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(obj, seg.name)) return value;
    const original = obj[seg.name];
    // Terminal key + drop mode → remove the key entirely (spec semantic).
    if (
      segIndex + 1 >= rule.segments.length &&
      rule.mode === "drop"
    ) {
      const next: Record<string, unknown> = { ...obj };
      delete next[seg.name];
      return next;
    }
    const replaced = await applyAtSegment(original, rule, segIndex + 1, tracker);
    if (replaced === original) return value;
    return { ...obj, [seg.name]: replaced };
  }

  if (seg.kind === "index") {
    if (!Array.isArray(value)) return value;
    if (seg.value >= value.length) return value;
    const original = value[seg.value];
    const replaced = await applyAtSegment(original, rule, segIndex + 1, tracker);
    if (replaced === original) return value;
    const next = value.slice();
    next[seg.value] = replaced;
    return next;
  }

  // Exhaustiveness — narrows to `never` if Segment is extended.
  const _exhaustive: never = seg;
  void _exhaustive;
  return value;
}

/**
 * Walk every immediate child of `value`, invoking `fn` on each. Returns
 * a new container if any child changed; otherwise returns the input
 * unchanged.
 */
async function walkChildren(
  value: unknown,
  fn: (child: unknown) => Promise<unknown>,
): Promise<unknown> {
  if (Array.isArray(value)) {
    let changed = false;
    const next: unknown[] = new Array(value.length);
    for (let i = 0; i < value.length; i += 1) {
      const replaced = await fn(value[i]);
      next[i] = replaced;
      if (replaced !== value[i]) changed = true;
    }
    return changed ? next : value;
  }
  if (isPlainObject(value)) {
    const obj = value as Record<string, unknown>;
    let changed = false;
    const next: Record<string, unknown> = {};
    for (const key of Object.keys(obj)) {
      const original = obj[key];
      const replaced = await fn(original);
      next[key] = replaced;
      if (replaced !== original) changed = true;
    }
    return changed ? next : value;
  }
  return value;
}

async function applyMode(
  value: unknown,
  mode: PiiFieldRule["mode"],
  tracker?: ApplyTrieTracker,
): Promise<unknown> {
  switch (mode) {
    case "drop":
      // Terminal-key drops are handled inline in `applyAtSegment` so the
      // key is removed entirely. Non-terminal drops (recursive descent
      // targeting a value, wildcards, array elements) fall through to
      // the sentinel.
      return REDACTED_LITERAL;
    case "mask":
      return MASK_LITERAL;
    case "hash": {
      const str = stringifyForMasking(value);
      if (tracker) tracker.hashOrTokenizeFired = true;
      return hash(str, getPiiSecrets());
    }
    case "tokenize": {
      const str = stringifyForMasking(value);
      if (tracker) tracker.hashOrTokenizeFired = true;
      return tokenize(str, getPiiSecrets());
    }
    default: {
      const _exhaustive: never = mode;
      void _exhaustive;
      throw new Error(`agentum.pii: unknown mode '${String(mode)}'`);
    }
  }
}

/**
 * Coerce a matched value into the string form the crypto primitives
 * consume. Objects / arrays are JSON-stringified (deterministic enough
 * for masking; full canonicalisation is Y06+ territory). Primitive
 * coercion follows the obvious mapping. `null` / `undefined` mask to the
 * literal string `"null"` / `"undefined"` so the trie stays
 * deterministic on partially-populated payloads.
 */
function stringifyForMasking(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null) return "null";
  if (value === undefined) return "undefined";
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return String(value);
  }
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return String(value);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  // Allow plain objects and `Object.create(null)`-style records.
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
