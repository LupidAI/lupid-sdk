/**
 * Module-level state for the active field-rule trie (Y03 Sub-C).
 *
 * Mirrors the `pii-state.ts` pattern from Y02 — a deep-frozen singleton
 * set once by `init()` (via `_setActiveFieldRuleTrie`) and read by
 * downstream consumers (Y05 pipeline orchestrator) at call time.
 *
 * Unlike `getActiveSchema()`, the reader here returns the empty trie
 * when `init()` has not yet populated it. Rationale: the trie is
 * additive — a missing trie legitimately means "no field rules
 * configured" and should be a no-op rather than a hard error. Throwing
 * here would make every audit emit before init complete fail.
 */

import {
  type FieldRuleTrie,
  compileFieldRuleTrie,
} from "./field-rule-trie.js";

/**
 * Lazily-constructed empty trie. Compiling the empty input is cheap and
 * deterministic; we still cache it once so the "trie not set" reader
 * path is a constant-time return.
 */
const EMPTY_TRIE: FieldRuleTrie = compileFieldRuleTrie([]);

let ACTIVE: FieldRuleTrie | null = null;

/**
 * Returns the active `FieldRuleTrie`. Returns the empty trie if
 * `init()` has not (yet) populated it — see module-level comment for
 * why this is not a throw.
 */
export function getActiveFieldRuleTrie(): FieldRuleTrie {
  return ACTIVE ?? EMPTY_TRIE;
}

/**
 * Test/init-only setter. Freezes the top-level trie object so downstream
 * consumers cannot accidentally rebind `byTool` / `wildcardTool`. The
 * internal compiled-rule arrays are populated once during
 * `compileFieldRuleTrie` and never mutated by `applyTrie` (which clones
 * on the spine of every match), so the surface freeze is sufficient.
 *
 * Re-init with a different trie in the same process is undefined
 * behaviour; this setter overwrites without question.
 */
export function _setActiveFieldRuleTrie(trie: FieldRuleTrie | null): void {
  ACTIVE = trie === null ? null : Object.freeze(trie);
}

/** Test-only — drop the active trie so a subsequent `init()` starts clean. */
export function _resetActiveFieldRuleTrieForTests(): void {
  ACTIVE = null;
}
