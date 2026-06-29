/**
 * Module-level state for the active manifest `pii:` block.
 *
 * Mirrors the `TenantSchema` storage pattern in `../manifest/state.ts` — a
 * deep-frozen singleton set once by `init()` (via `_setActivePiiBlock`)
 * and read by downstream consumers (Y03 field-rule trie, Y04 text
 * scanner) at call time.
 *
 * Unlike `getActiveSchema()`, the reader here returns an empty block
 * (`{}`) when `init()` has not yet populated it. Rationale: the schema
 * is load-bearing for every audit row (an unschema'd row is a wire
 * contract violation), but the `pii:` block is additive — a missing
 * block legitimately means "no field rules, no text scanners". Throwing
 * here would make legacy manifests that don't carry a `pii:` block
 * fail every read.
 */

import type { PiiManifestBlock } from "../types.js";

let ACTIVE: PiiManifestBlock | null = null;

/**
 * Returns the active `PiiManifestBlock`. Returns an empty block if
 * `init()` has not (yet) populated it — see module-level comment for
 * why this is not a throw.
 */
export function getActivePiiBlock(): PiiManifestBlock {
  return ACTIVE ?? {};
}

/**
 * Test/init-only setter. Deep-freezes the block so downstream consumers
 * cannot accidentally mutate `field_rules[*]` or `text_scanners[*]`.
 *
 * Re-init with a different block in the same process is undefined
 * behaviour; this setter overwrites without question.
 */
export function _setActivePiiBlock(block: PiiManifestBlock | null): void {
  ACTIVE = block === null ? null : deepFreeze(block);
}

/** Test-only — drop the active block so a subsequent `init()` starts clean. */
export function _resetActivePiiBlockForTests(): void {
  ACTIVE = null;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value as object)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}
