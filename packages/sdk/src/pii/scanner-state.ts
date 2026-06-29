/**
 * Module-level state for the active text scanner (Y04, Layer 2 of the
 * PII pipeline).
 *
 * Mirrors the `pii-state.ts` / `trie-state.ts` pattern from Y02 / Y03 — a
 * deep-frozen singleton set once by `init()` (via `_setActiveTextScanner`)
 * and read by downstream consumers (Y05 pipeline orchestrator) at call
 * time.
 *
 * Unlike `getActiveSchema()`, the reader here returns a no-op scanner
 * when `init()` has not yet populated it. Rationale: the scanner is
 * additive — a missing scanner legitimately means "no text scanning
 * configured" and should be a no-op rather than a hard error. Throwing
 * here would make every audit emit before init complete fail.
 */

import { compileScanner, type Scanner } from "./text-scanner.js";

/**
 * Lazily-constructed no-op scanner. Compiling `{ enabled: false }` yields
 * an empty pattern array; we still cache it once so the "scanner not set"
 * reader path is a constant-time return.
 */
const EMPTY_SCANNER: Scanner = compileScanner({ enabled: false });

let ACTIVE: Scanner | null = null;

/**
 * Returns the active `Scanner`. Returns the empty (no-op) scanner if
 * `init()` has not (yet) populated it — see module-level comment for
 * why this is not a throw.
 */
export function getActiveTextScanner(): Scanner {
  return ACTIVE ?? EMPTY_SCANNER;
}

/**
 * Test/init-only setter. Freezes the top-level scanner object so
 * downstream consumers cannot accidentally rebind `patterns`. The
 * compiled-pattern array is populated once during `compileScanner` and
 * never mutated by `scanAndMask` (regex `lastIndex` is reset on every
 * call). Surface freeze is sufficient.
 *
 * Re-init with a different scanner in the same process is undefined
 * behaviour; this setter overwrites without question.
 */
export function _setActiveTextScanner(scanner: Scanner | null): void {
  ACTIVE = scanner === null ? null : Object.freeze(scanner);
}

/** Test-only — drop the active scanner so a subsequent `init()` starts clean. */
export function _resetActiveTextScannerForTests(): void {
  ACTIVE = null;
}
