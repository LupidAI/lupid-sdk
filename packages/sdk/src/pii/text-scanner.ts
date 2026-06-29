/**
 * Y04 — Stage C (text-scanner / Layer 2) + Stage D (self-check) of the
 * PII pipeline.
 *
 * Layer 2 sweeps free-text values for the 14 canonical patterns embedded
 * at build time from `pii-patterns/default.yaml` (Y01 / generator script
 * at `sdk/typescript/scripts/generate-pii-patterns.mjs`). Operators opt
 * out per-agent via `pii.text_scanners: [{ enabled: false }]` in the
 * manifest, restrict to a subset via `patterns: ["email", "ssn_us"]`,
 * or extend with custom regexes via `custom: [{ id, pattern, severity }]`.
 *
 * Stage D re-scans the masked output once. If any pattern still matches
 * the scanner throws `PiiSelfCheckFailedError`. The caller (Y05) chooses
 * the failure semantic — the spec is fail-CLOSED at the pipeline level
 * (`.claude/rules/pii.md` invariant #11: "drop the event entirely … not
 * ship unmasked-with-warning").
 *
 * Edge safety: pure regex / string code; no `node:*` imports anywhere in
 * the module. Reachable from `index.ts` only via the `pii/*` subpath
 * export, which `tests/edge-entry.test.ts` audits post-build.
 *
 * Composition with Y03: this module is sync. Y03's `applyTrie` is async
 * because the `hash` / `tokenize` modes dynamically import `node:crypto`.
 * Regex replacement has no async dep, so `scanAndMask` stays sync — Y05
 * composes them with an `await applyTrie(...)` followed by a sync
 * `scanAndMask(...)`.
 */

import type { PiiTextScannerConfig } from "../types.js";
import { DEFAULT_PATTERNS, type EmbeddedPattern } from "./pii-patterns-embedded.js";

/**
 * One compiled pattern. The `regex` is constructed once at
 * `compileScanner` time and reused on every `scanAndMask` call — its
 * `lastIndex` is reset before each use so the global flag does not
 * leak state across invocations.
 */
export interface CompiledPattern {
  readonly id: string;
  readonly regex: RegExp;
  readonly severity: "low" | "medium" | "high" | "critical";
}

/**
 * A compiled scanner. Public shape is intentionally narrow — callers
 * receive a `Scanner` from `compileScanner` and pass it back to
 * `scanAndMask` / `selfCheck`. Y05's orchestrator is the only intended
 * consumer outside this module.
 */
export interface Scanner {
  readonly patterns: readonly CompiledPattern[];
}

/**
 * Thrown by {@link selfCheck} when the masked output still contains a
 * matchable PII span. The pipeline must fail-CLOSED on this — surface
 * the error to the orchestrator so the audit event is dropped (per
 * `.claude/rules/pii.md` invariant #11). `unmaskedPatternId` names the
 * offending pattern; `sample` is a short prefix of the residual match
 * for debugging (NEVER log this at info-level — it is by construction
 * still raw PII).
 */
export class PiiSelfCheckFailedError extends Error {
  constructor(
    public readonly unmaskedPatternId: string,
    public readonly sample: string,
  ) {
    super(
      `agentum.pii: self-check failed — pattern '${unmaskedPatternId}' ` +
        `still matches after masking`,
    );
    this.name = "PiiSelfCheckFailedError";
  }
}

/**
 * Build a scanner from the optional manifest config.
 *
 * Semantics:
 *   - `undefined` → enabled with all 14 default patterns.
 *   - `{ enabled: false }` → no patterns; `scanAndMask` is a no-op and
 *     `selfCheck` always succeeds.
 *   - `{ enabled: true }` → enabled with all 14 default patterns.
 *   - `{ enabled: true, patterns: [...] }` → enabled with only the
 *     default patterns whose `id` appears in the list. Unknown ids are
 *     dropped silently (Y09's parity gate is the right place to catch
 *     typos; failing-CLOSED on a single typo would surprise operators).
 *   - `{ enabled: true, custom: [...] }` → enabled with all 14 defaults
 *     plus the custom patterns (subset filter applies to defaults only).
 *
 * Pure: deterministic for a given input, no I/O, no `node:*` imports.
 * Throws on a `custom` entry whose `pattern` is not a valid JS regex —
 * the manifest validator in `manifest-block.ts` checks shape, but only
 * the engine knows whether the regex itself compiles.
 */
export function compileScanner(cfg?: PiiTextScannerConfig): Scanner {
  if (cfg?.enabled === false) {
    return { patterns: [] };
  }
  const defaults: readonly EmbeddedPattern[] = cfg?.patterns
    ? DEFAULT_PATTERNS.filter((p) => cfg.patterns!.includes(p.id))
    : DEFAULT_PATTERNS;

  const compiled: CompiledPattern[] = defaults.map((p) => ({
    id: p.id,
    regex: new RegExp(p.regexSource, p.regexFlags),
    severity: p.severity,
  }));

  if (cfg?.custom) {
    for (const c of cfg.custom) {
      compiled.push({
        id: c.id,
        // Always include `g` so iterative `replace` walks the whole string.
        regex: new RegExp(c.pattern, "g"),
        severity: c.severity ?? "medium",
      });
    }
  }
  return { patterns: compiled };
}

/**
 * Replace every PII match in `text` with the operator-visible marker
 * `***<pattern_id>***`. The marker is intentionally a fixed shape so
 * downstream tooling (the server-side sampler, the audit UI) can
 * recognise SDK-side masks and avoid double-scanning.
 *
 * Multiple-pass loop: some masks may expose new matches once neighbouring
 * runs collapse (rare, but cheap to handle). Bounded by `MAX_ITERATIONS`
 * so a degenerate pattern that matches its own output never spins
 * forever. The bound is paranoia — well-formed patterns reach a fixed
 * point on the first pass.
 *
 * The regex `lastIndex` is reset before each use (the patterns carry the
 * `g` flag so `replace` walks the whole string regardless, but resetting
 * defends against a `.exec(...)` callsite leaving state behind in
 * `selfCheck`).
 */
export function scanAndMask(text: string, scanner: Scanner): string {
  if (scanner.patterns.length === 0 || text.length === 0) return text;
  const MAX_ITERATIONS = 4;
  let out = text;
  for (let iter = 0; iter < MAX_ITERATIONS; iter += 1) {
    const before = out;
    for (const p of scanner.patterns) {
      p.regex.lastIndex = 0;
      out = out.replace(p.regex, `***${p.id}***`);
    }
    if (out === before) return out;
  }
  return out;
}

/**
 * Stage D — re-scan the masked output. Throws on the first pattern that
 * still matches; otherwise returns silently.
 *
 * `selfCheck` is intentionally a verification gate, not a masker. The
 * caller decides what to do on failure: Y05 drops the event entirely
 * with a `PiiPipelineError` audit (sans content) per the rules-file
 * invariant. Re-running `scanAndMask` from inside `selfCheck` would
 * smear the responsibility and make the failure path indistinguishable
 * from a clean run.
 */
export function selfCheck(masked: string, scanner: Scanner): void {
  if (scanner.patterns.length === 0) return;
  for (const p of scanner.patterns) {
    p.regex.lastIndex = 0;
    const m = p.regex.exec(masked);
    if (m && m[0]) {
      // Truncate to 30 chars so the error doesn't carry an arbitrarily
      // long PII payload through the throw site.
      const sample = m[0].length > 30 ? `${m[0].slice(0, 30)}…` : m[0];
      throw new PiiSelfCheckFailedError(p.id, sample);
    }
  }
}
