/**
 * Y09b — TypeScript side of the Rust/TS PII parity gate.
 *
 * Reads `pii-patterns/parity-tests.yaml` (the cross-language fixture
 * corpus committed in Y09a at `d2967759`) and asserts that the SDK's
 * `compileScanner` + a fresh match-extraction sweep return the same
 * `expected_matches` set, in the same order, that the Rust
 * `Detector::match_named_all` test (`crates/agentum-dlp/tests/parity.rs`)
 * asserts for its side.
 *
 * Together the two suites are the load-bearing CI gate enforcing
 * Rust/TS regex-engine parity for the canonical 14-pattern pack
 * (`pii-patterns/default.yaml`). `.github/workflows/pii-parity.yml`
 * runs both this test and the Rust counterpart on every PR that
 * touches `pii-patterns/**`, `crates/agentum-dlp/**`, or
 * `sdk/typescript/src/pii/**`.
 *
 * Critical contract notes (carried over from Y09a):
 *   - Each fixture is run with a single-pattern scanner
 *     (`compileScanner({ enabled: true, patterns: [fixture.pattern_id] })`)
 *     so multi-pattern shadowing — the `openai_key` ⊃ `anthropic_key`
 *     case in particular — does not pollute the per-pattern truth.
 *   - Fixtures carrying `shadowed_by: <id>` are SKIPPED here (and in the
 *     Rust counterpart). They exist in the YAML to document the
 *     relationship; the redact-pipeline contract for multi-pattern
 *     shadowing is verified elsewhere (see `tests/pii/pipeline.test.ts`).
 *   - The `phone_us` regex anchors with `\b` on the leading digit, so a
 *     leading `+` is OUTSIDE the match span on both engines. The YAML
 *     declares `"1 (212) 555-2000"` (no `+`) for that fixture — this
 *     test asserts that shape exactly, matching the Rust regex crate
 *     and JS `RegExp` behaviour.
 *
 * Edge-runtime constraint: this file lives under `tests/` (not under
 * `src/`), so the static `node:fs` / `node:path` / `yaml` imports here
 * are fine — the bundle audit (`tests/edge-entry.test.ts`) only scans
 * built `dist/` output.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { parse as parseYaml } from "yaml";

import {
  compileScanner,
  type Scanner,
} from "../../src/pii/text-scanner";
import { DEFAULT_PATTERNS } from "../../src/pii/pii-patterns-embedded";

// ── Locations ─────────────────────────────────────────────────────────
// tests/pii/parity.test.ts → repo root → pii-patterns/parity-tests.yaml.
// Mirrors `scripts/generate-pii-patterns.mjs`'s `REPO_ROOT` resolution
// (sdk/typescript/scripts → ../../). From tests/pii we go up three.
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const PARITY_YAML_PATH = path.join(
  REPO_ROOT,
  "pii-patterns",
  "parity-tests.yaml",
);
const DEFAULT_YAML_PATH = path.join(
  REPO_ROOT,
  "pii-patterns",
  "default.yaml",
);

// ── Fixture types ─────────────────────────────────────────────────────
// Narrow shape kept in sync with `crates/agentum-dlp/tests/parity.rs`'s
// `ParityFile` / `Fixture` structs. Optional fields (`shadowed_by`,
// `note`) are tolerated and surfaced as `undefined`.

interface ParityFixture {
  readonly pattern_id: string;
  readonly input: string;
  readonly expected_matches: readonly string[];
  readonly shadowed_by?: string;
  readonly note?: string;
}

interface ParityFile {
  readonly version: number;
  readonly description?: string;
  readonly fixtures: readonly ParityFixture[];
}

// Narrow `unknown` from the YAML parser without resorting to `any`. The
// shape is small enough that a hand-rolled guard beats schema deps.
function toParityFile(raw: unknown): ParityFile {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("parity-tests.yaml: top-level value is not an object");
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.version !== "number") {
    throw new Error("parity-tests.yaml: missing/invalid `version`");
  }
  if (!Array.isArray(obj.fixtures)) {
    throw new Error("parity-tests.yaml: missing/invalid `fixtures` array");
  }
  const fixtures: ParityFixture[] = obj.fixtures.map((entry, i) => {
    if (typeof entry !== "object" || entry === null) {
      throw new Error(`parity-tests.yaml: fixture[${i}] is not an object`);
    }
    const e = entry as Record<string, unknown>;
    if (typeof e.pattern_id !== "string") {
      throw new Error(`parity-tests.yaml: fixture[${i}].pattern_id is not a string`);
    }
    if (typeof e.input !== "string") {
      throw new Error(`parity-tests.yaml: fixture[${i}].input is not a string`);
    }
    if (!Array.isArray(e.expected_matches)) {
      throw new Error(
        `parity-tests.yaml: fixture[${i}].expected_matches is not an array`,
      );
    }
    const expected: string[] = e.expected_matches.map((m, j) => {
      if (typeof m !== "string") {
        throw new Error(
          `parity-tests.yaml: fixture[${i}].expected_matches[${j}] is not a string`,
        );
      }
      return m;
    });
    const fixture: ParityFixture = {
      pattern_id: e.pattern_id,
      input: e.input,
      expected_matches: expected,
      ...(typeof e.shadowed_by === "string" ? { shadowed_by: e.shadowed_by } : {}),
      ...(typeof e.note === "string" ? { note: e.note } : {}),
    };
    return fixture;
  });
  const file: ParityFile = {
    version: obj.version,
    ...(typeof obj.description === "string" ? { description: obj.description } : {}),
    fixtures,
  };
  return file;
}

function loadParityFile(): ParityFile {
  const raw = fs.readFileSync(PARITY_YAML_PATH, "utf8");
  const parsed: unknown = parseYaml(raw);
  return toParityFile(parsed);
}

/**
 * Collect every regex match in `text` for the single pattern carried
 * by `scanner`. The scanner's regex carries the `g` flag (enforced by
 * `compileScanner` and verified by the generator) so `String.matchAll`
 * walks left-to-right deterministically. Returns the raw match strings
 * (group 0), mirroring the Rust `match_named_all` return shape.
 *
 * Single-pattern invariant: this helper is only meaningful when the
 * scanner has exactly one pattern (the parity fixture contract). It
 * asserts the count to fail loudly if the caller mis-builds the
 * scanner (e.g., unknown id falls through `compileScanner` silently,
 * yielding zero patterns — see `text-scanner.ts:96-121`).
 */
function collectMatches(text: string, scanner: Scanner): string[] {
  if (scanner.patterns.length !== 1) {
    throw new Error(
      `parity.test: expected single-pattern scanner, got ${scanner.patterns.length} ` +
        `(likely an unknown pattern_id falling through compileScanner)`,
    );
  }
  const pattern = scanner.patterns[0];
  if (pattern === undefined) {
    throw new Error("parity.test: scanner pattern is undefined");
  }
  // Reset before iteration: the regex instance is shared across
  // `compileScanner` calls in `scanAndMask`, and a leftover `lastIndex`
  // would skip part of the input. `matchAll` requires the `g` flag.
  pattern.regex.lastIndex = 0;
  const out: string[] = [];
  for (const m of text.matchAll(pattern.regex)) {
    out.push(m[0]);
  }
  return out;
}

describe("Y09b — Rust/TS PII parity fixtures", () => {
  it("loads parity-tests.yaml with at least one fixture", () => {
    const file = loadParityFile();
    expect(file.fixtures.length).toBeGreaterThan(0);
  });

  it("covers every canonical pattern from pii-patterns/default.yaml", () => {
    // Mirror of `parity_yaml_loads_with_at_least_one_fixture_per_canonical_pattern`
    // on the Rust side — every embedded pattern must have an active
    // (non-shadowed) fixture so the gate exercises the full pack.
    const file = loadParityFile();
    const canonicalIds = DEFAULT_PATTERNS.map((p) => p.id);
    expect(canonicalIds.length).toBeGreaterThan(0);
    // Sanity-check the default.yaml file exists at the expected location
    // so a missing fixture is obviously a parity-yaml omission, not a
    // path bug. (Read kept tiny — `existsSync` would do, but a stat
    // surfaces a clearer error.)
    expect(fs.existsSync(DEFAULT_YAML_PATH)).toBe(true);

    for (const id of canonicalIds) {
      const covered = file.fixtures.some(
        (f) => f.pattern_id === id && f.shadowed_by === undefined,
      );
      expect({ id, covered }).toEqual({ id, covered: true });
    }
  });

  it("matches expected_matches exactly for every non-shadowed fixture", () => {
    const file = loadParityFile();
    let checked = 0;
    for (const fixture of file.fixtures) {
      if (fixture.shadowed_by !== undefined) {
        // Shadowed cases are intentionally skipped — see YAML header.
        continue;
      }
      const scanner = compileScanner({
        enabled: true,
        patterns: [fixture.pattern_id],
      });
      const actual = collectMatches(fixture.input, scanner);
      expect({
        pattern_id: fixture.pattern_id,
        matches: actual,
      }).toEqual({
        pattern_id: fixture.pattern_id,
        matches: [...fixture.expected_matches],
      });
      checked += 1;
    }
    expect(checked).toBeGreaterThan(0);
  });
});
