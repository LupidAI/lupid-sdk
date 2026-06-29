#!/usr/bin/env node
/**
 * Y04 — Generate `src/pii/pii-patterns-embedded.ts` from the canonical
 * `pii-patterns/default.yaml` at the repo root.
 *
 * Why a generator script rather than a runtime `fs.readFileSync` or a
 * bundler asset plugin:
 *
 *   - The SDK ships to edge runtimes (Cloudflare Workers, Vercel Edge).
 *     Static `node:fs` imports break module-load. The dynamic-import
 *     workaround would be reachable from `index.ts` via `pii/*`, which
 *     defeats the `tests/edge-entry.test.ts` regression guard.
 *   - `tsup`/`esbuild` does not natively understand `.yaml`. An asset
 *     loader plugin would be one more cross-file dep to keep parity with.
 *   - Generating a `.ts` source means the patterns embed as a plain
 *     `Uint8Array`-free literal string array. The TS file becomes part of
 *     the bundle the same way any other source does — fully tree-shaken,
 *     edge-safe, deterministic.
 *
 * Mirrors the Rust side, which does `include_str!("../../../pii-patterns/default.yaml")`
 * in `crates/agentum-dlp/src/detector.rs`. Y09's parity gate (pending)
 * will hash the YAML and assert the embed matches; until then a manual
 * `npm run prebuild` keeps the two in sync.
 *
 * Run via `npm run prebuild` (auto-fires before `npm run build`) or
 * standalone: `node scripts/generate-pii-patterns.mjs`.
 *
 * Exit codes:
 *   0  — embed written (or already up-to-date)
 *   1  — YAML missing / unparseable / schema mismatch
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse as parseYaml } from "yaml";

const HERE = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(SDK_ROOT, "..", "..");
const YAML_PATH = resolve(REPO_ROOT, "pii-patterns/default.yaml");
const OUT_PATH = resolve(SDK_ROOT, "src/pii/pii-patterns-embedded.ts");

if (!existsSync(YAML_PATH)) {
  console.error(
    `generate-pii-patterns: missing ${YAML_PATH}. The canonical pattern source ` +
      `is committed at the repo root; check that you ran this from inside the ` +
      `monorepo (sdk/typescript/).`,
  );
  process.exit(1);
}

const raw = readFileSync(YAML_PATH, "utf8");
let doc;
try {
  doc = parseYaml(raw);
} catch (err) {
  console.error(`generate-pii-patterns: failed to parse ${YAML_PATH}: ${err.message}`);
  process.exit(1);
}

if (!doc || typeof doc !== "object") {
  console.error("generate-pii-patterns: top-level YAML value is not an object");
  process.exit(1);
}
const version = doc.version;
const patterns = doc.patterns;
if (typeof version !== "number") {
  console.error("generate-pii-patterns: missing or non-numeric `version`");
  process.exit(1);
}
if (!Array.isArray(patterns)) {
  console.error("generate-pii-patterns: `patterns` is not an array");
  process.exit(1);
}

const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const normalised = [];
for (const [i, p] of patterns.entries()) {
  if (!p || typeof p !== "object") {
    console.error(`generate-pii-patterns: patterns[${i}] is not an object`);
    process.exit(1);
  }
  const { id, label, pattern, severity, description } = p;
  if (typeof id !== "string" || id.length === 0) {
    console.error(`generate-pii-patterns: patterns[${i}].id missing or non-string`);
    process.exit(1);
  }
  if (typeof pattern !== "string" || pattern.length === 0) {
    console.error(`generate-pii-patterns: patterns[${i}].pattern missing or non-string`);
    process.exit(1);
  }
  if (typeof severity !== "string" || !VALID_SEVERITIES.has(severity)) {
    console.error(
      `generate-pii-patterns: patterns[${i}].severity must be one of ` +
        `${[...VALID_SEVERITIES].join("|")} (got ${JSON.stringify(severity)})`,
    );
    process.exit(1);
  }
  normalised.push({
    id,
    label: typeof label === "string" ? label : id,
    pattern,
    severity,
    description: typeof description === "string" ? description : "",
  });
}

// Detect (?i) inline flag prefix and translate to a JS `i` flag, since
// JS RegExp doesn't accept PCRE inline flags. This mirrors what the Rust
// regex crate handles natively — TS-side we strip the prefix and tag the
// embed with the appropriate flag set.
//
// We drop the raw `pattern` field after translation: the JS embed only
// needs the regex-source + flags it actually consumes. Y09's parity gate
// reads the YAML directly to compare against the Rust side, so there is
// no need to carry the pre-translation string into the bundle.
const compiled = normalised.map((p) => {
  let regexSource = p.pattern;
  let regexFlags = "g";
  if (regexSource.startsWith("(?i)")) {
    regexSource = regexSource.slice(4);
    regexFlags = "gi";
  }
  return {
    id: p.id,
    label: p.label,
    severity: p.severity,
    description: p.description,
    regexSource,
    regexFlags,
  };
});

// Y09 — sha256 of the raw YAML bytes (NOT the parsed object). Embedded
// in the generated artifact so `scripts/check-pii-yaml-hash.sh` can diff
// the on-disk YAML against the bundled embed in CI.
const yamlSha256 = createHash("sha256").update(raw).digest("hex");

const header = `/* eslint-disable */
// AUTO-GENERATED by scripts/generate-pii-patterns.mjs from
// pii-patterns/default.yaml. DO NOT EDIT BY HAND.
//
// Y04 — embed the canonical 14 PII regex patterns at build time. Mirrors
// the Rust \`include_str!\` adoption in crates/agentum-dlp/src/detector.rs.
// Y09 (parity gate) will hash this file's source YAML and fail CI on drift.
`;

const body = `
export interface EmbeddedPattern {
  readonly id: string;
  readonly label: string;
  readonly severity: "low" | "medium" | "high" | "critical";
  readonly description: string;
  /** PCRE-derived source, with PCRE inline flags translated to JS \`flags\`. */
  readonly regexSource: string;
  /** JS RegExp flags (always includes \`g\` so iterative replace works). */
  readonly regexFlags: string;
}

export const PII_PATTERNS_YAML_VERSION = ${JSON.stringify(version)};

/**
 * Y09 — sha256 of the raw \`pii-patterns/default.yaml\` bytes the generator
 * consumed. The CI hash-check script (\`scripts/check-pii-yaml-hash.sh\`)
 * diffs this constant against a fresh \`shasum -a 256\` of the YAML on disk
 * and fails the build if they differ, catching the "edited YAML but forgot
 * to re-run \`npm run prebuild\`" footgun before parity tests even run.
 */
export const yamlSourceHash = ${JSON.stringify(yamlSha256)};

export const DEFAULT_PATTERNS: readonly EmbeddedPattern[] = ${JSON.stringify(
  compiled,
  null,
  2,
)} as const;
`;

const out = `${header}${body}`;

// Skip write if unchanged — keeps build incrementally idempotent.
if (existsSync(OUT_PATH) && readFileSync(OUT_PATH, "utf8") === out) {
  console.log(`generate-pii-patterns: up-to-date (${compiled.length} patterns)`);
  process.exit(0);
}

writeFileSync(OUT_PATH, out);
console.log(`generate-pii-patterns: wrote ${compiled.length} patterns → ${OUT_PATH}`);
