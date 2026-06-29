#!/usr/bin/env node
/**
 * S1-12a — Cross-validator parity gate.
 *
 * Iterates the shared `reject_cases.json` fixture, feeds each YAML
 * input to both the Rust `validate-cli` binary and the TS
 * `parseAndValidate`, and asserts:
 *
 *   1. Rust emits the expected `code`.
 *   2. TS emits the expected `code`.
 *   3. The two sides agree.
 *
 * Also runs `enterprise_v3.yaml` through both validators and asserts both
 * accept (no issues).
 *
 * No external deps beyond Node 20 + the SDK's own `yaml` dep — the
 * script is invoked from `.github/workflows/identity-schema-parity.yml`
 * after `npm run build` and `cargo build`.
 *
 * Environment:
 *   RUST_VALIDATE_CLI — absolute path to the Rust validator binary.
 *                       Defaults to `<repo>/target/release/validate-cli`.
 *
 * Exit codes:
 *   0  — all cases passed
 *   1  — at least one mismatch (logged to stderr)
 *   2  — harness error (binary missing, fixture corrupt, etc.)
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse as parseYaml } from "yaml";

// The SDK ships as a single CJS/ESM bundle via tsup; `parseAndValidate`
// is re-exported from `dist/index.mjs` (added in S1-12a so external
// tooling has a stable import surface). If the bundle is missing we
// fail fast with a concrete error rather than a cryptic import.
const HERE = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(HERE, "..");
const DIST_INDEX = resolve(SDK_ROOT, "dist/index.mjs");
if (!existsSync(DIST_INDEX)) {
  console.error(
    `parity-check: missing built SDK bundle at ${DIST_INDEX}. Run \`npm run build\` first.`,
  );
  process.exit(2);
}
const { parseAndValidate } = await import(DIST_INDEX);
if (typeof parseAndValidate !== "function") {
  console.error(
    `parity-check: \`parseAndValidate\` is not exported from ${DIST_INDEX}; expected a function.`,
  );
  process.exit(2);
}

const REJECT_PATH = resolve(
  SDK_ROOT,
  "tests/manifest/fixtures/reject_cases.json",
);
const ENTERPRISE_YAML_PATH = resolve(
  SDK_ROOT,
  "tests/manifest/fixtures/enterprise_v3.yaml",
);

const RUST_BIN =
  process.env.RUST_VALIDATE_CLI ??
  resolve(SDK_ROOT, "../../target/release/validate-cli");
if (!existsSync(RUST_BIN)) {
  console.error(
    `parity-check: missing Rust validator at ${RUST_BIN}. Run \`cargo build --release -p agentum-identity-schema --bin validate-cli\` first, or set RUST_VALIDATE_CLI.`,
  );
  process.exit(2);
}

/** Invoke the Rust binary with `yamlInput` on stdin. Returns `{ ok, code? }`. */
function runRust(yamlInput) {
  const r = spawnSync(RUST_BIN, [], {
    input: yamlInput,
    encoding: "utf8",
    timeout: 5000,
  });
  if (r.status !== 0) {
    throw new Error(
      `Rust validator exited ${r.status}: ${r.stderr || "(no stderr)"}`,
    );
  }
  const line = (r.stdout || "").trim();
  try {
    return JSON.parse(line);
  } catch {
    throw new Error(`Rust validator stdout was not JSON: ${line}`);
  }
}

/** Invoke the TS validator. Returns `{ ok, code? }`. */
function runTs(yamlInput) {
  let parsed;
  try {
    parsed = parseYaml(yamlInput);
  } catch {
    return { ok: false, code: "Yaml" };
  }
  try {
    parseAndValidate(parsed);
    return { ok: true };
  } catch (e) {
    // ManifestValidationError exposes `issues: ValidationIssue[]`.
    const code = e?.issues?.[0]?.code ?? "Validation";
    return { ok: false, code };
  }
}

/** Pretty-print a one-line result. */
function fmt(r) {
  return r.ok ? "accept" : `reject:${r.code}`;
}

// ── 1. Reject corpus ─────────────────────────────────────────────────
const rejectCases = JSON.parse(readFileSync(REJECT_PATH, "utf8"));
if (!Array.isArray(rejectCases) || rejectCases.length === 0) {
  console.error(`parity-check: ${REJECT_PATH} is empty or not an array`);
  process.exit(2);
}

// Pre-flight: duplicate-name detection — corrupt fixture is an
// operator error, not a parity failure.
const seenNames = new Set();
for (const c of rejectCases) {
  if (seenNames.has(c.name)) {
    console.error(`parity-check: duplicate case name in fixture: ${c.name}`);
    process.exit(2);
  }
  seenNames.add(c.name);
}

let failed = 0;
let passed = 0;
for (const c of rejectCases) {
  const rust = runRust(c.yaml);
  const ts = runTs(c.yaml);
  const expected = { ok: false, code: c.expected_code };

  const rustOk =
    rust.ok === expected.ok &&
    (rust.ok || rust.code === expected.code);
  const tsOk =
    ts.ok === expected.ok && (ts.ok || ts.code === expected.code);

  if (!rustOk || !tsOk) {
    failed++;
    console.error(
      `[FAIL] ${c.name}: expected=${fmt(expected)} rust=${fmt(rust)} ts=${fmt(ts)}`,
    );
  } else {
    passed++;
  }
}

// ── 2. Accept corpus — Enterprise v3 manifest ────────────────────────────
const enterpriseYaml = readFileSync(ENTERPRISE_YAML_PATH, "utf8");
const rustAcme = runRust(enterpriseYaml);
const tsAcme = runTs(enterpriseYaml);
if (!rustAcme.ok) {
  failed++;
  console.error(
    `[FAIL] enterprise_v3 accept (rust): expected accept, got ${fmt(rustAcme)}`,
  );
}
if (!tsAcme.ok) {
  failed++;
  console.error(
    `[FAIL] enterprise_v3 accept (ts): expected accept, got ${fmt(tsAcme)}`,
  );
}
if (rustAcme.ok && tsAcme.ok) {
  passed++;
}

// ── 3. Summary ───────────────────────────────────────────────────────
const total = rejectCases.length + 1;
if (failed === 0) {
  console.log(`parity-check: ${passed}/${total} cases agree`);
  process.exit(0);
}
console.error(`parity-check: ${failed} failure(s) across ${total} cases`);
process.exit(1);
