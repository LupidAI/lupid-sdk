/**
 * Y02 — parser/validator for the manifest's `pii:` block.
 *
 * Pure validation. No `node:*` imports, no I/O. Safe to evaluate on
 * edge runtimes — this file is only reached from `init.ts` (Node-only),
 * but the no-`node:*` rule still applies because the SDK's `pii/*`
 * subpath export keeps the module tree edge-clean.
 *
 * Stage in the pipeline:
 *   - `init.ts` reads the raw manifest via the existing `loadAndParse`
 *     path, then calls `parsePiiManifestBlock(rawManifest?.pii)`
 *   - On valid: the typed `PiiManifestBlock` is published via
 *     `_setActivePiiBlock` (see `./pii-state.ts`) for Y03's trie to
 *     consume at first masking call.
 *   - On invalid: throws `PiiManifestValidationError`, which init() lets
 *     propagate. The SDK fails-CLOSED at init rather than booting with a
 *     half-validated PII config — a typo in `pii.field_rules[2].path`
 *     must surface to the operator, not silently disable masking.
 *
 * JSONPath validation is intentionally lightweight at Y02: we only verify
 * the expression starts with `$.` and has balanced `[]`. A full JSONPath
 * engine ships with Y03 (the field-rule trie). Anything past syntactic
 * shape — semantic reachability, type checks against the tool arg
 * schema — is Y03 territory.
 */

import type {
  PiiManifestBlock,
  PiiFieldRule,
  PiiTextScannerConfig,
} from "../types.js";

/**
 * Thrown by {@link parsePiiManifestBlock} on any structural / syntactic
 * problem in the manifest's `pii` block. `path` is a dotted/bracketed
 * locator into the raw object (e.g. `"pii.field_rules[2].path"`); `detail`
 * is the one-line explanation. The exception message stitches both into a
 * single operator-actionable line.
 */
export class PiiManifestValidationError extends Error {
  constructor(
    public readonly validationPath: string,
    public readonly detail: string,
  ) {
    super(`pii manifest invalid at ${validationPath}: ${detail}`);
    this.name = "PiiManifestValidationError";
  }
}

const VALID_FIELD_MODES = new Set<PiiFieldRule["mode"]>([
  "drop",
  "hash",
  "tokenize",
  "mask",
]);

const VALID_SEVERITIES = new Set(["low", "medium", "high"]);

/**
 * Validate + narrow a raw manifest's `pii` block into the SDK's typed
 * shape.
 *
 * Returns an empty `PiiManifestBlock` (`{}`) for `null`/`undefined`
 * inputs so manifests that simply omit the `pii:` section boot
 * unchanged. Any structural mismatch — wrong top-level type, bad
 * field-rule shape, bad JSONPath, unknown mode — throws.
 */
export function parsePiiManifestBlock(raw: unknown): PiiManifestBlock {
  if (raw === null || raw === undefined) {
    return {};
  }
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new PiiManifestValidationError(
      "pii",
      `expected object, got ${describe(raw)}`,
    );
  }
  const obj = raw as Record<string, unknown>;
  const out: PiiManifestBlock = {};

  if (obj["field_rules"] !== undefined) {
    const fr = obj["field_rules"];
    if (!Array.isArray(fr)) {
      throw new PiiManifestValidationError(
        "pii.field_rules",
        `expected array, got ${describe(fr)}`,
      );
    }
    out.field_rules = fr.map((entry, i) =>
      validateFieldRule(entry, `pii.field_rules[${i}]`),
    );
  }

  if (obj["text_scanners"] !== undefined) {
    const ts = obj["text_scanners"];
    if (!Array.isArray(ts)) {
      throw new PiiManifestValidationError(
        "pii.text_scanners",
        `expected array, got ${describe(ts)}`,
      );
    }
    out.text_scanners = ts.map((entry, i) =>
      validateTextScanner(entry, `pii.text_scanners[${i}]`),
    );
  }

  return out;
}

function validateFieldRule(raw: unknown, path: string): PiiFieldRule {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PiiManifestValidationError(
      path,
      `expected object, got ${describe(raw)}`,
    );
  }
  const obj = raw as Record<string, unknown>;

  const tool = obj["tool"];
  if (typeof tool !== "string" || tool.length === 0) {
    throw new PiiManifestValidationError(
      `${path}.tool`,
      `expected non-empty string, got ${describe(tool)}`,
    );
  }

  const rulePath = obj["path"];
  if (typeof rulePath !== "string" || rulePath.length === 0) {
    throw new PiiManifestValidationError(
      `${path}.path`,
      `expected non-empty string, got ${describe(rulePath)}`,
    );
  }
  assertJsonPathSyntax(rulePath, `${path}.path`);

  const mode = obj["mode"];
  if (typeof mode !== "string" || !VALID_FIELD_MODES.has(mode as PiiFieldRule["mode"])) {
    throw new PiiManifestValidationError(
      `${path}.mode`,
      `expected one of ${Array.from(VALID_FIELD_MODES).join("|")}, got ${describe(mode)}`,
    );
  }

  return {
    tool,
    path: rulePath,
    mode: mode as PiiFieldRule["mode"],
  };
}

function validateTextScanner(raw: unknown, path: string): PiiTextScannerConfig {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PiiManifestValidationError(
      path,
      `expected object, got ${describe(raw)}`,
    );
  }
  const obj = raw as Record<string, unknown>;

  const enabled = obj["enabled"];
  if (typeof enabled !== "boolean") {
    throw new PiiManifestValidationError(
      `${path}.enabled`,
      `expected boolean, got ${describe(enabled)}`,
    );
  }

  const out: PiiTextScannerConfig = { enabled };

  if (obj["patterns"] !== undefined) {
    const p = obj["patterns"];
    if (!Array.isArray(p)) {
      throw new PiiManifestValidationError(
        `${path}.patterns`,
        `expected array, got ${describe(p)}`,
      );
    }
    p.forEach((id, i) => {
      if (typeof id !== "string" || id.length === 0) {
        throw new PiiManifestValidationError(
          `${path}.patterns[${i}]`,
          `expected non-empty string, got ${describe(id)}`,
        );
      }
    });
    out.patterns = p as string[];
  }

  if (obj["custom"] !== undefined) {
    const custom = obj["custom"];
    if (!Array.isArray(custom)) {
      throw new PiiManifestValidationError(
        `${path}.custom`,
        `expected array, got ${describe(custom)}`,
      );
    }
    out.custom = custom.map((entry, i) =>
      validateCustomPattern(entry, `${path}.custom[${i}]`),
    );
  }

  return out;
}

function validateCustomPattern(
  raw: unknown,
  path: string,
): { id: string; pattern: string; severity?: "low" | "medium" | "high" } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PiiManifestValidationError(
      path,
      `expected object, got ${describe(raw)}`,
    );
  }
  const obj = raw as Record<string, unknown>;

  const id = obj["id"];
  if (typeof id !== "string" || id.length === 0) {
    throw new PiiManifestValidationError(
      `${path}.id`,
      `expected non-empty string, got ${describe(id)}`,
    );
  }

  const pattern = obj["pattern"];
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new PiiManifestValidationError(
      `${path}.pattern`,
      `expected non-empty string, got ${describe(pattern)}`,
    );
  }

  const out: { id: string; pattern: string; severity?: "low" | "medium" | "high" } = {
    id,
    pattern,
  };

  if (obj["severity"] !== undefined) {
    const sev = obj["severity"];
    if (typeof sev !== "string" || !VALID_SEVERITIES.has(sev)) {
      throw new PiiManifestValidationError(
        `${path}.severity`,
        `expected one of low|medium|high, got ${describe(sev)}`,
      );
    }
    out.severity = sev as "low" | "medium" | "high";
  }

  return out;
}

/**
 * Lightweight JSONPath syntactic gate.
 *
 * Y02 only needs to reject manifestly-broken expressions before they reach
 * the trie compiler — the full traversal engine (which would parse
 * `$.foo[?(@.bar > 1)]` filters and `$..` recursive descent) lands in Y03.
 *
 * Rules enforced here:
 *   - must start with `$.` (canonical JSONPath root); a leading `$` alone
 *     (no dot) is rejected so an obvious typo like `$args.email` fails
 *     fast instead of being misread as a JSON-pointer.
 *   - `[` and `]` must be balanced; nesting is allowed.
 *
 * Anything richer (e.g. valid bracket-notation predicates) is accepted
 * leniently — Y03 owns the real grammar.
 */
function assertJsonPathSyntax(expr: string, locator: string): void {
  if (!expr.startsWith("$.")) {
    throw new PiiManifestValidationError(
      locator,
      `not a valid JSONPath expression (must start with "$."): ${expr}`,
    );
  }
  let depth = 0;
  for (let i = 0; i < expr.length; i += 1) {
    const c = expr[i];
    if (c === "[") {
      depth += 1;
    } else if (c === "]") {
      depth -= 1;
      if (depth < 0) {
        throw new PiiManifestValidationError(
          locator,
          `unbalanced "]" in JSONPath expression: ${expr}`,
        );
      }
    }
  }
  if (depth !== 0) {
    throw new PiiManifestValidationError(
      locator,
      `unbalanced "[" in JSONPath expression: ${expr}`,
    );
  }
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
