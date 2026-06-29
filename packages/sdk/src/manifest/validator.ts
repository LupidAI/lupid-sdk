/**
 * Client-side validator for `TenantSchema`.
 *
 * Implements the 7 SDK-applicable rules from Spec 1
 * (`.claude/plan/IDENTITY_SCHEMA_PRIMITIVE.md:172-183`). Rules 7 (dropped-
 * dimension data-loss window) and 8 (scoping change requires migration
 * plan) are install-time, two-schema diffs and live in the Rust
 * `TenantSchema::diff_against` — the SDK MUST NOT attempt them because it
 * does not have access to the previously-installed schema.
 *
 * Each rule emits a `ValidationIssue` with a `code` string that mirrors
 * the Rust `SchemaError` variant name 1-for-1, so the shared
 * `reject_cases.json` parity fixture compares diagnostics byte-for-byte.
 *
 * MIRROR map:
 *   Rule 1 → `crates/agentum-identity-schema/src/parse.rs:159-186`
 *   Rule 2 → `crates/agentum-identity-schema/src/parse.rs:189-197`
 *   Rule 3 → `crates/agentum-identity-schema/src/parse.rs:200-210`
 *   Rule 4 → `crates/agentum-identity-schema/src/parse.rs:213-226`
 *   Rule 5 → `crates/agentum-identity-schema/src/parse.rs:230-244`
 *   Rule 6 → `crates/agentum-identity-schema/src/parse.rs:247-256`
 *   Rule 9 → `crates/agentum-identity-schema/src/parse.rs:263-287`
 *   Rule 10 → `crates/agentum-identity-schema/src/parse.rs:293-308`
 */

import { ManifestValidationError } from "./errors.js";
import type {
  CedarBinding,
  CedarType,
  PiiMode,
  Source,
  TenantSchema,
} from "./types.js";
import type { ValidationIssue, ValidationIssueCode } from "./errors.js";

/**
 * Byte-exact mirror of the Rust regex at
 * `crates/agentum-identity-schema/src/parse.rs:316` —
 * `^[a-z][a-z0-9_]{0,31}$`.
 *
 * Drift here would break the parity-fixture contract.
 */
const DIMENSION_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;

/** Matches `${name}` and `${name | filter ...}` chunks. Same shape Rust uses. */
const DERIVED_VAR_RE = /\$\{\s*([a-z][a-z0-9_]{0,31})\s*(?:\||})/g;

/**
 * Parse a wire-shape JSON value or already-parsed YAML object into a
 * validated `TenantSchema`. Throws `ManifestValidationError` if any of the
 * 7 SDK rules fail.
 *
 * Accepts `unknown` so callers can pipe in the raw YAML / HTTP body.
 */
export function parseAndValidate(raw: unknown): TenantSchema {
  const issues: ValidationIssue[] = [];
  const schema = coerceSchema(raw, issues);
  if (issues.length > 0) {
    throw new ManifestValidationError(issues);
  }
  // `schema` is non-null when issues are empty (coerceSchema invariant).
  const s = schema as TenantSchema;
  const out = validate(s);
  if (out.length > 0) {
    throw new ManifestValidationError(out);
  }
  return s;
}

/**
 * Run the 7 SDK-applicable rules. Returns all issues found rather than
 * short-circuiting on the first — the parity fixtures pin one rule per
 * case so this is mostly cosmetic, but it makes operator output friendlier.
 */
export function validate(schema: TenantSchema): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  rule1ScopingExactlyOne(schema, issues);
  rule2DimensionNames(schema, issues);
  rule3CedarAttributeUniqueness(schema, issues);
  rule4ClickhouseColumns(schema, issues);
  rule5DerivedReferences(schema, issues);
  rule6EnrichmentRef(schema, issues);
  rule9PiiNeedsCedar(schema, issues);
  rule10MaterializedCount(schema, issues);
  ruleWhenMissingEnum(schema, issues);
  return issues;
}

// ---------------------------------------------------------------------------
// Shape coercion — narrow `unknown` into `TenantSchema`. Anything that fails
// here is a structural problem the Rust parser would surface as
// `SchemaError::Validation(...)` after `serde` deserialisation. We treat
// these as validator issues so the parity fixture can pin them.
// ---------------------------------------------------------------------------

function coerceSchema(raw: unknown, issues: ValidationIssue[]): TenantSchema | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    issues.push({
      code: "Validation",
      path: "",
      message:
        "tenant-schema root must be a YAML object with `version`, `dimensions`, " +
        "and (optionally) `scoping_dimension`. Got " +
        (raw === null ? "null" : Array.isArray(raw) ? "an array" : typeof raw),
    });
    return null;
  }
  const o = raw as Record<string, unknown>;

  if (typeof o["version"] !== "number") {
    issues.push({
      code: "Validation",
      path: "version",
      message: "`version` must be a number (tenant-schema version)",
    });
    return null;
  }
  if (!Array.isArray(o["dimensions"])) {
    issues.push({
      code: "InvalidDimensionName",
      path: "dimensions",
      message: "`dimensions` must be an array",
    });
    return null;
  }

  return raw as TenantSchema;
}

// ---------------------------------------------------------------------------
// Rule implementations.
// ---------------------------------------------------------------------------

/**
 * Rule 1 — at most one dimension flagged `scoping: true`, and if any is
 * flagged, it must match `scoping_dimension`. Surfaces as two distinct
 * Rust error variants so we mirror both codes.
 */
function rule1ScopingExactlyOne(s: TenantSchema, issues: ValidationIssue[]): void {
  const scoping = s.dimensions
    .map((d, i) => ({ dim: d, idx: i }))
    .filter((e) => e.dim.scoping === true);

  if (scoping.length > 1) {
    issue(issues, "MultipleScopingDimensions", "dimensions", `multiple scoping dimensions (max 1)`);
    return;
  }

  const declared = s.scoping_dimension;
  const first = scoping[0];
  if (first && declared !== undefined && first.dim.name !== declared) {
    issue(
      issues,
      "UnknownScopingDimension",
      "scoping_dimension",
      `scoping dimension '${declared}' not found in dimensions list`,
    );
  } else if (first && declared === undefined) {
    issue(
      issues,
      "UnknownScopingDimension",
      `dimensions[${first.idx}].scoping`,
      `scoping dimension '${first.dim.name}' not found in dimensions list`,
    );
  } else if (!first && declared !== undefined) {
    issue(
      issues,
      "UnknownScopingDimension",
      "scoping_dimension",
      `scoping dimension '${declared}' not found in dimensions list`,
    );
  }
}

/** Rule 2 — `^[a-z][a-z0-9_]{0,31}$`. */
function rule2DimensionNames(s: TenantSchema, issues: ValidationIssue[]): void {
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d) continue;
    if (typeof d.name !== "string" || !DIMENSION_NAME_RE.test(d.name)) {
      issue(
        issues,
        "InvalidDimensionName",
        `dimensions[${i}].name`,
        `invalid dimension name '${d.name}': must match [a-z][a-z0-9_]{0,31}`,
      );
    }
  }
}

/** Rule 3 — Cedar attribute uniqueness. */
function rule3CedarAttributeUniqueness(s: TenantSchema, issues: ValidationIssue[]): void {
  const seen = new Set<string>();
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d) continue;
    const attr = cedarAttribute(d.cedar);
    if (attr === undefined) continue;
    if (seen.has(attr)) {
      issue(
        issues,
        "DuplicateCedarAttribute",
        `dimensions[${i}].cedar.attribute`,
        `duplicate cedar attribute '${attr}'`,
      );
    } else {
      seen.add(attr);
    }
  }
}

/** Rule 4 — ClickHouse columns unique and `dim_`-prefixed. */
function rule4ClickhouseColumns(s: TenantSchema, issues: ValidationIssue[]): void {
  const seen = new Set<string>();
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d || !d.clickhouse) continue;
    const col = d.clickhouse.column;
    if (typeof col !== "string") {
      issue(
        issues,
        "InvalidClickhouseColumnPrefix",
        `dimensions[${i}].clickhouse.column`,
        `clickhouse column must be a string`,
      );
      continue;
    }
    if (!col.startsWith("dim_")) {
      issue(
        issues,
        "InvalidClickhouseColumnPrefix",
        `dimensions[${i}].clickhouse.column`,
        `clickhouse column '${col}' must start with 'dim_'`,
      );
      continue;
    }
    if (seen.has(col)) {
      issue(
        issues,
        "DuplicateClickhouseColumn",
        `dimensions[${i}].clickhouse.column`,
        `duplicate clickhouse column '${col}'`,
      );
    } else {
      seen.add(col);
    }
  }
}

/**
 * Rule 5 — derived templates only reference earlier-declared dimensions.
 * This naturally rejects forward refs, self-refs, and 2-cycles (the Rust
 * test cases at `parse.rs:517-568`).
 */
function rule5DerivedReferences(s: TenantSchema, issues: ValidationIssue[]): void {
  const seen = new Set<string>();
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d) continue;
    const src = d.source;
    if (src && src.kind === "derived" && typeof src.template === "string") {
      const refs = parseDerivedReferences(src.template);
      for (const ref of refs) {
        if (!seen.has(ref)) {
          issue(
            issues,
            "DerivedReferenceMissing",
            `dimensions[${i}].source.template`,
            `derived template references undeclared dimension '${ref}'`,
          );
          break; // mirror Rust short-circuit on first missing ref
        }
      }
    }
    if (typeof d.name === "string") seen.add(d.name);
  }
}

/** Rule 6 — `enrichment_ref` resolvable. */
function rule6EnrichmentRef(s: TenantSchema, issues: ValidationIssue[]): void {
  const enrichments = s.enrichments ?? {};
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d) continue;
    const src = d.source;
    if (src && src.kind === "enrichment") {
      const ref = src.enrichment_ref;
      if (typeof ref !== "string" || !(ref in enrichments)) {
        issue(
          issues,
          "UnknownEnrichmentRef",
          `dimensions[${i}].source.enrichment_ref`,
          `enrichment_ref '${ref}' has no matching enrichment block`,
        );
      }
    }
  }
}

/**
 * Rule 9 — `pii: hash | tokenize` requires a Cedar binding AND that binding
 * must be `String`-typed. Surfaces as two distinct codes; both mirror Rust.
 */
function rule9PiiNeedsCedar(s: TenantSchema, issues: ValidationIssue[]): void {
  for (let i = 0; i < s.dimensions.length; i++) {
    const d = s.dimensions[i];
    if (!d) continue;
    const pii: PiiMode = d.pii ?? "none";
    const masked = pii === "hash" || pii === "tokenize";
    if (!masked) continue;

    if (!d.cedar) {
      issue(
        issues,
        "PiiRequiresCedarAttribute",
        `dimensions[${i}].cedar`,
        `pii '${pii}' on '${d.name}' requires a cedar binding`,
      );
      continue;
    }
    const ct = cedarTypeOf(d.cedar);
    if (ct !== "String") {
      issue(
        issues,
        "PiiCedarTypeMismatch",
        `dimensions[${i}].cedar.cedar_type`,
        `pii '${pii}' on '${d.name}' requires cedar_type=String, got '${ct ?? "<unset>"}'`,
      );
    }
  }
}

/**
 * G13 — TS/Rust parity: server's `WhenMissing` enum is strictly
 * `reject | null | default`. Without this rule the TS validator accepts
 * any string (e.g. `"nullify"`) and the SDK boots happily until the
 * eventual server-side install rejects with `unknown variant`. Reject
 * here so the error surfaces at parse time with the field path.
 */
function ruleWhenMissingEnum(s: TenantSchema, issues: ValidationIssue[]): void {
  const ALLOWED = new Set(["reject", "null", "default"]);
  for (let i = 0; i < s.dimensions.length; i++) {
    const wm = (s.dimensions[i] as { when_missing?: unknown }).when_missing;
    if (wm !== undefined && (typeof wm !== "string" || !ALLOWED.has(wm))) {
      issue(
        issues,
        "Validation",
        `dimensions[${i}].when_missing`,
        `when_missing must be one of ${Array.from(ALLOWED).map((s) => `"${s}"`).join(" | ")}; got ${JSON.stringify(wm)}`,
      );
    }
  }
}

/** Rule 10 — materialised column count ≤ 24. */
function rule10MaterializedCount(s: TenantSchema, issues: ValidationIssue[]): void {
  let count = 0;
  for (const d of s.dimensions) {
    if (d.clickhouse && (d.clickhouse.materialized ?? true)) count += 1;
  }
  if (count > 24) {
    issue(
      issues,
      "TooManyMaterialized",
      "dimensions",
      `too many materialized dimensions (${count} > 24); mark some clickhouse.materialized: false`,
    );
  }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

function issue(
  out: ValidationIssue[],
  code: ValidationIssueCode,
  path: string,
  message: string,
): void {
  out.push({ code, path, message });
}

function cedarAttribute(c: CedarBinding | undefined): string | undefined {
  if (!c) return undefined;
  if (typeof c.attribute !== "string") return undefined;
  return c.attribute;
}

function cedarTypeOf(c: CedarBinding): CedarType | undefined {
  // The Rust serde accepts both `cedar_type` and `type` (alias). The SDK
  // accepts the same — operator-authored YAML often uses `type`.
  return c.cedar_type ?? c.type;
}

/**
 * Extract the dimension names referenced by a derived template.
 *
 * The Rust template grammar (`crates/agentum-identity-schema/src/derive.rs`)
 * is richer (filters like `regex_extract`, `default`, `lowercase`), but for
 * Rule 5 we only need the set of referenced dimension names — which all
 * appear as `${name | ...}` or `${name}` at the start of an expression.
 */
function parseDerivedReferences(template: string): string[] {
  const refs: string[] = [];
  let m: RegExpExecArray | null;
  // Reset lastIndex in case the regex was reused.
  DERIVED_VAR_RE.lastIndex = 0;
  while ((m = DERIVED_VAR_RE.exec(template)) !== null) {
    const name = m[1];
    if (name !== undefined) refs.push(name);
  }
  return refs;
}

// `Source` re-export for tests that want to construct fixture values
// directly without going through YAML. Internal-only.
export type { Source };
