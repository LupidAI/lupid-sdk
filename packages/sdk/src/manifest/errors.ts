/**
 * Error types for the manifest loader / validator / version-negotiation
 * pipeline.
 *
 * `ManifestError` covers loader-side problems (file not found, multiple
 * `.lupid.yaml`, YAML parse failure) and is also raised by `client.ts`
 * for unexpected transport shapes.
 *
 * `ManifestValidationError` carries a list of `ValidationIssue`s with
 * stable `code` strings that mirror the Rust `SchemaError` variant names
 * 1-for-1 — see `crates/agentum-identity-schema/src/error.rs`.
 *
 * `InitError` is the SDK-wide init-time failure used by `reconcile.ts`
 * when version negotiation rejects a local manifest, and elsewhere by
 * the manifest pipeline.
 */

import { AgentumError } from "../types.js";

/**
 * Codes mirror Rust `SchemaError` variant names 1-for-1.
 *
 * See `crates/agentum-identity-schema/src/error.rs` for the canonical list.
 * Rules 1's two failure modes surface as `MultipleScopingDimensions` and
 * `UnknownScopingDimension` (matching the Rust variants); rules 7 and 8 are
 * server-side only and not present in this union.
 */
export type ValidationIssueCode =
  | "MultipleScopingDimensions"
  | "UnknownScopingDimension"
  | "InvalidDimensionName"
  | "DuplicateCedarAttribute"
  | "DuplicateClickhouseColumn"
  | "InvalidClickhouseColumnPrefix"
  | "DerivedReferenceMissing"
  | "UnknownEnrichmentRef"
  | "PiiRequiresCedarAttribute"
  | "PiiCedarTypeMismatch"
  | "TooManyMaterialized"
  // Mirrors of the Rust `SchemaError` variants that surface from
  // `SchemaError::code()` but did not historically have a TS-side
  // structural rule. The parity script (and the future `parseYaml`
  // surface) emits these strings; including them in the union keeps
  // literal-typed assignments and the parity fixture in sync.
  | "Yaml"
  | "Validation"
  | "DerivedTemplate";

export interface ValidationIssue {
  code: ValidationIssueCode;
  /** Dot-path into the parsed object (e.g. `dimensions[3].cedar.attribute`). */
  path: string;
  message: string;
}

/**
 * Recoverable / unrecoverable problems on the loader and HTTP-client side
 * that are NOT validation issues (validation gets its own error type below).
 *
 * Extends `AgentumError` so callers that already catch the SDK error base
 * pick this up.
 */
export class ManifestError extends AgentumError {
  constructor(message: string, body?: unknown) {
    super(message, undefined, body);
    this.name = "ManifestError";
  }
}

/**
 * Thrown by `parseAndValidate` when at least one of the 7 SDK-side validation
 * rules fails (rules 1-6, 9, 10 — see
 * `crates/agentum-identity-schema/src/parse.rs:73-82` for the canonical
 * rule list).
 */
export class ManifestValidationError extends ManifestError {
  public readonly issues: ValidationIssue[];

  constructor(issues: ValidationIssue[]) {
    // Surface the first issue's message so the line operators actually see
    // names the failing field — the bare code list ("Validation, Validation")
    // doesn't tell anyone where to look. Falls back to the code list when
    // the issue has no message (defensive — every issue today carries one).
    const head = issues[0];
    const detail = head?.message
      ? `${head.code}${head.path ? ` at \`${head.path}\`` : ""}: ${head.message}`
      : issues.map((i) => i.code).join(", ");
    const tail = issues.length > 1 ? ` (+${issues.length - 1} more)` : "";
    super(`tenant-schema validation failed: ${detail}${tail}`);
    this.name = "ManifestValidationError";
    this.issues = issues;
  }
}

/**
 * Init-time refusal. Raised by `reconcileVersions` when the local manifest
 * is behind the live schema (would emit unschema'd events), and by
 * `getActiveSchema` when called before `init()`.
 */
export class InitError extends AgentumError {
  constructor(message: string) {
    super(message);
    this.name = "InitError";
  }
}
