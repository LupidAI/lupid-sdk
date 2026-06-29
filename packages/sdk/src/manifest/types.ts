/**
 * TypeScript port of the Rust tenant-schema types.
 *
 * Strict mirror of `crates/agentum-identity-schema/src/schema.rs:11-121` and
 * `crates/agentum-identity-schema/src/source.rs`. The shapes must round-trip
 * losslessly through the wire envelope returned by
 * `GET /api/v1/agents/{agent_id}/schema` (per-agent).
 *
 * Validation rule numbers cited in the SDK validator
 * (`sdk/typescript/src/manifest/validator.ts`) map 1-for-1 to the Rust
 * `SchemaError` variants in `crates/agentum-identity-schema/src/error.rs` so
 * the parity-fixture pipeline (`tests/manifest/fixtures/reject_cases.json`)
 * can compare diagnostics by `code` string.
 */

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:41-47`. */
export type PiiMode = "none" | "hash" | "tokenize" | "drop";

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:89-94`. */
export type WhenMissing = "reject" | "null" | "default";

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:107-112`. */
export type CedarType = "String" | "Long" | "Boolean";

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:142-145`. */
export type FailureMode = "fail_open" | "fail_closed";

/**
 * Source discriminated union.
 *
 * Mirrors `crates/agentum-identity-schema/src/source.rs:5-24`. The Rust
 * serde tag is `kind` with `rename_all = "snake_case"`; the TS shape
 * matches byte-for-byte.
 */
export type Source =
  | { kind: "context"; path: string }
  | {
      kind: "request_header";
      header: string;
      when_missing?: WhenMissing;
    }
  | {
      kind: "derived";
      template: string;
      enum_values?: string[];
    }
  | { kind: "enrichment"; enrichment_ref: string };

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:97-103`. */
export interface CedarBinding {
  attribute: string;
  /**
   * The Rust serde accepts both `type` and `cedar_type` keys via `alias`.
   * The SDK only sees the wire shape post-server-canonicalisation, which is
   * `cedar_type` on the way out, but local YAML manifests authored by
   * operators often use the arch-spec field name `type`. Both are accepted.
   */
  cedar_type?: CedarType;
  /** Arch-spec alias for `cedar_type`. */
  type?: CedarType;
  /** Canonical name; the spec YAML uses `enum`. */
  enum_values?: string[];
  /** Arch-spec alias for `enum_values`. */
  enum?: string[];
}

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:114-121`. */
export interface ClickhouseHint {
  column: string;
  /** Defaults to `LowCardinality(String)` on the Rust side. */
  codec?: string;
  /** Defaults to `true` on the Rust side. */
  materialized?: boolean;
}

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:22-37`. */
export interface Dimension {
  name: string;
  source: Source;
  scoping?: boolean;
  required?: boolean;
  cedar?: CedarBinding;
  clickhouse?: ClickhouseHint;
  /** Defaults to `"none"` on the Rust side. */
  pii?: PiiMode;
  /** Defaults to `"reject"` on the Rust side. */
  when_missing?: WhenMissing;
}

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:130-138`. */
export interface EnrichmentDef {
  kind: string;
  url: string;
  /**
   * The Rust struct uses `timeout_ms: u32`. The arch-spec YAML uses
   * `timeout: 250ms`; the validator does not normalise that today, so for
   * SDK-side validation we accept whatever the server returned.
   */
  timeout_ms?: number;
  on_failure?: FailureMode;
  include_dimensions?: string[];
  /**
   * The arch-spec carries auth/cache/request/response blocks. The slim Rust
   * struct ignores them. We keep them as `unknown`-typed passthrough so
   * round-trip is lossless; SDK callers should not depend on these fields.
   */
  [extra: string]: unknown;
}

/** Mirrors `crates/agentum-identity-schema/src/schema.rs:11-19`. */
export interface TenantSchema {
  version: number;
  scoping_dimension?: string;
  dimensions: Dimension[];
  enrichments?: Record<string, EnrichmentDef>;
}
