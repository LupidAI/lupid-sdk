/**
 * Types mirroring the Lupid capability-registry API response shape.
 *
 * Source of truth: `crates/agentum-api/src/routes/capabilities.rs` —
 * `CapabilityNode`, `CapabilityListResponse`, `ToggleResponse`.
 *
 * Z3 contract (Q-A pin): the API returns a FLAT list with `parent_id`
 * pointers — the React component reconstructs the tree client-side via
 * {@link import("./tree.js").buildTree}.
 */

/** One row in the catalog of capabilities for a (tenant, agent, scope). */
export interface CapabilityNode {
  /** Stable capability identifier, e.g. `cap.web_search`. */
  id: string;
  /** Parent capability id, or `null` for a root. */
  parent_id: string | null;
  /** Human-readable label; `null` if the manifest omits it. */
  display: string | null;
  /** Free-text description; `null` if the manifest omits it. */
  description: string | null;
  /** Risk tier — DB-CHECK enforces one of the three. */
  risk: "low" | "medium" | "high";
  /**
   * If `false`, the capability is system-only; the API rejects PUT on it.
   * The UI should not render a toggle for hidden caps.
   */
  customer_visible: boolean;
  /** Catalog default for this cap. */
  default: "enabled" | "disabled";
  /**
   * True iff the effective-set resolver yields ON for this cap in the
   * requested scope. This is what the resolver computes from
   * (default ⊕ override ⊕ ancestor ⊕ requires).
   */
  effective: boolean;
  /**
   * The operator's explicit override, when one exists. `null` means the
   * customer has not toggled this cap in this scope (default holds).
   */
  override_value: boolean | null;
}

/** The scope a list response is anchored to. Absent on the `/defaults` view. */
export interface ScopeIdentity {
  dimension: string;
  value: string;
}

/** Response of GET `…/capabilities/` and GET `…/capabilities/defaults`. */
export interface CapabilityListResponse {
  tenant_id: string;
  agent_name: string;
  /** Absent on the defaults response (no scope context). */
  scope?: ScopeIdentity;
  capabilities: CapabilityNode[];
}

/** Cascade preview returned by PUT/DELETE responses. */
export interface SideEffects {
  /** Caps whose effective state dropped ON→OFF via the parent-id chain. */
  descendants_now_effective_off: string[];
  /** Caps whose effective state dropped ON→OFF via a `requires_caps` dep. */
  dependents_now_effective_off: string[];
}

/** Response shape for PUT/DELETE/bulk POST. */
export interface ToggleResponse {
  /** The new effective-ON set after the toggle commit. */
  new_effective_set: string[];
  side_effects: SideEffects;
  /** Human-readable from-state (e.g. `"effective_on"`). */
  from_state: string;
  /** Human-readable to-state. */
  to_state: string;
}

/**
 * The closed set of error codes Lupid surfaces to a host BFF.
 *
 * - `scope_dimension_mismatch` — path dimension doesn't match the agent
 *   manifest's declared scoping dimension. Operator picked the wrong scope.
 * - `dimension_not_materialized` — the requested dimension exists in the
 *   manifest but has never been observed (no scope values yet).
 * - `too_many_dimension_filters` — the filter API was called with more
 *   dimensions than the agent declares.
 * - `bulk_too_large` — bulk PUT body exceeded the per-request cap (100).
 * - `not_customer_visible` — toggle attempted on a hidden capability.
 * - `no_scoping_dimension_declared` — the agent manifest has no scoping
 *   dimension; PDP can fall back, but the toggle UI cannot operate.
 * - `unknown_error` — fallback for shapes we don't recognize.
 */
export type LupidErrorCode =
  | "scope_dimension_mismatch"
  | "dimension_not_materialized"
  | "too_many_dimension_filters"
  | "bulk_too_large"
  | "not_customer_visible"
  | "no_scoping_dimension_declared"
  | "unknown_error";

/** A typed error thrown by the API wrappers. */
export class LupidError extends Error {
  readonly code: LupidErrorCode;
  readonly status: number;

  constructor(code: LupidErrorCode, message: string, status: number) {
    super(message);
    this.name = "LupidError";
    this.code = code;
    this.status = status;
  }
}

/** Scope discriminator passed to `<CapabilityToggles>`. */
export type CapabilityTogglesScope = ScopeIdentity | "defaults";
