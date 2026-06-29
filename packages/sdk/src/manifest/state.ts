/**
 * Module-level state for the active tenant schema.
 *
 * `resolve-dimensions.ts` and `enrichment/client.ts` both read the active
 * schema as a free function `getActiveSchema()` from this module. We
 * intentionally do NOT hang the active schema on `AgentumRuntime` — the
 * consumers lock in this shape.
 *
 * The schema is recursively deep-frozen on set so consumers cannot
 * accidentally mutate the cached object or any nested fields. The freeze
 * walks plain objects and arrays; non-data values (Date, Map, etc. —
 * none today) would be skipped.
 */

import type { TenantSchema } from "./types.js";
import { InitError } from "./errors.js";

let ACTIVE: TenantSchema | null = null;

/**
 * Returns the active tenant schema set by the last `init()` call.
 *
 * Throws `InitError` when called before `init()` has resolved a schema.
 * The strict-fail behaviour is intentional — consumers must not silently
 * fall back to a "no dimensions" mode when the schema is missing, because
 * that would emit unschema'd audit rows.
 */
export function getActiveSchema(): TenantSchema {
  if (ACTIVE === null) {
    throw new InitError(
      "agentum.init() has not completed: no active tenant schema. " +
        "Ensure `await agentum.init({...})` resolves before resolving dimensions.",
    );
  }
  return ACTIVE;
}

/**
 * Recursively freezes plain objects and arrays. Non-data values are
 * frozen at the top level only (sufficient for the `TenantSchema`
 * shape, which is pure JSON).
 */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.keys(value as object)) {
    deepFreeze((value as Record<string, unknown>)[key]);
  }
  return value;
}

/**
 * Test/init-only setter. Deep-freezes the schema so downstream consumers
 * cannot accidentally mutate nested fields such as `dimensions[*].source`
 * or `enrichments[*]`.
 *
 * Re-init with a different schema in the same process is undefined
 * behaviour; this setter overwrites without question.
 */
export function _setActiveSchema(schema: TenantSchema | null): void {
  ACTIVE = schema === null ? null : deepFreeze(schema);
}
