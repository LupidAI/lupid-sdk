/**
 * Barrel for the Spec 2 binding-mode pipeline (S2-E04).
 *
 * Exposed to `init.ts` and to public consumers (so callers can typecheck
 * against the same `BindingMode` union and catch the
 * `BindingModeNotYetSupportedError` deliberately).
 */

export {
  ALL_BINDING_MODES,
  ACTIVE_BINDING_MODES,
  DEFERRED_BINDING_MODES,
  MVP3_REFERENCE_TICKETS,
  BindingModeNotYetSupportedError,
  InvalidBindingModeError,
  type BindingMode,
} from "./types.js";

export {
  extractBindingMode,
  runPerModeScan,
  type BindingScanLogger,
  type PerModeScanResult,
} from "./dispatch.js";
