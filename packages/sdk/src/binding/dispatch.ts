/**
 * Per-mode init scan dispatcher.
 *
 * This runs at SDK init BEFORE any network call so an agent declared
 * against an MVP-3 binding mode (`per_subagent`, `acl_edge`,
 * `actor_per_instance`) fails fast — no JWKS handshake, no register
 * round-trip, no patch installation.
 *
 * Scope today (as scoped to MVP-1):
 *   - orchestrator    → proceed (legacy default behaviour)
 *   - framework_hook  → proceed (framework adapter wired separately)
 *   - per_subagent | acl_edge | actor_per_instance → throw
 *
 * The orchestrator-side capability resolution table, the
 * framework-adapter probe, and the MVP-3 scans themselves are deferred.
 */

import {
  ALL_BINDING_MODES,
  BindingModeNotYetSupportedError,
  InvalidBindingModeError,
  type BindingMode,
} from "./types.js";

/** Minimal logger shape — matches the rest of the SDK. */
export interface BindingScanLogger {
  log: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
}

/**
 * Result of `runPerModeScan`. The dispatcher returns the resolved mode
 * (with defaulting applied) so callers — primarily `init.ts` — can
 * record it on the init log line and pass it forward to downstream
 * stages (`/sdk/runtime-capabilities` payload).
 */
export interface PerModeScanResult {
  /** The mode the SDK is running under after defaulting. */
  bindingMode: BindingMode;
  /** True if the manifest did not declare `binding_mode` and we defaulted. */
  defaulted: boolean;
}

/**
 * Extract the binding mode from an already-YAML-parsed agent
 * manifest. Returns `null` if the manifest does not declare one (legacy
 * manifests), throws `InvalidBindingModeError` if the
 * declared value is not one of the five enum members.
 *
 * Accepts `unknown` so callers can pipe in the raw `loadAndParse` output
 * without an intermediate typed parse.
 */
export function extractBindingMode(raw: unknown): BindingMode | null {
  if (typeof raw !== "object" || raw === null) return null;
  const spec = (raw as Record<string, unknown>)["spec"];
  if (typeof spec !== "object" || spec === null) return null;
  const runtime = (spec as Record<string, unknown>)["runtime"];
  if (typeof runtime !== "object" || runtime === null) return null;
  const mode = (runtime as Record<string, unknown>)["binding_mode"];
  if (mode === undefined || mode === null) return null;
  if (typeof mode !== "string") {
    throw new InvalidBindingModeError(String(mode));
  }
  if (!ALL_BINDING_MODES.includes(mode as BindingMode)) {
    throw new InvalidBindingModeError(mode);
  }
  return mode as BindingMode;
}

/**
 * Run the per-mode init scan.
 *
 * Inputs:
 *   - `declared` is the value returned from `extractBindingMode` —
 *     `null` means the manifest did not declare a mode.
 *   - `logger` matches the SDK's `console`-shape logger.
 *
 * Behaviour:
 *   - `null` → default to `orchestrator`, emit a one-line `console.warn`
 *     so legacy manifests stay bootable while operators
 *     migrate.
 *   - `orchestrator` | `framework_hook` → return cleanly.
 *   - the three MVP-3 modes → throw `BindingModeNotYetSupportedError`.
 *
 * The `default:` branch is guarded by an exhaustiveness `never` check
 * so any future addition to the `BindingMode` union surfaces at compile
 * time rather than silently falling through.
 */
export function runPerModeScan(
  declared: BindingMode | null,
  logger: BindingScanLogger,
): PerModeScanResult {
  if (declared === null) {
    logger.warn(
      `[agentum] manifest does not declare spec.runtime.binding_mode; ` +
        `defaulting to "orchestrator". Set the field explicitly to silence ` +
        `this warning (see AGENT_MANIFEST_AND_REVISIONS.md §Archetype fit).`,
    );
    return { bindingMode: "orchestrator", defaulted: true };
  }

  switch (declared) {
    case "orchestrator":
    case "framework_hook":
      return { bindingMode: declared, defaulted: false };
    case "per_subagent":
    case "acl_edge":
    case "actor_per_instance":
      throw new BindingModeNotYetSupportedError(declared);
    default: {
      // Exhaustiveness — adding a new BindingMode without extending
      // this switch is a compile-time error.
      const _exhaustive: never = declared;
      throw new Error(
        `unhandled binding mode in dispatcher: ${String(_exhaustive)}`,
      );
    }
  }
}
