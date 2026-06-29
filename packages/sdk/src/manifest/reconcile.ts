/**
 * Pure version-negotiation function. Pulled out of `init.ts` for direct
 * unit-test coverage of the 6-case table.
 *
 * Case table:
 *   1. both null              → throw `InitError`
 *   2. only local present     → return local (offline-OK; caller warns)
 *   3. only live present      → return live  (no local manifest case)
 *   4. equal versions         → return local (deterministic; identical content)
 *   5. local.version > live.version → return live  (caller warns)
 *   6. local.version < live.version → throw `InitError` (would emit unschema'd events)
 *
 * Schema version negotiation at SDK boot is strict.
 */

import type { TenantSchema } from "./types.js";
import { InitError } from "./errors.js";

export interface ReconcileLogger {
  warn(message: string): void;
}

/**
 * Reconcile a local manifest version against the live server version.
 *
 * Returns the winning `TenantSchema`. Throws `InitError` on the two
 * unrecoverable cases (both null; local behind live).
 *
 * Optional `logger` receives advisory warnings; defaults to `console`.
 */
export function reconcileVersions(
  local: TenantSchema | null,
  live: TenantSchema | null,
  logger: ReconcileLogger = console,
): TenantSchema {
  if (!local && !live) {
    throw new InitError(
      "no local manifest and live schema fetch failed; cannot proceed",
    );
  }
  if (!local && live) {
    logger.warn(
      `[agentum] no local manifest; booting against live schema v${live.version}`,
    );
    return live;
  }
  if (local && !live) {
    // `live === null` covers two situations:
    //   (a) clean 404 — no schema installed for this agent yet (expected for
    //       a newly-registered agent; promote the local copy with
    //       `lupid revision push`)
    //   (b) the live-fetch attempt threw and `init.ts` set live=null after
    //       its own "live schema fetch failed" warn
    // We can't tell (a) from (b) here, but (b) already emitted its own
    // warning at the call site. Word this so case (a) reads as
    // informational, not as a network-error alarm.
    logger.warn(
      `[agentum] no live schema installed for this agent; booting against local ` +
        `tenant-schema v${local.version}. Promote with \`lupid revision push\` to make it live.`,
    );
    return local;
  }

  // Both present — narrow `as` is justified by the two null-checks above.
  const l = local as TenantSchema;
  const r = live as TenantSchema;

  if (l.version === r.version) {
    // Deterministic: pick local. The two are expected to be identical.
    return l;
  }
  if (l.version > r.version) {
    logger.warn(
      `[agentum] local manifest v${l.version} is ahead of live v${r.version}; ` +
        `using live. Run \`lupid revision push\` to promote the local manifest.`,
    );
    return r;
  }
  // l.version < r.version — refuse, would emit unschema'd events.
  throw new InitError(
    `local manifest version ${l.version} < live version ${r.version}; ` +
      `run \`lupid revision pull\` or upgrade the SDK before booting`,
  );
}
