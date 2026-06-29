/**
 * Runtime factory for the NestJS Agentum integration.
 *
 * A single runtime object holds the AgentumClient + resilience primitives and
 * is consumed by `AgentumGuard.canActivate`. Build it at application startup
 * (`forRoot`) and call `close()` during graceful shutdown.
 *
 * Two constructors:
 *
 * - {@link createAgentumRuntime} — synchronous. Convenient, but its HITL
 *   `approvalSession` is built over the shared API-key client with an empty JWT.
 *   The server's HITL agent endpoints authenticate via `Authorization: Bearer`
 *   only (never `X-API-Key`), so on the common API-key-only deployment the
 *   approval round-trip 401s and HITL escalation silently fails (SDK-HITL-A).
 *   Use this only when you know HITL escalation is not required, or when the
 *   client already carries a session JWT.
 * - {@link createAgentumRuntimeAsync} — asynchronous. Mints a real agent session
 *   (`client.connectExisting(agentId)`) for `approvalSession`, so the approval
 *   round-trip sends a Bearer JWT (with auto-refresh) and works on an API-key
 *   runtime. This is the recommended constructor when `autoEscalateHitl` is in
 *   use.
 */

import { AgentumError } from "../../types.js";
import { AgentumSession } from "../../session.js";
import { CircuitBreaker } from "../express/circuit-breaker.js";
import { DecisionCache } from "../express/decision-cache.js";
import { HealthMonitor } from "../express/health-check.js";
import type {
  AgentumNestInternals,
  AgentumNestRuntime,
  AgentumNestRuntimeOptions,
} from "./types.js";

function validate(opts: AgentumNestRuntimeOptions): void {
  if (!opts.runtime) {
    throw new AgentumError("createAgentumRuntime: `runtime` (AgentumClient) is required");
  }
  if (!opts.agentId) {
    throw new AgentumError("createAgentumRuntime: `agentId` is required");
  }
  if (typeof opts.userFromRequest !== "function") {
    throw new AgentumError("createAgentumRuntime: `userFromRequest` must be a function");
  }
}

/**
 * Build the resilience primitives + internals shared by both the sync and
 * async constructors. `approvalSession` is supplied by the caller: the sync
 * path passes a best-effort empty-JWT session; the async path passes a real
 * Bearer-authenticated agent session (or `undefined` if central was
 * unreachable).
 */
function buildInternals(
  opts: AgentumNestRuntimeOptions,
  approvalSession: AgentumSession | undefined,
): AgentumNestInternals {
  const dcOpts = opts.decisionCache ?? {};
  const dcEnabled = dcOpts.enabled !== false;
  const decisionCache = dcEnabled
    ? new DecisionCache({
        maxSize: dcOpts.maxSize ?? 10_000,
        ttlMs: dcOpts.ttlMs ?? 15_000,
      })
    : null;

  const cbOpts = opts.circuitBreaker ?? {};
  const cbEnabled = cbOpts.enabled !== false;
  const circuitBreaker = cbEnabled
    ? new CircuitBreaker({
        failureThreshold: cbOpts.failureThreshold ?? 5,
        resetTimeoutMs: cbOpts.resetTimeoutMs ?? 30_000,
      })
    : null;

  const hcOpts = opts.healthCheck ?? {};
  const hcEnabled = hcOpts.enabled !== false;
  const healthMonitor = hcEnabled
    ? new HealthMonitor({
        client: opts.runtime,
        intervalMs: hcOpts.intervalMs ?? 30_000,
      })
    : null;

  const internals: AgentumNestInternals = {
    client: opts.runtime,
    agentId: opts.agentId,
    tenantId: opts.tenantId,
    userFromRequest: opts.userFromRequest,
    decisionCache,
    circuitBreaker,
    healthMonitor,
    failMode: opts.failMode ?? "closed",
    ...(opts.onUnauthenticated ? { onUnauthenticated: opts.onUnauthenticated } : {}),
    // LIVE getter — re-reads the evaluator snapshot on every call. Wiring the
    // closure (not a captured boolean) is the correctness point the design
    // calls out: a creation-time snapshot would go stale when the addon is
    // toggled after runtime construction.
    hitlAddonEnabled: () => opts.runtime.isHitlAddonEnabled(opts.agentId),
    ...(approvalSession ? { approvalSession } : {}),
  };
  return internals;
}

/**
 * Synchronous runtime constructor.
 *
 * The `approvalSession` here is built over the shared (API-key) client with an
 * empty JWT. **HITL escalation does not work on an API-key-only deployment via
 * this constructor** — the server's HITL agent endpoints read
 * `Authorization: Bearer` only, so the create/poll round-trip 401s
 * (SDK-HITL-A). For working HITL escalation use {@link createAgentumRuntimeAsync}.
 */
export function createAgentumRuntime(opts: AgentumNestRuntimeOptions): AgentumNestRuntime {
  validate(opts);

  // HITL-6 — best-effort session over the runtime client. NOTE (SDK-HITL-A):
  // an empty JWT + the shared API-key client means the approval round-trip
  // authenticates with `X-API-Key`, which the server's `extract_bearer` ignores
  // → 401 on API-key-only runtimes. Kept for back-compat and for the case where
  // `opts.runtime` already carries a session JWT.
  const approvalSession = new AgentumSession(opts.runtime, opts.agentId, "", "", {});

  const internals = buildInternals(opts, approvalSession);

  return {
    _internals: internals,
    async close() {
      internals.healthMonitor?.stop();
    },
  };
}

/**
 * Asynchronous runtime constructor — the recommended path when HITL escalation
 * (`autoEscalateHitl`) is in use.
 *
 * Mints a real agent session for `approvalSession` via
 * `opts.runtime.connectExisting(opts.agentId)`. That session:
 *   - stamps `agentId` + `tenantId` and carries an `Authorization: Bearer` JWT,
 *     satisfying the server's `verify()` on the HITL agent endpoints
 *     (fixes the SDK-HITL-A 401);
 *   - carries a `refreshFn` backed by a long-lived API-key refresh client, so
 *     `requestApproval`'s `_ensureFresh` re-mints the JWT before expiry — a
 *     long-running guard never starts 401-ing mid-run.
 *
 * **Startup reachability:** `connectExisting` performs a network call. If
 * central is unreachable at construction time, the error is caught, a warning
 * is logged, and the runtime is returned with HITL escalation cleanly disabled
 * (no `approvalSession` → the guard lets a `require_hitl` Deny stand,
 * fail-CLOSED) rather than crashing application bootstrap. All other guard
 * behaviour (Allow/Deny via `simulatePolicy`) is unaffected.
 */
export async function createAgentumRuntimeAsync(
  opts: AgentumNestRuntimeOptions,
): Promise<AgentumNestRuntime> {
  validate(opts);

  let approvalSession: AgentumSession | undefined;
  try {
    // Mint a real agent session with a Bearer JWT + auto-refresh. We skip the
    // best-effort Cedar policy probe — the runtime drives its own
    // `simulatePolicy` and a probe warning here would be noise at bootstrap.
    const connectOpts: { skipPolicyCheck: boolean; tenantId?: string } = {
      skipPolicyCheck: true,
    };
    if (opts.tenantId !== undefined) connectOpts.tenantId = opts.tenantId;
    approvalSession = await opts.runtime.connectExisting(opts.agentId, connectOpts);
  } catch (err) {
    // Central unreachable at bootstrap — do not crash the app. HITL escalation
    // is disabled until the process is restarted with central reachable.
    console.warn(
      `[agentum] createAgentumRuntimeAsync: could not mint the HITL approval ` +
        `session for agent ${opts.agentId} (central unreachable?) — HITL ` +
        `escalation is DISABLED; require_hitl denials will stand. ` +
        `Cause: ${err instanceof Error ? err.message : String(err)}`,
    );
    approvalSession = undefined;
  }

  const internals = buildInternals(opts, approvalSession);

  return {
    _internals: internals,
    async close() {
      internals.healthMonitor?.stop();
      // Close the minted approval session (ends the server-side session, drains
      // its audit buffer, releases the refresh client). Best-effort.
      if (approvalSession) {
        await approvalSession.close().catch(() => {});
      }
    },
  };
}
