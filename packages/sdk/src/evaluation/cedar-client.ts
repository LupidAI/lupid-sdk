/**
 * Thin Cedar-evaluation client used by the auto-init monkeypatches.
 *
 * Wraps `POST /api/v1/sdk/evaluate-tool-call` with:
 *   - 200ms default timeout (configurable)
 *   - fail-closed default (network/timeout errors → `deny`)
 *   - LRU caching keyed by `(agent_id, tool_name, contextHash)` with
 *     server-supplied `ttl_ms` honored per entry
 *
 * The cache reuses the existing `DecisionCache` LRU from the Express
 * framework adapter (no reinvention).
 */

import { freshnessHeaders } from "../audit/freshness.js";
import { DecisionCache, hashContext } from "../frameworks/express/decision-cache.js";
import { getAgentumContext } from "../instrumentation/context.js";
import { resolveDimensions } from "../instrumentation/resolve-dimensions.js";
import { runPiiPipeline, isPiiPipelineNoOp } from "../pii/pipeline.js";
import { PiiSelfCheckFailedError } from "../pii/text-scanner.js";
import type { AuditIngestRequest, PolicySimulateResponse } from "../types.js";

/**
 * Categorical deny code emitted by the policy engine. Stable wire
 * strings; SDK consumers should branch on these instead of regex-matching
 * the free-text `reason`. Allow decisions never carry a code.
 *
 * Mirror of the Rust `DenyCode` enum at
 * `crates/agentum-authz/src/policy.rs`. Appending is safe; renaming or
 * removing a value is a breaking SDK change.
 */
/**
 * Tri-state enablement of an SDK in-process feature (policy addon), derived
 * from the live PDP `/v1/authorize` response snapshot.
 *
 * - `"enabled"`  — a snapshot has been received AND `enabled_addons`
 *   includes the addon id.
 * - `"disabled"` — a snapshot has been received AND `enabled_addons` does
 *   NOT include the addon id. This is the fail-CLOSED "feature was turned
 *   off" signal: a populated-then-emptied bundle yields `"disabled"`.
 * - `"unknown"`  — no snapshot has been received yet (cold start, central-
 *   only deployment, PDP not wired, or post-invalidation gap). Callers
 *   pick a per-feature SAFE default for this state (PII → masked, HITL →
 *   no auto-escalate). This is NOT a blanket fail-OPEN.
 *
 * INTEG-B1: replaces the prior fail-OPEN `isAddonEnabled` boolean which
 * treated an empty snapshot as "everything enabled" — that made
 * "disable a feature" untrustworthy on cold start.
 */
export type FeatureState = "enabled" | "disabled" | "unknown";

export type DenyCode =
  | "deny_cedar_policy"
  | "deny_no_policy"
  | "deny_invalid_context"
  | "deny_invalid_request"
  | "deny_hitl_pending"
  | "deny_declared_tools_mismatch"
  | "deny_fail_closed"
  // 401 from local PDP — misconfigured AGENTUM_PDP_SERVICE_TOKEN
  | "deny_pdp_unauthorized"
  // An ungranted MCP server was called in enforce mode (MCP fence).
  // Mirrors Rust `DenyCode::DenyMcpServerNotGranted`
  // (`crates/agentum-api/src/routes/sdk.rs`).
  | "deny_mcp_server_not_granted";

export interface ToolCallEvaluation {
  decision: "allow" | "deny";
  ruleId?: string;
  reason?: string;
  /**
   * Categorical machine-readable code attached to every deny.
   * Populated for both server-issued denies (via the `deny_code` field
   * on `/sdk/evaluate-tool-call`) and SDK-side fail-closed paths
   * (timeout, transport error). Undefined on allow.
   */
  denyCode?: DenyCode;
  advice?: string[];
  /** HITL-1: derived flag — `true` iff the decision was `deny` AND `advice`
   *  carried a `require_hitl` directive AND no live grant short-circuited.
   *  Surfaced from the PDP/central `hitl_pending` field. Absent on older API
   *  versions; callers fall back to {@link parseHitlAdvice}(`advice`). The
   *  autopatch/NextJS planes use this to emit the "HITL unsupported in v1"
   *  warning (HITL-8) before standing by their fail-CLOSED deny. */
  hitlPending?: boolean;
  ttlMs: number;
  /** Hash of the policy bundle that produced this decision. Surfaced
   *  from PDP (`policy_hash`) and central (when present). Threaded
   *  through audit so stale-policy decisions can be detected. */
  policyHash?: string;
  /** Which evaluation plane produced this decision. Used by audit to
   *  attribute decisions correctly when both PDP and central are wired. */
  decisionSource?: "pdp" | "central";
  /** True when the PDP evaluated this decision against its in-memory
   *  bundle. Surfaced from PDP `evaluated_locally`. */
  evaluatedLocally?: boolean;
  /** PDP-measured evaluation latency in microseconds. Surfaced from PDP
   *  `latency_us`. Independent of `decisionSource` — the PDP
   *  measures every decision regardless of bundle origin. */
  pdpLatencyUs?: number;
}

export interface CedarClientOptions {
  baseUrl: string;
  apiKey: string;
  agentId: string;
  /** Default 200ms. */
  timeoutMs?: number;
  /** Default 1024. */
  cacheMaxSize?: number;
  /** Default `"deny"` — fail closed. Set `"allow"` only for dev-mode.
   *  Applied on transport error / timeout. */
  failMode?: "deny" | "allow";
  /** Test/runtime injection hook. */
  fetchImpl?: typeof fetch;
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Default 1500ms. Timeout for observe-prompt audit emissions. */
  observePromptTimeoutMs?: number;
  /** Default 1. Max retries for observe-prompt audit emissions. */
  observePromptMaxRetries?: number;
  /** Local-PDP sidecar URL. When set (and the PDP `/v1/health` probe
   *  succeeds), tool-call evaluation is routed to `${pdpUrl}/v1/authorize`
   *  with `Authorization: Bearer <pdpServiceToken>`. Falls back to central
   *  on transport / 5xx. A `401` is loud and fails closed (no fallback).
   *  Default is set by `init.ts` to `http://127.0.0.1:7080`. */
  pdpUrl?: string;
  /** Bearer token sent on `/v1/authorize{,/batch}`. Required by PDP unless
   *  it was started with `--allow-unauthenticated`. */
  pdpServiceToken?: string;
  /** TTL on the cached `/v1/health` probe result. Default 30s. */
  pdpDiscoveryTtlMs?: number;
  /** Abort timeout for the `/v1/health` probe. Default 50ms. */
  pdpProbeTimeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 200;
const DEFAULT_CACHE_SIZE = 1024;
const DEFAULT_PDP_DISCOVERY_TTL_MS = 30_000;
const DEFAULT_PDP_PROBE_TIMEOUT_MS = 50;
/** Bound on the in-process approval-grant LRU. Approvals are
 *  human-operator events, not per-call, so a few hundred entries are
 *  ample for the dominant LobeChat-style "one-worker-per-conversation"
 *  shape. Older entries are evicted on overflow without erroring. */
const DEFAULT_APPROVAL_GRANT_MAX = 256;

export class CedarToolCallClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly agentId: string;
  private readonly timeoutMs: number;
  private readonly failMode: "deny" | "allow";
  private readonly fetchFn: typeof fetch;
  private readonly logger: Pick<Console, "log" | "warn" | "error">;
  // Re-using the express DecisionCache: it stores `PolicySimulateResponse`
  // shapes, but the underlying machinery only cares about LRU + TTL semantics,
  // so we treat the cached value as our own `ToolCallEvaluation`. The
  // wrapper below adapts the surface.
  private readonly observePromptTimeoutMs: number;
  private readonly observePromptMaxRetries: number;
  private readonly cache: DecisionCache;
  // Local-PDP routing.
  private readonly pdpUrl: string | undefined;
  private readonly pdpServiceToken: string | undefined;
  private readonly pdpDiscoveryTtlMs: number;
  private readonly pdpProbeTimeoutMs: number;
  // `null` = never probed; `true`/`false` = last probe result, valid until
  // `pdpAliveExpiresAt`. Mutated only inside `discoverPdp` and the PDP
  // request path (5xx / transport errors flip alive→false to avoid hammering
  // a sick sidecar until the next discovery window).
  private pdpAlive: boolean | null = null;
  private pdpAliveExpiresAt = 0;
  // Last `policy_hash` observed from a PDP/central response. Used as
  // the 5th component of the DecisionCache key so a policy churn during the
  // ~1s cache window can no longer serve a stale decision: lookups under
  // the new hash miss every entry seeded under the old hash.
  private lastPolicyHash: string | undefined = undefined;
  // R45b / INTEG-B1 — last `enabled_addons` snapshot observed from a PDP
  // `/v1/authorize` response. Drives `featureState()`, which the
  // observe-prompt PII gate and the framework HITL escalation guards
  // consult. Only parsed from the PDP path (`attemptPdp`); central's
  // `/sdk/evaluate-tool-call` does not carry it. Reset (along with
  // `snapshotReceived`) on policy / capability invalidation so a stale
  // snapshot can't outlive a bundle churn.
  private lastEnabledAddons: readonly string[] = [];
  // INTEG-B1 — whether ANY non-error PDP authorize response has carried
  // addon-snapshot data (an `enabled_addons` array OR `bundle_loaded:true`).
  // The PDP now ALWAYS emits `enabled_addons:[]` + `bundle_loaded:true` when
  // a bundle is loaded, so this flips true on the first authorize against a
  // loaded engine. While `false`, `featureState()` returns `"unknown"` and
  // callers apply a per-feature SAFE default — NOT a blanket fail-OPEN.
  // Reset to `false` on policy / capability invalidation so the next
  // authorize re-establishes ground truth.
  private snapshotReceived = false;
  // Fire-and-forget audit POSTs from `postAuditEvent` can
  // outlive the surrounding async call (and, in tests, the surrounding
  // Jest test). Track the in-flight promises here so `flushPendingAudits()`
  // can `await` them at teardown. Production callers do not need to
  // await; the set self-empties as each POST resolves.
  private readonly pendingAudits: Set<Promise<void>> = new Set();
  // HITL post-approval grant ledger keyed on
  // `(agent_id, tool_name, args_hash)`. Insertion-ordered Map → LRU on
  // overflow; per-entry expiry derived from the `require_hitl:timeout=NNN`
  // advice on the prior PDP decision. A hit short-circuits the next
  // identical tool call (same tool AND same canonical-JSON args hash) so
  // the user is not re-prompted for every successive call within the grant
  // window; a call with different args misses and re-escalates. Grant key
  // is intentionally NOT session-scoped — the internal cohort is
  // single-session-per-PDP and adding session_id later is non-breaking.
  private readonly approvalGrants: ApprovalGrantCache;
  // PASS2-SDK-01 Item C — local fail-CLOSED suspend deny-set. Populated by the
  // `agent_suspended` lifecycle SSE event (`sse-subscriber.ts`) and cleared by
  // `agent_activated`. Checked at the top of `evaluateToolCall` so a suspended
  // agent denies in-process without a wasted PDP/central round-trip. Suspend
  // *already* propagates via the `policy` reload event (which invalidates the
  // decision cache and re-pulls a bundle that denies the suspended agent); this
  // set is a latency fast-path, not the only enforcement of suspend. Keyed by
  // agent_id so a future multi-agent evaluator can scope per agent; today every
  // entry is `this.agentId`.
  private readonly suspendedAgents = new Set<string>();

  constructor(opts: CedarClientOptions) {
    if (!opts.baseUrl) throw new Error("CedarToolCallClient: baseUrl required");
    if (!opts.apiKey)  throw new Error("CedarToolCallClient: apiKey required");
    if (!opts.agentId) throw new Error("CedarToolCallClient: agentId required");
    this.baseUrl   = opts.baseUrl.replace(/\/$/, "");
    this.apiKey    = opts.apiKey;
    this.agentId   = opts.agentId;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.failMode  = opts.failMode ?? "deny";
    this.fetchFn   = opts.fetchImpl ?? fetch;
    this.logger    = opts.logger ?? console;
    this.observePromptTimeoutMs = opts.observePromptTimeoutMs ?? 1500;
    this.observePromptMaxRetries = opts.observePromptMaxRetries ?? 1;
    this.pdpUrl = opts.pdpUrl ? opts.pdpUrl.replace(/\/$/, "") : undefined;
    this.pdpServiceToken = opts.pdpServiceToken;
    this.pdpDiscoveryTtlMs = opts.pdpDiscoveryTtlMs ?? DEFAULT_PDP_DISCOVERY_TTL_MS;
    this.pdpProbeTimeoutMs = opts.pdpProbeTimeoutMs ?? DEFAULT_PDP_PROBE_TIMEOUT_MS;
    // ttlMs on the cache itself is a hard upper bound; per-entry TTLs come
    // from the server response. We use an effectively unbounded ttl on the
    // shell and store the server `ttl_ms` in the smuggled response object.
    this.cache = new DecisionCache({
      maxSize: opts.cacheMaxSize ?? DEFAULT_CACHE_SIZE,
      ttlMs:   60_000,
    });
    this.approvalGrants = new ApprovalGrantCache(DEFAULT_APPROVAL_GRANT_MAX);
  }

  /**
   * Evaluate a single tool call. Cached entries are returned immediately;
   * misses route to the local PDP sidecar (when configured + healthy) and
   * fall back to central on PDP transport / 5xx error. A `401` from the
   * PDP is loud and fails closed (no central fallback).
   * Network or timeout errors on central resolve to the configured
   * `failMode` and are NOT cached.
   */
  async evaluateToolCall(args: {
    toolName: string;
    arguments?: unknown;
    /**
     * MCP-REDESIGN Phase 2b — the MCP server endpoint URL (origin + pathname)
     * for HTTP MCP transports. The SDK has no server registry; central
     * resolves the canonical `server_id` from this. Additive: omitted for
     * non-MCP tool calls. Sent alongside the legacy namespaced `toolName`
     * so an old central still matches existing `tool:*` policies.
     */
    mcpServerUrl?: string;
    /**
     * MCP-REDESIGN Phase 2b — the MCP server's self-reported name
     * (`serverInfo.name` for stdio, or the recorded alias for HTTP). Central
     * resolves this alias to the canonical `server_id`. Additive.
     */
    mcpServerName?: string;
  }): Promise<ToolCallEvaluation> {
    // PASS2-SDK-01 Item C — local fail-CLOSED suspend fast-path. When the
    // `agent_suspended` lifecycle SSE event has marked this agent as suspended,
    // deny immediately without consulting the grant ledger, the decision cache,
    // the PDP, or central. This takes precedence over a live HITL approval
    // grant: a suspended agent must not be able to act on a stale grant. The
    // set clears on the `agent_activated` event.
    if (this.suspendedAgents.has(this.agentId)) {
      const out: ToolCallEvaluation = {
        decision: "deny",
        ttlMs: 0,
        reason: "agent suspended",
      };
      this.emitLocalPdpDecisionAudit({
        toolName: args.toolName,
        evaluation: out,
        source: "local_pdp",
      });
      return out;
    }

    // Short-circuit on a live HITL approval grant. The grant is
    // recorded by `session.requestApproval()` after a successful operator
    // approval; subsequent identical tool calls within the grant TTL skip
    // re-escalation and return `allow` without consulting PDP or central.
    // Fail-CLOSED preserved: only a positive in-window hit short-circuits;
    // miss / expiry / parse-error fall through to the normal PDP path.
    // The grant key includes a canonical-JSON SHA-256 of the call's
    // `arguments`, so a benign approval cannot unlock different args.
    // Optimisation: skip the per-call digest entirely when the ledger is
    // empty (the common case). On hash failure (no SHA-256 source) skip the
    // short-circuit and fall through to the normal PDP path (fail-CLOSED).
    // `args.arguments` must hash the SAME value the PDP receives as
    // `context.arguments` (`attemptPdp` sends `arguments: args.arguments ?? null`);
    // `hashArgsCanonical` maps `undefined → "null"`, preserving that equivalence.
    let grant: ApprovalGrantEntry | undefined;
    if (this.approvalGrants.size > 0) {
      const argsHash = await hashArgsCanonical(args.arguments);
      if (argsHash !== undefined) {
        grant = this.approvalGrants.find(this.agentId, args.toolName, argsHash);
      }
    }
    if (grant) {
      const out: ToolCallEvaluation = {
        decision: "allow",
        ttlMs: 0,
      };
      const auditArgs: {
        toolName: string;
        evaluation: ToolCallEvaluation;
        source: "approval_grant";
        approvalRequestId?: string;
      } = {
        toolName: args.toolName,
        evaluation: out,
        source: "approval_grant",
      };
      if (grant.requestId !== undefined) {
        auditArgs.approvalRequestId = grant.requestId;
      }
      this.emitLocalPdpDecisionAudit(auditArgs);
      return out;
    }

    // Resolve tenant-schema dimensions and fold them into the
    // request body so the gateway's `/sdk/evaluate-tool-call` handler can
    // thread them into Cedar context. Resolver failures (pre-init, required-
    // dimension missing, malformed enrichment block) degrade to empty
    // dimensions: a Cedar policy gated on an undefined attribute still
    // evaluates consistently, and the resolver's own audit-emit path
    // surfaces the underlying error. The eval call MUST NOT throw on
    // resolver errors.
    const dimsWithNulls: Record<string, string | null> =
      await resolveDimensions().catch(() => ({}));
    // The Rust handler at `/sdk/evaluate-tool-call` deserialises the
    // `dimensions` field as `Option<BTreeMap<String, String>>` — Serde
    // rejects the whole map when any value is `null`. The resolver
    // legitimately produces nulls for optional `enrichment` / `derived`
    // dims that didn't resolve; strip them on the wire and the audit /
    // Cedar plane keeps the parity invariant intact (an absent key
    // hashes the same as a present-null one).
    const dims: Record<string, string> = {};
    for (const [k, v] of Object.entries(dimsWithNulls)) {
      if (typeof v === "string") {
        dims[k] = v;
      }
    }

    // Folding dims into the same hash invalidates ALL prior cache entries on
    // rollout because the wrapping shape changes from `{ _raw: ... }`/raw
    // arguments to `{ args, dims }`. That is acceptable — cache TTL is short
    // and a one-time wave of misses is harmless. The wrapping object is
    // stable-stringified (sorted keys), so an empty `dims: {}` hashes
    // deterministically and equal-dim calls hit the cache.
    const ctxHash = hashContext({
      args: args.arguments,
      dims,
    });
    // Look up under the most recently observed policy hash. When the PDP
    // returns a fresh hash we update `lastPolicyHash` and future lookups
    // will use the new key — entries from the prior generation become
    // unreachable without an explicit invalidation pass.
    const lookupKey = DecisionCache.key(
      this.agentId,
      `tool:${args.toolName}`,
      "*",
      ctxHash,
      this.lastPolicyHash,
    );

    const cached = this.cache.get(lookupKey);
    if (cached) {
      // We smuggled `ToolCallEvaluation` through the cache; cast back.
      const cachedEval = (cached as unknown) as ToolCallEvaluation;
      // Emit a `LocalPdpDecision` audit event for cache hits. The
      // underlying decision still came from the PDP or central, but from
      // the audit pipeline's perspective we want `decision_source: "cache"`
      // so dashboards can answer "did we hit the wire?".
      this.emitLocalPdpDecisionAudit({
        toolName: args.toolName,
        evaluation: cachedEval,
        source: "cache",
      });
      return cachedEval;
    }

    const ctx = getAgentumContext();

    // Try local PDP first (if configured and healthy).
    if (await this.discoverPdp()) {
      const pdpResult = await this.attemptPdp(args, ctx, dims);
      if (pdpResult !== "fallback") {
        // `LocalPdpStale` detection. Compare the freshly-observed
        // `policy_hash` against the last hash we saw and emit a stale
        // audit event when they differ. Lazy emission: only on the first
        // mismatch observed for a given (prior, current) pair, then
        // `lastPolicyHash` is updated below so we don't tight-loop.
        const prior = this.lastPolicyHash;
        const observed = pdpResult.policyHash;
        if (
          prior !== undefined &&
          observed !== undefined &&
          prior !== observed
        ) {
          this.emitLocalPdpStaleAudit({
            toolName: args.toolName,
            expectedPolicyHash: prior,
            observedPolicyHash: observed,
          });
        }
        if (observed !== undefined) {
          this.lastPolicyHash = observed;
        }
        if (pdpResult.ttlMs > 0) {
          const putKey = DecisionCache.key(
            this.agentId,
            `tool:${args.toolName}`,
            "*",
            ctxHash,
            pdpResult.policyHash,
          );
          this.cache.put(putKey, (pdpResult as unknown) as PolicySimulateResponse);
        }
        // Record the PDP-served decision in audit.
        this.emitLocalPdpDecisionAudit({
          toolName: args.toolName,
          evaluation: pdpResult,
          source: "local_pdp",
        });
        return pdpResult;
      }
      // Fall through to central exactly once.
    }

    const signal = AbortSignal.timeout(this.timeoutMs);
    try {
      // Pull session/user from ALS → env → process defaults so the server
      // can upsert into `sessions` (Sessions UI population) and tag audit
      // events with proper user attribution. Fallback chain is implemented
      // in `getAgentumContext`.
      const resp = await this.fetchFn(`${this.baseUrl}/api/v1/sdk/evaluate-tool-call`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": this.apiKey,
        },
        body: JSON.stringify({
          agent_id:  this.agentId,
          tool_name: args.toolName,
          arguments: args.arguments ?? null,
          session_id: ctx.sessionId ?? null,
          user_id:    ctx.userId    ?? null,
          // Thread resolved dimensions through to the gateway.
          // Backward-compatible: empty `{}` is treated as `Option::None` on the
          // Rust side (per the parity invariant in `hash_authz_context_with_dims`).
          dimensions: dims,
          // MCP-REDESIGN Phase 2b — send the MCP server identifier so central
          // can resolve the canonical `server_id` (the SDK has no registry).
          // Additive + dual-accept: `tool_name` above still carries its current
          // namespaced form so an old central matches existing policies. Both
          // fields are serde-default on the Rust side; omit when undefined.
          ...(args.mcpServerUrl !== undefined
            ? { mcp_server_url: args.mcpServerUrl }
            : {}),
          ...(args.mcpServerName !== undefined
            ? { mcp_server_name: args.mcpServerName }
            : {}),
        }),
        signal,
      });

      if (!resp.ok) {
        const body = await safeText(resp);
        this.logger.warn(
          `[agentum] evaluate-tool-call HTTP ${resp.status} for tool=${args.toolName}: ${body}`,
        );
        return this.failClosed();
      }

      const data = (await resp.json()) as {
        decision: string;
        rule_id?: string;
        reason?: string;
        deny_code?: string;
        advice?: string[];
        hitl_pending?: boolean;
        ttl_ms: number;
        policy_hash?: string;
      };

      const out: ToolCallEvaluation = {
        decision: data.decision === "allow" ? "allow" : "deny",
        ttlMs:    typeof data.ttl_ms === "number" ? data.ttl_ms : 0,
        decisionSource: "central",
      };
      if (data.rule_id) out.ruleId = data.rule_id;
      if (data.reason)  out.reason = data.reason;
      if (typeof data.deny_code === "string" && data.deny_code.length > 0) {
        out.denyCode = data.deny_code as DenyCode;
      }
      if (Array.isArray(data.advice)) out.advice = data.advice;
      if (data.hitl_pending === true) out.hitlPending = true;
      if (typeof data.policy_hash === "string" && data.policy_hash.length > 0) {
        out.policyHash = data.policy_hash;
      }

      // Cache only if server gave a positive ttl. Smuggle the
      // `ToolCallEvaluation` through the `PolicySimulateResponse`-typed
      // store; the cache treats it as opaque.
      if (out.policyHash !== undefined) {
        this.lastPolicyHash = out.policyHash;
      }
      if (out.ttlMs > 0) {
        const putKey = DecisionCache.key(
          this.agentId,
          `tool:${args.toolName}`,
          "*",
          ctxHash,
          out.policyHash,
        );
        this.cache.put(putKey, (out as unknown) as PolicySimulateResponse);
      }
      // Record the central-served decision in audit.
      this.emitLocalPdpDecisionAudit({
        toolName: args.toolName,
        evaluation: out,
        source: "central",
      });
      return out;
    } catch (err) {
      const errName = (err as Error)?.name;
      const reason = (errName === "AbortError" || errName === "TimeoutError")
        ? `timeout after ${this.timeoutMs}ms`
        : (err as Error)?.message ?? String(err);
      this.logger.warn(
        `[agentum] evaluate-tool-call failed for tool=${args.toolName}: ${reason}`,
      );
      return this.failClosed(reason);
    }
  }

  /**
   * Probe `${pdpUrl}/v1/health` and cache the result for `pdpDiscoveryTtlMs`.
   * Returns `false` immediately when no `pdpUrl` is configured; otherwise
   * returns `true` only when the probe gets a 2xx within `pdpProbeTimeoutMs`
   * AND the response body reports `agent_id === this.agentId`.
   *
   * `agent_id` mismatch is fail-closed. If a sibling PDP is serving a
   * different agent (uid skew during a migration, wrong sidecar wired up,
   * etc.) we MUST NOT trust its decisions. Mismatch flips `pdpAlive=false`
   * for the rest of the discovery window so subsequent calls fall through to
   * central without re-probing. The error is logged once per discovery
   * window — the next probe (after TTL expiry) will log again if the misconfig
   * persists.
   *
   * This is the steady-state fast path: once the PDP is known alive, every
   * subsequent `evaluateToolCall` for the next 30s skips the probe and goes
   * straight to `/v1/authorize`. A 5xx / transport error in `attemptPdp`
   * flips the cached state to unhealthy so we don't hammer a sick sidecar.
   */
  private async discoverPdp(): Promise<boolean> {
    if (!this.pdpUrl) return false;
    const now = Date.now();
    if (this.pdpAlive !== null && now < this.pdpAliveExpiresAt) {
      return this.pdpAlive;
    }
    let alive = false;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.pdpProbeTimeoutMs);
      try {
        const r = await this.fetchFn(`${this.pdpUrl}/v1/health`, {
          method: "GET",
          signal: ctrl.signal,
        });
        if (r.ok) {
          // agent_id must match. Parse the body; treat parse failure or
          // mismatch as fail-closed.
          let parsed: { agent_id?: unknown } | undefined;
          try {
            parsed = (await r.json()) as { agent_id?: unknown };
          } catch (parseErr) {
            this.logger.error(
              `[agentum] PDP /v1/health returned 2xx but body did not parse as JSON: ` +
              `${(parseErr as Error).message}. Failing closed; will not route to PDP ` +
              `until next discovery window.`,
            );
            parsed = undefined;
          }
          const got = parsed && typeof parsed.agent_id === "string"
            ? parsed.agent_id
            : undefined;
          if (got === this.agentId) {
            alive = true;
          } else {
            this.logger.error(
              `[agentum] PDP /v1/health agent_id mismatch — expected="${this.agentId}", ` +
              `got=${got === undefined ? "<missing>" : `"${got}"`}. Failing closed; ` +
              `will route to central until next discovery window.`,
            );
            alive = false;
          }
        } else {
          alive = false;
        }
      } finally {
        clearTimeout(timer);
      }
    } catch {
      alive = false;
    }
    this.pdpAlive = alive;
    this.pdpAliveExpiresAt = now + this.pdpDiscoveryTtlMs;
    return alive;
  }

  /**
   * POST to the local PDP `/v1/authorize`. Returns either a finished
   * `ToolCallEvaluation` (200, or 401 fail-closed) or the sentinel
   * `"fallback"` to signal that the caller should hit central.
   *
   * Status handling:
   *   - 200: parse `{decision, rule_id?, reason?, policy_hash, advice?}`,
   *     stamp `decisionSource: "pdp"` + `policyHash`, return.
   *   - 401: log error (misconfigured token), fail closed, **do NOT** fall
   *     back to central (strict).
   *   - 5xx / transport / timeout: mark PDP unhealthy for the rest of the
   *     discovery window, return `"fallback"` so central runs once.
   *   - Other 4xx (400/404/422): treat as caller misuse; return `"fallback"`
   *     so central is the safety net but PDP stays "alive" (don't punish
   *     well-behaved peers for one bad request).
   *
   * NOTE: the PDP `AuthorizeRequest` shape is
   * `{ principal: Option<String>, action: String, resource: String,
   *    context: Option<JSON>, dimensions: BTreeMap<String,String> }`
   * (`crates/agentum-pdp/src/server.rs` `struct AuthorizeRequest`).
   * The PDP merges the top-level `dimensions` onto `context` via
   * `merge_dimensions_into_context`, so dimension-keyed Cedar policies
   * (and S3-15b per-scope capability sets) now evaluate identically on the
   * PDP plane and the central `/sdk/evaluate-tool-call` plane. The
   * `dimensions` field carries serde-default semantics — older PDP builds
   * that predate the field ignore it (tolerant deserialise), so sending it
   * is always safe.
   *
   * Central's `/api/v1/sdk/evaluate-tool-call` still takes a flatter shape
   * (`{agent_id, tool_name, arguments, session_id, user_id, dimensions}`).
   * The two envelopes remain structurally different — TODO: once the PDP
   * enforcement-bundle extension lands, unify these so `tool_name` /
   * `arguments` map cleanly onto Cedar `(action, resource, context)`
   * server-side.
   */
  private async attemptPdp(
    args: {
      toolName: string;
      arguments?: unknown;
      mcpServerUrl?: string;
      mcpServerName?: string;
    },
    ctx: ReturnType<typeof getAgentumContext>,
    dims: Record<string, string>,
  ): Promise<ToolCallEvaluation | "fallback"> {
    if (!this.pdpUrl) return "fallback";
    const signal = AbortSignal.timeout(this.timeoutMs);
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.pdpServiceToken) {
      headers["Authorization"] = `Bearer ${this.pdpServiceToken}`;
    }
    const body = JSON.stringify({
      // PDP defaults `principal` to its own `agent_id` when omitted; we send
      // it explicitly so audit attribution stays correct if the sidecar
      // serves multiple agents in future.
      principal: this.agentId,
      action: `tool:${args.toolName}`,
      resource: args.toolName,
      context: {
        arguments: args.arguments ?? null,
        session_id: ctx.sessionId ?? null,
        user_id: ctx.userId ?? null,
        // MCP-REDESIGN Phase 2b — additive free-JSON context inputs so a
        // PDP build that resolves `server_id` can do so without the central
        // round-trip. Omit when undefined; older PDP builds ignore unknown
        // context keys (tolerant deserialise).
        ...(args.mcpServerUrl !== undefined
          ? { mcp_server_url: args.mcpServerUrl }
          : {}),
        ...(args.mcpServerName !== undefined
          ? { mcp_server_name: args.mcpServerName }
          : {}),
      },
      // Top-level resolved tenant-schema dimensions (string→string; nulls
      // already stripped by the caller). The PDP merges these onto `context`
      // server-side, matching the central plane's behaviour. Empty `{}` is
      // the serde default and is treated as "no dimensions".
      dimensions: dims,
    });

    let resp: Response;
    try {
      resp = await this.fetchFn(`${this.pdpUrl}/v1/authorize`, {
        method: "POST",
        headers,
        body,
        signal,
      });
    } catch (err) {
      // Transport error / timeout — mark PDP unhealthy and fall back.
      this.markPdpUnhealthy();
      const errName = (err as Error)?.name;
      const reason = (errName === "AbortError" || errName === "TimeoutError")
        ? `timeout after ${this.timeoutMs}ms`
        : (err as Error)?.message ?? String(err);
      this.logger.warn(
        `[agentum] PDP /v1/authorize transport error for tool=${args.toolName}: ${reason} (falling back to central)`,
      );
      return "fallback";
    }

    if (resp.status === 401) {
      this.logger.error(
        "[agentum] PDP returned 401 — check AGENTUM_PDP_SERVICE_TOKEN. " +
        "Failing closed; will NOT fall back to central.",
      );
      return this.failClosed("pdp_unauthorized");
    }

    if (resp.status >= 500) {
      this.markPdpUnhealthy();
      const text = await safeText(resp);
      this.logger.warn(
        `[agentum] PDP /v1/authorize HTTP ${resp.status} for tool=${args.toolName}: ${text} (falling back to central)`,
      );
      return "fallback";
    }

    if (!resp.ok) {
      // Other 4xx — likely a misshapen request. Fall back without marking
      // PDP unhealthy.
      const text = await safeText(resp);
      this.logger.warn(
        `[agentum] PDP /v1/authorize HTTP ${resp.status} for tool=${args.toolName}: ${text} (falling back to central)`,
      );
      return "fallback";
    }

    const data = (await resp.json()) as {
      decision: string;
      rule_id?: string;
      reason?: string;
      policy_hash?: string;
      evaluated_locally?: boolean;
      latency_us?: number;
      advice?: unknown;
      hitl_pending?: unknown;
      enabled_addons?: unknown;
      bundle_loaded?: unknown;
    };

    // R45b / INTEG-B1 — capture the bundle's `enabled_addons` so the PII
    // gate and the framework HITL guards can consult `featureState()`. The
    // PDP now ALWAYS serializes `enabled_addons` (even `[]`) plus
    // `bundle_loaded:true` once a bundle is loaded, so an authorize against
    // a loaded engine carries the snapshot even when zero addons are on.
    //
    // `snapshotReceived` flips true once we observe either signal — an
    // `enabled_addons` array OR `bundle_loaded:true`. From that point an
    // addon absent from the array is `"disabled"` (fail-CLOSED), not
    // `"unknown"`. A response that carries NEITHER signal (a pre-INTEG-B1
    // PDP, or `bundle_loaded:false` pre-sync) leaves `snapshotReceived`
    // untouched so callers keep their SAFE default. Filter to strings;
    // ignore non-string members.
    const bundleLoaded = data.bundle_loaded === true;
    if (Array.isArray(data.enabled_addons)) {
      this.lastEnabledAddons = (data.enabled_addons as unknown[]).filter(
        (s): s is string => typeof s === "string",
      );
      this.snapshotReceived = true;
    } else if (bundleLoaded) {
      // Loaded bundle but no array field (older PDP that gates
      // `bundle_loaded` but still skip-empties `enabled_addons`): treat as
      // a loaded bundle with zero addons.
      this.lastEnabledAddons = [];
      this.snapshotReceived = true;
    } else {
      // No snapshot signal at all — preserve any prior snapshot and the
      // current `snapshotReceived` state rather than silently clearing it.
      this.lastEnabledAddons = [];
    }

    const out: ToolCallEvaluation = {
      decision: data.decision === "allow" ? "allow" : "deny",
      // PDP doesn't currently surface a per-decision TTL — treat each
      // response as cacheable for a short window. The DecisionCache shell
      // ttlMs (60s) bounds this in practice.
      ttlMs: 1_000,
      decisionSource: "pdp",
    };
    if (data.rule_id) out.ruleId = data.rule_id;
    if (data.reason)  out.reason = data.reason;
    if (typeof data.policy_hash === "string" && data.policy_hash.length > 0) {
      out.policyHash = data.policy_hash;
    }
    // Surface PDP observability fields so audit emit sites can
    // attribute decisions correctly and operators can graph PDP latency.
    if (typeof data.evaluated_locally === "boolean") {
      out.evaluatedLocally = data.evaluated_locally;
    }
    if (typeof data.latency_us === "number") {
      out.pdpLatencyUs = data.latency_us;
    }
    // PDP returns `advice: Vec<String>` byte-identical to central's
    // `AuthzDecision`. Mirror the central-path passthrough above; explicit
    // type-narrow keeps `strict` happy without `any`.
    if (Array.isArray(data.advice)) {
      const advice = (data.advice as unknown[]).filter(
        (s): s is string => typeof s === "string",
      );
      if (advice.length > 0) out.advice = advice;
    }
    // HITL-1: PDP serializes `hitl_pending` (serde-skipped when false).
    if (data.hitl_pending === true) out.hitlPending = true;
    return out;
  }

  private markPdpUnhealthy(): void {
    this.pdpAlive = false;
    this.pdpAliveExpiresAt = Date.now() + this.pdpDiscoveryTtlMs;
  }

  /**
   * INTEG-B1 — tri-state enablement of a policy addon for this agent's
   * loaded bundle. Consulted by the observe-prompt PII gate
   * (`addon.policy.pii-advanced`) and the framework HITL escalation guards
   * (`addon.policy.hitl`).
   *
   * - No snapshot received yet (cold start / central-only / PDP not wired /
   *   post-invalidation gap) → `"unknown"`. Callers apply a per-feature
   *   SAFE default — NOT a blanket fail-OPEN.
   * - Snapshot received AND addon present → `"enabled"`.
   * - Snapshot received AND addon absent → `"disabled"` (fail-CLOSED). This
   *   is the trustworthy "the feature was turned off" signal: a
   *   populated-then-emptied bundle (`enabled_addons:[]`,
   *   `bundle_loaded:true`) yields `"disabled"`.
   *
   * Replaces the prior fail-OPEN `isAddonEnabled`, which reported every
   * addon enabled on an empty snapshot.
   */
  public featureState(addonId: string): FeatureState {
    if (!this.snapshotReceived) return "unknown";
    return this.lastEnabledAddons.includes(addonId) ? "enabled" : "disabled";
  }

  /**
   * INTEG-B1 — has ANY non-error PDP authorize response carried addon
   * snapshot data yet? `false` means `featureState()` returns `"unknown"`
   * for every addon. Exposed for tests and for callers that want to log the
   * cold-start vs. live-snapshot distinction.
   */
  public hasAddonSnapshot(): boolean {
    return this.snapshotReceived;
  }

  /**
   * R45b / INTEG-B1 — the last-observed `enabled_addons` snapshot. Empty
   * when no PDP authorize has populated it yet OR when a loaded bundle
   * enables zero addons — use {@link hasAddonSnapshot}/{@link featureState}
   * to distinguish those two cases. Retained for the interceptor install
   * sites and inspection.
   */
  public enabledAddonsSnapshot(): readonly string[] {
    return this.lastEnabledAddons;
  }

  /**
   * Public, fire-and-forget MCP-stdio audit emit (R26). The MCP-stdio patch
   * has no `AgentumClient` handle (it only receives `_config` + a thunk to
   * this evaluator), so it routes audit events through here. We reuse the
   * same `attachDimensionsAndPost` → `postAuditEvent` pipeline that the
   * tool-call decision audits use: that path resolves tenant-schema
   * dimensions, runs the PII pipeline, and POSTs to the real
   * `/api/v1/audit/ingest` ingest contract with replay-prevention freshness
   * headers — none of which the patch's raw-fetch fallback could replicate
   * without duplicating logic.
   *
   * `eventType` MUST be a snake_case string that parses via the Rust
   * `AuditEventType::from_str` (`crates/agentum-core/src/models/audit.rs`);
   * `mcp_tool_call` / `mcp_tool_deny` map to real variants. Anything else
   * lands as `Unknown` and is invisible to event-type filters.
   */
  public emitMcpAudit(args: {
    eventType: string;
    toolName: string;
    outcome: string;
    detail?: Record<string, unknown>;
  }): void {
    const ctx = getAgentumContext();
    const event: AuditIngestRequest = {
      agent_id: this.agentId,
      session_id: ctx.sessionId ?? "",
      event_type: args.eventType,
      outcome: args.outcome,
      tool: args.toolName,
      detail: args.detail ?? { tool: args.toolName },
    };
    this.attachDimensionsAndPost(event);
  }

  /**
   * Fire-and-forget POST to `/api/v1/audit/ingest` recording a
   * `LocalPdpDecision` event for the just-resolved tool-call decision.
   * Mirrors the Rust `AuditEventType::LocalPdpDecision` variant so
   * analytics can attribute decisions to their plane (PDP vs. central
   * vs. cache).
   *
   * Failures are swallowed at warn — audit must never block a live tool
   * call.
   */
  private emitLocalPdpDecisionAudit(args: {
    toolName: string;
    evaluation: ToolCallEvaluation;
    source: "local_pdp" | "central" | "cache" | "approval_grant";
    /** Correlation id of the prior `requestApproval` whose grant
     *  short-circuited this call. Only set when `source === "approval_grant"`.
     *  Threaded into `detail.approval_request_id` so audit consumers can
     *  join the short-circuited allow row back to the original approval. */
    approvalRequestId?: string;
  }): void {
    const ctx = getAgentumContext();
    const detail: Record<string, unknown> = {
      tool: args.toolName,
      decision: args.evaluation.decision,
    };
    if (args.evaluation.ruleId) detail["rule_id"] = args.evaluation.ruleId;
    if (args.evaluation.reason) detail["reason"] = args.evaluation.reason;
    if (typeof args.evaluation.evaluatedLocally === "boolean") {
      detail["evaluated_locally"] = args.evaluation.evaluatedLocally;
    }
    if (typeof args.evaluation.pdpLatencyUs === "number") {
      detail["pdp_latency_us"] = args.evaluation.pdpLatencyUs;
    }
    if (args.approvalRequestId) {
      detail["approval_request_id"] = args.approvalRequestId;
    }
    const event: AuditIngestRequest = {
      agent_id: this.agentId,
      session_id: ctx.sessionId ?? "",
      event_type: "local_pdp_decision",
      outcome: args.evaluation.decision,
      tool: args.toolName,
      decision_source: args.source,
      detail,
    };
    if (args.evaluation.policyHash) {
      event.policy_hash = args.evaluation.policyHash;
    }
    // Split the cache-served and HITL-grant semantics
    // out of `decision_source` onto dedicated wire fields:
    //   * `cache_hit: true` whenever the SDK short-circuited without
    //     reaching the wire — the in-process `DecisionCache` (`cache`
    //     source) and the `ApprovalGrantCache` (`approval_grant`
    //     source) are both cache-served from the audit pipeline's
    //     perspective.
    //   * `hitl_grant_id` carries the grant UUID on the
    //     `approval_grant` path so dashboards can join the cached
    //     allow back to its originating approval. The check shape-
    //     gates the UUID because the Rust ingest field is
    //     `Option<uuid::Uuid>` (strict serde parse) and a malformed
    //     string would 422 the whole event.
    if (args.source === "cache" || args.source === "approval_grant") {
      event.cache_hit = true;
    }
    if (
      args.source === "approval_grant" &&
      args.approvalRequestId &&
      isUuidV4Shape(args.approvalRequestId)
    ) {
      event.hitl_grant_id = args.approvalRequestId;
    }
    this.attachDimensionsAndPost(event);
  }

  /**
   * Fire-and-forget POST recording a `LocalPdpStale` event when the
   * SDK observes a `policy_hash` from the PDP that differs from the most
   * recently-seen hash (`expectedPolicyHash`). Both hashes are carried in
   * `detail` for forensic correlation. Lazy emission — fired once per
   * mismatch transition, not per cached decision under the new hash.
   */
  private emitLocalPdpStaleAudit(args: {
    toolName: string;
    expectedPolicyHash: string;
    observedPolicyHash: string;
  }): void {
    const ctx = getAgentumContext();
    const event: AuditIngestRequest = {
      agent_id: this.agentId,
      session_id: ctx.sessionId ?? "",
      event_type: "local_pdp_stale",
      outcome: "stale",
      tool: args.toolName,
      policy_hash: args.observedPolicyHash,
      decision_source: "local_pdp",
      detail: {
        tool: args.toolName,
        expected_policy_hash: args.expectedPolicyHash,
        observed_policy_hash: args.observedPolicyHash,
      },
    };
    this.attachDimensionsAndPost(event);
  }

  /**
   * Resolve tenant-schema dimensions for this audit event and POST.
   * Fire-and-forget: any resolver error (e.g. missing required dimension, PII
   * masking failure) is swallowed at warn so audit emission never blocks a
   * live tool call. Events still ship with `dimensions` omitted on resolver
   * failure — the gateway tolerates the absence.
   *
   * Pre-init callers (no active schema) are not expected to reach this code
   * path — `emitLocalPdpDecisionAudit` only fires after a decision, which
   * implies `init()` has run. The try/catch below covers the corner case
   * defensively.
   */
  private attachDimensionsAndPost(event: AuditIngestRequest): void {
    resolveDimensions()
      .then((dims) => {
        if (dims && Object.keys(dims).length > 0) {
          event.dimensions = dims;
        }
        this.postAuditEvent(event);
      })
      .catch(() => {
        // Resolver failed (pre-init, schema parse error, required-dimension
        // missing). Ship the event without dimensions rather than dropping it.
        this.postAuditEvent(event);
      });
  }

  /**
   * Internal — fire-and-forget POST to `/api/v1/audit/ingest`. Same
   * posture as `emitStreamingUnenforced` in `fetch-interceptor.ts`: never
   * throws, never blocks the tool call, never retries. The runtime audit
   * buffer (`AgentumClient.ingestAuditEvent`) is the durability path —
   * cedar-client.ts is reached from contexts that do not own a client
   * handle, so we POST directly with a short timeout.
   */
  private postAuditEvent(event: AuditIngestRequest): void {
    const url = `${this.baseUrl}/api/v1/audit/ingest`;
    // Q4: send replay-prevention headers on every audit POST. Central
    // default `audit_ingest_require_freshness` is TRUE post-Q4; requests
    // without these headers are rejected on net-new tenants.
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Api-Key": this.apiKey,
      ...freshnessHeaders(),
    };
    const timeoutMs = this.observePromptTimeoutMs;
    const fire = async (): Promise<void> => {
      // Y05 — run the PII pipeline before the wire emit. Fail-CLOSED:
      // on `PiiSelfCheckFailedError` we drop the event entirely rather
      // than emit unmasked-with-warning (per `.claude/rules/pii.md`
      // invariant #11). Pipeline bugs (non-PII errors) propagate to the
      // outer try/catch where they are warn-logged like any other audit
      // ingest failure — they're not leaks but they are still
      // operationally interesting.
      let scrubbed: AuditIngestRequest;
      try {
        if (event.detail === undefined || isPiiPipelineNoOp()) {
          scrubbed = event;
        } else {
          const { detail: scrubbedDetail, pii_key_id } = await runPiiPipeline(
            event.detail,
            event.tool ?? "*",
          );
          // Y06 — when hash/tokenize fired the pipeline returns a key
          // fingerprint that must reach the wire. Allocate a fresh
          // request even on identity-equal `detail` so the new field
          // is set.
          if (scrubbedDetail === event.detail && pii_key_id === undefined) {
            scrubbed = event;
          } else {
            scrubbed = {
              ...event,
              detail: scrubbedDetail as Record<string, unknown>,
            };
            if (pii_key_id !== undefined) scrubbed.pii_key_id = pii_key_id;
          }
        }
      } catch (err) {
        if (err instanceof PiiSelfCheckFailedError) {
          this.logger.warn(
            JSON.stringify({
              level: "warn",
              source: "agentum-sdk",
              component: "pii-pipeline",
              metric: "pii_self_check_failed_total",
              reason: "pii_self_check_failed",
              pattern: err.unmaskedPatternId,
              event_type: event.event_type,
              tool: event.tool,
            }),
          );
          return; // drop the event entirely — never emit unmasked
        }
        this.logger.warn(
          `[agentum] pii pipeline error for ${event.event_type}: ${(err as Error).message}`,
        );
        return;
      }
      const payload = JSON.stringify(scrubbed);
      try {
        const resp = await this.fetchFn(url, {
          method: "POST",
          headers,
          body: payload,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!resp.ok) {
          this.logger.warn(
            `[agentum] audit/ingest ${event.event_type} HTTP ${resp.status}`,
          );
        }
      } catch (err) {
        this.logger.warn(
          `[agentum] audit/ingest ${event.event_type} failed: ${(err as Error).message}`,
        );
      }
    };
    // Register the in-flight promise so test teardown can
    // `await flushPendingAudits()`. Self-evicts on settle so production
    // memory does not grow.
    const p = fire().finally(() => {
      this.pendingAudits.delete(p);
    });
    this.pendingAudits.add(p);
  }

  /**
   * Await every fire-and-forget audit POST currently in flight.
   *
   * Production code never needs to call this — the POSTs self-resolve.
   * Tests should call it in `afterEach`/`afterAll` so a pending POST
   * does not race the test boundary and produce a Jest "Cannot log
   * after tests are done" notice or hold a worker open past test end.
   *
   * Resolves once every queued POST has settled. Subsequent
   * `postAuditEvent` calls after this resolves are not awaited.
   */
  async flushPendingAudits(): Promise<void> {
    if (this.pendingAudits.size === 0) return;
    await Promise.allSettled(Array.from(this.pendingAudits));
  }

  /** Drop all cached decisions. Call on PolicyUpdated webhook. */
  invalidateAll(): void {
    this.cache.invalidateAll();
    this.approvalGrants.clear();
  }

  /**
   * Drop cached decisions for the given agent in response to a central
   * `policy` SSE event. Central's policy bundle is tenant-wide so the
   * event payload does NOT carry an `agent_id` (verified against
   * `crates/agentum-api/src/routes/policy_distribution.rs::UrgentEvent::Policy`
   * — `{ version, bundle_hash_hex, reason }`). This client is bound to
   * exactly one `agentId` for its lifetime, so we treat a tenant-wide
   * policy churn as an invalidation for our agent and clear the whole
   * decision cache. The HITL approval-grant ledger is preserved — those
   * grants reflect explicit operator approvals, not policy state.
   *
   * The `agentId` argument is accepted for API symmetry and so a future
   * multi-agent evaluator can short-circuit on mismatch; today a mismatch
   * is logged and the call is a no-op.
   *
   * Also clears `lastPolicyHash` so the next decision can re-key the
   * cache under whatever fresh hash central or the PDP returns.
   */
  invalidatePolicyCache(agentId?: string): void {
    if (agentId !== undefined && agentId !== this.agentId) {
      this.logger.warn(
        `[agentum] invalidatePolicyCache: agent mismatch (got ${agentId}, bound to ${this.agentId}); ignoring`,
      );
      return;
    }
    this.cache.invalidateAll();
    this.lastPolicyHash = undefined;
    // R45b / INTEG-B1 — a policy churn can flip addon enablement; drop the
    // snapshot AND the received flag so the next PDP authorize re-establishes
    // ground truth. In the gap `featureState()` returns `"unknown"` and
    // callers apply their per-feature SAFE default.
    this.lastEnabledAddons = [];
    this.snapshotReceived = false;
  }

  /**
   * Drop cached decisions in response to a central
   * `capability_effective_set_changed` SSE event. The wire shape from
   * `UrgentEvent::CapabilityEffectiveSetChanged` is
   * `{ scope_value, capability_set_hash }` — there is no `agent_id` or
   * `scope_dimension` field today, so the SDK invalidates the whole
   * decision cache (capabilities feed Cedar evaluation so a capability
   * churn invalidates every prior decision). `scopeValue` is accepted
   * for forensic logging and so a future per-scope invalidation can
   * narrow this without changing the call sites.
   */
  invalidateCapabilityCache(scopeValue?: string): void {
    if (scopeValue !== undefined) {
      this.logger.log(
        `[agentum] invalidateCapabilityCache: scope_value=${scopeValue}`,
      );
    }
    this.cache.invalidateAll();
    this.lastPolicyHash = undefined;
    // R45b / INTEG-B1 — a capability churn can flip addon enablement; drop
    // the snapshot AND the received flag so the next PDP authorize
    // re-establishes ground truth (`featureState()` → `"unknown"` in the gap).
    this.lastEnabledAddons = [];
    this.snapshotReceived = false;
  }

  /**
   * Record a HITL approval grant. Called by
   * `AgentumSession.requestApproval` after the operator approves so that
   * the next identical `evaluateToolCall({ toolName })` short-circuits
   * to `allow` without re-prompting. `ttlMs` is parsed from the
   * `require_hitl:timeout=NNN` advice on the original decision (defaults
   * to 300_000 ms upstream when no timeout was declared). `requestId`
   * is the correlation id returned by `createHitlAgentRequest`; it is
   * threaded into the `LocalPdpDecision` audit row when a grant
   * short-circuits a call so the audit trail joins back to the original
   * approval.
   *
   * `agentId` MUST match the client's constructor `agentId` for the grant
   * to ever be found (the find call below pins on `this.agentId`); the
   * argument is accepted for API symmetry with `findApprovalGrant` and
   * to defend against future multi-agent evaluator sharing.
   */
  async recordApprovalGrant(args: {
    agentId: string;
    toolName: string;
    ttlMs: number;
    requestId?: string;
    /** The tool-call arguments the approval covered. Hashed (canonical-JSON
     *  SHA-256, mirroring agentum-pdp/src/hitl.rs::hash_args) into the grant
     *  key so an approval for one args shape cannot unlock different args.
     *  Absent/undefined hashes as JSON `null` — matching an
     *  `evaluateToolCall({ toolName })` call with no `arguments`. */
    toolArgs?: unknown;
  }): Promise<void> {
    if (args.agentId !== this.agentId) return;
    if (!args.toolName) return;
    const ttl = Math.max(0, args.ttlMs | 0);
    if (ttl === 0) return;
    const argsHash = await hashArgsCanonical(args.toolArgs);
    if (argsHash === undefined) {
      this.logger.warn(
        "[agentum] recordApprovalGrant: no SHA-256 source in runtime; grant NOT recorded (fail-closed)",
      );
      return;
    }
    this.approvalGrants.put(
      args.agentId,
      args.toolName,
      argsHash,
      ttl,
      args.requestId,
    );
  }

  /**
   * Find a live (non-expired) approval grant for the given
   * `(agentId, toolName, argsHash)`. `toolArgs` is canonical-JSON-hashed
   * into the key; absent/undefined hashes as JSON `null`. Returns
   * `undefined` on miss, expiry, or when no SHA-256 source exists. Exposed
   * primarily for test inspection and for future planes that want to
   * consult the ledger before issuing their own escalation; the
   * `evaluateToolCall` short-circuit uses the internal cache directly.
   */
  async findApprovalGrant(args: {
    agentId: string;
    toolName: string;
    toolArgs?: unknown;
  }): Promise<{ requestId?: string; expiresAt: number } | undefined> {
    if (args.agentId !== this.agentId) return undefined;
    const argsHash = await hashArgsCanonical(args.toolArgs);
    if (argsHash === undefined) return undefined;
    return this.approvalGrants.find(args.agentId, args.toolName, argsHash);
  }

  /**
   * PASS2-SDK-01 Item C — pre-populate a HITL approval grant from the
   * `hitl_grant` lifecycle SSE event. Unlike {@link recordApprovalGrant}, the
   * `args_hash` is supplied directly (the SSE payload carries the canonical-JSON
   * SHA-256 already computed by the PDP, `agentum-pdp/src/hitl.rs::hash_args`),
   * so no re-hash of raw arguments is required — and the SSE payload never
   * carries the raw arguments anyway. This closes GR-08's missing-`args_hash`
   * gap: the SDK-side grant key now includes the same canonical args hash the
   * PDP uses, so a benign approval cannot unlock a different args shape.
   *
   * `agentId` MUST match the client's constructor `agentId`; a mismatch is a
   * no-op (the grant could never be found via the `this.agentId`-pinned lookup
   * in `evaluateToolCall`). `ttlMs <= 0` is a no-op. `requestId` is the HITL
   * request correlation id threaded into the grant-hit audit row.
   */
  recordApprovalGrantByHash(args: {
    agentId: string;
    toolName: string;
    argsHash: string;
    ttlMs: number;
    requestId?: string;
  }): void {
    if (args.agentId !== this.agentId) return;
    if (!args.toolName || !args.argsHash) return;
    const ttl = Math.max(0, args.ttlMs | 0);
    if (ttl === 0) return;
    this.approvalGrants.put(
      args.agentId,
      args.toolName,
      args.argsHash,
      ttl,
      args.requestId,
    );
  }

  /**
   * PASS2-SDK-01 Item C — mark an agent as suspended from the
   * `agent_suspended` lifecycle SSE event. Subsequent `evaluateToolCall` for
   * this agent deny in-process (fail-CLOSED fast-path) until
   * {@link clearSuspended} is called from the `agent_activated` event. A
   * mismatched `agentId` (not this client's agent) is ignored — this evaluator
   * only governs `this.agentId`.
   */
  markSuspended(agentId: string): void {
    if (agentId !== this.agentId) return;
    this.suspendedAgents.add(agentId);
  }

  /**
   * PASS2-SDK-01 Item C — clear the local suspend deny-set entry for an agent
   * from the `agent_activated` lifecycle SSE event. No-op for a mismatched
   * `agentId`.
   */
  clearSuspended(agentId: string): void {
    if (agentId !== this.agentId) return;
    this.suspendedAgents.delete(agentId);
  }

  /**
   * PASS2-SDK-01 Item C — test/inspection accessor: is the given agent in the
   * local fail-CLOSED suspend deny-set?
   */
  isSuspended(agentId: string): boolean {
    return this.suspendedAgents.has(agentId);
  }

  /**
   * Fire-and-forget POST to `/sdk/observe-prompt` recording that a plain-text
   * (non-tool-call) LLM completion finished. Without this, every plain-text
   * turn left zero post-flight events because the tool-call enforcement path
   * was the only emit site.
   *
   * The envelope reuses `observe-prompt` (no server schema change required —
   * `params` is free-form and the server accepts a
   * `kind: "plaintext_completion"` discriminator there).
   * `messages` is left empty: the prompt body is already audited by the
   * fetch-interceptor's request-side observe-prompt; this event is a
   * response-side companion correlated by a fresh request_id.
   *
   * Fire-and-forget. Failures are swallowed and logged at warn — the live
   * LLM response is never blocked on an audit emission.
   */
  recordPlaintextCompletion(meta: {
    provider: string;
    model: string;
    finishReason?: string | null;
    role?: string | null;
    completionId?: string | null;
    usage?: Record<string, unknown> | null;
    contentByteCount?: number | null;
  }): void {
    const requestId = randomUuid();
    if (!requestId) {
      // No UUID source available (very old runtime). Skip — emitting with a
      // non-UUID would be rejected server-side as a 4xx and the warn log
      // would just be noise.
      return;
    }
    const ctx = getAgentumContext();
    const params: Record<string, unknown> = {
      kind: "plaintext_completion",
    };
    if (meta.finishReason !== undefined && meta.finishReason !== null) {
      params["finish_reason"] = meta.finishReason;
    }
    if (meta.role) params["role"] = meta.role;
    if (meta.completionId) params["completion_id"] = meta.completionId;
    if (meta.usage) params["usage"] = meta.usage;
    if (typeof meta.contentByteCount === "number") {
      params["content_byte_count"] = meta.contentByteCount;
    }
    const payload = JSON.stringify({
      agent_id: this.agentId,
      request_id: requestId,
      provider: meta.provider,
      model: meta.model || "unknown",
      params,
      messages: [],
      tools_advertised: [],
      session_id: ctx.sessionId ?? null,
      user_id: ctx.userId ?? null,
      client_ts: new Date().toISOString(),
    });

    const url = `${this.baseUrl}/api/v1/sdk/observe-prompt`;

    // Detached async retry loop — same semantics as fetch-interceptor.ts.
    // The server's observe-prompt endpoint is idempotent on
    // (agent_id, request_id) so retry is safe. 4xx is permanent (no retry);
    // 5xx and transport errors are retried with exponential backoff.
    const doPost = async (): Promise<void> => {
      const timeoutMs = this.observePromptTimeoutMs;
      const maxRetries = this.observePromptMaxRetries;
      const attempts = Math.max(1, maxRetries + 1);
      let lastError: string | undefined;
      for (let i = 0; i < attempts; i++) {
        try {
          const resp = await this.fetchFn(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-Api-Key": this.apiKey,
            },
            body: payload,
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (resp.ok) return;
          // 4xx is permanent — don't retry.
          if (resp.status >= 400 && resp.status < 500) {
            this.logger.warn(
              `[agentum] plaintext-audit observe-prompt HTTP ${resp.status} (no retry)`,
            );
            return;
          }
          lastError = `HTTP ${resp.status}`;
        } catch (err) {
          lastError = (err as Error).message;
        }
        if (i < attempts - 1) {
          // Exponential backoff: 50ms, 200ms, 800ms, ...
          await sleep(50 * Math.pow(4, i));
        }
      }
      this.logger.warn(
        `[agentum] plaintext-audit dropped after ${attempts} attempt(s): ${lastError}`,
      );
    };

    void doPost();
  }

  private failClosed(reason?: string): ToolCallEvaluation {
    if (this.failMode === "allow") {
      return { decision: "allow", ttlMs: 0 };
    }
    return {
      decision: "deny",
      ttlMs:    0,
      reason:   reason ? `agentum-fail-closed: ${reason}` : "agentum-fail-closed",
      // The synthetic deny emitted on transport/timeout failure carries
      // the same `deny_fail_closed` code the server emits for explicit
      // fail-closed paths, so consumers can branch identically. The one
      // exception is a 401 from the local PDP (`reason === "pdp_unauthorized"`):
      // that is a misconfigured `AGENTUM_PDP_SERVICE_TOKEN`, not a transport
      // failure, so it gets its own `deny_pdp_unauthorized` code to let
      // callers branch on the auth case vs. a generic transport deny.
      denyCode: reason === "pdp_unauthorized" ? "deny_pdp_unauthorized" : "deny_fail_closed",
    };
  }
}

async function safeText(resp: Response): Promise<string> {
  try {
    return await resp.text();
  } catch {
    return "";
  }
}

/**
 * Best-effort UUID-v4 generator. `globalThis.crypto.randomUUID` is
 * available on Node ≥ 19 and on Vercel Edge / Cloudflare Workers; we avoid
 * `node:crypto` here so this client stays edge-loadable. Returns
 * `undefined` if no source is available — callers must handle that.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Bounded in-process LRU keyed on `(agentId, toolName)` with
 * per-entry expiry. Backs `CedarToolCallClient.{recordApprovalGrant,
 * findApprovalGrant}` so identical tool calls within the HITL grant
 * window skip re-escalation.
 *
 * Why not reuse `DecisionCache`? That LRU stores `PolicySimulateResponse`
 * shapes and applies a single ambient `ttlMs` across the whole map;
 * grant TTL is per-entry (derived from the `require_hitl:timeout=NNN`
 * advice on the originating decision), so a parallel structure is the
 * simpler fit.
 *
 * Eviction policy: insertion-ordered `Map`, so on overflow `.keys()`
 * yields the oldest insertion first and we delete it. `find()` is
 * LRU-bump-on-hit to keep hot entries warm.
 *
 * NOT cross-process. Multi-worker Next.js deployments will see each
 * worker maintain its own grant ledger; cross-process sharing is
 * a follow-up.
 */
interface ApprovalGrantEntry {
  expiresAt: number;
  requestId?: string;
}

export class ApprovalGrantCache {
  private readonly maxSize: number;
  private readonly entries = new Map<string, ApprovalGrantEntry>();

  constructor(maxSize: number) {
    this.maxSize = Math.max(1, maxSize | 0);
  }

  private static key(
    agentId: string,
    toolName: string,
    argsHash: string,
  ): string {
    // Pipe separator matches the `DecisionCache` convention and the Rust
    // joined form `{agent_id}|{tool}|{args_hash}` (hitl.rs:204); `agentId`
    // and `toolName` are opaque strings supplied by the SDK caller and
    // `argsHash` is hex (no pipe), so no sanitisation needed — both ends
    // are local in-process.
    return `${agentId}|${toolName}|${argsHash}`;
  }

  put(
    agentId: string,
    toolName: string,
    argsHash: string,
    ttlMs: number,
    requestId: string | undefined,
  ): void {
    const key = ApprovalGrantCache.key(agentId, toolName, argsHash);
    // Refresh-on-update: drop any prior entry so the new one inserts at
    // the tail of the iteration order (= most recently used).
    this.entries.delete(key);
    if (this.entries.size >= this.maxSize) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    const entry: ApprovalGrantEntry = {
      expiresAt: Date.now() + ttlMs,
    };
    if (requestId !== undefined) entry.requestId = requestId;
    this.entries.set(key, entry);
  }

  find(
    agentId: string,
    toolName: string,
    argsHash: string,
  ): ApprovalGrantEntry | undefined {
    const key = ApprovalGrantCache.key(agentId, toolName, argsHash);
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // LRU-bump on hit so an actively-used grant survives overflow.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry;
  }

  clear(): void {
    this.entries.clear();
  }

  /**
   * Number of live grant entries. Used by `evaluateToolCall` to skip the
   * per-call SHA-256 of `arguments` when the ledger is empty (the common
   * case), and by tests for eviction assertions.
   */
  get size(): number {
    return this.entries.size;
  }
}

function randomUuid(): string | undefined {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return undefined;
}

/**
 * Canonical-JSON stringify — byte-for-byte mirror of the PDP's
 * `agentum-pdp/src/hitl.rs::canonical_json` + `Value::to_string()`:
 * recursive object-key sort in code-point order, array order preserved,
 * compact output (no whitespace). The SHA-256 of this string is the
 * grant-key `args_hash` on both planes.
 */
export function canonicalJsonStringify(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "string") {
    // JSON.stringify: non-finite numbers -> "null" (Rust Value cannot
    // represent them, so no cross-plane conflict); string escaping is
    // identical to serde_json for well-formed strings (", \, \b \t \n
    // \f \r, \u00XX lowercase hex for other control chars).
    return JSON.stringify(v) ?? "null";
  }
  if (Array.isArray(v)) {
    // JSON.stringify parity: undefined / function / symbol elements -> null.
    return "[" + v.map((el) => canonicalJsonStringify(el)).join(",") + "]";
  }
  if (typeof v === "object") {
    // Honor toJSON (Date etc.) so the canonical form matches what
    // JSON.stringify would put on the wire to the PDP.
    const maybe = v as { toJSON?: unknown };
    if (typeof maybe.toJSON === "function") {
      return canonicalJsonStringify((maybe.toJSON as () => unknown).call(v));
    }
    const rec = v as Record<string, unknown>;
    // Code-point sort, NOT default Array.sort (UTF-16 code-unit order) —
    // Rust String::cmp compares UTF-8 bytes, which equals code-point
    // order. Default sort() diverges for keys mixing non-BMP chars with
    // U+E000..U+FFFF. Object.keys() insertion order is also unusable:
    // integer-like keys ("2" vs "10") iterate numerically in JS but sort
    // byte-wise in Rust.
    const keys = Object.keys(rec)
      .filter((k) => rec[k] !== undefined) // JSON.stringify drops undefined values
      .sort(compareCodePoints);
    const parts = keys.map(
      (k) => JSON.stringify(k) + ":" + canonicalJsonStringify(rec[k]),
    );
    return "{" + parts.join(",") + "}";
  }
  // function / symbol / bigint at top level — not representable; JSON
  // null is the safe canonical form (bigint would throw in
  // JSON.stringify; the PDP can never receive one anyway).
  return "null";
}

function compareCodePoints(a: string, b: string): number {
  // Iterate by code point (for..of) so surrogate pairs compare as full
  // code points — equivalent to Rust's byte-wise UTF-8 String::cmp.
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const ra = ia.next();
    const rb = ib.next();
    if (ra.done && rb.done) return 0;
    if (ra.done) return -1;
    if (rb.done) return 1;
    const ca = ra.value.codePointAt(0) ?? 0;
    const cb = rb.value.codePointAt(0) ?? 0;
    if (ca !== cb) return ca - cb;
  }
}

/**
 * SHA-256 hex of the canonical-JSON form of `args`. `undefined` and
 * missing args hash as JSON `null`, matching the PDP's
 * `hash_args(&Value::Null)`. Returns `undefined` when no SHA-256
 * source exists in the runtime — callers MUST treat that as
 * "cannot hash" and skip the grant path entirely (fail-CLOSED:
 * no record, no short-circuit; the call falls through to PDP/central).
 */
export async function hashArgsCanonical(
  args: unknown,
): Promise<string | undefined> {
  const serialised = canonicalJsonStringify(args);
  const bytes = new TextEncoder().encode(serialised);
  const subtle = (globalThis as {
    crypto?: { subtle?: { digest?: (alg: string, d: Uint8Array) => Promise<ArrayBuffer> } };
  }).crypto?.subtle;
  if (subtle && typeof subtle.digest === "function") {
    const buf = await subtle.digest("SHA-256", bytes);
    return toHex(new Uint8Array(buf));
  }
  try {
    const { createHash } = await import("node:crypto");
    return createHash("sha256").update(serialised, "utf8").digest("hex");
  } catch {
    return undefined;
  }
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Shape-gate the `hitl_grant_id` audit field. The Rust
 * ingest handler (`crates/agentum-api/src/routes/audit_ingest.rs`)
 * deserialises it as `Option<uuid::Uuid>` with strict serde parsing; a
 * malformed string would 422 the entire batch. We accept only the
 * canonical 8-4-4-4-12 hex layout (any version digit, any variant) which
 * is what `crypto.randomUUID()` and `Uuid::new_v4().to_string()` both
 * emit. `request_id`s minted outside that path are passed through
 * `detail.approval_request_id` only.
 */
const UUID_SHAPE_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuidV4Shape(s: string): boolean {
  return UUID_SHAPE_RE.test(s);
}
