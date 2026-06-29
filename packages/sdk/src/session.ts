/**
 * AgentumSession — a live, authenticated agent session.
 *
 * Returned by `AgentumClient.connect()` and `AgentumClient.connectExisting()`.
 * Wraps a session-scoped `AgentumClient` and provides convenience methods that
 * automatically inject `agentId` / `sessionId` so callers never have to.
 *
 * Supports TC39 Explicit Resource Management via `Symbol.asyncDispose`:
 *   ```ts
 *   await using session = await client.connect({ ... });
 *   // session is automatically closed when the block exits
 *   ```
 */

import type { AgentumClient } from "./client.js";
import type { ToolCallEvaluation } from "./evaluation/cedar-client.js";
import type {
  ApprovalResult,
  AuditIngestRequest,
  RequestApprovalOptions,
} from "./types.js";
import {
  AgentumError,
  AgentumHitlDeniedError,
  AgentumHitlTimeoutError,
} from "./types.js";

/**
 * Extract the `timeout=NNN` (seconds) value from a Cedar
 * `@advice("require_hitl[:approvals=N,timeout=S]")` advice string and
 * return it in milliseconds. Mirrors the Rust parser at
 * `crates/agentum-authz/src/policy.rs::parse_require_hitl`.
 *
 * The TS port intentionally diverges from the Rust impl in one place:
 * Rust returns `Err(...)` on unknown keys / bad integers so a typo
 * rejects the policy install. The SDK is on the EVAL side — by the time
 * advice reaches here it has already passed the install-boundary
 * validator (`validate_advice_annotations`), so we silently skip
 * unparseable entries and fall back to the caller's default. Fail-CLOSED
 * is preserved: when no `timeout=` is parseable, no grant is recorded
 * unless the caller passes a default, and the next call re-escalates.
 *
 * Returns `undefined` if no `require_hitl` directive carries a valid
 * `timeout=` integer.
 */
export function parseRequireHitlTimeoutMs(
  advice: string[] | undefined,
): number | undefined {
  if (!advice) return undefined;
  for (const raw of advice) {
    if (typeof raw !== "string") continue;
    // Accept both bare `require_hitl` (no params → no timeout) and
    // `require_hitl:key=val[,key=val]`. The bare form yields no timeout.
    let rest: string;
    if (raw === "require_hitl") {
      rest = "";
    } else if (raw.startsWith("require_hitl:")) {
      rest = raw.slice("require_hitl:".length);
    } else {
      continue;
    }
    if (rest.length === 0) continue;
    for (const pairRaw of rest.split(",")) {
      const pair = pairRaw.trim();
      if (pair.length === 0) continue;
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      const key = pair.slice(0, eq).trim();
      const val = pair.slice(eq + 1).trim();
      if (key !== "timeout") continue;
      // Strict integer parse: bare digits only (matches Rust `parse::<u32>`).
      if (!/^\d+$/.test(val)) continue;
      const secs = Number.parseInt(val, 10);
      if (!Number.isFinite(secs) || secs <= 0) continue;
      return secs * 1000;
    }
  }
  return undefined;
}

/** Decode the `exp` claim from a JWT payload without verifying the signature. */
function decodeJwtExpiry(jwt: string): Date {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return new Date(8_640_000_000_000_000);
    // Base64url → base64 → UTF-8 string
    const padded = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
    const decoded =
      typeof atob === "function"
        ? atob(padded)
        : Buffer.from(padded, "base64").toString("utf-8");
    const payload = JSON.parse(decoded) as Record<string, unknown>;
    if (typeof payload["exp"] === "number") {
      return new Date(payload["exp"] * 1000);
    }
  } catch {
    // malformed JWT — treat as never-expiring
  }
  return new Date(8_640_000_000_000_000); // max JS date
}

/**
 * Fail-soft allow/deny outcome returned by {@link AgentumSession.isAllowed}
 * when invoked in structured-result mode (`{ structured: true }`). The
 * scalar boolean form is retained as the default for backwards
 * compatibility; the structured form lets callers distinguish a true
 * policy Deny (`reason: "policy_deny"`) from an inability to refresh
 * the session JWT (`reason: "refresh_failed"`) without exceptions.
 */
export interface PolicyOutcome {
  outcome: "allow" | "deny";
  reason?: "policy_deny" | "refresh_failed" | string;
}

/** Options for configuring auto-refresh behaviour. */
export interface AgentumSessionOptions {
  /**
   * Callback that fetches a fresh session JWT.
   * When provided, `AgentumSession` will call this automatically before API
   * calls when the JWT is within `refreshThresholdMs` of expiry.
   */
  refreshFn?: () => Promise<{ jwt: string; session_id: string }>;
  /**
   * How many milliseconds before JWT expiry to trigger a proactive refresh.
   * Defaults to 60_000 (60 seconds).
   */
  refreshThresholdMs?: number;
  /**
   * When `true`, {@link AgentumSession.close} also calls
   * `client.close()` to drain the audit buffer and clear timers.
   * Sessions created by `AgentumClient.connect()` / `connectExisting()`
   * own their forked client and set this to `true`; callers who pass in
   * their own client should leave this `false` (the default) so the SDK
   * does not unexpectedly shut down a shared client.
   */
  ownsClient?: boolean;
  /**
   * Optional long-lived refresh client that was allocated by
   * `connect()` / `connectExisting()` so a new refresh does not
   * allocate a fresh `AgentumClient` per call. Closed alongside the
   * session when `ownsClient` is true.
   */
  refreshClient?: AgentumClient;
}

export class AgentumSession {
  /** The registered agent's ID. */
  readonly agentId: string;
  /** The underlying client, pre-authenticated with the session JWT. */
  readonly client: AgentumClient;
  /** How many milliseconds before expiry to trigger a proactive refresh. */
  readonly refreshThresholdMs: number;

  private _sessionId: string;
  private _jwt: string;
  private _expiresAt: Date;
  private readonly _refreshFn: (() => Promise<{ jwt: string; session_id: string }>) | null;
  private _refreshPromise: Promise<void> | null = null;
  private _closePromise: Promise<void> | null = null;
  private readonly _ownsClient: boolean;
  private readonly _refreshClient: AgentumClient | null;

  /** The active session ID. Updated after a successful `refresh()`. */
  get sessionId(): string {
    return this._sessionId;
  }

  /** The session JWT. Updated after a successful `refresh()`. */
  get jwt(): string {
    return this._jwt;
  }

  /** UTC timestamp at which this session JWT expires. Updated after `refresh()`. */
  get expiresAt(): Date {
    return this._expiresAt;
  }

  constructor(
    client: AgentumClient,
    agentId: string,
    sessionId: string,
    jwt: string,
    opts?: AgentumSessionOptions,
  ) {
    this.client = client;
    this.agentId = agentId;
    this._sessionId = sessionId;
    this._jwt = jwt;
    this._expiresAt = decodeJwtExpiry(jwt);
    this._refreshFn = opts?.refreshFn ?? null;
    this.refreshThresholdMs = opts?.refreshThresholdMs ?? 60_000;
    this._ownsClient = opts?.ownsClient === true;
    this._refreshClient = opts?.refreshClient ?? null;

    // Wire the refresh function into the client so 401-retry and audit
    // flush can recover without dragging the session into every code path.
    if (this._refreshFn) {
      const rf = this._refreshFn;
      client.setTokenRefreshFn(async () => {
        const { jwt: freshJwt, session_id } = await rf();
        this._jwt = freshJwt;
        this._sessionId = session_id;
        this._expiresAt = decodeJwtExpiry(freshJwt);
        return freshJwt;
      });
    }
  }

  /**
   * Returns `true` if the session JWT has passed its `exp` timestamp.
   * Does **not** contact the server — purely a local clock check.
   */
  isExpired(): boolean {
    return Date.now() >= this._expiresAt.getTime();
  }

  /**
   * Returns `true` if the session JWT will expire within `refreshThresholdMs`.
   * Useful for manually deciding when to call `refresh()`.
   */
  isNearExpiry(): boolean {
    return Date.now() >= this._expiresAt.getTime() - this.refreshThresholdMs;
  }

  /**
   * Explicitly refresh the session JWT by calling `startSession` again.
   *
   * Concurrent calls coalesce — only one network request is in-flight at a time;
   * subsequent callers await the same promise.
   *
   * @throws {Error} If no `refreshFn` was provided when the session was created.
   */
  refresh(): Promise<void> {
    if (!this._refreshFn) {
      return Promise.reject(
        new Error("AgentumSession: no refreshFn configured — cannot refresh"),
      );
    }
    // Coalesce concurrent refreshes into a single in-flight promise.
    if (this._refreshPromise !== null) return this._refreshPromise;
    this._refreshPromise = this._doRefresh().finally(() => {
      this._refreshPromise = null;
    });
    return this._refreshPromise;
  }

  private async _doRefresh(): Promise<void> {
    const { jwt, session_id } = await this._refreshFn!();
    this._jwt = jwt;
    this._sessionId = session_id;
    this._expiresAt = decodeJwtExpiry(jwt);
    this.client.setToken(jwt);
  }

  /** Auto-refresh the JWT if a refreshFn is configured and expiry is near. */
  private async _ensureFresh(): Promise<void> {
    if (this._refreshFn !== null && this.isNearExpiry()) {
      await this.refresh();
    }
  }

  /**
   * Check whether Cedar policy allows `action` on `resource` for this session's agent.
   *
   * **Refresh semantics (fail-soft):** if the JWT is near expiry and the
   * refresh call fails, `isAllowed` returns `false` — deny-safe — rather
   * than propagating the refresh error, so a transient IAM outage cannot
   * silently allow a request. For a structured result that distinguishes
   * `policy_deny` from `refresh_failed`, use
   * {@link AgentumSession.checkPolicy}.
   *
   * The `agentId` is injected automatically.
   */
  async isAllowed(action: string, resource: string): Promise<boolean> {
    try {
      await this._ensureFresh();
    } catch {
      return false;
    }
    return this.client.isAllowed(this.agentId, action, resource);
  }

  /**
   * Structured-outcome companion to {@link AgentumSession.isAllowed}.
   * Returns `{outcome:"deny", reason:"refresh_failed"}` when JWT refresh
   * fails, so callers can log / alert on credential-stale conditions
   * without conflating them with true policy denials.
   */
  async checkPolicy(action: string, resource: string): Promise<PolicyOutcome> {
    try {
      await this._ensureFresh();
    } catch {
      return { outcome: "deny", reason: "refresh_failed" };
    }
    const allowed = await this.client.isAllowed(this.agentId, action, resource);
    return allowed
      ? { outcome: "allow" }
      : { outcome: "deny", reason: "policy_deny" };
  }

  /**
   * Evaluate a single tool call and return the rich
   * {@link ToolCallEvaluation} (carries `decision`, `policyHash`,
   * `decisionSource`, `evaluatedLocally`, `pdpLatencyUs`).
   *
   * Unlike {@link AgentumSession.isAllowed} this is NOT fail-soft —
   * refresh errors and transport errors propagate. Framework call sites
   * (`enforceAllTools`) catch and emit a `mcp_tool_deny` with
   * `reason: "refresh_failed"` so the audit pipeline still records the
   * denied call.
   */
  async evaluateToolCall(
    req: { toolName: string; arguments?: unknown },
  ): Promise<ToolCallEvaluation> {
    await this._ensureFresh();
    return this.client.evaluateToolCall(this.agentId, req);
  }

  /**
   * Ingest a custom audit event, automatically tagging it with `agentId` and `sessionId`.
   *
   * **Refresh semantics (fail-soft):** intentionally enqueues the event
   * regardless of JWT staleness. The background flusher calls
   * `tokenRefreshFn` on 401 and retries once; if refresh still fails,
   * the batch is dropped and `onAuditError` is invoked. This diverges
   * from {@link AgentumSession.isAllowed} (which is deny-safe on
   * refresh failure) because dropping audit on transient auth errors
   * would silently break compliance.
   */
  async ingestAuditEvent(
    req: Omit<AuditIngestRequest, "agent_id" | "session_id">,
  ): Promise<void> {
    try {
      await this._ensureFresh();
    } catch {
      // Refresh failure must not block audit ingestion
    }
    return this.client.ingestAuditEvent({
      ...req,
      agent_id: this.agentId,
      session_id: this._sessionId,
    });
  }

  /**
   * R45b / INTEG-B1 — should a Deny carrying `require_hitl` advice be
   * auto-escalated to a HITL approval round-trip for this session's agent?
   * Thin delegate to {@link AgentumClient.isHitlAddonEnabled}.
   *
   * Returns `true` ONLY when `addon.policy.hitl` is explicitly `"enabled"`
   * in the live PDP snapshot. SAFE default on `"unknown"` (cold start /
   * central-only / PDP not wired) and `"disabled"` is to NOT escalate — see
   * the client method's contract.
   */
  isHitlAddonEnabled(): boolean {
    return this.client.isHitlAddonEnabled(this.agentId);
  }

  /**
   * Block on a human approval before proceeding.
   *
   * Creates an approval request server-side, then polls until the reviewer
   * approves, denies, or the client-side `timeout` elapses. Resolves with
   * `{ status: 'approved', decided_by, reason? }` on approval; throws
   * {@link AgentumHitlDeniedError} on denial; throws
   * {@link AgentumHitlTimeoutError} on timeout.
   *
   * **Session refresh safety:** if the session JWT expires while polling,
   * the underlying client's auto-refresh mints a new session. The HITL gate
   * is keyed by `request_id` (not session_id), so the approval still
   * resolves correctly. The audit trail records the original session_id
   * for traceability.
   *
   * @example
   *   const result = await session.requestApproval({
   *     action: 'http.post',
   *     resource: 'api.codeforge.io',
   *     context: { path: '/repos/main/prs/42/merge' },
   *     reason: 'Agent wants to merge PR #42',
   *     timeout: 300_000,
   *   });
   *   // throws on deny/timeout; reaches here only on approval.
   */
  async requestApproval(opts: RequestApprovalOptions): Promise<ApprovalResult> {
    if (!opts.action || !opts.resource) {
      throw new AgentumError("requestApproval: action and resource are required");
    }
    const timeoutMs = opts.timeout ?? 60_000;
    const pollMs = Math.max(250, Math.min(opts.pollIntervalMs ?? 1_000, 10_000));
    const requiredApprovals = opts.requiredApprovals ?? 1;

    try {
      await this._ensureFresh();
    } catch {
      // Refresh failure must not block the create; the request below will
      // surface the underlying 401 if the JWT is truly dead.
    }

    const createBody: {
      action: string;
      resource: string;
      context?: unknown;
      reason?: string;
      timeout_seconds: number;
      required_approvals: number;
    } = {
      action: opts.action,
      resource: opts.resource,
      // Server bounds [10, 3600]; we send seconds + a small buffer so the
      // server entry outlives the client poll window.
      timeout_seconds: Math.max(10, Math.ceil(timeoutMs / 1000) + 5),
      required_approvals: requiredApprovals,
    };
    // GR-07 follow-up: thread the tool-call arguments into the approval
    // request's `context.arguments` whenever they are present. Central's
    // HITL decide handler (crates/agentum-api/src/routes/hitl.rs
    // ::derive_grant_from_request) reads `context["arguments"]` and keys the
    // derived PDP grant on its canonical-JSON SHA-256 — the SAME hash the SDK
    // computes locally in `recordApprovalGrant` below. Sending the same
    // logical args object here keeps the central grant key byte-identical to
    // the local one; omitting it (no `toolArgs`) matches central's `hash(null)`
    // semantics, where the grant only ever covers argument-less calls.
    const context: Record<string, unknown> | undefined =
      opts.toolArgs !== undefined
        ? { ...(opts.context ?? {}), arguments: opts.toolArgs }
        : opts.context;
    if (context !== undefined) createBody.context = context;
    if (opts.reason !== undefined) createBody.reason = opts.reason;
    const created = await this.client.createHitlAgentRequest(createBody);
    const requestId = created.request_id;

    const deadline = Date.now() + timeoutMs;
    const signal = opts.signal;
    while (Date.now() < deadline) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error
          ? signal.reason
          : new AgentumError("requestApproval aborted by caller");
      }
      try {
        await this._ensureFresh();
      } catch {
        // Same rationale as above — let the poll below surface auth errors.
      }
      const polled = await this.client.getHitlAgentRequest(requestId);
      if (polled.status === "approved") {
        const result: ApprovalResult = {
          status: "approved",
          decided_by: polled.decided_by,
          request_id: requestId,
        };
        if (polled.reason !== null) result.reason = polled.reason;
        // Record a post-approval grant so the next identical tool call
        // within the HITL timeout window skips re-escalation. Only fires
        // when the caller threaded `toolName` through the options
        // (back-compat: callers that omit it see no behavior change).
        // TTL derives from the `require_hitl:timeout=NNN` advice on the
        // originating decision; defaults to 5 minutes when absent.
        if (opts.toolName) {
          const ttlMs =
            parseRequireHitlTimeoutMs(opts.advice) ?? 300_000;
          await this.client.recordApprovalGrant({
            agentId: this.agentId,
            toolName: opts.toolName,
            ttlMs,
            requestId,
            ...(opts.toolArgs !== undefined ? { toolArgs: opts.toolArgs } : {}),
          });
        }
        return result;
      }
      if (polled.status === "denied") {
        throw new AgentumHitlDeniedError(
          requestId,
          polled.decided_by,
          polled.reason ?? undefined,
        );
      }
      if (polled.status === "timeout") {
        // Server-side sweeper beat us to it.
        throw new AgentumHitlTimeoutError(requestId, timeoutMs);
      }
      // Still pending — sleep and re-poll. Use the smaller of pollMs and
      // remaining-deadline so we don't oversleep past the user's timeout.
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise((r) => setTimeout(r, Math.min(pollMs, remaining)));
    }
    throw new AgentumHitlTimeoutError(requestId, timeoutMs);
  }

  /**
   * End the session on the server and de-authenticate the underlying client.
   *
   * Idempotent and concurrent-safe: concurrent callers all await the same
   * in-flight promise, so `endSession` is called at most once. `clearToken`
   * is guaranteed to run even if `endSession` rejects.
   *
   * When the session owns its client (i.e. was produced by
   * `AgentumClient.connect()` / `connectExisting()`), this also drains
   * the audit buffer and releases the refresh client so there is no
   * background timer / memory leak.
   */
  async close(): Promise<void> {
    if (this._closePromise !== null) return this._closePromise;
    this._closePromise = (async () => {
      try {
        await this.client.endSession(this._sessionId);
      } finally {
        this.client.clearToken();
        if (this._ownsClient) {
          // Best-effort: drain audit buffer + stop timers.
          await this.client.close().catch(() => {});
          if (this._refreshClient) {
            await this._refreshClient.close().catch(() => {});
          }
        }
      }
    })();
    return this._closePromise;
  }

  /**
   * TC39 Explicit Resource Management — called automatically by `await using`.
   */
  [Symbol.asyncDispose](): Promise<void> {
    return this.close();
  }
}
