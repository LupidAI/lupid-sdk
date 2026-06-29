/**
 * `AgentumAgentAdminClient` — scope-locked admin client for a single agent.
 *
 * Pairs with an API key whose `agent_scope` matches the `agentId` passed to
 * the constructor. Every method is pinned to that agentId — there is no way
 * to address a different agent through this client, which is the whole
 * point of the separation:
 *
 * ```ts
 * import { AgentumAgentAdminClient } from "@lupid/sdk";
 *
 * const agentAdmin = new AgentumAgentAdminClient({
 *   baseUrl: "http://localhost:7071",
 *   apiKey: process.env.AGENTUM_SCOPED_KEY!,   // key.agent_scope === "a-uuid"
 *   agentId: "a-uuid",
 * });
 *
 * // Fail fast if the key's agent_scope doesn't match:
 * await agentAdmin.verify();
 *
 * await agentAdmin.policies.put("permit(principal, action, resource);");
 * await agentAdmin.mcp.grantAccess("stripe-mcp", ["charge"]);
 * const recent = await agentAdmin.audit.list({ limit: 50 });
 * ```
 *
 * ## Constructor / async init
 *
 * JavaScript constructors can't be `async`, so scope verification is **lazy
 * by default**: the first scope-sensitive method call awaits a cached
 * `GET /whoami` round-trip and throws {@link AgentumScopeMismatchError} if
 * the key's `agent_scope` does not match `agentId`.
 *
 * Two options let callers fail fast instead:
 *   - `await client.verify()` — explicit one-shot verification;
 *   - `await AgentumAgentAdminClient.create(cfg)` — static async factory
 *     that constructs, verifies, and returns the ready client.
 *
 * Repeat calls to `verify()` reuse the cached promise — there is at most
 * one `/whoami` round-trip per client instance.
 *
 * ## Type safety
 *
 * This class intentionally does NOT expose `mcp.registerServer()`,
 * `agents.register()`, or `apiKeys.mint()` — those are tenant-wide
 * operations that a scoped key cannot perform. A `tsc` strict build
 * catches the mistake at compile time; the runtime also rejects it
 * server-side (`reject_scoped_key` in `middleware/auth.rs`).
 */

import {
  AgentumError,
  AgentumScopeMismatchError,
  type AgentAuditQuery,
  type AgentumClientConfig,
  type AuditEvent,
  type AuditListResponse,
  type DeclarativePolicySpec,
  type McpAccessGrant,
  type WhoAmIResponse,
} from "../types.js";
import { AdminHttpClient } from "./http.js";
import { type AgentPolicyRecord, type ApplyDeclarativeResponse } from "./policies.js";

/**
 * Configuration for {@link AgentumAgentAdminClient}. Narrower than
 * {@link AgentumClientConfig} — audit-buffer tuning does not apply to
 * admin flows — with an added mandatory `agentId`.
 */
export type AgentumAgentAdminClientConfig = Omit<
  AgentumClientConfig,
  | "auditBufferSize"
  | "auditFlushIntervalMs"
  | "auditFlushBatchSize"
  | "auditMaxBackoffMs"
  | "onAuditError"
  | "disableAuditBuffer"
> & {
  /**
   * The agent this client is pinned to. Must match the API key's
   * `agent_scope` — otherwise `AgentumScopeMismatchError` is thrown on
   * the first scope-sensitive call (or immediately if `verify()` /
   * `create()` is used).
   */
  agentId: string;
};

// ─── Sub-APIs ────────────────────────────────────────────────────────────────

class AgentScopedPoliciesApi {
  constructor(
    private readonly http: AdminHttpClient,
    private readonly agentId: string,
    private readonly ensureVerified: () => Promise<void>,
  ) {}

  /**
   * Replace the Cedar policy for this agent. Server body shape: `{ policy }`.
   */
  async put(cedarSource: string): Promise<void> {
    await this.ensureVerified();
    await this.http.put<unknown>(`policies/${this.agentId}`, { policy: cedarSource });
  }

  /** Fetch the Cedar policy for this agent. */
  async get(): Promise<AgentPolicyRecord> {
    await this.ensureVerified();
    const res = await this.http.get<{
      agent_id: string;
      policy: string | null;
      note?: string;
    }>(`policies/${this.agentId}`);
    const record: AgentPolicyRecord = { source: res.policy };
    if (res.note !== undefined) record.note = res.note;
    return record;
  }

  /**
   * Delete the Cedar policy for this agent.
   *
   * **Not implemented server-side yet** — mirrors the admin-client method
   * so callers can switch in one line once `DELETE /policies/:agent_id`
   * lands.
   */
  async delete(): Promise<void> {
    await this.ensureVerified();
    throw new AgentumError(
      "AgentumAgentAdminClient.policies.delete() is not implemented — the server does not expose DELETE /policies/:agent_id yet",
    );
  }

  /**
   * Compile a declarative policy spec to Cedar and apply it atomically.
   *
   * **Placeholder.** Throws until `agentum-policy-dsl` ships.
   *
   * The spec's `agent_id` is auto-filled from the client's pinned
   * agentId; any value the caller supplies is ignored.
   */
  async applyDeclarative(
    spec: Omit<DeclarativePolicySpec, "agent_id"> & { agent_id?: string },
  ): Promise<ApplyDeclarativeResponse> {
    await this.ensureVerified();
    // Intentionally unused until the server endpoint ships; keep the
    // parameter named so the real wiring can drop in later.
    void spec;
    throw new AgentumError(
      "AgentumAgentAdminClient.policies.applyDeclarative() is not implemented — ships with Sprint 1.4 (agentum-policy-dsl)",
    );
  }
}

class AgentScopedMcpApi {
  constructor(
    private readonly http: AdminHttpClient,
    private readonly agentId: string,
    private readonly ensureVerified: () => Promise<void>,
  ) {}

  /**
   * Grant this agent access to the named MCP server. `allowedTools` is
   * a list of tool names the agent may call; pass `["*"]` to allow all.
   */
  async grantAccess(serverId: string, allowedTools: string[]): Promise<McpAccessGrant> {
    await this.ensureVerified();
    return this.http.post<McpAccessGrant>(`mcp/servers/${serverId}/access`, {
      agent_id: this.agentId,
      allowed_tools: allowedTools,
    });
  }

  /** Revoke this agent's access to the named MCP server. */
  async revokeAccess(serverId: string): Promise<void> {
    await this.ensureVerified();
    await this.http.delete<unknown>(`mcp/servers/${serverId}/access/${this.agentId}`);
  }
}

class AgentScopedAuditApi {
  constructor(
    private readonly http: AdminHttpClient,
    private readonly agentId: string,
    private readonly ensureVerified: () => Promise<void>,
  ) {}

  /**
   * Query audit events for this agent. All filters optional. `agent_id`
   * is pinned by the client and cannot be overridden through this call.
   */
  async list(opts: AgentAuditQuery = {}): Promise<AuditListResponse> {
    await this.ensureVerified();
    return this.http.get<AuditListResponse>("audit", {
      agent_id: this.agentId,
      event_type: opts.event_type,
      from: opts.from,
      to: opts.to,
      user_email: opts.user_email,
      user_trust: opts.user_trust,
      resource_id: opts.resource_id,
      limit: opts.limit,
      offset: opts.offset,
    });
  }

  /**
   * Convenience wrapper: list events whose `event_type` matches the
   * supplied string. The server has no full-text search endpoint today,
   * so this is a narrow `event_type` filter — kept on the surface to
   * match the plan's ergonomics and let a future full-text backend slot
   * in without changing the public API.
   */
  async search(eventType: string, opts: Omit<AgentAuditQuery, "event_type"> = {}): Promise<AuditEvent[]> {
    const res = await this.list({ ...opts, event_type: eventType });
    return res.events;
  }
}

// ─── Main client ─────────────────────────────────────────────────────────────

export class AgentumAgentAdminClient {
  private readonly http: AdminHttpClient;
  readonly agentId: string;

  /** Memoised verification promise — at most one `/whoami` per instance. */
  private verifyPromise: Promise<void> | null = null;

  readonly policies: AgentScopedPoliciesApi;
  readonly mcp: AgentScopedMcpApi;
  readonly audit: AgentScopedAuditApi;

  constructor(config: AgentumAgentAdminClientConfig) {
    if (!config.agentId || typeof config.agentId !== "string") {
      throw new AgentumError("Invalid agentId: must be a non-empty string");
    }
    this.agentId = config.agentId;
    this.http = new AdminHttpClient(config);

    const ensureVerified = () => this.verify();
    this.policies = new AgentScopedPoliciesApi(this.http, this.agentId, ensureVerified);
    this.mcp = new AgentScopedMcpApi(this.http, this.agentId, ensureVerified);
    this.audit = new AgentScopedAuditApi(this.http, this.agentId, ensureVerified);
  }

  /**
   * Construct and eagerly verify. Equivalent to `new` + `await verify()`
   * but in a single statement — useful when you want to fail fast on a
   * bad key before wiring the client into a request handler.
   */
  static async create(
    config: AgentumAgentAdminClientConfig,
  ): Promise<AgentumAgentAdminClient> {
    const c = new AgentumAgentAdminClient(config);
    await c.verify();
    return c;
  }

  /**
   * Confirm the configured API key is scoped to `this.agentId`. Cached:
   * subsequent calls (including lazy verification inside other methods)
   * reuse the same in-flight or resolved promise.
   *
   * Throws:
   *   - {@link AgentumScopeMismatchError} if `whoami.agent_scope !== agentId`.
   *   - Any transport-level {@link AgentumError} subclass if `/whoami`
   *     itself fails (401, network error, etc.).
   */
  async verify(): Promise<void> {
    if (this.verifyPromise === null) {
      this.verifyPromise = this.runVerify().catch((err) => {
        // Invalidate the cache on failure so the caller can retry after
        // fixing transient issues (e.g. token refresh, DNS flap).
        this.verifyPromise = null;
        throw err;
      });
    }
    return this.verifyPromise;
  }

  private async runVerify(): Promise<void> {
    const who = await this.http.get<WhoAmIResponse>("whoami");
    if (who.agent_scope !== this.agentId) {
      throw new AgentumScopeMismatchError(this.agentId, who.agent_scope, who);
    }
  }

  /** Release any resources held by the client. No-op today; kept for symmetry. */
  async close(): Promise<void> {
    // Intentionally empty.
  }
}
