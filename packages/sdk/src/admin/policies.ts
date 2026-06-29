/**
 * `AgentumAdminClient.policies` — Cedar policy management.
 *
 * Wraps `GET /policies/:agent_id`, `PUT /policies/:agent_id`,
 * `POST /policies/reload`, and `POST /policies/declarative/:agent_id`.
 *
 * **Known gap (plan vs. code):** the plan lists a `delete(agentId)`
 * method but no `DELETE /policies/:agent_id` route exists today. The
 * SDK method is kept on the surface for forward-compat and throws
 * `AgentumError` with a descriptive message until the server adds it.
 */

import {
  AgentumError,
  type ApproveProposalResponse,
  type CreateProposalRequest,
  type CreateProposalResponse,
  type DeclarativePolicySpec,
  type DeclarativeRule,
  type ListProposalsQuery,
  type ListProposalsResponse,
  type OpenApiImportOptions,
  type OpenApiImportResult,
  type PolicyProposal,
  type PolicySimulateInlineRequest,
  type PolicySimulateResponse,
  type RejectProposalResponse,
  type ReviewProposalRequest,
  type WithdrawProposalResponse,
} from "../types.js";
import type { AdminHttpClient } from "./http.js";
import { PolicyBuilder, type ApplyDeclarativeResult } from "./policy-builder.js";

export interface AgentPolicyRecord {
  /** The Cedar source text for the agent, or `null` if no policy is written. */
  source: string | null;
  /** Present when the server had no policy file; otherwise `undefined`. */
  note?: string;
}

/**
 * Server response for `POST /policies/declarative/:agent_id`, camelCase at
 * the SDK boundary. The raw server body is snake_case
 * (`compiled_cedar`/`applied_at`/`policy_id`).
 */
export type ApplyDeclarativeResponse = ApplyDeclarativeResult;

export class PoliciesApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Replace the Cedar policy for an agent. Server-side route expects a
   * body of `{ policy: string }`; the SDK accepts the Cedar source
   * directly.
   */
  async put(agentId: string, cedarSource: string): Promise<void> {
    await this.http.put<unknown>(`policies/${agentId}`, { policy: cedarSource });
  }

  /**
   * Fetch the Cedar policy for an agent. Returns the source text plus an
   * optional `note` when no policy has been written yet.
   */
  async get(agentId: string): Promise<AgentPolicyRecord> {
    const res = await this.http.get<{
      agent_id: string;
      policy: string | null;
      note?: string;
    }>(`policies/${agentId}`);
    const record: AgentPolicyRecord = { source: res.policy };
    if (res.note !== undefined) record.note = res.note;
    return record;
  }

  /**
   * Delete the Cedar policy for an agent.
   *
   * **Not implemented server-side yet** — no `DELETE /policies/:agent_id`
   * route exists. The method is kept on the surface so callers can switch
   * to it in one line once the route lands.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async delete(_agentId: string): Promise<void> {
    throw new AgentumError(
      "AgentumAdminClient.policies.delete() is not implemented — the server does not expose DELETE /policies/:agent_id yet",
    );
  }

  /**
   * Compile a declarative policy spec to Cedar and apply it atomically.
   *
   * The server runs DSL compile → Cedar parse → disk write → hot reload
   * in a single request. Throws `AgentumError` (400) on compile/parse
   * failure, `AgentumPermissionError` (403) on role or scope mismatch.
   *
   * @param agentId — Path agent UUID. Must match `spec.agent_id` (the
   *  server rejects mismatches with a 400).
   * @param spec — Wire-shape declarative spec. Build this by hand with
   *  the typed `DeclarativeRule` union, or use the
   *  {@link AgentumAdminClient#policies.builder} chainable helper.
   */
  async applyDeclarative(
    agentId: string,
    spec: DeclarativePolicySpec,
  ): Promise<ApplyDeclarativeResponse> {
    if (spec.agent_id !== agentId) {
      throw new AgentumError(
        `spec.agent_id "${spec.agent_id}" does not match path agentId "${agentId}"`,
      );
    }
    const res = await this.http.post<{
      compiled_cedar: string;
      applied_at: string;
      policy_id: string;
    }>(`policies/declarative/${agentId}`, spec);
    return {
      compiledCedar: res.compiled_cedar,
      appliedAt: res.applied_at,
      policyId: res.policy_id,
    };
  }

  /**
   * Start a chainable {@link PolicyBuilder} for `agentId`. Call
   * `permitHttp`/`forbidHttp`/`permitMcp`/`forbidMcp` to stage rules,
   * then `apply()` to compile server-side, or `build()` to inspect the
   * wire spec without sending.
   */
  builder(agentId: string): PolicyBuilder {
    return new PolicyBuilder(this.http, agentId);
  }

  /**
   * Reload all on-disk Cedar policies. Requires `Admin` role.
   *
   * Returns when the server has re-scanned the policy directory and
   * invalidated the decision cache.
   */
  async reload(): Promise<void> {
    await this.http.post<unknown>("policies/reload");
  }

  /**
   * Generate Cedar policy rules from an OpenAPI 3.x or Swagger 2.0 spec.
   *
   * Provide exactly one of `spec` (inline string) or `specUrl` (server-side
   * fetch). The server extracts every `paths.*.{get|post|put|delete|patch}`
   * entry, normalises path templates (`{id}` → `*`), groups contiguous paths
   * by two-segment prefix, applies `overrides`, and returns the generated
   * {@link DeclarativeRule} array plus compiled Cedar.
   *
   * Defaults to `dryRun: true` — call again with `dryRun: false` (or reuse
   * the returned `rules` via {@link applyDeclarative}) to persist.
   */
  async importFromOpenAPI(
    opts: OpenApiImportOptions,
  ): Promise<OpenApiImportResult> {
    if (!opts.agentId) {
      throw new AgentumError("importFromOpenAPI: agentId is required");
    }
    const hasSpec = typeof opts.spec === "string" && opts.spec.trim().length > 0;
    const hasUrl = typeof opts.specUrl === "string" && opts.specUrl.trim().length > 0;
    if (hasSpec === hasUrl) {
      throw new AgentumError(
        "importFromOpenAPI: supply exactly one of `spec` or `specUrl`",
      );
    }
    const body: Record<string, unknown> = {
      agent_id: opts.agentId,
      dry_run: opts.dryRun ?? true,
    };
    if (hasSpec) body.spec = opts.spec;
    if (hasUrl) body.spec_url = opts.specUrl;
    if (opts.defaultEffect) body.default_effect = opts.defaultEffect;
    if (opts.hostOverride) body.host_override = opts.hostOverride;
    if (opts.overrides && opts.overrides.length > 0) {
      body.overrides = opts.overrides.map((ov) => {
        const wire: Record<string, unknown> = {
          path_pattern: ov.pathPattern,
          effect: ov.effect,
        };
        if (ov.method) wire.method = ov.method;
        return wire;
      });
    }
    const res = await this.http.post<{
      rules: DeclarativeRule[];
      compiled_cedar: string;
      endpoint_count: number;
      applied_at?: string;
      policy_id?: string;
      dry_run: boolean;
    }>("policies/import-openapi", body);
    const out: OpenApiImportResult = {
      rules: res.rules,
      compiledCedar: res.compiled_cedar,
      endpointCount: res.endpoint_count,
      dryRun: res.dry_run,
    };
    if (res.applied_at !== undefined) out.appliedAt = res.applied_at;
    if (res.policy_id !== undefined) out.policyId = res.policy_id;
    return out;
  }

  /**
   * Dry-run a proposed Cedar policy without deploying it.
   *
   * CI pipelines call this in their PR-review step: load the proposed
   * `.cedar` file or {@link PolicyBuilder} output into `cedarSource`, run
   * a simulate against the request the policy is meant to gate, and assert
   * the expected decision before merging.
   *
   * The server parses the Cedar source, evaluates the request against it,
   * and returns the decision — **nothing is written to disk** and no hot
   * reload is triggered. Requires `Admin` role (the endpoint could
   * otherwise be used to probe policy behaviour by trying many inputs).
   *
   * @param agentId — Agent UUID the inline policy belongs to. Used as the
   *   Cedar `principal` for evaluation.
   * @param cedarSource — Raw Cedar source OR `compiled_cedar` output from
   *   `applyDeclarative` / the declarative DSL. Both are accepted.
   * @param req — The `{action, resource, context?, user?}` to evaluate.
   */
  async simulateWithSource(
    agentId: string,
    cedarSource: string,
    req: PolicySimulateInlineRequest,
  ): Promise<PolicySimulateResponse> {
    if (typeof agentId !== "string" || agentId.length === 0) {
      throw new AgentumError("simulateWithSource: agentId is required");
    }
    if (typeof cedarSource !== "string" || cedarSource.trim().length === 0) {
      throw new AgentumError("simulateWithSource: cedarSource must be non-empty");
    }
    const body: Record<string, unknown> = {
      agent_id: agentId,
      action: req.action,
      resource: req.resource,
      policy_source: cedarSource,
    };
    if (req.context !== undefined) body.context = req.context;
    if (req.user !== undefined) body.user = req.user;
    return this.http.post<PolicySimulateResponse>("policies/simulate", body);
  }

  // ── Policy proposals ──────────────────────────────────────────────────────

  /**
   * Create a pending policy proposal. Admins can propose and review — the
   * server blocks self-approval (proposer ≠ approver) but not proposer-role.
   * Callers MUST set exactly one of `cedar_source` or `declarative_spec`.
   *
   * See {@link AgentumClient.proposePolicy} for the runtime equivalent.
   */
  proposeProposal(req: CreateProposalRequest): Promise<CreateProposalResponse> {
    return this.http.post<CreateProposalResponse>("policies/proposals", req);
  }

  /**
   * List policy proposals visible to the caller. Admin keys see all
   * proposals in their tenant; scoped keys see only their bound agent.
   */
  listProposals(query?: ListProposalsQuery): Promise<ListProposalsResponse> {
    const q: Record<string, string | undefined> = {};
    if (query?.status) q.status = query.status;
    if (query?.agent_id) q.agent_id = query.agent_id;
    return this.http.get<ListProposalsResponse>("policies/proposals", q);
  }

  /**
   * Fetch a single proposal by id. 404 for cross-tenant / out-of-scope
   * rows (existence-hiding, same precedent as admin_keys).
   */
  getProposal(proposalId: string): Promise<PolicyProposal> {
    return this.http.get<PolicyProposal>(`policies/proposals/${proposalId}`);
  }

  /**
   * Approve a pending proposal. Writes the compiled Cedar to
   * `{agent_id}.cedar`, reloads the policy engine, and transitions the
   * proposal to `approved`. Anti-self-approval enforced server-side
   * (proposer's email ≠ caller's email) — returns 403 on violation.
   *
   * @rbac Requires `Admin` role.
   */
  approveProposal(
    proposalId: string,
    body?: ReviewProposalRequest,
  ): Promise<ApproveProposalResponse> {
    return this.http.post<ApproveProposalResponse>(
      `policies/proposals/${proposalId}/approve`,
      body ?? {},
    );
  }

  /**
   * Reject a pending proposal. Does NOT touch `{agent_id}.cedar` — just
   * records the reviewer decision + optional note and transitions the
   * proposal to `rejected`.
   *
   * @rbac Requires `Admin` role.
   */
  rejectProposal(
    proposalId: string,
    body?: ReviewProposalRequest,
  ): Promise<RejectProposalResponse> {
    return this.http.post<RejectProposalResponse>(
      `policies/proposals/${proposalId}/reject`,
      body ?? {},
    );
  }

  /**
   * Withdraw a proposal. Only the original proposer (matched by email) may
   * withdraw — other operators (including other Admins) get 403. Only
   * pending proposals can be withdrawn.
   */
  withdrawProposal(proposalId: string): Promise<WithdrawProposalResponse> {
    return this.http.post<WithdrawProposalResponse>(
      `policies/proposals/${proposalId}/withdraw`,
      {},
    );
  }
}
