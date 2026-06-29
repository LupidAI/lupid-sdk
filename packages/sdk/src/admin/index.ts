/**
 * `AgentumAdminClient` — the admin/management SDK surface.
 *
 * Keeps the runtime `AgentumClient` free of admin-only verbs (policy CRUD,
 * MCP server registration, API-key minting). A webapp that only needs
 * runtime auth flows can import `AgentumClient` and tree-shakes this out.
 *
 * ```ts
 * import { AgentumAdminClient } from "@lupid/sdk";
 *
 * const admin = new AgentumAdminClient({
 *   baseUrl: "http://localhost:7071",
 *   apiKey: process.env.AGENTUM_ADMIN_KEY!,
 * });
 *
 * await admin.policies.put("agent-uuid", `permit(principal, action, resource);`);
 * await admin.close();
 * ```
 *
 * @rbac All admin verbs require `Admin` or higher. Scoped keys are
 * rejected for cross-agent operations; see per-method JSDoc.
 */

import type {
  AgentumClientConfig,
  BootstrapResult,
  BootstrapSpec,
  BootstrapApiKeySpec,
  BootstrapGrantSpec,
  BootstrapMcpServerSpec,
} from "../types.js";
import { AdminHttpClient } from "./http.js";
import { AgentsApi } from "./agents.js";
import { PoliciesApi } from "./policies.js";
import { McpApi } from "./mcp.js";
import { ApiKeysApi } from "./api-keys.js";
import { RetentionApi } from "./retention.js";
import { TenantAuditKeysApi } from "./tenant-audit-keys.js";
import { TenantClassificationsApi } from "./tenant-classifications.js";
import { DataSubjectsApi } from "./data-subjects.js";
import { PolicyBundleApi } from "./policy-bundle.js";

/**
 * Admin-plane config. A narrower view of {@link AgentumClientConfig} that
 * omits audit-buffer tuning — admin flows do not emit runtime audit events.
 */
export type AgentumAdminClientConfig = Omit<
  AgentumClientConfig,
  | "auditBufferSize"
  | "auditFlushIntervalMs"
  | "auditFlushBatchSize"
  | "auditMaxBackoffMs"
  | "onAuditError"
  | "disableAuditBuffer"
>;

export class AgentumAdminClient {
  private readonly http: AdminHttpClient;

  readonly agents: AgentsApi;
  readonly policies: PoliciesApi;
  readonly mcp: McpApi;
  readonly apiKeys: ApiKeysApi;
  readonly retention: RetentionApi;
  readonly tenantAuditKeys: TenantAuditKeysApi;
  readonly tenantClassifications: TenantClassificationsApi;
  readonly dataSubjects: DataSubjectsApi;
  readonly policyBundle: PolicyBundleApi;

  constructor(config: AgentumAdminClientConfig | string) {
    const cfg: AgentumClientConfig =
      typeof config === "string" ? { baseUrl: config } : config;

    this.http = new AdminHttpClient(cfg);
    this.agents = new AgentsApi(this.http);
    this.policies = new PoliciesApi(this.http);
    this.mcp = new McpApi(this.http);
    this.apiKeys = new ApiKeysApi(this.http);
    this.retention = new RetentionApi(this.http);
    this.tenantAuditKeys = new TenantAuditKeysApi(this.http);
    this.tenantClassifications = new TenantClassificationsApi(this.http);
    this.dataSubjects = new DataSubjectsApi(this.http);
    this.policyBundle = new PolicyBundleApi(this.http);
  }

  /**
   * Atomic idempotent bulk onboarding. One call provisions an agent plus
   * its MCP servers, grants, declarative policies, and API keys.
   *
   * Safe to re-run from Terraform / CI — each sub-resource is upserted by
   * stable key (agent.name, mcpServer.name, apiKey.label). Existing
   * resources come back with `created: false`; newly-minted API keys come
   * back with `plaintextKey` set (one-shot — the plaintext is never
   * surfaced again).
   */
  async bootstrap(spec: BootstrapSpec): Promise<BootstrapResult> {
    const wire = toBootstrapWire(spec);
    const raw = await this.http.post<BootstrapWireResponse>(
      "admin/bootstrap",
      wire,
    );
    return fromBootstrapWire(raw);
  }

  /**
   * Release any resources held by the client. Currently a no-op — the
   * admin client does not hold timers or buffers — but exposed for
   * forward compatibility and symmetry with `AgentumClient.close()`.
   */
  async close(): Promise<void> {
    // Intentionally empty: no audit buffer, no timers, no pooled connections.
  }
}

export { AgentsApi } from "./agents.js";
export { PoliciesApi, type AgentPolicyRecord, type ApplyDeclarativeResponse } from "./policies.js";
export {
  PolicyBuilder,
  type ApplyDeclarativeResult,
  type AllActionsRuleInput,
  type ApprovalConfigInput,
  type HttpRuleInput,
  type McpRuleInput,
  type RoleInput,
  type WhenContextInput,
  type WhenUserInput,
} from "./policy-builder.js";
export { McpApi } from "./mcp.js";
export { ApiKeysApi } from "./api-keys.js";
export {
  RetentionApi,
  type RetentionStatus,
  type RetentionOutcome,
  type ColdScanQuery,
  type ColdScanResponse,
} from "./retention.js";
export {
  TenantAuditKeysApi,
  type RotateTenantAuditKeysResponse,
} from "./tenant-audit-keys.js";
export {
  TenantClassificationsApi,
  type ClassificationRecord,
  type ClassificationMatch,
  type ClassificationSensitivity,
  type CreateClassificationRequest,
  type UpdateClassificationRequest,
  type ListClassificationsResponse,
  type TestClassificationResponse,
} from "./tenant-classifications.js";
export {
  DataSubjectsApi,
  type DataSubjectType,
  type DataSubjectExportRequest,
  type DataSubjectExportResponse,
  type DataSubjectSession,
  type DataSubjectHitlRequest,
} from "./data-subjects.js";
export {
  PolicyBundleApi,
  type BundleSyncResponse,
  type BundleSyncOptions,
} from "./policy-bundle.js";
export {
  AgentumAgentAdminClient,
  type AgentumAgentAdminClientConfig,
} from "./agent-scoped.js";

// ─── Bootstrap wire marshalling ─────────────────────────────────────────────
// The SDK surface uses camelCase; the server expects snake_case. Keep the
// conversion local to the admin client so bootstrap spec authors only see
// the idiomatic TS shape.

interface BootstrapWireResponse {
  agent: { agent_id: string; name: string; created: boolean };
  mcp_servers: Array<{ server_id: string; name: string; created: boolean }>;
  grants: Array<{
    mcp_server_name: string;
    server_id: string;
    allowed_tools: string[];
    created: boolean;
  }>;
  policy?: { policy_id: string; applied: boolean; rule_count: number };
  api_keys: Array<{
    id: string;
    label?: string | null;
    role: string;
    agent_scope?: string | null;
    created: boolean;
    plaintext_key?: string | null;
  }>;
}

function mcpToWire(s: BootstrapMcpServerSpec): Record<string, unknown> {
  const auth = s.auth
    ? {
        type: s.auth.type,
        ...(s.auth.token !== undefined ? { token: s.auth.token } : {}),
        ...(s.auth.headerName !== undefined
          ? { header_name: s.auth.headerName }
          : {}),
      }
    : undefined;
  return {
    name: s.name,
    url: s.url,
    ...(s.description !== undefined ? { description: s.description } : {}),
    ...(auth ? { auth } : {}),
    ...(s.status !== undefined ? { status: s.status } : {}),
  };
}

function grantToWire(g: BootstrapGrantSpec): Record<string, unknown> {
  return {
    mcp_server_name: g.mcpServerName,
    ...(g.allowedTools !== undefined ? { allowed_tools: g.allowedTools } : {}),
  };
}

function apiKeyToWire(k: BootstrapApiKeySpec): Record<string, unknown> {
  return {
    ...(k.role !== undefined ? { role: k.role } : {}),
    ...(k.label !== undefined ? { label: k.label } : {}),
    ...(k.agentScope !== undefined ? { agent_scope: k.agentScope } : {}),
    ...(k.expiresAt !== undefined ? { expires_at: k.expiresAt } : {}),
    ...(k.ipAllowCidrs !== undefined ? { ip_allow_cidrs: k.ipAllowCidrs } : {}),
    ...(k.scopeFeatures !== undefined ? { scope_features: k.scopeFeatures } : {}),
    ...(k.email !== undefined ? { email: k.email } : {}),
    ...(k.platformAction !== undefined ? { platform_action: k.platformAction } : {}),
  };
}

function toBootstrapWire(spec: BootstrapSpec): Record<string, unknown> {
  return {
    agent: {
      name: spec.agent.name,
      owner_email: spec.agent.ownerEmail,
      purpose: spec.agent.purpose,
      framework: spec.agent.framework,
      ...(spec.agent.ownerTeam !== undefined
        ? { owner_team: spec.agent.ownerTeam }
        : {}),
      ...(spec.agent.declaredTools !== undefined
        ? { declared_tools: spec.agent.declaredTools }
        : {}),
      ...(spec.agent.dataClasses !== undefined
        ? { data_classes: spec.agent.dataClasses }
        : {}),
      ...(spec.agent.policyProfile !== undefined
        ? { policy_profile: spec.agent.policyProfile }
        : {}),
    },
    ...(spec.mcpServers?.length
      ? { mcp_servers: spec.mcpServers.map(mcpToWire) }
      : {}),
    ...(spec.grants?.length ? { grants: spec.grants.map(grantToWire) } : {}),
    ...(spec.policies !== undefined ? { policies: spec.policies } : {}),
    ...(spec.apiKeys?.length
      ? { api_keys: spec.apiKeys.map(apiKeyToWire) }
      : {}),
  };
}

function fromBootstrapWire(raw: BootstrapWireResponse): BootstrapResult {
  return {
    agent: {
      agentId: raw.agent.agent_id,
      name: raw.agent.name,
      created: raw.agent.created,
    },
    mcpServers: raw.mcp_servers.map((s) => ({
      serverId: s.server_id,
      name: s.name,
      created: s.created,
    })),
    grants: raw.grants.map((g) => ({
      mcpServerName: g.mcp_server_name,
      serverId: g.server_id,
      allowedTools: g.allowed_tools,
      created: g.created,
    })),
    ...(raw.policy
      ? {
          policy: {
            policyId: raw.policy.policy_id,
            applied: raw.policy.applied,
            ruleCount: raw.policy.rule_count,
          },
        }
      : {}),
    apiKeys: raw.api_keys.map((k) => ({
      id: k.id,
      ...(k.label ? { label: k.label } : {}),
      role: k.role,
      ...(k.agent_scope ? { agentScope: k.agent_scope } : {}),
      created: k.created,
      ...(k.plaintext_key ? { plaintextKey: k.plaintext_key } : {}),
    })),
  };
}
