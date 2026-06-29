/**
 * `AgentumAdminClient.policyBundle` — GitOps policy bundle sync.
 * Wraps `POST /admin/policy-bundle/sync/:tenant_id`.
 *
 * Bundle mode lets operators source `.cedar` files and MCP server
 * metadata from a signed HTTPS tarball (git / object store / CI).
 * While a tenant is in bundle mode, direct write APIs (`PUT /policies`,
 * `POST /policies/declarative`, `POST /admin/bootstrap`, MCP CRUD, and
 * the policy-proposals route) all return `423 BundleReadOnly`.
 */

import type { AdminHttpClient } from "./http.js";

export interface BundleSyncResponse {
  tenantId: string;
  commitSha: string;
  bundleSha256: string;
  url: string;
  agentsUpdated: number;
  agentsUnchanged: number;
  agentsRemoved: number;
  mcpServersUpdated: number;
  durationMs: number;
  trigger: string;
  /** True when the remote commit matched the tenant's persisted
   * `last_commit` and no on-disk mutation happened.  Callers typically
   * render "already up to date" in this case. */
  noChange: boolean;
}

export interface BundleSyncOptions {
  /** Force re-apply even when the commit SHA matches `last_commit`. */
  force?: boolean;
}

interface RawBundleSyncResponse {
  tenant_id: string;
  commit_sha: string;
  bundle_sha256: string;
  url: string;
  agents_updated: number;
  agents_unchanged: number;
  agents_removed: number;
  mcp_servers_updated: number;
  duration_ms: number;
  trigger: string;
  no_change: boolean;
}

export class PolicyBundleApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Manually trigger a bundle sync for a tenant.  Admins may sync their
   * own tenant; SuperAdmins may pass any tenant.
   *
   * @throws {AgentumPermissionError} non-admin callers.
   * @throws {AgentumError} tenant not in bundle mode / upstream fetch
   *   failed / apply failed (bundle manifest malformed, cedar syntax
   *   error, etc.).  The tenant's `policy_bundle_last_error` is
   *   updated to surface the failure in the dashboard.
   */
  async sync(
    tenantId: string,
    opts: BundleSyncOptions = {},
  ): Promise<BundleSyncResponse> {
    if (!tenantId || !tenantId.trim()) {
      throw new Error("tenantId is required");
    }
    const query = opts.force ? "?force=true" : "";
    const raw = await this.http.post<RawBundleSyncResponse>(
      `admin/policy-bundle/sync/${encodeURIComponent(tenantId)}${query}`,
    );
    return {
      tenantId: raw.tenant_id,
      commitSha: raw.commit_sha,
      bundleSha256: raw.bundle_sha256,
      url: raw.url,
      agentsUpdated: raw.agents_updated,
      agentsUnchanged: raw.agents_unchanged,
      agentsRemoved: raw.agents_removed,
      mcpServersUpdated: raw.mcp_servers_updated,
      durationMs: raw.duration_ms,
      trigger: raw.trigger,
      noChange: raw.no_change,
    };
  }
}
