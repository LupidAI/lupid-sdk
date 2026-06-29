/**
 * `AgentumAdminClient.tenantAuditKeys` — per-tenant audit key rotation.
 * Wraps `POST /admin/tenant-audit-keys/:tenant_id/rotate`.
 *
 * Rotation regenerates the tenant's HMAC salt and DEK; historical audit
 * rows keep the HMACs they were stored with. Only new events go through
 * the new salt. SuperAdmin only.
 */

import type { AdminHttpClient } from "./http.js";

export interface RotateTenantAuditKeysResponse {
  tenantId: string;
  dekVersion: number;
  rotatedAt: string;
}

interface RawRotateResponse {
  tenant_id: string;
  dek_version: number;
  rotated_at: string;
}

export class TenantAuditKeysApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Rotate the HMAC salt + DEK for a tenant. Returns the new
   * `dekVersion` (monotonic counter) and `rotatedAt` timestamp.
   *
   * @param tenantId — the tenant UUID.
   * @throws {AgentumPermissionError} non-SuperAdmin callers.
   * @throws {AgentumNotFoundError} unknown tenant.
   */
  async rotate(tenantId: string): Promise<RotateTenantAuditKeysResponse> {
    if (!tenantId || !tenantId.trim()) {
      throw new Error("tenantId is required");
    }
    const raw = await this.http.post<RawRotateResponse>(
      `admin/tenant-audit-keys/${encodeURIComponent(tenantId)}/rotate`,
    );
    return {
      tenantId: raw.tenant_id,
      dekVersion: raw.dek_version,
      rotatedAt: raw.rotated_at,
    };
  }
}
