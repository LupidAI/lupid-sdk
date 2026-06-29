/**
 * `AgentumAdminClient.retention` — tiered retention engine.
 *
 * Wraps three routes:
 *   * `GET  /retention/status`       — snapshot current tier sizes.
 *   * `POST /retention/run-now`      — synchronous tick for one tenant.
 *   * `GET  /audit/cold`             — decompress cold files in a window.
 *
 * The hot tier is ClickHouse `audit_events`; the cold tier is zstd-compressed
 * JSONL files on the filesystem (or a mounted bucket) under
 * `<retention_cold_storage_dir>/<tenant_id>/<yyyy-mm>/<uuid>.jsonl.zst`.
 * Per-tenant thresholds flow from the compliance profile's
 * `retention_hot_days` / `retention_cold_days`.
 */

import type { AdminHttpClient } from "./http.js";

export interface RetentionStatus {
  tenantId: string;
  effectiveHotDays: number;
  effectiveColdDays: number;
  hotEventCount: number;
  coldFileCount: number;
  coldBytesOnDisk: number;
  coldDir: string;
  /** RFC3339 timestamp of the next scheduled 02:00 UTC tick. */
  nextRunAt: string;
}

export interface RetentionOutcome {
  tenantId: string;
  hotToColdEvents: number;
  hotToColdBytes: number;
  hotToColdFiles: number;
  coldDeletedFiles: number;
  coldDeletedBytes: number;
}

export interface ColdScanQuery {
  /** Cross-tenant read; SuperAdmin only. Own-tenant callers omit. */
  tenantId?: string;
  /** Inclusive lower bound. Defaults to `to - 365d`. */
  from?: Date;
  /** Inclusive upper bound. Defaults to `now`. */
  to?: Date;
  /** Max events returned; capped at 10 000. Defaults to 500. */
  limit?: number;
}

export interface ColdScanResponse {
  tenantId: string;
  from: string;
  to: string;
  limit: number;
  count: number;
  events: unknown[];
}

interface RawRetentionStatus {
  tenant_id: string;
  effective_hot_days: number;
  effective_cold_days: number;
  hot_event_count: number;
  cold_file_count: number;
  cold_bytes_on_disk: number;
  cold_dir: string;
  next_run_at: string;
}

interface RawRetentionOutcome {
  tenant_id: string;
  hot_to_cold_events: number;
  hot_to_cold_bytes: number;
  hot_to_cold_files: number;
  cold_deleted_files: number;
  cold_deleted_bytes: number;
}

export class RetentionApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Snapshot the hot + cold tier sizes for a tenant.
   *
   * @param tenantId Cross-tenant read — SuperAdmin only; own-tenant callers
   *   omit and the server uses the caller's tenant.
   */
  async status(tenantId?: string): Promise<RetentionStatus> {
    const qs = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
    const raw = await this.http.get<RawRetentionStatus>(`retention/status${qs}`);
    return {
      tenantId: raw.tenant_id,
      effectiveHotDays: raw.effective_hot_days,
      effectiveColdDays: raw.effective_cold_days,
      hotEventCount: raw.hot_event_count,
      coldFileCount: raw.cold_file_count,
      coldBytesOnDisk: raw.cold_bytes_on_disk,
      coldDir: raw.cold_dir,
      nextRunAt: raw.next_run_at,
    };
  }

  /**
   * Synchronous tiered transition for one tenant. Admin on own tenant,
   * SuperAdmin for cross-tenant via `tenantId`. Returns the tick outcome.
   */
  async runNow(tenantId?: string): Promise<RetentionOutcome> {
    const qs = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
    const raw = await this.http.post<RawRetentionOutcome>(
      `retention/run-now${qs}`,
    );
    return {
      tenantId: raw.tenant_id,
      hotToColdEvents: raw.hot_to_cold_events,
      hotToColdBytes: raw.hot_to_cold_bytes,
      hotToColdFiles: raw.hot_to_cold_files,
      coldDeletedFiles: raw.cold_deleted_files,
      coldDeletedBytes: raw.cold_deleted_bytes,
    };
  }

  /**
   * Decompress cold files whose header window intersects `[from, to]` and
   * return the contained events. Viewer role (own tenant) or SuperAdmin.
   */
  async scanCold(q: ColdScanQuery = {}): Promise<ColdScanResponse> {
    const params: string[] = [];
    if (q.tenantId) params.push(`tenant_id=${encodeURIComponent(q.tenantId)}`);
    if (q.from) params.push(`from=${encodeURIComponent(q.from.toISOString())}`);
    if (q.to) params.push(`to=${encodeURIComponent(q.to.toISOString())}`);
    if (q.limit !== undefined) params.push(`limit=${q.limit}`);
    const qs = params.length ? `?${params.join("&")}` : "";
    return await this.http.get<ColdScanResponse>(`audit/cold${qs}`);
  }
}
