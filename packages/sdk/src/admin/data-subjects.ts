/**
 * `AgentumAdminClient.dataSubjects` — GDPR Article 15 (right of access) /
 * Article 20 (data portability) export endpoint.
 *
 * Wraps `POST /data-subjects/export` — an Admin call that returns everything
 * Agentum holds about a named `user` or `agent` subject as a machine-readable
 * JSON bundle (audit events, sessions, HITL requests).
 *
 * The subject's plaintext identifier is never stored on the resulting audit
 * trail — only its HMAC — so exporting doesn't re-introduce PII for the
 * person exercising their right of access.
 *
 * @example
 * ```ts
 * const bundle = await admin.dataSubjects.export({
 *   subjectType: "user",
 *   subjectId: "alice@example.com",
 * });
 * console.log(bundle.auditEvents.length, "events");
 * ```
 */

import type { AdminHttpClient } from "./http.js";

export type DataSubjectType = "user" | "agent";

export interface DataSubjectExportRequest {
  subjectType: DataSubjectType;
  /** Email (for `user`) or agent UUID (for `agent`). */
  subjectId: string;
  /** SuperAdmin only — cross-tenant export; omit for own-tenant. */
  tenantId?: string;
}

export interface DataSubjectSession {
  sessionId: string;
  agentId: string;
  sourceIp?: string;
  startedAt: string;
  endedAt?: string;
  status: string;
}

export interface DataSubjectHitlRequest {
  requestId: string;
  agentId: string;
  sessionId?: string;
  tool: string;
  resource?: string;
  reason?: string;
  requestedAt: string;
  timeoutAt: string;
  status: string;
  decidedBy?: string;
  decidedAt?: string;
  comment?: string;
}

export interface DataSubjectExportResponse {
  subjectType: DataSubjectType;
  /** Per-tenant HMAC-SHA256 of the subject_id — the stable correlation key. */
  subjectHmac: string;
  tenantId: string;
  exportedAt: string;
  /** Raw audit event rows (server-side shape — untyped here because the
   * `detail` field is free-form JSON that depends on the event type). */
  auditEvents: unknown[];
  sessions: DataSubjectSession[];
  hitlRequests: DataSubjectHitlRequest[];
}

// ─── Wire shapes (snake_case) ────────────────────────────────────────────────

interface RawSession {
  session_id: string;
  agent_id: string;
  source_ip?: string | null;
  started_at: string;
  ended_at?: string | null;
  status: string;
}

interface RawHitl {
  request_id: string;
  agent_id: string;
  session_id?: string | null;
  tool: string;
  resource?: string | null;
  reason?: string | null;
  requested_at: string;
  timeout_at: string;
  status: string;
  decided_by?: string | null;
  decided_at?: string | null;
  comment?: string | null;
}

interface RawExportResponse {
  subject_type: DataSubjectType;
  subject_hmac: string;
  tenant_id: string;
  exported_at: string;
  audit_events: unknown[];
  sessions: RawSession[];
  hitl_requests: RawHitl[];
}

function sessionFromWire(r: RawSession): DataSubjectSession {
  return {
    sessionId: r.session_id,
    agentId: r.agent_id,
    ...(r.source_ip ? { sourceIp: r.source_ip } : {}),
    startedAt: r.started_at,
    ...(r.ended_at ? { endedAt: r.ended_at } : {}),
    status: r.status,
  };
}

function hitlFromWire(r: RawHitl): DataSubjectHitlRequest {
  return {
    requestId: r.request_id,
    agentId: r.agent_id,
    ...(r.session_id ? { sessionId: r.session_id } : {}),
    tool: r.tool,
    ...(r.resource ? { resource: r.resource } : {}),
    ...(r.reason ? { reason: r.reason } : {}),
    requestedAt: r.requested_at,
    timeoutAt: r.timeout_at,
    status: r.status,
    ...(r.decided_by ? { decidedBy: r.decided_by } : {}),
    ...(r.decided_at ? { decidedAt: r.decided_at } : {}),
    ...(r.comment ? { comment: r.comment } : {}),
  };
}

export class DataSubjectsApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Export all data Agentum holds about a subject.
   *
   * @throws {Error} if `subjectType` or `subjectId` is empty.
   * @throws {AgentumPermissionError} for non-Admin callers, or
   *   Admin callers targeting a different tenant.
   */
  async export(
    req: DataSubjectExportRequest,
  ): Promise<DataSubjectExportResponse> {
    if (!req.subjectType) {
      throw new Error("subjectType is required");
    }
    if (!req.subjectId || !req.subjectId.trim()) {
      throw new Error("subjectId is required");
    }
    const wire: Record<string, unknown> = {
      subject_type: req.subjectType,
      subject_id: req.subjectId,
    };
    if (req.tenantId !== undefined) {
      wire.tenant_id = req.tenantId;
    }
    const raw = await this.http.post<RawExportResponse>(
      "data-subjects/export",
      wire,
    );
    return {
      subjectType: raw.subject_type,
      subjectHmac: raw.subject_hmac,
      tenantId: raw.tenant_id,
      exportedAt: raw.exported_at,
      auditEvents: raw.audit_events,
      sessions: raw.sessions.map(sessionFromWire),
      hitlRequests: raw.hitl_requests.map(hitlFromWire),
    };
  }
}
