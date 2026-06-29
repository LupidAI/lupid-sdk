/**
 * `AgentumAdminClient.tenantClassifications` — per-tenant custom field
 * classification rules. Rules flow into the Stage-1 audit masking
 * annotator alongside the built-in PII/SSN/CC scanner.
 *
 * Rule shapes mirror the server (see `routes/tenant_classifications.rs`):
 * - `pattern` only → regex match anywhere inside `detail`.
 * - `pattern` + `fieldPaths` → regex match only at the given dotted paths.
 * - `fieldPaths` only → always flag those paths (e.g. `detail.legal_memo`).
 *
 * Masking mode per label is configured via the tenant's compliance
 * overrides (`byLabel: { "PHI:MRN": "encrypt" }`).
 *
 * ```ts
 * const rule = await admin.tenantClassifications.create(tenantId, {
 *   label: "PHI:MRN",
 *   pattern: "\\bMRN-\\d{8}\\b",
 *   sensitivity: "phi",
 * });
 *
 * const preview = await admin.tenantClassifications.test(tenantId, {
 *   detail: { patient: "MRN-12345678" },
 * });
 * // preview.matches[0] → { fieldPath: "detail.patient", labels: ["PHI:MRN"], sensitivity: "phi" }
 * ```
 */

import type { AdminHttpClient } from "./http.js";

/** Accepted sensitivity tier values. Wire-compatible with `FieldSensitivity`. */
export type ClassificationSensitivity =
  | "public"
  | "internal"
  | "pii"
  | "phi"
  | "pci"
  | "secret";

export interface ClassificationRecord {
  id: string;
  tenantId: string;
  label: string;
  pattern: string | null;
  fieldPaths: string[];
  sensitivity: ClassificationSensitivity;
  createdAt: string;
  updatedAt: string;
}

export interface CreateClassificationRequest {
  label: string;
  /** `null`/omitted → path-only rule (requires `fieldPaths` non-empty). */
  pattern?: string | null;
  fieldPaths?: string[];
  /** Defaults to `"pii"` on the server when omitted. */
  sensitivity?: ClassificationSensitivity;
}

export interface UpdateClassificationRequest {
  label?: string;
  /** `undefined` → keep current; `null` → clear; string → update. */
  pattern?: string | null;
  fieldPaths?: string[];
  sensitivity?: ClassificationSensitivity;
}

export interface ClassificationMatch {
  fieldPath: string;
  labels: string[];
  sensitivity: ClassificationSensitivity;
}

export interface TestClassificationResponse {
  tenantId: string;
  matches: ClassificationMatch[];
}

export interface ListClassificationsResponse {
  tenantId: string;
  count: number;
  classifications: ClassificationRecord[];
}

// ─── Wire shapes (snake_case) ──────────────────────────────────────────────

interface RawClassificationRecord {
  id: string;
  tenant_id: string;
  label: string;
  pattern: string | null;
  field_paths: string[];
  sensitivity: ClassificationSensitivity;
  created_at: string;
  updated_at: string;
}

interface RawListResponse {
  tenant_id: string;
  count: number;
  classifications: RawClassificationRecord[];
}

interface RawMatch {
  field_path: string;
  labels: string[];
  sensitivity: ClassificationSensitivity;
}

interface RawTestResponse {
  tenant_id: string;
  matches: RawMatch[];
}

function fromRaw(raw: RawClassificationRecord): ClassificationRecord {
  return {
    id: raw.id,
    tenantId: raw.tenant_id,
    label: raw.label,
    pattern: raw.pattern,
    fieldPaths: raw.field_paths ?? [],
    sensitivity: raw.sensitivity,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

function toCreateWire(
  req: CreateClassificationRequest,
): Record<string, unknown> {
  const body: Record<string, unknown> = { label: req.label };
  if (req.pattern !== undefined) body.pattern = req.pattern;
  if (req.fieldPaths !== undefined) body.field_paths = req.fieldPaths;
  if (req.sensitivity !== undefined) body.sensitivity = req.sensitivity;
  return body;
}

function toUpdateWire(
  req: UpdateClassificationRequest,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (req.label !== undefined) body.label = req.label;
  if (req.pattern !== undefined) body.pattern = req.pattern;
  if (req.fieldPaths !== undefined) body.field_paths = req.fieldPaths;
  if (req.sensitivity !== undefined) body.sensitivity = req.sensitivity;
  return body;
}

// ─── API class ─────────────────────────────────────────────────────────────

export class TenantClassificationsApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * List all classification rules for a tenant.
   *
   * @throws {AgentumPermissionError} tenant-Admin calling outside own tenant.
   * @throws {AgentumNotFoundError} unknown tenant.
   */
  async list(tenantId: string): Promise<ListClassificationsResponse> {
    ensureTenantId(tenantId);
    const raw = await this.http.get<RawListResponse>(
      `admin/tenant-classifications/${encodeURIComponent(tenantId)}`,
    );
    return {
      tenantId: raw.tenant_id,
      count: raw.count,
      classifications: raw.classifications.map(fromRaw),
    };
  }

  /**
   * Create a new rule. Rule must have either `pattern` or non-empty
   * `fieldPaths` — rules with neither are rejected (422).
   *
   * @throws {Error} invalid regex (422 from server).
   * @throws {Error} duplicate label for this tenant (422 from server).
   */
  async create(
    tenantId: string,
    req: CreateClassificationRequest,
  ): Promise<ClassificationRecord> {
    ensureTenantId(tenantId);
    ensureLabel(req.label);
    if (
      (req.pattern === undefined || req.pattern === null || req.pattern === "") &&
      (!req.fieldPaths || req.fieldPaths.length === 0)
    ) {
      throw new Error(
        "classification rule requires either `pattern` or non-empty `fieldPaths`",
      );
    }
    const raw = await this.http.post<RawClassificationRecord>(
      `admin/tenant-classifications/${encodeURIComponent(tenantId)}`,
      toCreateWire(req),
    );
    return fromRaw(raw);
  }

  /**
   * Partial update — fields not present in `req` retain their current
   * value. Pass `pattern: null` to explicitly clear a regex.
   */
  async update(
    tenantId: string,
    id: string,
    req: UpdateClassificationRequest,
  ): Promise<ClassificationRecord> {
    ensureTenantId(tenantId);
    ensureRuleId(id);
    const raw = await this.http.put<RawClassificationRecord>(
      `admin/tenant-classifications/${encodeURIComponent(tenantId)}/${encodeURIComponent(id)}`,
      toUpdateWire(req),
    );
    return fromRaw(raw);
  }

  /** Delete a rule. Returns `true` on success, throws on not-found. */
  async delete(tenantId: string, id: string): Promise<void> {
    ensureTenantId(tenantId);
    ensureRuleId(id);
    await this.http.delete<void>(
      `admin/tenant-classifications/${encodeURIComponent(tenantId)}/${encodeURIComponent(id)}`,
    );
  }

  /**
   * Dry-run: feed a sample `detail` through the tenant's current rule set
   * (plus the built-in PII scanner) and return per-field labels + effective
   * sensitivity. Useful for "would this rule match my data?" previews.
   */
  async test(
    tenantId: string,
    sample: { detail: unknown },
  ): Promise<TestClassificationResponse> {
    ensureTenantId(tenantId);
    const raw = await this.http.post<RawTestResponse>(
      `admin/tenant-classifications/${encodeURIComponent(tenantId)}/test`,
      { detail: sample.detail },
    );
    return {
      tenantId: raw.tenant_id,
      matches: raw.matches.map((m) => ({
        fieldPath: m.field_path,
        labels: m.labels,
        sensitivity: m.sensitivity,
      })),
    };
  }
}

// ─── Client-side validation ───────────────────────────────────────────────

function ensureTenantId(tenantId: string): void {
  if (!tenantId || !tenantId.trim()) {
    throw new Error("tenantId is required");
  }
}

function ensureRuleId(id: string): void {
  if (!id || !id.trim()) {
    throw new Error("rule id is required");
  }
}

function ensureLabel(label: string): void {
  if (!label || !label.trim()) {
    throw new Error("label is required");
  }
}
