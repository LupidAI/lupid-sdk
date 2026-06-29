/**
 * Thin fetch wrappers around the Lupid capability-registry API.
 *
 * The host application's BFF is expected to sit between this component and
 * the real Lupid API; the `apiBase` argument is the BFF base URL. Auth
 * (HMAC, session token, etc.) is the BFF's responsibility — callers can
 * forward arbitrary header pairs via `authHeaders`.
 *
 * All non-2xx responses are mapped to a typed {@link LupidError}.
 */

import {
  LupidError,
  type CapabilityListResponse,
  type LupidErrorCode,
  type ScopeIdentity,
  type ToggleResponse,
} from "./types.js";

/** Set of error codes we recognize from the backend's `{ error, code }` body. */
const KNOWN_CODES = new Set<LupidErrorCode>([
  "scope_dimension_mismatch",
  "dimension_not_materialized",
  "too_many_dimension_filters",
  "bulk_too_large",
  "not_customer_visible",
  "no_scoping_dimension_declared",
  "unknown_error",
]);

/** Build a header object, merging defaults + caller overrides. */
function buildHeaders(authHeaders: Record<string, string> | undefined, json: boolean): HeadersInit {
  const h: Record<string, string> = { Accept: "application/json" };
  if (json) {
    h["Content-Type"] = "application/json";
  }
  if (authHeaders) {
    for (const [k, v] of Object.entries(authHeaders)) {
      h[k] = v;
    }
  }
  return h;
}

/** Trim a trailing slash from `apiBase` so URL concatenation is unambiguous. */
function normalizeBase(apiBase: string): string {
  return apiBase.endsWith("/") ? apiBase.slice(0, -1) : apiBase;
}

/**
 * Parse a non-2xx response body into a {@link LupidError}.
 *
 * The backend's error envelope is either:
 *   `{ "error": "<message>", "code": "<known_code>" }` (structured)
 *   `{ "error": "<message>" }`                          (generic; `code`
 *                                                       is the message
 *                                                       in many cases —
 *                                                       e.g.
 *                                                       `"scope_dimension_mismatch"`)
 *
 * We prefer the `code` field when present; otherwise we try to detect a
 * known code in the `error` message; otherwise `unknown_error`.
 */
async function parseError(res: Response): Promise<LupidError> {
  let bodyText = "";
  try {
    bodyText = await res.text();
  } catch {
    // Ignore — fall through with empty body.
  }
  let code: LupidErrorCode = "unknown_error";
  let message = bodyText || `HTTP ${res.status}`;
  if (bodyText.length > 0) {
    try {
      const parsed: unknown = JSON.parse(bodyText);
      if (parsed !== null && typeof parsed === "object") {
        const obj = parsed as Record<string, unknown>;
        const candidateCode = typeof obj.code === "string" ? obj.code : undefined;
        const candidateError = typeof obj.error === "string" ? obj.error : undefined;
        if (candidateCode !== undefined && KNOWN_CODES.has(candidateCode as LupidErrorCode)) {
          code = candidateCode as LupidErrorCode;
        } else if (
          candidateError !== undefined &&
          KNOWN_CODES.has(candidateError as LupidErrorCode)
        ) {
          // Backend used the generic envelope and stuffed the code into `error`.
          code = candidateError as LupidErrorCode;
        }
        if (candidateError !== undefined) {
          message = candidateError;
        }
      }
    } catch {
      // Non-JSON body; keep the text we already have.
    }
  }
  return new LupidError(code, message, res.status);
}

/** Best-effort JSON parse; throws as a `LupidError` with `unknown_error` on failure. */
async function parseJson<T>(res: Response): Promise<T> {
  try {
    return (await res.json()) as T;
  } catch (err) {
    throw new LupidError(
      "unknown_error",
      `failed to parse response body: ${(err as Error).message}`,
      res.status,
    );
  }
}

/** Wrap `fetch` so network-level errors also surface as `LupidError`. */
async function safeFetch(input: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init);
  } catch (err) {
    throw new LupidError("unknown_error", `network error: ${(err as Error).message}`, 0);
  }
}

/**
 * GET …/scopes/:dim/:value/capabilities/
 *
 * Returns the flat list of capabilities (with `parent_id`, `effective`,
 * and `override_value`) for the requested scope.
 */
export async function listCapabilities(
  apiBase: string,
  tenant: string,
  agent: string,
  scope: ScopeIdentity,
  authHeaders?: Record<string, string>,
): Promise<CapabilityListResponse> {
  const base = normalizeBase(apiBase);
  const url =
    `${base}/api/v1/tenants/${encodeURIComponent(tenant)}` +
    `/agents/${encodeURIComponent(agent)}` +
    `/scopes/${encodeURIComponent(scope.dimension)}/${encodeURIComponent(scope.value)}` +
    `/capabilities/`;
  const res = await safeFetch(url, { method: "GET", headers: buildHeaders(authHeaders, false) });
  if (!res.ok) {
    throw await parseError(res);
  }
  return parseJson<CapabilityListResponse>(res);
}

/**
 * GET …/capabilities/defaults
 *
 * Returns the catalog defaults for the agent (no scope context); used to
 * render the empty-state view in `<CapabilityToggles scope="defaults" />`.
 */
export async function getDefaults(
  apiBase: string,
  tenant: string,
  agent: string,
  authHeaders?: Record<string, string>,
): Promise<CapabilityListResponse> {
  const base = normalizeBase(apiBase);
  const url =
    `${base}/api/v1/tenants/${encodeURIComponent(tenant)}` +
    `/agents/${encodeURIComponent(agent)}` +
    `/capabilities/defaults`;
  const res = await safeFetch(url, { method: "GET", headers: buildHeaders(authHeaders, false) });
  if (!res.ok) {
    throw await parseError(res);
  }
  return parseJson<CapabilityListResponse>(res);
}

/**
 * PUT …/scopes/:dim/:value/capabilities/:capability_id
 *
 * Set an explicit per-scope override (enabled or disabled). The backend
 * returns the new effective set + the cascade preview.
 */
export async function toggleCapability(
  apiBase: string,
  tenant: string,
  agent: string,
  scope: ScopeIdentity,
  capabilityId: string,
  enabled: boolean,
  authHeaders?: Record<string, string>,
  reason?: string,
): Promise<ToggleResponse> {
  const base = normalizeBase(apiBase);
  const url =
    `${base}/api/v1/tenants/${encodeURIComponent(tenant)}` +
    `/agents/${encodeURIComponent(agent)}` +
    `/scopes/${encodeURIComponent(scope.dimension)}/${encodeURIComponent(scope.value)}` +
    `/capabilities/${encodeURIComponent(capabilityId)}`;
  const body: { enabled: boolean; reason?: string } = { enabled };
  if (reason !== undefined) {
    body.reason = reason;
  }
  const res = await safeFetch(url, {
    method: "PUT",
    headers: buildHeaders(authHeaders, true),
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  return parseJson<ToggleResponse>(res);
}

/**
 * DELETE …/scopes/:dim/:value/capabilities/:capability_id/override
 *
 * Reset the per-scope override to "no opinion" — the resolver falls back
 * to the catalog default.
 */
export async function deleteOverride(
  apiBase: string,
  tenant: string,
  agent: string,
  scope: ScopeIdentity,
  capabilityId: string,
  authHeaders?: Record<string, string>,
): Promise<ToggleResponse> {
  const base = normalizeBase(apiBase);
  const url =
    `${base}/api/v1/tenants/${encodeURIComponent(tenant)}` +
    `/agents/${encodeURIComponent(agent)}` +
    `/scopes/${encodeURIComponent(scope.dimension)}/${encodeURIComponent(scope.value)}` +
    `/capabilities/${encodeURIComponent(capabilityId)}/override`;
  const res = await safeFetch(url, {
    method: "DELETE",
    headers: buildHeaders(authHeaders, false),
  });
  if (!res.ok) {
    throw await parseError(res);
  }
  return parseJson<ToggleResponse>(res);
}
