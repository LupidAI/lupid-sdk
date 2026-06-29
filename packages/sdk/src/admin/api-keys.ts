/**
 * `AgentumAdminClient.apiKeys` — tenant-plane API key CRUD.
 *
 * Wraps `POST /tenant/api-keys`, `GET /tenant/api-keys`,
 * `DELETE /tenant/api-keys/:id`, and `POST /tenant/api-keys/:id/rotate`.
 *
 * **Response normalisation:** the server returns snake-case field names
 * (`plaintext_key`, `new_key_id`, `new_key_plaintext`, `old_key_id`,
 * `old_key_grace_until`). The SDK normalises them to the plan's stable
 * camelCase contract so callers see `{plaintext}` / `{newKeyId, …}`.
 */

import type {
  ApiKeyMetadata,
  MintApiKeyRequest,
  MintApiKeyResponse,
  RotateApiKeyResponse,
} from "../types.js";
import type { AdminHttpClient } from "./http.js";

interface RawMintResponse {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  agent_scope: string | null;
  expires_at: string | null;
  created_at: string;
  plaintext_key: string;
}

interface RawRotateResponse {
  new_key_id: string;
  new_key_plaintext: string;
  old_key_id: string;
  old_key_grace_until: string;
}

interface RawListResponse {
  keys: ApiKeyMetadata[];
  total: number;
}

export class ApiKeysApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Mint a new API key. The plaintext is returned exactly once — there is
   * no way to recover it later; store it in a secrets manager immediately.
   */
  async mint(req: MintApiKeyRequest): Promise<MintApiKeyResponse> {
    const raw = await this.http.post<RawMintResponse>("tenant/api-keys", req);
    return {
      id: raw.id,
      plaintext: raw.plaintext_key,
      tenant_id: raw.tenant_id,
      email: raw.email,
      role: raw.role,
      agent_scope: raw.agent_scope,
      expires_at: raw.expires_at,
      created_at: raw.created_at,
    };
  }

  /** Revoke an API key. Idempotent on an already-revoked key. */
  async revoke(id: string): Promise<void> {
    await this.http.delete<unknown>(`tenant/api-keys/${id}`);
  }

  /**
   * Rotate an API key. Mints a new plaintext and starts a grace window
   * (default 24h server-side) during which both the old and new keys
   * authenticate. Pass `graceSeconds` to override.
   */
  async rotate(id: string, graceSeconds?: number): Promise<RotateApiKeyResponse> {
    const body = graceSeconds !== undefined ? { grace_seconds: graceSeconds } : {};
    const raw = await this.http.post<RawRotateResponse>(
      `tenant/api-keys/${id}/rotate`,
      body,
    );
    return {
      newKeyId: raw.new_key_id,
      newPlaintext: raw.new_key_plaintext,
      oldKeyId: raw.old_key_id,
      oldGraceUntil: raw.old_key_grace_until,
    };
  }

  /**
   * List API keys visible to the caller. SuperAdmins see all tenants;
   * tenant Admins see their own tenant only.
   */
  async list(): Promise<ApiKeyMetadata[]> {
    const raw = await this.http.get<RawListResponse | ApiKeyMetadata[]>(
      "tenant/api-keys",
    );
    if (Array.isArray(raw)) return raw;
    return raw.keys ?? [];
  }
}
