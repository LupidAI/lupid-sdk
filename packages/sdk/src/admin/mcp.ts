/**
 * `AgentumAdminClient.mcp` — MCP server registry and per-agent access.
 *
 * Wraps `POST /mcp/servers`, `PUT /mcp/servers/:id`,
 * `DELETE /mcp/servers/:id`, `POST /mcp/servers/:server_id/access`, and
 * `DELETE /mcp/servers/:server_id/access/:agent_id`.
 */

import type {
  McpAccessGrant,
  McpAuthType,
  McpCredentialSource,
  RegisterMcpServerRequest,
  RegisterMcpServerResponse,
  UpdateMcpServerRequest,
} from "../types.js";
import type { AdminHttpClient } from "./http.js";

/**
 * External-secrets-manager binding for [`McpApi.registerWithExternalCredential`].
 * The gateway resolves the credential from the named backend on the MCP
 * tool-call hot path; rotating the secret in the backend propagates without
 * an Agentum API call or restart.
 */
export interface RegisterMcpExternalCredentialRequest {
  name: string;
  url: string;
  description?: string;
  /** How to inject the resolved value. `"oauth2_cc"` is not supported here. */
  auth_type?: Exclude<McpAuthType, "oauth2_cc">;
  auth_header_name?: string;
  status?: "active" | "disabled";
  credential: {
    /** One of `"aws_sm"`, `"hashicorp"`, `"azure_kv"`. */
    source: Exclude<McpCredentialSource, "static">;
    /** Backend-specific reference (AWS ARN/name, Vault path, Key Vault URL). */
    ref: string;
    /** Override the per-server cache TTL (default 300 s). */
    cache_ttl_seconds?: number;
  };
}

/**
 * OAuth 2.0 client-credentials options for
 * [`McpApi.registerOAuthServer`]. Mirrors the server-side wire shape
 * under a single nested object to keep the call site readable.
 */
export interface RegisterMcpOAuthServerRequest {
  name: string;
  url: string;
  description?: string;
  auth_header_name?: string;
  status?: "active" | "disabled";
  /** RFC 6749 client-credentials parameters. */
  oauth: {
    client_id: string;
    client_secret: string;
    token_url: string;
    /** Space-separated scope list; optional. */
    scopes?: string;
  };
}

export class McpApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Register a new MCP server. Requires `Admin` role; scoped keys are
   * rejected (matches `routes/mcp_servers.rs::register_server`).
   */
  registerServer(req: RegisterMcpServerRequest): Promise<RegisterMcpServerResponse> {
    return this.http.post<RegisterMcpServerResponse>("mcp/servers", req);
  }

  /**
   * Register an OAuth 2.0 client-credentials MCP server. The gateway
   * fetches and auto-refreshes the access token — the agent never needs
   * to handle 401s or token rotation.
   *
   * Throws a runtime error before hitting the network if any of
   * `client_id`, `client_secret`, or `token_url` is empty, so misuse
   * surfaces in the calling frame instead of as a 400 from the API.
   */
  registerOAuthServer(
    req: RegisterMcpOAuthServerRequest,
  ): Promise<RegisterMcpServerResponse> {
    const { oauth } = req;
    if (!oauth.client_id?.trim()) {
      throw new Error("registerOAuthServer: oauth.client_id is required");
    }
    if (!oauth.client_secret) {
      throw new Error("registerOAuthServer: oauth.client_secret is required");
    }
    if (!oauth.token_url?.trim()) {
      throw new Error("registerOAuthServer: oauth.token_url is required");
    }
    const flat: RegisterMcpServerRequest = {
      name: req.name,
      url: req.url,
      auth_type: "oauth2_cc",
      oauth_client_id: oauth.client_id,
      oauth_client_secret: oauth.client_secret,
      oauth_token_url: oauth.token_url,
    };
    if (req.description !== undefined) flat.description = req.description;
    if (req.auth_header_name !== undefined) flat.auth_header_name = req.auth_header_name;
    if (req.status !== undefined) flat.status = req.status;
    if (oauth.scopes !== undefined) flat.oauth_scopes = oauth.scopes;
    return this.http.post<RegisterMcpServerResponse>("mcp/servers", flat);
  }

  /**
   * Register an MCP server whose credential is resolved at injection time
   * from an external secrets manager. Rotate the secret in the backend;
   * the gateway picks up the new value within `cache_ttl_seconds`
   * (default 300 s) without an Agentum API call.
   *
   * Throws before the network round-trip if `credential.source` or
   * `credential.ref` is missing/blank, so misuse surfaces in the calling
   * frame rather than as a 400 from the API.
   */
  registerWithExternalCredential(
    req: RegisterMcpExternalCredentialRequest,
  ): Promise<RegisterMcpServerResponse> {
    const { credential } = req;
    if (!credential?.source) {
      throw new Error(
        "registerWithExternalCredential: credential.source is required",
      );
    }
    if (!credential.ref?.trim()) {
      throw new Error(
        "registerWithExternalCredential: credential.ref is required",
      );
    }
    const flat: RegisterMcpServerRequest = {
      name: req.name,
      url: req.url,
      auth_type: req.auth_type ?? "bearer",
      credential_source: credential.source,
      credential_ref: credential.ref,
    };
    if (req.description !== undefined) flat.description = req.description;
    if (req.auth_header_name !== undefined)
      flat.auth_header_name = req.auth_header_name;
    if (req.status !== undefined) flat.status = req.status;
    if (credential.cache_ttl_seconds !== undefined)
      flat.credential_cache_ttl_seconds = credential.cache_ttl_seconds;
    return this.http.post<RegisterMcpServerResponse>("mcp/servers", flat);
  }

  /** Patch a registered MCP server. Requires `Admin` role. */
  updateServer(
    id: string,
    patch: UpdateMcpServerRequest,
  ): Promise<RegisterMcpServerResponse> {
    return this.http.put<RegisterMcpServerResponse>(`mcp/servers/${id}`, patch);
  }

  /** Delete an MCP server. Scoped keys are rejected. */
  async deleteServer(id: string): Promise<void> {
    await this.http.delete<unknown>(`mcp/servers/${id}`);
  }

  /**
   * Grant an agent access to the named MCP server. `allowedTools` is a
   * list of tool names the agent may call; pass `["*"]` to allow all.
   */
  async grantAccess(
    serverId: string,
    agentId: string,
    allowedTools: string[],
  ): Promise<McpAccessGrant> {
    return this.http.post<McpAccessGrant>(`mcp/servers/${serverId}/access`, {
      agent_id: agentId,
      allowed_tools: allowedTools,
    });
  }

  /** Revoke an agent's access to the named MCP server. */
  async revokeAccess(serverId: string, agentId: string): Promise<void> {
    await this.http.delete<unknown>(`mcp/servers/${serverId}/access/${agentId}`);
  }
}
