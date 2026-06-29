/**
 * `AgentumAdminClient.agents` — admin-plane agent lifecycle.
 *
 * Wraps `POST /agents`, `GET /agents`, `GET /agents/:id`,
 * `POST /agents/:id/kill`, `POST /agents/:id/quarantine`, and
 * `POST /agents/:id/activate`.
 */

import type {
  Agent,
  ListAgentsQuery,
  PaginatedResponse,
  RegisterAgentRequest,
  RegisterAgentResponse,
} from "../types.js";
import type { AdminHttpClient } from "./http.js";

export class AgentsApi {
  constructor(private readonly http: AdminHttpClient) {}

  /**
   * Register a new agent. Requires `Admin` role; scoped keys are rejected.
   */
  register(req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    return this.http.post<RegisterAgentResponse>("agents", {
      ...req,
      framework: req.framework ?? "agentum-ts-sdk",
      declared_tools: req.declared_tools ?? [],
      data_classes: req.data_classes ?? [],
    });
  }

  /**
   * List agents. Handles both `{ agents: [...] }` and paginated responses
   * from the server for forward-compat.
   */
  async list(opts?: ListAgentsQuery): Promise<Agent[]> {
    const result = await this.http.get<
      Agent[] | { agents: Agent[] } | PaginatedResponse<Agent>
    >("agents", {
      status: opts?.status,
      team: opts?.team,
      search: opts?.search,
      limit: opts?.limit,
      offset: opts?.offset,
    });
    if (Array.isArray(result)) return result;
    if ("items" in result) return result.items;
    if ("agents" in result) return result.agents ?? [];
    return [];
  }

  /** Fetch a single agent by ID. */
  get(id: string): Promise<Agent> {
    return this.http.get<Agent>(`agents/${id}`);
  }

  /**
   * Trigger the kill-switch: revoke all credentials and move the agent to
   * `decommissioned`. Requires `Admin`; scoped keys must match the agent.
   */
  async kill(id: string): Promise<void> {
    await this.http.post<unknown>(`agents/${id}/kill`);
  }

  /** Quarantine an agent — blocks runtime traffic pending investigation. */
  async quarantine(id: string): Promise<void> {
    await this.http.post<unknown>(`agents/${id}/quarantine`);
  }

  /**
   * Restore a quarantined or suspended agent.
   *
   * Maps to `POST /agents/:id/activate` server-side. Requires `Operator` or
   * higher; the server validates the prior state transition (quarantined →
   * active is allowed; others are rejected).
   */
  async restore(id: string): Promise<void> {
    await this.http.post<unknown>(`agents/${id}/activate`);
  }
}
