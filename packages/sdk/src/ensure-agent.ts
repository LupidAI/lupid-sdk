/**
 * Universal "register or get" primitive — the foundation of Agentum's
 * hassle-free onboarding story.
 *
 * `ensureAgent({...})` calls `POST /api/v1/sdk/register` (idempotent on
 * `(tenant_id, name)`) and returns `{agentId, ...flags}`. It works for
 * **any** caller, framework-agnostic:
 *
 *   - Express webapps via `frameworks/express`'s `autoRegisterMiddleware`
 *   - FastAPI / Flask / Django (Python SDK calls the same endpoint)
 *   - LangGraph / LangChain agents that just want to scope a session
 *   - AutoGen / CrewAI orchestrators whose runtime isn't HTTP at all
 *   - Custom CI/CD jobs that need to onboard an agent via the CLI
 *
 * The function is the SDK-side mirror of `agentum onboard` — both call
 * the same server endpoint, both behave identically for the same
 * `(name, framework, declaredTools)` triple. Choose whichever fits the
 * caller's lifecycle (CLI for ops, programmatic for runtime).
 *
 * @example Programmatic register-or-get (any TS/JS runtime):
 * ```ts
 * import { ensureAgent } from '@lupid/sdk';
 *
 * const { agentId } = await ensureAgent({
 *   baseUrl: process.env.AGENTUM_BASE_URL!,
 *   apiKey: process.env.AGENTUM_API_KEY!,
 *   name: 'my-langgraph-agent',
 *   framework: 'langgraph',
 *   declaredTools: ['search_web', 'send_email'],
 * });
 * ```
 */

/** Capabilities-v2 booleans. All optional — absent keys round-trip
 *  through `extra` so customers can prototype new capabilities without
 *  an SDK update. */
export interface AgentCapabilities {
  web_search?: boolean;
  file_search?: boolean;
  execute_code?: boolean;
  image_generation?: boolean;
  ocr?: boolean;
  artifacts?: boolean;
  chain?: boolean;
  memory?: boolean;
  /** Forward-compat for new capability names. */
  [extra: string]: boolean | undefined;
}

/** Per-agent MCP-server inventory entry — one per server the agent
 *  declares it's using. */
export interface AgentMcpServer {
  /** Server-local name e.g. `'firecrawl-mcp'`, `'context7-docs'`. */
  server_name: string;
  /** `'stdio'` | `'streamable-http'` | `'sse'` | `'unknown'`. */
  transport: string;
  /** Upstream host the server reaches when known (e.g.
   *  `'api.firecrawl.dev'`). Empty string when unknown (most stdio MCPs). */
  upstream: string;
  /** LLM wire-format names with the `_mcp_<server>` suffix already
   *  applied (matches what the LLM filter sees in tool_call events). */
  tools: string[];
}

export interface EnsureAgentOptions {
  /** Agentum API base, e.g. `http://agentum:7071`. */
  baseUrl: string;
  /** Operator+ API key (`ak_*`). */
  apiKey: string;
  /** Stable agent name. The same name in the same tenant always
   *  resolves to the same `agentId`, regardless of how many times
   *  this is called. */
  name: string;
  /** Framework label written to the agent row on first-create.
   *  Matches the chips in the Agentum dashboard: `'langchain'`,
   *  `'langgraph'`, `'autogen'`, `'crewai'`, `'openai'`, `'anthropic'`,
   *  `'llamaindex'`, `'custom'`, or any free-text label. Defaults to
   *  `'agentum-sdk'`. */
  framework?: string;
  /** Free-text purpose. Defaults to `'Agentum SDK auto-registered agent'`. */
  purpose?: string;
  /** Declared tool names. CSV string or string[]. The server diffs
   *  the supplied set against what's stored and patches in-place —
   *  call this with the latest set on every restart. */
  declaredTools?: string | string[];
  /** Capabilities-v2 booleans. Higher-level agent powers
   *  that are NOT named LLM tools but ARE policy-relevant. Cedar
   *  policies target these via `agent.capabilities.web_search` etc.
   *  Pass only the keys you've actually computed; absent keys are
   *  treated as `false` by the policy engine. */
  capabilities?: AgentCapabilities;
  /** Per-agent MCP-server inventory. Each entry describes
   *  one MCP server the agent declares it's using (name, transport,
   *  upstream host, list of LLM-wire-format tool names that server
   *  exposes — i.e. tools already include the `_mcp_<server>` suffix).
   *  Server replaces the rows for this agent with the supplied list,
   *  so call with the full inventory every time. */
  mcpServers?: AgentMcpServer[];
  /** Whether the agent represents a multi-user webapp where each
   *  end-user gets their own scoped session under the same agent.
   *  Defaults to `false`. */
  sharedUserModel?: boolean;
  /** Disable the auto-applied default permit Cedar policy on
   *  first-create. Operators bringing their own policy via
   *  `agentum policy put` should pass `false`. Defaults to `true`. */
  defaultPolicy?: boolean;
  /** Optional override for the default `fetch`. Useful for tests
   *  and for runtimes that need to inject a custom HTTP agent. */
  fetchImpl?: typeof fetch;
  /** Custom logger; defaults to `console`. */
  logger?: Pick<Console, "log" | "warn" | "error">;
}

export interface EnsureAgentResult {
  /** Server-assigned UUID. Stable across calls for the same name. */
  agentId: string;
  /** Tenant the agent belongs to (derived from the API key). */
  tenantId: string;
  /** True iff this call was the one that inserted the row.
   *  False on every subsequent call. */
  created: boolean;
  /** True iff the default permit policy was written on this call. */
  defaultPolicyApplied: boolean;
  /** True iff `declared_tools` were updated on this call (because the
   *  caller-supplied set differed from the stored set). */
  declaredToolsSynced: boolean;
  /** True iff capabilities-v2 booleans were patched on this call. */
  capabilitiesSynced: boolean;
  /** True iff the per-agent MCP-server inventory was
   *  modified (rows added, removed, or updated). */
  mcpServersSynced: boolean;
  /** Z08 / S01 — bootstrap agent-scoped session JWT returned by the
   *  slow-path (newly-created agent). Absent on fast-path re-register
   *  and on the race fallback. Consumers without a pre-provisioned
   *  AGENTUM_API_KEY use this to issue subsequent SDK calls without an
   *  out-of-band credential exchange. */
  sessionJwt?: string;
}

/**
 * Idempotently register or fetch an agent by name. See module doc.
 *
 * Throws on transport errors and on non-2xx responses; the caller
 * decides retry policy. The Express middleware preset retries on the
 * next request; a CLI/CI caller usually wants to fail loudly.
 */
export async function ensureAgent(
  opts: EnsureAgentOptions,
): Promise<EnsureAgentResult> {
  if (!opts.baseUrl) throw new Error("ensureAgent: baseUrl is required");
  if (!opts.apiKey) throw new Error("ensureAgent: apiKey is required");
  if (!opts.name || !opts.name.trim()) {
    throw new Error("ensureAgent: name is required");
  }

  const fetchFn = opts.fetchImpl ?? fetch;
  const logger = opts.logger ?? console;

  const url = `${opts.baseUrl.replace(/\/$/, "")}/api/v1/sdk/register`;

  const body: Record<string, unknown> = {
    name: opts.name,
    framework: opts.framework ?? "agentum-sdk",
    purpose: opts.purpose ?? "Agentum SDK auto-registered agent",
    shared_user_model: opts.sharedUserModel ?? false,
  };
  if (opts.defaultPolicy !== undefined) {
    body.default_policy = opts.defaultPolicy;
  }
  const tools = parseDeclaredTools(opts.declaredTools);
  if (tools !== null) {
    body.declared_tools = tools;
  }
  if (opts.capabilities !== undefined) {
    body.capabilities = opts.capabilities;
  }
  if (opts.mcpServers !== undefined) {
    body.mcp_servers = opts.mcpServers;
  }

  const resp = await fetchFn(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": opts.apiKey,
    },
    body: JSON.stringify(body),
  });

  if (resp.status !== 200 && resp.status !== 201) {
    const text = await resp.text();
    throw new Error(
      `ensureAgent: /sdk/register failed for name=${opts.name}: ${resp.status} ${text}`,
    );
  }

  const respBody = (await resp.json()) as {
    agent_id?: string;
    tenant_id?: string;
    created?: boolean;
    default_policy_applied?: boolean;
    declared_tools_synced?: boolean;
    capabilities_synced?: boolean;
    mcp_servers_synced?: boolean;
    session_jwt?: string;
  };

  if (!respBody.agent_id || !respBody.tenant_id) {
    throw new Error(
      `ensureAgent: /sdk/register returned malformed body: ${JSON.stringify(respBody)}`,
    );
  }

  const result: EnsureAgentResult = {
    agentId: respBody.agent_id,
    tenantId: respBody.tenant_id,
    created: Boolean(respBody.created),
    defaultPolicyApplied: Boolean(respBody.default_policy_applied),
    declaredToolsSynced: Boolean(respBody.declared_tools_synced),
    capabilitiesSynced: Boolean(respBody.capabilities_synced),
    mcpServersSynced: Boolean(respBody.mcp_servers_synced),
    ...(respBody.session_jwt ? { sessionJwt: respBody.session_jwt } : {}),
  };

  logger.log(
    `[agentum] ensureAgent resolved name=${opts.name} → agent_id=${result.agentId} ` +
      `(created=${result.created}, default_policy_applied=${result.defaultPolicyApplied}, ` +
      `declared_tools_synced=${result.declaredToolsSynced})`,
  );

  return result;
}

function parseDeclaredTools(
  raw: string | string[] | undefined,
): string[] | null {
  if (raw === undefined) return null;
  if (Array.isArray(raw)) {
    const cleaned = raw.map((s) => s.trim()).filter(Boolean);
    return cleaned;
  }
  const cleaned = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return cleaned;
}
