/**
 * MCP-REDESIGN Phase 2b — `CedarToolCallClient.evaluateToolCall` ships the
 * additive `mcp_server_url` / `mcp_server_name` identifiers so an old central
 * (which has no SDK-side server registry) can resolve the canonical
 * `server_id`. The change is additive + dual-accept: the legacy namespaced
 * `tool_name` (central) / `action` + nested `context` (PDP) are unchanged, and
 * the new fields are OMITTED entirely when undefined (non-MCP tool calls).
 *
 * Coverage:
 *   1. Central `/sdk/evaluate-tool-call` body carries `mcp_server_url` +
 *      `mcp_server_name` when supplied; `tool_name` keeps its namespaced form.
 *   2. PDP `/v1/authorize` body carries `mcp_server_url` / `mcp_server_name`
 *      inside `context` (additive free-JSON); `action`/`resource` unchanged.
 *   3. A non-MCP call (no mcp fields) OMITS both keys on the central body.
 *   4. The DecisionCache hit shape is unaffected — two identical MCP calls
 *      hit the wire once (the new fields are evaluation inputs, not part of
 *      the legacy cache-key action string).
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import { _setActiveSchema } from "../src/manifest/state";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

interface CapturedRequest {
  url: string;
  body: Record<string, unknown>;
}

const AGENT_ID = "agent-acme";
const PDP_URL = "http://127.0.0.1:7080";

/** Central-only recording fetch double (no PDP). Records evaluate-tool-call. */
function centralRecordingFetch(recorded: CapturedRequest[]): typeof fetch {
  return (async (url: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : "";
    const raw = init?.body;
    const parsed =
      typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : {};
    if (urlStr.includes("/sdk/evaluate-tool-call")) {
      recorded.push({ url: urlStr, body: parsed });
    }
    return new Response(JSON.stringify({ decision: "allow", ttl_ms: 5000 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

/** PDP recording fetch double: answers /v1/health + /v1/authorize. */
function pdpRecordingFetch(recorded: CapturedRequest[]): typeof fetch {
  return (async (url: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : "";
    if (urlStr.endsWith("/v1/health")) {
      return new Response(JSON.stringify({ agent_id: AGENT_ID }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (urlStr.endsWith("/v1/authorize")) {
      const raw = init?.body;
      const parsed =
        typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : {};
      recorded.push({ url: urlStr, body: parsed });
      return new Response(
        JSON.stringify({ decision: "allow", policy_hash: "h1" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    // Audit-ingest fire-and-forget — swallow.
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function newCentralClient(fetchImpl: typeof fetch): CedarToolCallClient {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: AGENT_ID,
    pdpUrl: "",
    timeoutMs: 200,
    fetchImpl,
    logger: silentLogger(),
  });
}

function newPdpClient(fetchImpl: typeof fetch): CedarToolCallClient {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: AGENT_ID,
    pdpUrl: PDP_URL,
    pdpServiceToken: "svc-token",
    timeoutMs: 200,
    fetchImpl,
    logger: silentLogger(),
  });
}

afterEach(() => {
  _setActiveSchema(null);
});

describe("CedarToolCallClient — MCP-REDESIGN Phase 2b server_id inputs", () => {
  test("central body carries mcp_server_url + mcp_server_name; tool_name keeps namespaced form", async () => {
    const recorded: CapturedRequest[] = [];
    const client = newCentralClient(centralRecordingFetch(recorded));

    await client.evaluateToolCall({
      toolName: "read_text_file_mcp_agentum-fs",
      arguments: { path: "/etc/hosts" },
      mcpServerUrl: "https://mcp.example.com/mcp",
      mcpServerName: "agentum-fs",
    });

    expect(recorded).toHaveLength(1);
    const body = recorded[0]!.body;
    // Dual-accept: the legacy namespaced tool_name is unchanged.
    expect(body["tool_name"]).toBe("read_text_file_mcp_agentum-fs");
    // New additive identifiers present.
    expect(body["mcp_server_url"]).toBe("https://mcp.example.com/mcp");
    expect(body["mcp_server_name"]).toBe("agentum-fs");
  });

  test("PDP /v1/authorize context carries mcp_server_url / mcp_server_name; action unchanged", async () => {
    const recorded: CapturedRequest[] = [];
    const client = newPdpClient(pdpRecordingFetch(recorded));

    const result = await client.evaluateToolCall({
      toolName: "read_text_file_mcp_agentum-fs",
      mcpServerUrl: "https://mcp.example.com/mcp",
      mcpServerName: "agentum-fs",
    });

    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("pdp");

    const authorize = recorded.find((r) => r.url.endsWith("/v1/authorize"));
    expect(authorize).toBeDefined();
    // Legacy action subject unchanged (dual-accept).
    expect(authorize!.body["action"]).toBe("tool:read_text_file_mcp_agentum-fs");
    const ctx = authorize!.body["context"] as Record<string, unknown>;
    expect(ctx["mcp_server_url"]).toBe("https://mcp.example.com/mcp");
    expect(ctx["mcp_server_name"]).toBe("agentum-fs");
  });

  test("non-MCP call OMITS both mcp_server_* keys from the central body", async () => {
    const recorded: CapturedRequest[] = [];
    const client = newCentralClient(centralRecordingFetch(recorded));

    await client.evaluateToolCall({ toolName: "search_web" });

    expect(recorded).toHaveLength(1);
    const body = recorded[0]!.body;
    expect("mcp_server_url" in body).toBe(false);
    expect("mcp_server_name" in body).toBe(false);
  });

  test("DecisionCache hit shape unaffected — identical MCP calls hit the wire once", async () => {
    const recorded: CapturedRequest[] = [];
    const client = newCentralClient(centralRecordingFetch(recorded));

    const call = {
      toolName: "read_text_file_mcp_agentum-fs",
      arguments: { path: "/etc/hosts" },
      mcpServerUrl: "https://mcp.example.com/mcp",
      mcpServerName: "agentum-fs",
    };
    await client.evaluateToolCall(call);
    await client.evaluateToolCall(call);

    // Second call is served from the DecisionCache — the new fields are
    // evaluation inputs, not part of the legacy cache-key action string.
    expect(recorded).toHaveLength(1);
  });
});
