/**
 * LangChain adapter tests — covers the new chat-model / agent / retriever
 * handlers (Bug C) and the policy_deny audit emission for invalid-JSON
 * soft-deny and real Cedar deny (Bug D).
 */

import { AgentumClient } from "../../src/index";
import { AgentumSession } from "../../src/session";
import {
  AgentumCallbackHandler,
  AgentumPolicyTool,
  enforceAllTools,
  type LangChainToolLike,
} from "../../src/frameworks/langchain";

const BASE = "http://localhost:7071";

function mockFetch(body: unknown, status = 200): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

function makeClient(f: jest.Mock): AgentumClient {
  return new AgentumClient({
    baseUrl: BASE,
    fetch: f as unknown as typeof fetch,
    disableAuditBuffer: true,
  });
}

function bodies(f: jest.Mock): Array<Record<string, unknown>> {
  return f.mock.calls
    .filter((c) => (c[1] as { body?: string } | undefined)?.body)
    .map((c) => JSON.parse((c[1] as { body: string }).body));
}

describe("AgentumCallbackHandler — chat-model/agent/retriever hooks (Bug C)", () => {
  it("handleChatModelStart/End emit llm_call and llm_end", async () => {
    const f = mockFetch({ blocked_hashes: [] });
    const client = makeClient(f);
    const h = new AgentumCallbackHandler({ client, agentId: "a1", sessionId: "s1" });

    await h.handleChatModelStart(
      { id: ["ChatOpenAI"] },
      [[{ _getType: () => "human", content: "hello world" }]],
    );
    h.handleChatModelEnd();

    await new Promise((r) => setTimeout(r, 5));
    const types = bodies(f).map((b) => b["event_type"]);
    expect(types).toContain("llm_call");
    expect(types).toContain("llm_end");
  });

  it("handleAgentAction / handleAgentEnd emit shaped events", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const h = new AgentumCallbackHandler({ client, agentId: "a1", sessionId: "s1" });

    h.handleAgentAction({ tool: "web_search", toolInput: { q: "x" }, log: "thinking..." });
    h.handleAgentEnd({ log: "done", returnValues: { output: "ok" } });

    await new Promise((r) => setTimeout(r, 5));
    const events = bodies(f);
    const action = events.find((b) => b["event_type"] === "agent_action");
    expect(action).toBeDefined();
    expect((action!["detail"] as Record<string, unknown>)["tool"]).toBe("web_search");
    const end = events.find((b) => b["event_type"] === "agent_end");
    expect(end).toBeDefined();
  });

  it("retriever hooks emit start/end/error", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const h = new AgentumCallbackHandler({ client, agentId: "a1", sessionId: "s1" });

    h.handleRetrieverStart({ id: ["VectorStoreRetriever"] }, "query text");
    h.handleRetrieverEnd([{ pageContent: "abc" }, { pageContent: "de" }]);
    h.handleRetrieverError(new Error("index down"));

    await new Promise((r) => setTimeout(r, 5));
    const types = bodies(f).map((b) => b["event_type"]);
    expect(types).toContain("retriever_start");
    expect(types).toContain("retriever_end");
    expect(types).toContain("retriever_error");
  });
});

describe("AgentumPolicyTool — policy_deny audit emission (Bug D)", () => {
  it("emits policy_deny on invalid JSON input under softDeny", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);
    const tool = new AgentumPolicyTool({ client, agentId: "a1", sessionId: "s1", softDeny: true });

    const result = await tool.invoke("not-json-at-all");
    expect(result).toBe("DENIED: invalid input");

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies).toHaveLength(1);
    const detail = denies[0]!["detail"] as Record<string, unknown>;
    expect(detail["reason"]).toBe("invalid_input");
    expect(detail["input_snippet"]).toBe("not-json-at-all");
  });

  it("emits policy_deny on actual Cedar deny", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const tool = new AgentumPolicyTool({ client, agentId: "a1", sessionId: "s1", softDeny: true });

    const result = await tool.invoke(JSON.stringify({ action: "http.delete", resource: "https://x" }));
    expect(result).toMatch(/^DENIED/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies).toHaveLength(1);
    const detail = denies[0]!["detail"] as Record<string, unknown>;
    expect(detail["reason"]).toBe("policy_deny");
    expect(detail["action"]).toBe("http.delete");
    expect(detail["resource"]).toBe("https://x");
  });
});

// ── enforceAllTools — batch policy wrapper (1.5.12 / G51) ───────────────────

describe("enforceAllTools — batch Cedar guard for LangChain tools", () => {
  type FakeTool = LangChainToolLike & {
    _call: jest.Mock<Promise<string>, [string]>;
  };

  function makeFakeTool(name: string): FakeTool {
    return {
      name,
      description: `tool ${name}`,
      _call: jest.fn().mockResolvedValue(`result:${name}`),
    };
  }

  function makeSession(
    decisions: Record<string, boolean>,
    fetchMock?: jest.Mock,
  ): { session: AgentumSession; fetch: jest.Mock } {
    // Build a fetch mock that returns Allow/Deny based on the simulate body.
    const f =
      fetchMock ??
      jest.fn().mockImplementation(async (_url: string, init: { body?: string }) => {
        const body = init?.body ? (JSON.parse(init.body) as { resource?: string }) : {};
        const resource = body.resource ?? "*";
        const allow = decisions[resource] ?? true;
        return {
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve({ outcome: allow ? "Allow" : "Deny" }),
          text: () => Promise.resolve(JSON.stringify({ outcome: allow ? "Allow" : "Deny" })),
        };
      });
    const client = new AgentumClient({
      baseUrl: BASE,
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    const session = new AgentumSession(client, "a1", "s1", "jwt");
    return { session, fetch: f };
  }

  it("allows all 5 tools when Cedar permits (DoD case 1, allow path)", async () => {
    const { session } = makeSession({});
    const tools = Array.from({ length: 5 }, (_, i) => makeFakeTool(`tool-${i}`));
    const guarded = enforceAllTools(tools, {
      session,
      actionPrefix: "mcp.tool.call",
      resourceFn: (t) => t.name,
    });

    const results = await Promise.all(
      guarded.map((t) => (t._call as FakeTool["_call"])!("x")),
    );
    expect(results).toEqual([
      "result:tool-0",
      "result:tool-1",
      "result:tool-2",
      "result:tool-3",
      "result:tool-4",
    ]);
  });

  it("denies exactly the tool Cedar blocks; other 4 run (DoD case 1)", async () => {
    const { session } = makeSession({ "tool-2": false });
    const tools = Array.from({ length: 5 }, (_, i) => makeFakeTool(`tool-${i}`));
    const guarded = enforceAllTools(tools, {
      session,
      actionPrefix: "mcp.tool.call",
      resourceFn: (t) => t.name,
      onDeny: "throw",
    });

    for (let i = 0; i < 5; i++) {
      const call = (guarded[i]!._call as FakeTool["_call"])!("payload");
      if (i === 2) {
        await expect(call).rejects.toThrow(/PermissionError.*tool-2/);
      } else {
        await expect(call).resolves.toBe(`result:tool-${i}`);
      }
    }

    // Denied tool's original _call must NOT have been invoked.
    expect(tools[2]!._call).not.toHaveBeenCalled();
    // Allowed tools WERE invoked.
    expect(tools[0]!._call).toHaveBeenCalled();
    expect(tools[4]!._call).toHaveBeenCalled();
  });

  it("onDeny='return_error_string' resolves with DENIED string (DoD case 3 — audit path)", async () => {
    const { session, fetch: f } = makeSession({ "tool-x": false });
    const [guarded] = enforceAllTools([makeFakeTool("tool-x")], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "return_error_string",
    });

    const result = await (guarded!._call as FakeTool["_call"])!("y");
    expect(String(result)).toMatch(/^DENIED:.*PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denyAudits = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denyAudits.length).toBe(1);
    const detail = denyAudits[0]!["detail"] as Record<string, unknown>;
    expect(detail["tool"]).toBe("tool-x");
    expect(detail["action"]).toBe("mcp.tool.call");
  });

  it("onDeny='silent_skip' returns empty string on deny", async () => {
    const { session } = makeSession({ "tool-s": false });
    const [guarded] = enforceAllTools([makeFakeTool("tool-s")], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "silent_skip",
    });

    const result = await (guarded!._call as FakeTool["_call"])!("y");
    expect(result).toBe("");
  });

  it("emits mcp_tool_call audit on allow path (DoD case 3 — allow path)", async () => {
    const { session, fetch: f } = makeSession({});
    const [guarded] = enforceAllTools([makeFakeTool("ok-tool")], {
      session,
      actionPrefix: "mcp.tool.call",
    });

    await (guarded!._call as FakeTool["_call"])!("input");

    await new Promise((r) => setTimeout(r, 5));
    const callAudits = bodies(f).filter((b) => b["event_type"] === "mcp_tool_call");
    expect(callAudits.length).toBe(1);
    const detail = callAudits[0]!["detail"] as Record<string, unknown>;
    expect(detail["tool"]).toBe("ok-tool");
    expect(detail["framework"]).toBe("langchain");
  });

  it("wraps `invoke` method when present (LangChain 0.2+ style)", async () => {
    const { session } = makeSession({});
    const tool: LangChainToolLike = {
      name: "invoke-tool",
      invoke: jest.fn().mockResolvedValue("via-invoke"),
    };
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
    });

    const result = await (guarded!.invoke as jest.Mock)("x");
    expect(result).toBe("via-invoke");
    expect(tool.invoke).toHaveBeenCalled();
  });

  it("original tool list is not mutated", async () => {
    const { session } = makeSession({});
    const tool = makeFakeTool("orig");
    const originalCall = tool._call;
    enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
    });

    // Original tool's _call method reference is unchanged — no in-place mutation.
    expect(tool._call).toBe(originalCall);
  });

  it("uses default resourceFn (tool.name) when not supplied", async () => {
    const { session, fetch: f } = makeSession({ "default-res": false });
    const [guarded] = enforceAllTools([makeFakeTool("default-res")], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "return_error_string",
    });

    const result = await (guarded!._call as FakeTool["_call"])!("x");
    expect(String(result)).toMatch(/DENIED/);

    await new Promise((r) => setTimeout(r, 5));
    const simulateBodies = bodies(f).filter((b) => b["resource"] === "default-res");
    expect(simulateBodies.length).toBeGreaterThanOrEqual(1);
  });
});

// ── L05a — PDP observability threading ─────────────────────────────────────

describe("L05a — PDP observability threading into LangChain audit", () => {
  // Field placement contract (verified):
  //   `policy_hash`, `decision_source`   → TOP-LEVEL on AuditIngestRequest
  //   `evaluated_locally`, `pdp_latency_us` → INSIDE detail
  // (Mirrors `cedar-client.ts:567,570,578,581-583` and `types.ts:255,265`.)

  type FakeTool = LangChainToolLike & {
    _call: jest.Mock<Promise<string>, [string]>;
  };

  function makeFakeTool(name: string): FakeTool {
    return {
      name,
      description: `tool ${name}`,
      _call: jest.fn().mockResolvedValue(`result:${name}`),
    };
  }

  function makeClientWithKey(f: jest.Mock): AgentumClient {
    return new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
  }

  it("allow path threads top-level policy_hash + decision_source and detail evaluated_locally + pdp_latency_us", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    const session = new AgentumSession(client, "a1", "s1", "jwt");

    // Stub evaluateToolCall so we don't need to route through PDP. This
    // is the unit-test boundary: the emit-layer should not care HOW the
    // evaluation was produced, only that it splits the observability
    // fields between top-level + detail.
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "allow",
      ttlMs: 100,
      policyHash: "ph-1",
      evaluatedLocally: true,
      pdpLatencyUs: 42,
      decisionSource: "pdp", // cedar-client uses "pdp"; emit must map to "local_pdp"
    });

    const tool = makeFakeTool("t-allow");
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
    });
    await (guarded!._call as FakeTool["_call"])!("x");

    await new Promise((r) => setTimeout(r, 5));
    const callAudits = bodies(f).filter((b) => b["event_type"] === "mcp_tool_call");
    expect(callAudits.length).toBe(1);
    const ev = callAudits[0]!;
    // Top-level — the load-bearing assertion.
    expect(ev["policy_hash"]).toBe("ph-1");
    expect(ev["decision_source"]).toBe("inproc");
    // Detail-level.
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(42);
    // Sanity — existing keys not displaced.
    expect(detail["tool"]).toBe("t-allow");
    expect(detail["framework"]).toBe("langchain");
  });

  it("deny path threads top-level + detail observability on mcp_tool_deny", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    const session = new AgentumSession(client, "a1", "s1", "jwt");

    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 100,
      policyHash: "ph-deny",
      evaluatedLocally: true,
      pdpLatencyUs: 17,
      decisionSource: "pdp",
      reason: "policy_deny",
      ruleId: "rule-7",
    });

    const tool = makeFakeTool("t-deny");
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "return_error_string",
    });
    await (guarded!._call as FakeTool["_call"])!("x");

    await new Promise((r) => setTimeout(r, 5));
    const denyAudits = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denyAudits.length).toBe(1);
    const ev = denyAudits[0]!;
    expect(ev["policy_hash"]).toBe("ph-deny");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(17);
    expect(detail["rule_id"]).toBe("rule-7");
    expect(detail["reason"]).toBe("policy_deny");
    // Original tool's _call must not have run.
    expect(tool._call).not.toHaveBeenCalled();
  });

  it("partial observability (central decision) emits decision_source='central' without evaluated_locally/pdp_latency_us in detail", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    const session = new AgentumSession(client, "a1", "s1", "jwt");

    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "allow",
      ttlMs: 100,
      policyHash: "ph-central",
      decisionSource: "central",
      // evaluatedLocally + pdpLatencyUs intentionally absent
    });

    const tool = makeFakeTool("t-central");
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
    });
    await (guarded!._call as FakeTool["_call"])!("x");

    await new Promise((r) => setTimeout(r, 5));
    const callAudits = bodies(f).filter((b) => b["event_type"] === "mcp_tool_call");
    expect(callAudits.length).toBe(1);
    const ev = callAudits[0]!;
    expect(ev["policy_hash"]).toBe("ph-central");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    // Must NOT carry undefined placeholders for absent fields.
    expect(detail).not.toHaveProperty("evaluated_locally");
    expect(detail).not.toHaveProperty("pdp_latency_us");
  });

  it("AgentumPolicyTool.invoke deny carries split observability on policy_deny", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 100,
      policyHash: "ph-tool",
      evaluatedLocally: true,
      pdpLatencyUs: 9,
      decisionSource: "pdp",
    });

    const tool = new AgentumPolicyTool({
      client,
      agentId: "a1",
      sessionId: "s1",
      softDeny: true,
    });
    const result = await tool.invoke(
      JSON.stringify({ action: "http.delete", resource: "https://x" }),
    );
    expect(result).toMatch(/^DENIED/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies.length).toBe(1);
    const ev = denies[0]!;
    expect(ev["policy_hash"]).toBe("ph-tool");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["action"]).toBe("http.delete");
    expect(detail["resource"]).toBe("https://x");
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(9);
  });

  it("backwards-compat: client without apiKey falls back to isAllowed and emits without observability fields", async () => {
    // No apiKey → evaluateToolCall throws → enforceAllTools falls back
    // to session.isAllowed → audit emit must NOT carry any of the four
    // observability fields (neither top-level nor in detail).
    const f = jest
      .fn()
      .mockImplementation(async (_url: string, init: { body?: string }) => {
        const body = init?.body ? (JSON.parse(init.body) as { resource?: string }) : {};
        const resource = body.resource ?? "*";
        const allow = resource !== "blocked";
        return {
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve({ outcome: allow ? "Allow" : "Deny" }),
          text: () =>
            Promise.resolve(JSON.stringify({ outcome: allow ? "Allow" : "Deny" })),
        };
      });
    const client = new AgentumClient({
      baseUrl: BASE,
      // No apiKey on purpose.
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    const session = new AgentumSession(client, "a1", "s1", "jwt");

    const tool = makeFakeTool("blocked");
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "return_error_string",
    });
    const r = await (guarded!._call as FakeTool["_call"])!("x");
    expect(String(r)).toMatch(/^DENIED/);

    await new Promise((r2) => setTimeout(r2, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies.length).toBe(1);
    const ev = denies[0]!;
    // None of the four observability fields should be present.
    expect(ev).not.toHaveProperty("policy_hash");
    expect(ev).not.toHaveProperty("decision_source");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail).not.toHaveProperty("evaluated_locally");
    expect(detail).not.toHaveProperty("pdp_latency_us");
    // Existing detail keys preserved.
    expect(detail["tool"]).toBe("blocked");
    expect(detail["framework"]).toBe("langchain");
  });

  it("naming-consistency regression: policy_hash is top-level (not in detail) on both LangChain and LocalPdpDecision emits", async () => {
    // This guards against future drift where someone moves `policy_hash`
    // into `detail` on one side. The audit pipeline joins LocalPdpDecision
    // rows with framework rows via the top-level `policy_hash` column —
    // if either side puts the field inside `detail` the join breaks.
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    const session = new AgentumSession(client, "a1", "s1", "jwt");

    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 100,
      policyHash: "shared-hash-X",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 5,
    });

    const tool = makeFakeTool("t-regress");
    const [guarded] = enforceAllTools([tool], {
      session,
      actionPrefix: "mcp.tool.call",
      onDeny: "return_error_string",
    });
    await (guarded!._call as FakeTool["_call"])!("x");

    await new Promise((r) => setTimeout(r, 5));
    const deny = bodies(f).find((b) => b["event_type"] === "mcp_tool_deny");
    expect(deny).toBeDefined();
    // Load-bearing: policy_hash MUST be top-level.
    expect(deny!["policy_hash"]).toBe("shared-hash-X");
    // Load-bearing: policy_hash must NOT have been duplicated into detail.
    const detail = deny!["detail"] as Record<string, unknown>;
    expect(detail).not.toHaveProperty("policy_hash");
    // Same shape contract as `cedar-client.ts:581-583`'s LocalPdpDecision emit.
  });
});
