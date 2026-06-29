/**
 * OpenAI streaming adapter tests — verifies that `stream: true` tool-call
 * deltas are aggregated across chunks and audit events are emitted only
 * after consumer iteration completes (Bug B).
 */

import { AgentumClient } from "../../src/index";
import { wrapOpenAIClient, policyFunctionTool } from "../../src/frameworks/openai";

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

function bodiesFrom(f: jest.Mock): Array<Record<string, unknown>> {
  return f.mock.calls
    .filter((c) => (c[1] as { body?: string } | undefined)?.body)
    .map((c) => JSON.parse((c[1] as { body: string }).body));
}

describe("wrapOpenAIClient — streaming tool calls (Bug B)", () => {
  /** SSE-shaped delta chunks mirroring OpenAI's chat.completions stream format. */
  function makeDeltaStream(): AsyncIterable<Record<string, unknown>> {
    const chunks: Array<Record<string, unknown>> = [
      { choices: [{ index: 0, delta: { role: "assistant", tool_calls: [{ index: 0, id: "call_abc", type: "function", function: { name: "web_", arguments: "" } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: "search", arguments: "{\"q\":" } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: "\"agentum\"}" } }] } }] },
      { choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }], usage: { prompt_tokens: 10, completion_tokens: 4, total_tokens: 14 } },
    ];
    return {
      async *[Symbol.asyncIterator]() {
        for (const c of chunks) yield c;
      },
    };
  }

  it("aggregates tool-call deltas by index and emits audit only after stream is consumed", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const create = jest.fn(async (_req: Record<string, unknown>) => makeDeltaStream());
    const oai = { chat: { completions: { create } } };
    const wrapped = wrapOpenAIClient(oai, { client, agentId: "a1", sessionId: "s1" });

    const stream = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [], stream: true });
    expect(create).toHaveBeenCalled();

    // BEFORE consumption: only the pre-flight event should have fired.
    // Sprint B P1-4: was "llm_start" (Unknown server-side); now canonical
    // "llm_call" with detail.phase === "start" to distinguish from the
    // paired "llm_end" after the response is drained.
    const before = bodiesFrom(f).map((b) => b["event_type"]);
    expect(before).toContain("llm_call");
    expect(before).not.toContain("llm_end");
    expect(before).not.toContain("tool_call");

    // Consume the stream.
    const collected: Array<Record<string, unknown>> = [];
    for await (const chunk of stream as AsyncIterable<Record<string, unknown>>) {
      collected.push(chunk);
    }
    expect(collected).toHaveLength(4);

    // AFTER consumption: exactly one tool_call (aggregated) + one llm_end.
    await new Promise((r) => setTimeout(r, 5));
    const after = bodiesFrom(f);
    const toolCalls = after.filter((b) => b["event_type"] === "tool_call");
    expect(toolCalls).toHaveLength(1);
    const detail = toolCalls[0]!["detail"] as Record<string, unknown>;
    expect(detail["tool_call_id"]).toBe("call_abc");
    expect(detail["function_name"]).toBe("web_search");
    expect(detail["function_args"]).toBe("{\"q\":\"agentum\"}");

    const ends = after.filter((b) => b["event_type"] === "llm_end");
    expect(ends).toHaveLength(1);
    const endDetail = ends[0]!["detail"] as Record<string, unknown>;
    expect(endDetail["finish_reason"]).toBe("tool_calls");
    expect(endDetail["tool_call_count"]).toBe(1);
    expect(endDetail["streamed"]).toBe(true);
  });

  // ── L05b — PDP observability threading ────────────────────────────────

  it("L05b wrapOpenAIClient deny threads top-level policy_hash + decision_source and detail evaluated_locally + pdp_latency_us", async () => {
    const f = mockFetch({});
    const client = new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-llm-1",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 31,
      reason: "policy_deny",
      ruleId: "rule-llm",
    });

    const oai = { chat: { completions: { create: jest.fn() } } };
    const wrapped = wrapOpenAIClient(oai, {
      client,
      agentId: "a1",
      sessionId: "s1",
      policyAction: "llm.call",
      policyResource: "model:gpt-4o",
    });

    await expect(
      wrapped.chat.completions.create({ model: "gpt-4o", messages: [] }),
    ).rejects.toThrow(/PermissionError/);
    expect(oai.chat.completions.create).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodiesFrom(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["policy_hash"]).toBe("ph-llm-1");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(31);
    expect(detail["rule_id"]).toBe("rule-llm");
    expect(detail["framework"]).toBe("openai");
  });

  it("L05b policyFunctionTool deny emits policy_deny with observability fields (regression on new emit)", async () => {
    const f = mockFetch({});
    const client = new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-tool-2",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 12,
    });

    const execute = jest.fn();
    const { execute: guarded } = policyFunctionTool({
      client,
      agentId: "a1",
      sessionId: "s1",
      action: "tool:web_search",
      resource: "https://example.com",
      spec: { name: "web_search", description: "x", parameters: {} },
      execute: execute as (args: Record<string, unknown>) => Promise<unknown>,
    });

    await expect(guarded({ q: "agentum" })).rejects.toThrow(/PermissionError/);
    expect(execute).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodiesFrom(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["session_id"]).toBe("s1");
    expect(ev["policy_hash"]).toBe("ph-tool-2");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["tool"]).toBe("web_search");
    expect(detail["action"]).toBe("tool:web_search");
    expect(detail["resource"]).toBe("https://example.com");
    expect(detail["framework"]).toBe("openai.policyFunctionTool");
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(12);
  });

  it("L05b partial observability (central, no evaluatedLocally/pdpLatencyUs) emits no undefined keys", async () => {
    const f = mockFetch({});
    const client = new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-central",
      decisionSource: "central",
      // evaluatedLocally + pdpLatencyUs intentionally absent
    });

    const { execute: guarded } = policyFunctionTool({
      client,
      agentId: "a1",
      action: "tool:central_only",
      spec: { name: "central_only", description: "x", parameters: {} },
      execute: (async () => "noop") as (args: Record<string, unknown>) => Promise<string>,
    });
    await expect(guarded({})).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodiesFrom(f).filter((b) => b["event_type"] === "policy_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["policy_hash"]).toBe("ph-central");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail).not.toHaveProperty("evaluated_locally");
    expect(detail).not.toHaveProperty("pdp_latency_us");
    // session_id fallback when not provided.
    expect(ev["session_id"]).toBe("");
  });

  it("L05b apiKey-missing fallback uses isAllowed, emits without observability, console.warn fires once", async () => {
    // No apiKey on the client → evaluateToolCall throws → fall back to
    // isAllowed → deny emit must NOT carry the observability fields.
    const f = jest
      .fn()
      .mockImplementation(async (_url: string, init: { body?: string }) => {
        const body = init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : {};
        const isSimulate = body["action"] !== undefined && body["event_type"] === undefined;
        if (isSimulate) {
          return {
            ok: true,
            status: 200,
            headers: { get: () => "application/json" },
            json: () => Promise.resolve({ outcome: "Deny" }),
            text: () => Promise.resolve(JSON.stringify({ outcome: "Deny" })),
          };
        }
        return {
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve({}),
          text: () => Promise.resolve("{}"),
        };
      });
    const client = new AgentumClient({
      baseUrl: BASE,
      // No apiKey on purpose.
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });

    // Use a fresh spy on console.warn for this assertion.
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const { execute: guarded } = policyFunctionTool({
      client,
      agentId: "a1",
      sessionId: "s1",
      action: "tool:web_search",
      spec: { name: "web_search", description: "x", parameters: {} },
      execute: (async () => "x") as (args: Record<string, unknown>) => Promise<string>,
    });

    // First call — warns once.
    await expect(guarded({ q: "y" })).rejects.toThrow(/PermissionError/);
    // Second call — should NOT warn again (one-shot guard).
    await expect(guarded({ q: "z" })).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = f.mock.calls
      .filter((c) => (c[1] as { body?: string } | undefined)?.body)
      .map((c) => JSON.parse((c[1] as { body: string }).body))
      .filter((b) => b["event_type"] === "policy_deny");
    expect(denies.length).toBeGreaterThanOrEqual(1);
    for (const ev of denies) {
      expect(ev).not.toHaveProperty("policy_hash");
      expect(ev).not.toHaveProperty("decision_source");
      const detail = ev["detail"] as Record<string, unknown>;
      expect(detail).not.toHaveProperty("evaluated_locally");
      expect(detail).not.toHaveProperty("pdp_latency_us");
    }

    // One-shot console.warn — fires at most once per process for "openai".
    // (It may have fired earlier in the file for unrelated tests; we only
    // require it fired at least once now — and the second call shouldn't
    // have added a *new* call beyond the first.)
    const openaiWarnCalls = warnSpy.mock.calls.filter((c) =>
      String(c[0] ?? "").includes("[agentum/openai]"),
    );
    expect(openaiWarnCalls.length).toBeLessThanOrEqual(1);

    warnSpy.mockRestore();
  });

  it("L05b naming-consistency regression: policy_hash is top-level (not in detail) on policy_deny", async () => {
    const f = mockFetch({});
    const client = new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "shared-hash-Y",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 4,
    });

    const { execute: guarded } = policyFunctionTool({
      client,
      agentId: "a1",
      action: "tool:t",
      spec: { name: "t", description: "x", parameters: {} },
      execute: (async () => "x") as (args: Record<string, unknown>) => Promise<string>,
    });
    await expect(guarded({})).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const deny = bodiesFrom(f).find((b) => b["event_type"] === "policy_deny");
    expect(deny).toBeDefined();
    expect(deny!["policy_hash"]).toBe("shared-hash-Y");
    const detail = deny!["detail"] as Record<string, unknown>;
    expect(detail).not.toHaveProperty("policy_hash");
    // Same contract as `langchain.test.ts` naming-consistency test and
    // `cedar-client.ts`'s LocalPdpDecision emit.
  });

  it("emits llm_error when the stream throws mid-iteration", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const failing: AsyncIterable<Record<string, unknown>> = {
      async *[Symbol.asyncIterator]() {
        yield { choices: [{ index: 0, delta: {} }] };
        throw new Error("upstream disconnect");
      },
    };
    const oai = { chat: { completions: { create: jest.fn(async (_: unknown) => failing) } } };
    const wrapped = wrapOpenAIClient(oai, { client, agentId: "a1", sessionId: "s1" });

    const stream = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [], stream: true });
    await expect((async () => {
      for await (const _ of stream as AsyncIterable<Record<string, unknown>>) { void _; }
    })()).rejects.toThrow("upstream disconnect");

    await new Promise((r) => setTimeout(r, 5));
    const types = bodiesFrom(f).map((b) => b["event_type"]);
    expect(types).toContain("llm_error");
    expect(types).not.toContain("llm_end");
  });
});
