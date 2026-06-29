/**
 * Vercel AI adapter streaming tests — verifies afterGenerate fires only
 * after the consumer has finished iterating the returned stream (Bug A).
 */

import { AgentumClient } from "../../src/index";
import { createAgentumMiddleware, agentumTool } from "../../src/frameworks/vercel-ai";

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

function eventTypes(f: jest.Mock): string[] {
  return f.mock.calls
    .filter((c) => (c[1] as { body?: string } | undefined)?.body)
    .map((c) => JSON.parse((c[1] as { body: string }).body)["event_type"] as string);
}

describe("Vercel AI middleware — doStream relays (Bug A)", () => {
  it("defers afterGenerate until the consumer finishes iterating", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const chunks = [
      { type: "text-delta", textDelta: "he" },
      { type: "tool-call", toolCallId: "tc1", toolName: "web_search", args: { q: "x" } },
      { type: "finish", finishReason: "stop", usage: { promptTokens: 3, completionTokens: 7 } },
    ];

    const stream: AsyncIterable<Record<string, unknown>> = {
      async *[Symbol.asyncIterator]() {
        for (const c of chunks) yield c;
      },
    };

    const model = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream }),
    };

    const wrapped = mw.wrapLanguageModel(model);
    const result = await (wrapped as typeof model).doStream({});

    // Pre-iteration: only llm_start should have fired.
    await new Promise((r) => setTimeout(r, 5));
    // Sprint B P1-4: was "llm_start" (Unknown server-side); canonical is
    // "llm_call" with detail.phase === "start".
    expect(eventTypes(f)).toEqual(["llm_call"]);

    // Drive the iterator manually — step-by-step — to prove afterGenerate
    // does not fire until the upstream signals done.
    const inner = (result as { stream: AsyncIterable<Record<string, unknown>> }).stream;
    const it = inner[Symbol.asyncIterator]();

    const s1 = await it.next();
    expect(s1.done).toBe(false);
    await new Promise((r) => setTimeout(r, 5));
    // Sprint B P1-4: was "llm_start" (Unknown server-side); canonical is
    // "llm_call" with detail.phase === "start".
    expect(eventTypes(f)).toEqual(["llm_call"]);

    const s2 = await it.next();
    expect(s2.done).toBe(false);
    await new Promise((r) => setTimeout(r, 5));
    // Sprint B P1-4: was "llm_start" (Unknown server-side); canonical is
    // "llm_call" with detail.phase === "start".
    expect(eventTypes(f)).toEqual(["llm_call"]);

    const s3 = await it.next();
    expect(s3.done).toBe(false);

    const s4 = await it.next();
    expect(s4.done).toBe(true);

    // After done: tool_call and llm_end should be present.
    await new Promise((r) => setTimeout(r, 5));
    const types = eventTypes(f);
    expect(types).toContain("tool_call");
    expect(types).toContain("llm_end");
  });

  it("emits llm_stream_error when the upstream iterator throws", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const stream: AsyncIterable<Record<string, unknown>> = {
      async *[Symbol.asyncIterator]() {
        yield { type: "text-delta", textDelta: "a" };
        yield { type: "text-delta", textDelta: "b" };
        yield { type: "text-delta", textDelta: "c" };
        throw new Error("boom");
      },
    };

    const model = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream }),
    };
    const wrapped = mw.wrapLanguageModel(model);
    const result = await (wrapped as typeof model).doStream({});
    const inner = (result as { stream: AsyncIterable<Record<string, unknown>> }).stream;

    await expect((async () => {
      for await (const _ of inner) { void _; }
    })()).rejects.toThrow("boom");

    await new Promise((r) => setTimeout(r, 5));
    const types = eventTypes(f);
    // Sprint B P1-4: was "llm_stream_error" (Unknown); canonical is
    // "llm_error" with detail.streaming === true distinguishing from
    // non-streaming errors.
    expect(types).toContain("llm_error");
    expect(types).not.toContain("llm_end");
  });
});

// ── L05b — PDP observability threading ─────────────────────────────────────

describe("L05b — Vercel AI PDP observability threading into audit", () => {
  function bodies(f: jest.Mock): Array<Record<string, unknown>> {
    return f.mock.calls
      .filter((c) => (c[1] as { body?: string } | undefined)?.body)
      .map((c) => JSON.parse((c[1] as { body: string }).body));
  }

  function makeClientWithKey(f: jest.Mock): AgentumClient {
    return new AgentumClient({
      baseUrl: BASE,
      apiKey: "test-api-key",
      fetch: f as unknown as typeof fetch,
      disableAuditBuffer: true,
    });
  }

  it("beforeGenerate deny threads top-level policy_hash + decision_source and detail observability", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-vai-1",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 22,
      ruleId: "rule-vai",
    });
    const mw = createAgentumMiddleware({
      client,
      agentId: "a1",
      sessionId: "s1",
      policyAction: "llm.call",
      policyResource: "model:gpt-4o",
    });
    const model = {
      doGenerate: jest.fn(),
    };
    const wrapped = mw.wrapLanguageModel(model);

    await expect((wrapped as typeof model).doGenerate({})).rejects.toThrow(
      /PermissionError/,
    );
    expect(model.doGenerate).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["policy_hash"]).toBe("ph-vai-1");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(22);
    expect(detail["rule_id"]).toBe("rule-vai");
    expect(detail["framework"]).toBe("vercel-ai");
  });

  it("auditToolCall allow + deny both carry split observability fields", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    const spy = jest
      .spyOn(client, "evaluateToolCall")
      .mockResolvedValueOnce({
        decision: "allow",
        ttlMs: 100,
        policyHash: "ph-allow",
        decisionSource: "pdp",
        evaluatedLocally: true,
        pdpLatencyUs: 8,
      })
      .mockResolvedValueOnce({
        decision: "deny",
        ttlMs: 100,
        policyHash: "ph-deny",
        decisionSource: "pdp",
        evaluatedLocally: true,
        pdpLatencyUs: 13,
      });

    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });
    await mw.auditToolCall("web_search", "https://x", "tool:web_search");
    await expect(
      mw.auditToolCall("delete_file", "/etc/passwd", "tool:delete"),
    ).rejects.toThrow(/PermissionError/);

    expect(spy).toHaveBeenCalledTimes(2);
    await new Promise((r) => setTimeout(r, 5));

    const allows = bodies(f).filter((b) => b["event_type"] === "tool_call");
    expect(allows).toHaveLength(1);
    const allow = allows[0]!;
    expect(allow["policy_hash"]).toBe("ph-allow");
    expect(allow["decision_source"]).toBe("inproc");
    const allowDetail = allow["detail"] as Record<string, unknown>;
    expect(allowDetail["evaluated_locally"]).toBe(true);
    expect(allowDetail["pdp_latency_us"]).toBe(8);
    expect(allowDetail["framework"]).toBe("vercel-ai");

    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies).toHaveLength(1);
    const deny = denies[0]!;
    expect(deny["policy_hash"]).toBe("ph-deny");
    expect(deny["decision_source"]).toBe("inproc");
    const denyDetail = deny["detail"] as Record<string, unknown>;
    expect(denyDetail["evaluated_locally"]).toBe(true);
    expect(denyDetail["pdp_latency_us"]).toBe(13);
    expect(denyDetail["framework"]).toBe("vercel-ai");
  });

  it("agentumTool deny carries session_id from options + observability fields", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-agentumtool",
      decisionSource: "pdp",
      evaluatedLocally: true,
      pdpLatencyUs: 5,
    });

    const exec = jest.fn();
    const guarded = agentumTool({
      client,
      agentId: "a1",
      sessionId: "session-X",
      action: "tool:web_search",
      execute: exec as (args: { q: string }) => Promise<string>,
    });

    await expect(guarded({ q: "agentum" })).rejects.toThrow(/PermissionError/);
    expect(exec).not.toHaveBeenCalled();

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["session_id"]).toBe("session-X");
    expect(ev["policy_hash"]).toBe("ph-agentumtool");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail["framework"]).toBe("vercel-ai.agentumTool");
    expect(detail["evaluated_locally"]).toBe(true);
    expect(detail["pdp_latency_us"]).toBe(5);
  });

  it("agentumTool without sessionId option falls back to empty string (backwards compat)", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      decisionSource: "pdp",
    });
    const guarded = agentumTool({
      client,
      agentId: "a1",
      action: "tool:t",
      execute: (async () => "noop") as (args: Record<string, unknown>) => Promise<string>,
    });
    await expect(guarded({})).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies).toHaveLength(1);
    expect(denies[0]!["session_id"]).toBe("");
  });

  it("partial observability (central, no evaluatedLocally/pdpLatencyUs) emits no undefined keys", async () => {
    const f = mockFetch({});
    const client = makeClientWithKey(f);
    jest.spyOn(client, "evaluateToolCall").mockResolvedValue({
      decision: "deny",
      ttlMs: 0,
      policyHash: "ph-central-vai",
      decisionSource: "central",
    });
    const guarded = agentumTool({
      client,
      agentId: "a1",
      sessionId: "s1",
      action: "tool:t",
      execute: (async () => "noop") as (args: Record<string, unknown>) => Promise<string>,
    });
    await expect(guarded({})).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies).toHaveLength(1);
    const ev = denies[0]!;
    expect(ev["policy_hash"]).toBe("ph-central-vai");
    expect(ev["decision_source"]).toBe("inproc");
    const detail = ev["detail"] as Record<string, unknown>;
    expect(detail).not.toHaveProperty("evaluated_locally");
    expect(detail).not.toHaveProperty("pdp_latency_us");
  });

  it("apiKey-missing fallback uses isAllowed, emits without observability fields", async () => {
    // No apiKey → evaluateToolCall throws → fall back to isAllowed →
    // deny emit MUST NOT carry the four observability fields.
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
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    const guarded = agentumTool({
      client,
      agentId: "a1",
      sessionId: "s1",
      action: "tool:web_search",
      execute: (async () => "x") as (args: Record<string, unknown>) => Promise<string>,
    });
    await expect(guarded({})).rejects.toThrow(/PermissionError/);

    await new Promise((r) => setTimeout(r, 5));
    const denies = bodies(f).filter((b) => b["event_type"] === "mcp_tool_deny");
    expect(denies.length).toBeGreaterThanOrEqual(1);
    for (const ev of denies) {
      expect(ev).not.toHaveProperty("policy_hash");
      expect(ev).not.toHaveProperty("decision_source");
      const detail = ev["detail"] as Record<string, unknown>;
      expect(detail).not.toHaveProperty("evaluated_locally");
      expect(detail).not.toHaveProperty("pdp_latency_us");
    }

    // One-shot warner — at most one [agentum/vercel-ai] line in this process.
    const vaiWarnCalls = warnSpy.mock.calls.filter((c) =>
      String(c[0] ?? "").includes("[agentum/vercel-ai]"),
    );
    expect(vaiWarnCalls.length).toBeLessThanOrEqual(1);
    warnSpy.mockRestore();
  });
});
