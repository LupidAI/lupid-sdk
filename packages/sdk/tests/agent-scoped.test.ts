/**
 * Unit tests for AgentumAgentAdminClient (Sprint 1.3.3).
 *
 * Mirrors the mock-fetch pattern used by `client.test.ts` and
 * `admin.test.ts`. No live server required.
 */

import {
  AgentumAgentAdminClient,
  AgentumError,
  AgentumScopeMismatchError,
  type WhoAmIResponse,
} from "../src/index";

const BASE = "http://localhost:7071";
const AGENT_ID = "agent-uuid-abc";

/**
 * Build a mock fetch that returns the supplied responses in order. The
 * last response is reused once the queue is exhausted (matches the
 * `admin.test.ts` helper behaviour).
 */
function mockSequenceFetch(
  responses: Array<{ body: unknown; status?: number }>,
): jest.Mock {
  let i = 0;
  return jest.fn().mockImplementation(() => {
    const r = responses[i++] ?? responses[responses.length - 1];
    const status = r?.status ?? 200;
    return Promise.resolve({
      ok: status < 400,
      status,
      headers: { get: () => "application/json" },
      json: () => Promise.resolve(r?.body),
      text: () => Promise.resolve(JSON.stringify(r?.body)),
    });
  });
}

function whoamiResp(agentScope: string | null): WhoAmIResponse {
  return {
    email: "alice@example.com",
    role: "admin",
    tenant_id: "t-1",
    agent_scope: agentScope,
    scope_features: null,
    expires_at: null,
  };
}

describe("AgentumAgentAdminClient", () => {
  describe("constructor", () => {
    it("rejects empty agentId", () => {
      expect(
        () =>
          new AgentumAgentAdminClient({
            baseUrl: BASE,
            apiKey: "ak",
            agentId: "",
          }),
      ).toThrow(AgentumError);
    });

    it("constructs when agentId is provided", () => {
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
      });
      expect(c).toBeInstanceOf(AgentumAgentAdminClient);
      expect(c.agentId).toBe(AGENT_ID);
    });

    it("close() resolves (no-op)", async () => {
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
      });
      await expect(c.close()).resolves.toBeUndefined();
    });
  });

  describe("verify()", () => {
    it("passes when /whoami returns matching agent_scope", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(AGENT_ID) }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.verify()).resolves.toBeUndefined();
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/whoami`);
    });

    it("throws AgentumScopeMismatchError when agent_scope differs", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp("some-other-agent") }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.verify()).rejects.toBeInstanceOf(AgentumScopeMismatchError);
    });

    it("throws AgentumScopeMismatchError when key is unscoped (null)", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(null) }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      try {
        await c.verify();
        fail("expected AgentumScopeMismatchError");
      } catch (err) {
        expect(err).toBeInstanceOf(AgentumScopeMismatchError);
        const scopeErr = err as AgentumScopeMismatchError;
        expect(scopeErr.expected).toBe(AGENT_ID);
        expect(scopeErr.actual).toBeNull();
      }
    });

    it("memoises the /whoami round-trip on success", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(AGENT_ID) }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.verify();
      await c.verify();
      await c.verify();
      const whoamiCalls = f.mock.calls.filter((call) =>
        String((call as unknown[])[0]).endsWith("/whoami"),
      );
      expect(whoamiCalls).toHaveLength(1);
    });

    it("allows retry after a transient verify failure", async () => {
      // First /whoami errors, second succeeds. Note: retries is 0 on the
      // client so the first error surfaces immediately rather than being
      // retried internally — the SDK must not cache the failed promise.
      const f = mockSequenceFetch([
        { body: { error: "kaboom" }, status: 500 },
        { body: whoamiResp(AGENT_ID) },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.verify()).rejects.toThrow(AgentumError);
      await expect(c.verify()).resolves.toBeUndefined();
    });
  });

  describe("create() static factory", () => {
    it("returns a verified client on match", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(AGENT_ID) }]);
      const c = await AgentumAgentAdminClient.create({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      expect(c).toBeInstanceOf(AgentumAgentAdminClient);
    });

    it("rejects on scope mismatch", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp("wrong") }]);
      await expect(
        AgentumAgentAdminClient.create({
          baseUrl: BASE,
          apiKey: "ak",
          agentId: AGENT_ID,
          fetch: f as unknown as typeof fetch,
          retries: 0,
        }),
      ).rejects.toBeInstanceOf(AgentumScopeMismatchError);
    });
  });

  describe("policies (scope-locked)", () => {
    it("put() targets /policies/:agentId with pinned agentId", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        { body: { written: true } },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.policies.put("permit(principal, action, resource);");
      const putCall = f.mock.calls[1] as unknown[];
      expect(putCall[0]).toBe(`${BASE}/api/v1/policies/${AGENT_ID}`);
      const init = putCall[1] as { method: string; body: string };
      expect(init.method).toBe("PUT");
      expect(JSON.parse(init.body)).toEqual({
        policy: "permit(principal, action, resource);",
      });
    });

    it("get() maps server {policy,note?} → {source,note?}", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        {
          body: {
            agent_id: AGENT_ID,
            policy: null,
            note: "No policy file found for this agent",
          },
        },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await c.policies.get();
      expect(rec.source).toBeNull();
      expect(rec.note).toBe("No policy file found for this agent");
    });

    it("delete() throws 'not implemented' after passing scope check", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(AGENT_ID) }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.policies.delete()).rejects.toThrow(/not implemented/i);
    });

    it("applyDeclarative() throws placeholder error until Sprint 1.4", async () => {
      const f = mockSequenceFetch([{ body: whoamiResp(AGENT_ID) }]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.policies.applyDeclarative({ rules: [] })).rejects.toThrow(
        /Sprint 1\.4/,
      );
    });

    it("scope-sensitive methods fail fast if verify fails", async () => {
      // The put() call should never be issued — verify() throws first.
      const f = mockSequenceFetch([
        { body: whoamiResp("wrong-agent") },
        { body: { written: true } },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(c.policies.put("permit(...);")).rejects.toBeInstanceOf(
        AgentumScopeMismatchError,
      );
      // Exactly one fetch call — the /whoami check, not the put.
      expect(f).toHaveBeenCalledTimes(1);
    });
  });

  describe("mcp (scope-locked)", () => {
    it("grantAccess() binds the agentId from the client config", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        {
          body: {
            server_id: "stripe-mcp",
            agent_id: AGENT_ID,
            allowed_tools: ["charge"],
            created_at: "2026-01-01T00:00:00Z",
          },
        },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.mcp.grantAccess("stripe-mcp", ["charge"]);
      const grantCall = f.mock.calls[1] as unknown[];
      expect(grantCall[0]).toBe(`${BASE}/api/v1/mcp/servers/stripe-mcp/access`);
      const init = grantCall[1] as { method: string; body: string };
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({
        agent_id: AGENT_ID,
        allowed_tools: ["charge"],
      });
    });

    it("revokeAccess() targets /mcp/servers/:id/access/:agentId", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        { body: {} },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.mcp.revokeAccess("stripe-mcp");
      const call = f.mock.calls[1] as unknown[];
      expect(call[0]).toBe(`${BASE}/api/v1/mcp/servers/stripe-mcp/access/${AGENT_ID}`);
      expect((call[1] as { method: string }).method).toBe("DELETE");
    });
  });

  describe("audit (scope-filtered)", () => {
    it("list() sends agent_id query param pinned to config.agentId", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        { body: { events: [], total: 0, page_count: 0, limit: 100, offset: 0 } },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.audit.list({ limit: 50 });
      const auditCall = f.mock.calls[1] as unknown[];
      const url = auditCall[0] as string;
      expect(url).toContain(`${BASE}/api/v1/audit`);
      expect(url).toContain(`agent_id=${AGENT_ID}`);
      expect(url).toContain("limit=50");
    });

    it("search() adds an event_type filter", async () => {
      const f = mockSequenceFetch([
        { body: whoamiResp(AGENT_ID) },
        {
          body: {
            events: [{ event_id: "e1", event_type: "PolicyDenied", ts: "2026-01-01", agent_id: AGENT_ID, session_id: null, actor: null, tool: null, resource: null, outcome: "deny", risk_score: 0 }],
            total: 1,
            page_count: 1,
            limit: 100,
            offset: 0,
          },
        },
      ]);
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rows = await c.audit.search("PolicyDenied");
      expect(rows).toHaveLength(1);
      const url = (f.mock.calls[1] as unknown[])[0] as string;
      expect(url).toContain("event_type=PolicyDenied");
      expect(url).toContain(`agent_id=${AGENT_ID}`);
    });
  });

  describe("type-surface expectations", () => {
    it("does not expose tenant-wide admin verbs", () => {
      const c = new AgentumAgentAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        agentId: AGENT_ID,
      });
      // Structural runtime check that mirrors the TS type surface: the
      // agent-scoped client must NOT carry `agents`/`apiKeys` sub-APIs,
      // and its `mcp` surface must NOT carry registerServer.
      expect((c as unknown as { agents?: unknown }).agents).toBeUndefined();
      expect((c as unknown as { apiKeys?: unknown }).apiKeys).toBeUndefined();
      expect(
        (c.mcp as unknown as { registerServer?: unknown }).registerServer,
      ).toBeUndefined();
    });
  });
});
