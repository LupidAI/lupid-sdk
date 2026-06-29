/**
 * Unit tests for AgentumClient.
 * Uses a mock fetch so no live server is required.
 */

import { AgentumClient, AgentumSession, AgentumError, AgentumNotFoundError, AgentumPermissionError, AgentumAuthError } from "../src/index";

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

function mockNoContentFetch(status = 204): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: { get: () => "" },
    json: () => Promise.reject(new Error("no body")),
    text: () => Promise.resolve(""),
  });
}

describe("AgentumClient", () => {
  describe("constructor", () => {
    it("accepts a plain URL string", () => {
      const c = new AgentumClient(BASE);
      expect(c.getToken()).toBeNull();
    });

    it("strips trailing slash from baseUrl", () => {
      const f = mockFetch({ status: "ok" });
      const c = new AgentumClient({ baseUrl: `${BASE}/`, fetch: f as unknown as typeof fetch });
      void c.health();
      expect((f.mock.calls[0] as unknown[])[0]).toBe(`${BASE}/health`);
    });

    it("accepts config object with token", () => {
      const c = new AgentumClient({ baseUrl: BASE, token: "my-jwt" });
      expect(c.getToken()).toBe("my-jwt");
    });

    it("injects X-Tenant-ID header when tenantId is set", async () => {
      const f = mockFetch({ agent_id: "a1" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, tenantId: "tid-abc" });
      await c.getAgent("a1");
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["X-Tenant-ID"]).toBe("tid-abc");
    });

    it("does not inject X-Tenant-ID when tenantId is omitted", async () => {
      const f = mockFetch({ agent_id: "a1" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.getAgent("a1");
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["X-Tenant-ID"]).toBeUndefined();
    });
  });

  describe("setToken / clearToken", () => {
    it("setToken attaches Authorization header on next request", async () => {
      const f = mockFetch({ agent_id: "a1" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      c.setToken("tok-123");
      await c.getAgent("a1");
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["Authorization"]).toBe("Bearer tok-123");
    });

    it("clearToken removes Authorization header", async () => {
      const f = mockFetch({ agents: [] });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      c.setToken("tok").clearToken();
      await c.listAgents();
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["Authorization"]).toBeUndefined();
    });
  });

  describe("health()", () => {
    it("calls /health and returns payload", async () => {
      const f = mockFetch({ status: "ok" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const h = await c.health();
      expect(h.status).toBe("ok");
      expect((f.mock.calls[0] as unknown[])[0]).toBe(`${BASE}/health`);
    });

    it("respects configured timeout", async () => {
      jest.useFakeTimers();
      try {
        const f = jest.fn().mockImplementation((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        }));
        const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, timeoutMs: 10 });

        const pending = c.health();
        const expectation = expect(pending).rejects.toThrow("Request timed out after 10ms: GET http://localhost:7071/health");
        await jest.advanceTimersByTimeAsync(10);
        await expectation;
      } finally {
        jest.useRealTimers();
      }
    });
  });

  describe("registerAgent()", () => {
    // Sprint 1.3.1 deprecates this method. `console.warn` fires at most once
    // per process (module-scoped flag); since this describe holds the first
    // `registerAgent` call in the test file, we assert the warning here and
    // silence it for the remaining tests so Jest output stays clean.
    let warnSpy: jest.SpyInstance;
    beforeEach(() => {
      warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    });
    afterEach(() => {
      warnSpy.mockRestore();
    });

    it("posts to /api/v1/agents, returns registration data, and emits the deprecation warning", async () => {
      const payload = {
        agent_id: "a-uuid-1",
        name: "test-bot",
        status: "active",
        public_key_pem: "---PEM---",
        session_jwt: "jwt.tok.en",
      };
      const f = mockFetch(payload, 201);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.registerAgent({ name: "test-bot", owner_email: "o@test.com", purpose: "testing" });
      expect(result.agent_id).toBe("a-uuid-1");
      expect(result.session_jwt).toBe("jwt.tok.en");

      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/agents`);
      expect((init as { method: string }).method).toBe("POST");

      // Deprecation notice is the first message and points to the replacement.
      const firstWarn = warnSpy.mock.calls[0]?.[0];
      expect(String(firstWarn)).toContain("registerAgent() is deprecated");
      expect(String(firstWarn)).toContain("AgentumAdminClient.agents.register()");
    });

    it("does not re-warn on subsequent calls (one-shot per process)", async () => {
      const f = mockFetch({ agent_id: "b", session_jwt: "j" }, 201);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.registerAgent({ name: "x", owner_email: "o@e.com", purpose: "p" });
      // Flag is set by the earlier test; this spy should see no deprecation warning.
      const deprecationCalls = warnSpy.mock.calls.filter(([m]) =>
        typeof m === "string" && m.includes("registerAgent() is deprecated"),
      );
      expect(deprecationCalls).toHaveLength(0);
    });
  });

  describe("getAgent()", () => {
    it("calls /api/v1/agents/:id", async () => {
      const agent = { agent_id: "a1", name: "bot" };
      const f = mockFetch(agent);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getAgent("a1");
      expect(result.agent_id).toBe("a1");
      expect((f.mock.calls[0] as [string])[0]).toBe(`${BASE}/api/v1/agents/a1`);
    });

    it("includes tenant_id when present in response", async () => {
      const f = mockFetch({ agent_id: "a1", name: "bot", tenant_id: "tid-001" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getAgent("a1");
      expect(result.tenant_id).toBe("tid-001");
    });

    it("tenant_id is undefined when absent in response (backward compat)", async () => {
      const f = mockFetch({ agent_id: "a1", name: "bot" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getAgent("a1");
      expect(result.tenant_id).toBeUndefined();
    });
  });

  describe("listAgents()", () => {
    it("unwraps array result", async () => {
      const f = mockFetch([{ agent_id: "a1" }, { agent_id: "a2" }]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const list = await c.listAgents();
      expect(list).toHaveLength(2);
    });

    it("unwraps { agents: [...] } result", async () => {
      const f = mockFetch({ agents: [{ agent_id: "a1" }] });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const list = await c.listAgents();
      expect(list).toHaveLength(1);
    });

    it("passes query params", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.listAgents({ status: "active", limit: 10 });
      expect((f.mock.calls[0] as [string])[0]).toContain("status=active");
      expect((f.mock.calls[0] as [string])[0]).toContain("limit=10");
    });
  });

  describe("simulatePolicy()", () => {
    it("returns Allow outcome", async () => {
      const f = mockFetch({ outcome: "Allow", rule_id: "r1", reason: null });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.simulatePolicy({ agent_id: "a1", action: "http.get", resource: "https://api.example.com" });
      expect(result.outcome).toBe("Allow");
    });
  });

  describe("proposePolicy() / listPolicyProposals() / getPolicyProposal() / withdrawPolicyProposal() (Sprint 2.1.5)", () => {
    it("proposePolicy() POSTs to /policies/proposals and returns the created row", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        tenant_id: "t1",
        agent_id: "a1",
        proposed_by: "dev@example.com",
        proposed_at: "2026-04-19T12:00:00Z",
        status: "pending",
        author_mode: "declarative",
      });
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await c.proposePolicy({
        agent_id: "a1",
        declarative_spec: { agent_id: "a1", rules: [] },
        note: "first pass",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/proposals`);
      expect(init.method).toBe("POST");
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.agent_id).toBe("a1");
      expect(sent.declarative_spec).toEqual({ agent_id: "a1", rules: [] });
      expect(res.author_mode).toBe("declarative");
    });

    it("listPolicyProposals() forwards status + agent_id as query params", async () => {
      const f = mockFetch({ proposals: [], total: 0 });
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await c.listPolicyProposals({ status: "approved", agent_id: "a1" });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toContain("status=approved");
      expect(url).toContain("agent_id=a1");
    });

    it("getPolicyProposal() GETs /policies/proposals/:id", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        tenant_id: "t1",
        agent_id: "a1",
        proposed_by: "dev@example.com",
        proposed_at: "2026-04-19T12:00:00Z",
        status: "pending",
      });
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await c.getPolicyProposal("p1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1`);
      expect(rec.proposal_id).toBe("p1");
    });

    it("withdrawPolicyProposal() POSTs empty body to /withdraw", async () => {
      const f = mockFetch({ proposal_id: "p1", status: "withdrawn" });
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await c.withdrawPolicyProposal("p1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string; method: string };
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1/withdraw`);
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({});
      expect(res.status).toBe("withdrawn");
    });
  });

  describe("isAllowed()", () => {
    it("returns true when outcome is Allow", async () => {
      const f = mockFetch({ outcome: "Allow" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      expect(await c.isAllowed("a1", "http.get", "https://api.example.com")).toBe(true);
    });

    it("returns false when outcome is Deny", async () => {
      const f = mockFetch({ outcome: "Deny" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      expect(await c.isAllowed("a1", "http.delete", "https://api.example.com")).toBe(false);
    });
  });

  describe("startSession() / endSession()", () => {
    it("starts a session and returns session info", async () => {
      const sess = { session_id: "s-1", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.startSession("a1");
      expect(result.session_id).toBe("s-1");
    });

    it("startSession forwards trusted-mode user under `user` key", async () => {
      const sess = { session_id: "s-u", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.startSession("a1", { id: "u1", email: "u@corp.example", attributes: { role: "admin" } });
      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.agent_id).toBe("a1");
      expect(body.user).toEqual({ id: "u1", email: "u@corp.example", attributes: { role: "admin" } });
      expect(body.user_token).toBeUndefined();
    });

    it("startSession forwards verified-mode token under `user_token`", async () => {
      const sess = { session_id: "s-v", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.startSession("a1", { token: "eyJ.verified.jwt" });
      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.user_token).toBe("eyJ.verified.jwt");
      expect(body.user).toBeUndefined();
    });

    it("startSession omits user keys when no user is provided", async () => {
      const sess = { session_id: "s-n", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.startSession("a1");
      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.user).toBeUndefined();
      expect(body.user_token).toBeUndefined();
      expect(body.service).toBeUndefined();
    });

    it("startSession forwards service-mode under `service` (+ `service_source`)", async () => {
      const sess = { session_id: "s-svc", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.startSession("a1", { service: "github-webhook", source: "github.com/acme/repo" });
      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.service).toBe("github-webhook");
      expect(body.service_source).toBe("github.com/acme/repo");
      expect(body.user).toBeUndefined();
      expect(body.user_token).toBeUndefined();
    });

    it("startSession service-mode omits `service_source` when source not given", async () => {
      const sess = { session_id: "s-svc2", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.startSession("a1", { service: "cron-nightly" });
      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.service).toBe("cron-nightly");
      expect(body.service_source).toBeUndefined();
    });

    it("endSession does not throw on success", async () => {
      const f = mockFetch({});
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.endSession("s-1")).resolves.not.toThrow();
    });

    it("getSession fetches a single session by id", async () => {
      const sess = { session_id: "s-1", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getSession("s-1");
      expect(result.session_id).toBe("s-1");
      expect((f.mock.calls[0] as [string])[0]).toBe(`${BASE}/api/v1/sessions/s-1`);
    });

    it("includes tenant_id when present in session response", async () => {
      const sess = { session_id: "s-1", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z", tenant_id: "tid-002" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getSession("s-1");
      expect(result.tenant_id).toBe("tid-002");
    });

    it("tenant_id is undefined when absent in session response (backward compat)", async () => {
      const sess = { session_id: "s-1", agent_id: "a1", jwt: "jwt", started_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getSession("s-1");
      expect(result.tenant_id).toBeUndefined();
    });
  });

  describe("issueCredential()", () => {
    it("returns a credential lease", async () => {
      const lease = { lease_id: "l-1", agent_id: "a1", service_name: "stripe", value: "sk_test", expires_at: "2024-01-01T01:00:00Z" };
      const f = mockFetch(lease);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.issueCredential({ agent_id: "a1", service_name: "stripe" });
      expect(result.lease_id).toBe("l-1");
      expect(result.value).toBe("sk_test");
    });
  });

  describe("revokeCredential()", () => {
    it("sends DELETE to /vault/leases/:leaseId", async () => {
      const f = mockNoContentFetch(204);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.revokeCredential("l-1")).resolves.toBeUndefined();
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/vault/leases/l-1`);
      expect((init as { method: string }).method).toBe("DELETE");
    });
  });

  describe("updateAgent()", () => {
    it("sends PUT to /agents/:id", async () => {
      const agent = { agent_id: "a1", name: "bot" };
      const f = mockFetch(agent);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.updateAgent("a1", { purpose: "updated" });
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/agents/a1`);
      expect((init as { method: string }).method).toBe("PUT");
    });

    it("killAgent posts to /agents/:id/kill", async () => {
      const payload = { agent_id: "a1", name: "bot", status: "quarantined" };
      const f = mockFetch(payload);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.killAgent("a1");
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/agents/a1/kill`);
      expect((init as { method: string }).method).toBe("POST");
      expect(result.status).toBe("quarantined");
    });
  });

  describe("listSessions()", () => {
    it("calls GET /sessions", async () => {
      const sessions = [{ session_id: "s1", agent_id: "a1" }];
      const f = mockFetch(sessions);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listSessions();
      expect(result).toHaveLength(1);
      expect((f.mock.calls[0] as [string])[0]).toContain("/api/v1/sessions");
    });

    it("unwraps { sessions: [...] } shape", async () => {
      const f = mockFetch({ sessions: [{ session_id: "s1" }, { session_id: "s2" }] });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listSessions();
      expect(result).toHaveLength(2);
    });
  });

  describe("listShadowAgents()", () => {
    it("calls GET /shadow (not /agents/shadow)", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.listShadowAgents();
      expect((f.mock.calls[0] as [string])[0]).toContain("/api/v1/shadow");
      expect((f.mock.calls[0] as [string])[0]).not.toContain("/agents/shadow");
    });
  });

  describe("listAudit()", () => {
    it("unwraps { events: [...] } result", async () => {
      const events = [{ event_id: "e1" }, { event_id: "e2" }];
      const f = mockFetch({ events });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listAudit({ limit: 2, agentId: "a1" });
      expect(result).toHaveLength(2);
      expect((f.mock.calls[0] as [string])[0]).toContain("/api/v1/audit");
      expect((f.mock.calls[0] as [string])[0]).toContain("agent_id=a1");
    });
  });

  describe("alerts", () => {
    it("listAlerts unwraps { alerts: [...] } result", async () => {
      const alerts = [{ alert_id: "al-1" }];
      const f = mockFetch({ alerts });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listAlerts({ severity: "critical", agentId: "a1", limit: 5 });
      expect(result).toHaveLength(1);
      expect((f.mock.calls[0] as [string])[0]).toContain("/api/v1/alerts");
      expect((f.mock.calls[0] as [string])[0]).toContain("severity=critical");
    });

    it("ackAlert posts to /alerts/:id/ack", async () => {
      const alert = { alert_id: "al-1", acked: true };
      const f = mockFetch(alert);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.ackAlert("al-1", "operator@acme.com");
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/alerts/al-1/ack`);
      expect((init as { method: string }).method).toBe("POST");
      expect(JSON.parse((init as { body: string }).body).acked_by).toBe("operator@acme.com");
      expect(result.acked).toBe(true);
    });
  });

  describe("promoteShadowAgent()", () => {
    it("calls POST /shadow/:id/promote", async () => {
      const payload = { agent_id: "a1", name: "promoted", status: "active", public_key_pem: "", session_jwt: "jwt" };
      const f = mockFetch(payload);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.promoteShadowAgent("sh-1", { name: "promoted", owner_email: "o@e.com", purpose: "p" });
      const [url] = f.mock.calls[0] as [string];
      expect(url).toBe(`${BASE}/api/v1/shadow/sh-1/promote`);
    });
  });

  describe("mcp servers", () => {
    it("listMcpServers unwraps { servers: [...] } result", async () => {
      const f = mockFetch({ servers: [{ server_id: "srv-1", name: "Public API" }] });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listMcpServers();
      expect(result).toHaveLength(1);
      expect((f.mock.calls[0] as [string])[0]).toBe(`${BASE}/api/v1/mcp/servers`);
    });

    it("getMcpServer fetches a single MCP server by id", async () => {
      const f = mockFetch({ server_id: "srv-1", name: "Public API" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getMcpServer("srv-1");
      expect(result.server_id).toBe("srv-1");
      expect((f.mock.calls[0] as [string])[0]).toBe(`${BASE}/api/v1/mcp/servers/srv-1`);
    });
  });

  describe("listHitlRequests()", () => {
    it("calls GET /hitl/requests", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.listHitlRequests();
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toContain("/api/v1/hitl/requests");
      expect((init as { method: string }).method).toBe("GET");
    });
  });

  describe("getHitlRequest()", () => {
    it("calls GET /hitl/requests/:id", async () => {
      const req = { request_id: "hr-1", agent_id: "a1", action: "delete", resource: "/data", status: "pending" };
      const f = mockFetch(req);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getHitlRequest("hr-1");
      expect(result.request_id).toBe("hr-1");
      expect((f.mock.calls[0] as [string])[0]).toContain("/api/v1/hitl/requests/hr-1");
    });
  });

  describe("decideHitlRequest()", () => {
    it("calls POST /hitl/requests/:id/decide", async () => {
      const resp = { request_id: "hr-1", status: "approved", decided_by: "op1", decision_reason: null, decided_at: "2024-01-01T00:00:00Z" };
      const f = mockFetch(resp);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.decideHitlRequest("hr-1", { decision: "approve" });
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toContain("/api/v1/hitl/requests/hr-1/decide");
      expect((init as { method: string }).method).toBe("POST");
      expect(result.status).toBe("approved");
    });
  });

  describe("issueDelegation()", () => {
    it("calls POST /agents/:agentId/delegate with correct body", async () => {
      const resp = { delegation_token: "tok.del.egate", expires_at: "2024-01-01T01:00:00Z" };
      const f = mockFetch(resp);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.issueDelegation("ag-delegator", "ag-delegate", ["read:data"]);
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/agents/ag-delegator/delegate`);
      expect((init as { method: string }).method).toBe("POST");
      const body = JSON.parse((init as { body: string }).body);
      expect(body.delegate_id).toBe("ag-delegate");
      expect(body.scope).toEqual(["read:data"]);
      expect(result.delegation_token).toBe("tok.del.egate");
    });
  });

  describe("verifyDelegation()", () => {
    it("calls GET /agents/:agentId/delegate/verify?token=...", async () => {
      const resp = { valid: true, delegator_id: "ag-delegator", delegate_id: "ag-delegate", scope: ["read:data"], expires_at: "2024-01-01T01:00:00Z" };
      const f = mockFetch(resp);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.verifyDelegation("ag-delegator", "tok.del.egate");
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toContain("/api/v1/agents/ag-delegator/delegate/verify");
      expect(url).toContain("token=tok.del.egate");
      expect((init as { method: string }).method).toBe("GET");
      expect(result.valid).toBe(true);
    });
  });

  describe("error handling", () => {
    it("throws AgentumAuthError on 401", async () => {
      const f = mockFetch({ error: "Unauthorized" }, 401);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.listAgents()).rejects.toBeInstanceOf(AgentumAuthError);
    });

    it("throws AgentumPermissionError on 403", async () => {
      const f = mockFetch({ error: "Forbidden" }, 403);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.listAgents()).rejects.toBeInstanceOf(AgentumPermissionError);
    });

    it("throws AgentumNotFoundError on 404", async () => {
      const f = mockFetch({ error: "Not found" }, 404);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.getAgent("missing")).rejects.toBeInstanceOf(AgentumNotFoundError);
    });

    it("throws AgentumError on 500", async () => {
      const f = mockFetch({ error: "Internal error" }, 500);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.listAgents()).rejects.toBeInstanceOf(AgentumError);
    });

    it("throws AgentumError on network failure", async () => {
      const f = jest.fn().mockRejectedValue(new TypeError("fetch failed"));
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.listAgents()).rejects.toBeInstanceOf(AgentumError);
    });
  });

  describe("ingestAuditEvent()", () => {
    it("swallows errors silently when buffer is disabled", async () => {
      const f = mockFetch({ error: "server error" }, 500);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, disableAuditBuffer: true });
      // Must not throw
      await expect(
        c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "llm_start" })
      ).resolves.toBeUndefined();
    });

    it("buffers events by default and drains on flushAuditBuffer() as a single batch POST", async () => {
      const f = mockFetch({ ingested: 2 });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "tool_call" });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "llm_start" });
      // No POST fired yet — events are buffered.
      expect(f).not.toHaveBeenCalled();
      expect(c.auditBufferLength()).toBe(2);
      await c.flushAuditBuffer();
      // Batch flusher: one POST per slice (L05), not per-event.
      expect(f).toHaveBeenCalledTimes(1);
      const [url, init] = f.mock.calls[0] as [string, RequestInit];
      expect(url).toContain("audit/ingest/batch");
      const body = JSON.parse((init as { body: string }).body) as { events: Array<{ event_type: string }> };
      expect(body.events.map((e) => e.event_type)).toEqual(["tool_call", "llm_start"]);
      expect(c.auditBufferLength()).toBe(0);
      await c.close();
    });

    it("drops oldest on overflow and calls onAuditError", async () => {
      const onAuditError = jest.fn();
      const f = mockFetch({});
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        auditBufferSize: 2,
        onAuditError,
      });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "e1" });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "e2" });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "e3" });
      expect(onAuditError).toHaveBeenCalledWith(
        expect.objectContaining({ reason: "overflow", dropped: 1, bufferedRemaining: 1 }),
      );
      expect(c.auditBufferLength()).toBe(2);
      await c.flushAuditBuffer();
      // The first event was dropped; e2 and e3 should have been POSTed in one batch.
      expect(f).toHaveBeenCalledTimes(1);
      const [, init] = f.mock.calls[0] as [string, RequestInit];
      const body = JSON.parse((init as { body: string }).body) as { events: Array<{ event_type: string }> };
      expect(body.events.map((e) => e.event_type)).toEqual(["e2", "e3"]);
      await c.close();
    });

    it("retries after a transient failure and preserves ordering", async () => {
      const onAuditError = jest.fn();
      let call = 0;
      const f = jest.fn().mockImplementation(() => {
        call += 1;
        // First attempt: 500. Subsequent: 200.
        if (call === 1) {
          return Promise.resolve({
            ok: false,
            status: 500,
            headers: { get: () => "application/json" },
            json: () => Promise.resolve({ error: "boom" }),
            text: () => Promise.resolve("boom"),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve({}),
          text: () => Promise.resolve("{}"),
        });
      });
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        onAuditError,
        retries: 0, // disable request-level retry so the 500 surfaces immediately
        auditMaxBackoffMs: 50,
        auditFlushIntervalMs: 100,
      });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "ev-1" });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "ev-2" });
      // First flush: batch POST fails (5xx); whole batch re-prepended and onAuditError fired.
      await c.flushAuditBuffer();
      expect(onAuditError).toHaveBeenCalledWith(
        expect.objectContaining({ reason: "ingest_failed", attempt: 1 }),
      );
      expect(c.auditBufferLength()).toBe(2);
      // close() forces a drain ignoring backoff; both events should be delivered.
      await c.close();
      expect(c.auditBufferLength()).toBe(0);
      const postedBatches = f.mock.calls
        .filter((call) => {
          const [url] = call as [string, RequestInit];
          return url.includes("audit/ingest/batch");
        })
        .map((call) => {
          const [, init] = call as [string, RequestInit];
          return JSON.parse((init as { body: string }).body) as {
            events: Array<{ event_type: string }>;
          };
        });
      // Two POSTs total (5xx, then 2xx); each carried both events in order.
      expect(postedBatches.length).toBe(2);
      expect(postedBatches[0]!.events.map((e) => e.event_type)).toEqual(["ev-1", "ev-2"]);
      expect(postedBatches[1]!.events.map((e) => e.event_type)).toEqual(["ev-1", "ev-2"]);
    });

    it("close() drains pending events and drops survivors with dropped_on_close", async () => {
      const onAuditError = jest.fn();
      const f = jest.fn().mockRejectedValue(new TypeError("permanently down"));
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        onAuditError,
        retries: 0,
      });
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "dead" });
      await c.close();
      expect(c.auditBufferLength()).toBe(0);
      expect(onAuditError).toHaveBeenCalledWith(
        expect.objectContaining({ reason: "dropped_on_close", dropped: 1 }),
      );
    });

    it("post-close ingestAuditEvent drops the event", async () => {
      const onAuditError = jest.fn();
      const f = mockFetch({});
      const c = new AgentumClient({
        baseUrl: BASE,
        fetch: f as unknown as typeof fetch,
        onAuditError,
      });
      await c.close();
      await c.ingestAuditEvent({ agent_id: "a1", session_id: "s1", event_type: "late" });
      expect(onAuditError).toHaveBeenCalledWith(
        expect.objectContaining({ reason: "dropped_on_close", dropped: 1 }),
      );
      expect(c.auditBufferLength()).toBe(0);
    });

    // Q4: replay-prevention. Every audit POST must carry both
    // `x-agentum-nonce` (UUID) and `x-agentum-timestamp` (Unix-ms within
    // ±5s of now). Central default `audit_ingest_require_freshness`
    // flips to TRUE post-Q4; missing headers → 4xx and lost audit on
    // net-new tenants.
    describe("Q4 freshness headers", () => {
      // RFC 4122 UUID, any version. `crypto.randomUUID()` emits v4 but
      // we don't pin the version here — server-side check is format-only.
      const UUID_RE =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

      function extractHeaders(call: unknown): Record<string, string> {
        const init = (call as [string, RequestInit])[1] as {
          headers: Record<string, string>;
        };
        return init.headers;
      }

      it("synchronous POST (disableAuditBuffer) carries nonce + timestamp", async () => {
        const f = mockFetch({ ingested: 1 });
        const c = new AgentumClient({
          baseUrl: BASE,
          fetch: f as unknown as typeof fetch,
          disableAuditBuffer: true,
        });
        const before = Date.now();
        await c.ingestAuditEvent({
          agent_id: "a1",
          session_id: "s1",
          event_type: "tool_call",
        });
        const after = Date.now();
        expect(f).toHaveBeenCalledTimes(1);
        const headers = extractHeaders(f.mock.calls[0]);
        expect(headers["x-agentum-nonce"]).toMatch(UUID_RE);
        const ts = Number(headers["x-agentum-timestamp"]);
        expect(Number.isFinite(ts)).toBe(true);
        // Within ±5s of wall-clock (spec asserts within 5s; we tighten
        // to the actual call window since this is in-process).
        expect(ts).toBeGreaterThanOrEqual(before - 5000);
        expect(ts).toBeLessThanOrEqual(after + 5000);
      });

      it("batched POST carries nonce + timestamp", async () => {
        const f = mockFetch({ ingested: 2 });
        const c = new AgentumClient({
          baseUrl: BASE,
          fetch: f as unknown as typeof fetch,
        });
        const before = Date.now();
        await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "e1" });
        await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "e2" });
        await c.flushAuditBuffer();
        const after = Date.now();
        const batchCalls = f.mock.calls.filter((call) =>
          (call as [string, RequestInit])[0].includes("audit/ingest/batch"),
        );
        expect(batchCalls.length).toBe(1);
        const headers = extractHeaders(batchCalls[0]);
        expect(headers["x-agentum-nonce"]).toMatch(UUID_RE);
        const ts = Number(headers["x-agentum-timestamp"]);
        expect(Number.isFinite(ts)).toBe(true);
        expect(ts).toBeGreaterThanOrEqual(before - 5000);
        expect(ts).toBeLessThanOrEqual(after + 5000);
        await c.close();
      });

      it("each batched POST generates a fresh nonce (no replay across calls)", async () => {
        // 250 events at default batchSize=100 → 3 batch POSTs. Every
        // POST must carry a unique nonce; reusing one would let an
        // attacker replay the second batch as the first.
        const f = mockFetch({ ingested: 100 });
        const c = new AgentumClient({
          baseUrl: BASE,
          fetch: f as unknown as typeof fetch,
          auditBufferSize: 1000,
          auditFlushBatchSize: 100,
        });
        for (let i = 0; i < 250; i++) {
          await c.ingestAuditEvent({
            agent_id: "a",
            session_id: "s",
            event_type: `e${i}`,
          });
        }
        await c.close();
        const batchCalls = f.mock.calls.filter((call) =>
          (call as [string, RequestInit])[0].includes("audit/ingest/batch"),
        );
        expect(batchCalls.length).toBe(3);
        const nonces = batchCalls.map((call) => extractHeaders(call)["x-agentum-nonce"]);
        nonces.forEach((n) => expect(n).toMatch(UUID_RE));
        expect(new Set(nonces).size).toBe(nonces.length);
      });
    });
  });

  describe("API key auth", () => {
    it("injects X-API-Key header on every request when apiKey is configured", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-test-key" });
      await c.listAgents();
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["X-API-Key"]).toBe("sk-test-key");
    });

    it("sends both X-API-Key and Authorization when apiKey and token are set", async () => {
      const f = mockFetch({ agent_id: "a1" });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-mgmt" });
      c.setToken("bearer-jwt");
      await c.getAgent("a1");
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["X-API-Key"]).toBe("sk-mgmt");
      expect(headers.headers["Authorization"]).toBe("Bearer bearer-jwt");
    });

    it("does not send X-API-Key when apiKey is not configured", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.listAgents();
      const headers = (f.mock.calls[0] as unknown[])[1] as { headers: Record<string, string> };
      expect(headers.headers["X-API-Key"]).toBeUndefined();
    });
  });

  describe("connect()", () => {
    function makeConnectFetch(
      registrationPayload: object,
      sessionPayload: object,
    ): jest.Mock {
      return jest.fn()
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve(registrationPayload),
          text: () => Promise.resolve(JSON.stringify(registrationPayload)),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve(sessionPayload),
          text: () => Promise.resolve(JSON.stringify(sessionPayload)),
        })
        .mockResolvedValue({
          ok: true,
          status: 204,
          headers: { get: () => "" },
          json: () => Promise.reject(new Error("no body")),
          text: () => Promise.resolve(""),
        });
    }

    const REG = {
      agent_id: "ag-connect-1",
      name: "connect-bot",
      status: "active",
      public_key_pem: "---PEM---",
      session_jwt: "initial.session.jwt",
    };
    const SESS = {
      session_id: "sess-connect-1",
      agent_id: "ag-connect-1",
      jwt: "tracked.session.jwt",
      started_at: "2024-01-01T00:00:00Z",
    };

    it("returns an AgentumSession with correct ids and jwt", async () => {
      const f = makeConnectFetch(REG, SESS);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      const session = await c.connect({ name: "connect-bot", owner_email: "o@e.com", purpose: "test" });
      expect(session).toBeInstanceOf(AgentumSession);
      expect(session.agentId).toBe("ag-connect-1");
      expect(session.sessionId).toBe("sess-connect-1");
      expect(session.jwt).toBe("tracked.session.jwt");
    });

    it("does NOT mutate the outer client token after connect", async () => {
      const f = makeConnectFetch(REG, SESS);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      await c.connect({ name: "connect-bot", owner_email: "o@e.com", purpose: "test" });
      // The management client must remain untouched so concurrent/subsequent sessions
      // on the same client don't inherit or overwrite each other's JWTs.
      expect(c.getToken()).toBeNull();
    });

    it("session client carries the tracked session JWT", async () => {
      const f = makeConnectFetch(REG, SESS);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      const session = await c.connect({ name: "connect-bot", owner_email: "o@e.com", purpose: "test" });
      expect(session.client.getToken()).toBe("tracked.session.jwt");
    });

    it("two concurrent connect() calls produce independent sessions", async () => {
      const REG2 = { ...REG, agent_id: "ag-connect-2", session_jwt: "initial.session.jwt.B" };
      const SESS2 = { ...SESS, session_id: "sess-connect-2", agent_id: "ag-connect-2", jwt: "tracked.session.jwt.B" };

      // Build a fetch that can serve two concurrent connect() flows interleaved.
      // Each connect() does registerAgent (→ REG/REG2) then startSession (→ SESS/SESS2).
      let regCount = 0;
      let sessCount = 0;
      const f = jest.fn().mockImplementation((url: string) => {
        if ((url as string).endsWith("/agents")) {
          const payload = regCount++ === 0 ? REG : REG2;
          return Promise.resolve({
            ok: true, status: 201,
            headers: { get: () => "application/json" },
            json: () => Promise.resolve(payload),
            text: () => Promise.resolve(JSON.stringify(payload)),
          });
        }
        // /sessions
        const payload = sessCount++ === 0 ? SESS : SESS2;
        return Promise.resolve({
          ok: true, status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve(payload),
          text: () => Promise.resolve(JSON.stringify(payload)),
        });
      });

      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      const [sessA, sessB] = await Promise.all([
        c.connect({ name: "agent-A", owner_email: "a@e.com", purpose: "A" }),
        c.connect({ name: "agent-B", owner_email: "b@e.com", purpose: "B" }),
      ]);

      // Sessions are independent — each has its own JWT.
      expect(sessA.jwt).not.toBe(sessB.jwt);
      expect(sessA.client).not.toBe(sessB.client);
      expect(sessA.client.getToken()).not.toBe(sessB.client.getToken());
      // Outer client untouched.
      expect(c.getToken()).toBeNull();
    });

    it("calls registerAgent then startSession in sequence", async () => {
      const f = makeConnectFetch(REG, SESS);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      await c.connect({ name: "connect-bot", owner_email: "o@e.com", purpose: "test" });

      const [regUrl, regInit] = f.mock.calls[0] as [string, RequestInit];
      expect(regUrl).toBe(`${BASE}/api/v1/agents`);
      expect((regInit as { method: string }).method).toBe("POST");

      const [sessUrl, sessInit] = f.mock.calls[1] as [string, RequestInit];
      expect(sessUrl).toBe(`${BASE}/api/v1/sessions`);
      expect((sessInit as { method: string }).method).toBe("POST");
    });

    it("uses the initial session_jwt as Bearer when calling startSession", async () => {
      const f = makeConnectFetch(REG, SESS);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk-key" });
      await c.connect({ name: "connect-bot", owner_email: "o@e.com", purpose: "test" });

      const sessHeaders = (f.mock.calls[1] as unknown[])[1] as { headers: Record<string, string> };
      expect(sessHeaders.headers["Authorization"]).toBe("Bearer initial.session.jwt");
    });
  });

  describe("AgentumSession.close()", () => {
    it("calls endSession with the correct sessionId", async () => {
      const endFetch = mockNoContentFetch(204);
      const c = new AgentumClient({ baseUrl: BASE, fetch: endFetch as unknown as typeof fetch });
      const session = new AgentumSession(c, "ag-1", "sess-1", "jwt");
      await session.close();
      const [url, init] = endFetch.mock.calls[0] as [string, RequestInit];
      expect(url).toBe(`${BASE}/api/v1/sessions/sess-1/end`);
      expect((init as { method: string }).method).toBe("POST");
    });

    it("clears the session JWT from the client after close()", async () => {
      const endFetch = mockNoContentFetch(204);
      const c = new AgentumClient({ baseUrl: BASE, fetch: endFetch as unknown as typeof fetch, token: "session.jwt" });
      expect(c.getToken()).toBe("session.jwt");
      const session = new AgentumSession(c, "ag-1", "sess-1", "session.jwt");
      await session.close();
      expect(c.getToken()).toBeNull();
    });
  });

  // ── Task 2.1.2: baseUrl validation ────────────────────────────────────────
  describe("baseUrl validation", () => {
    it("throws AgentumError for a URL missing scheme", () => {
      expect(() => new AgentumClient("localhost:7071")).toThrow("Invalid baseUrl");
    });

    it("throws AgentumError for a URL with wrong scheme", () => {
      expect(() => new AgentumClient("ftp://localhost:7071")).toThrow("Invalid baseUrl");
    });

    it("accepts http:// URLs", () => {
      expect(() => new AgentumClient("http://localhost:7071")).not.toThrow();
    });

    it("accepts https:// URLs", () => {
      expect(() => new AgentumClient("https://api.example.com")).not.toThrow();
    });
  });

  // ── Task 2.1.2: PaginatedResponse unwrapping ──────────────────────────────
  describe("PaginatedResponse unwrapping", () => {
    it("listAgents unwraps PaginatedResponse<Agent>", async () => {
      const paginated = { items: [{ agent_id: "a-1" }], total: 1, limit: 10, offset: 0 };
      const f = mockFetch(paginated);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listAgents();
      expect(result).toHaveLength(1);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.agent_id).toBe("a-1");
    });

    it("listSessions unwraps PaginatedResponse<Session>", async () => {
      const paginated = { items: [{ session_id: "s-1" }], total: 1, limit: 10, offset: 0 };
      const f = mockFetch(paginated);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listSessions();
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.session_id).toBe("s-1");
    });

    it("listAudit unwraps PaginatedResponse<AuditEvent>", async () => {
      const paginated = { items: [{ event_id: "e-1", event_type: "tool_call" }], total: 1, limit: 10, offset: 0 };
      const f = mockFetch(paginated);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listAudit();
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.event_id).toBe("e-1");
    });

    it("listAlerts unwraps PaginatedResponse<Alert>", async () => {
      const paginated = { items: [{ alert_id: "al-1" }], total: 1, limit: 10, offset: 0 };
      const f = mockFetch(paginated);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listAlerts();
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.alert_id).toBe("al-1");
    });
  });

  // ── Task 2.1.2: listComplianceReport ─────────────────────────────────────
  describe("listComplianceReport", () => {
    it("returns a bare array response", async () => {
      const f = mockFetch([{ agent_id: "a-1", compliant: true, issues: [], checked_at: "" }]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listComplianceReport();
      expect(result).toHaveLength(1);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.agent_id).toBe("a-1");
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.compliant).toBe(true);
    });

    it("unwraps wrapped { report: [...] } response", async () => {
      const f = mockFetch({ report: [{ agent_id: "a-2", compliant: false, issues: ["missing policy"], checked_at: "" }] });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.listComplianceReport();
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.agent_id).toBe("a-2");
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      expect(result[0]!.issues).toContain("missing policy");
    });

    it("calls GET /api/v1/compliance/report", async () => {
      const f = mockFetch([]);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await c.listComplianceReport();
      const [url] = f.mock.calls[0] as [string];
      expect(url).toBe(`${BASE}/api/v1/compliance/report`);
    });
  });

  describe("retry on transient errors", () => {
    function mockFetchSequence(...responses: { status: number; body?: unknown }[]): jest.Mock {
      let call = 0;
      return jest.fn().mockImplementation(() => {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const r = responses[Math.min(call++, responses.length - 1)]!;
        return Promise.resolve({
          ok: r.status < 400,
          status: r.status,
          headers: { get: (h: string) => h === "content-type" ? "application/json" : null },
          json: () => Promise.resolve(r.body ?? {}),
        });
      });
    }

    it("retries on 503 and succeeds on second attempt", async () => {
      const f = mockFetchSequence({ status: 503 }, { status: 200, body: { status: "ok" } });
      // retryDelayMs: 0 keeps tests instant without fake timers
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 3, retryDelayMs: 0 });
      const result = await c.health();
      expect(result.status).toBe("ok");
      expect(f).toHaveBeenCalledTimes(2);
    });

    it("throws after exhausting all retries", async () => {
      const f = mockFetchSequence(
        { status: 429 },
        { status: 429 },
        { status: 429 },
        { status: 429 },
      );
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 3, retryDelayMs: 0 });
      await expect(c.health()).rejects.toThrow(AgentumError);
      expect(f).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
    });

    it("does not retry on 404", async () => {
      const f = mockFetchSequence({ status: 404 }, { status: 200, body: {} });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 3, retryDelayMs: 0 });
      await expect(c.getAgent("missing")).rejects.toThrow(AgentumNotFoundError);
      expect(f).toHaveBeenCalledTimes(1);
    });

    it("retries on 429, 502, 503, 504", async () => {
      for (const status of [429, 502, 503, 504]) {
        const f = mockFetchSequence({ status }, { status: 200, body: { status: "ok" } });
        const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 1, retryDelayMs: 0 });
        await expect(c.health()).resolves.toBeDefined();
        expect(f).toHaveBeenCalledTimes(2);
      }
    });

    it("retries 503 → 503 → 200 and succeeds on third attempt", async () => {
      const f = mockFetchSequence(
        { status: 503 },
        { status: 503 },
        { status: 200, body: { status: "ok" } },
      );
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 3, retryDelayMs: 0 });
      const result = await c.health();
      expect(result.status).toBe("ok");
      expect(f).toHaveBeenCalledTimes(3);
    });

    it("does not retry when retries=0", async () => {
      const f = mockFetchSequence({ status: 503 }, { status: 200, body: { status: "ok" } });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 0, retryDelayMs: 0 });
      await expect(c.health()).rejects.toThrow(AgentumError);
      expect(f).toHaveBeenCalledTimes(1); // no retry attempts
    });

    it("respects Retry-After seconds header", async () => {
      jest.useFakeTimers();
      let call = 0;
      const f = jest.fn().mockImplementation(() => {
        const isFirst = call++ === 0;
        return Promise.resolve({
          ok: !isFirst,
          status: isFirst ? 429 : 200,
          headers: { get: (h: string) => {
            if (h === "content-type") return "application/json";
            if (h === "retry-after" && isFirst) return "2";
            return null;
          }},
          json: () => Promise.resolve(isFirst ? {} : { status: "ok" }),
        });
      });
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, retries: 1, retryDelayMs: 0 });
      const p = c.health();
      // Advance past the 2-second Retry-After delay
      await jest.advanceTimersByTimeAsync(3000);
      const result = await p;
      expect(result.status).toBe("ok");
      jest.useRealTimers();
    });
  });

  // ── AgentStatus type contract ─────────────────────────────────────────────

  describe("AgentStatus enum contract", () => {
    const allBackendStatuses = [
      "provisioning",
      "active",
      "inactive",
      "suspended",
      "quarantined",
      "decommissioned",
    ] as const;

    it.each(allBackendStatuses)(
      "accepts '%s' as a valid AgentStatus (matches backend enum)",
      async (status) => {
        // getAgent returning any of these statuses must not throw or be rejected.
        const agent = { agent_id: "a1", name: "bot", status };
        const f = mockFetch(agent);
        const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
        const result = await c.getAgent("a1");
        expect(result.status).toBe(status);
      },
    );

    it("killAgent response carries status 'quarantined', not 'killed'", async () => {
      // The backend quarantines agents on kill — the phantom 'killed' status
      // was never emitted by the server. This test locks in the correct value.
      const payload = { agent_id: "a1", name: "bot", status: "quarantined" };
      const f = mockFetch(payload);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.killAgent("a1");
      expect(result.status).toBe("quarantined");
      expect(result.status).not.toBe("killed");
    });

    it("listAgents accepts status filter for all backend statuses", async () => {
      for (const status of allBackendStatuses) {
        const f = mockFetch([]);
        const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
        // Must not throw a TypeScript type error or runtime error.
        await c.listAgents({ status });
        const [url] = f.mock.calls[0] as [string];
        expect(url).toContain(`status=${status}`);
      }
    });
  });

  // ── Session.jwt optionality ───────────────────────────────────────────────

  describe("Session.jwt optionality", () => {
    it("startSession response includes jwt and it is accessible", async () => {
      const sess = {
        session_id: "s-1",
        agent_id: "a1",
        jwt: "session.bearer.token",
        started_at: "2024-01-01T00:00:00Z",
      };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.startSession("a1");
      // jwt IS present in startSession — must be accessible.
      expect(result.jwt).toBe("session.bearer.token");
    });

    it("getSession response without jwt field returns undefined for jwt", async () => {
      // Backend GET /sessions/:id does NOT return the jwt field.
      // The SDK must not throw — jwt is optional on Session.
      const sess = {
        session_id: "s-2",
        agent_id: "a1",
        status: "active",
        started_at: "2024-01-01T00:00:00Z",
        ended_at: null,
        source_ip: "127.0.0.1",
        // No jwt field — mirrors the real backend response.
      };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      const result = await c.getSession("s-2");
      expect(result.session_id).toBe("s-2");
      // jwt must be undefined, not an empty string or null.
      expect(result.jwt).toBeUndefined();
    });

    it("connect() uses the jwt from startSession to build the AgentumSession", async () => {
      // Verifies the non-null assertion path: session.jwt! must equal the value
      // returned by startSession so the AgentumSession is correctly authenticated.
      const REG = {
        agent_id: "ag-jwt-1",
        name: "bot",
        status: "provisioning",
        public_key_pem: "",
        session_jwt: "reg.jwt.here",
      };
      const SESS = {
        session_id: "sess-jwt-1",
        agent_id: "ag-jwt-1",
        jwt: "session.jwt.here",
        started_at: "2024-01-01T00:00:00Z",
      };
      const PROBE = { outcome: "Allow", rule_id: "r1", reason: null };

      let call = 0;
      const f = jest.fn().mockImplementation(() => {
        const bodies = [REG, SESS, PROBE];
        const body = bodies[call++] ?? {};
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: { get: () => "application/json" },
          json: () => Promise.resolve(body),
        });
      });

      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const session = await c.connect({ name: "bot", owner_email: "o@e.com", purpose: "test" });
      // The AgentumSession must carry the JWT from startSession, not from registration.
      expect(session.jwt).toBe("session.jwt.here");
    });
  });

  describe("configureMitmProxy() (Sprint 2.3.1)", () => {
    const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const ENROLL = {
      agent_id: "ag-mitm-1",
      session_id: "sess-mitm-1",
      session_jwt: "mitm.session.jwt",
      proxy_token: "proxy-token-xyz",
      proxy_token_expires_at: "2099-01-01T00:00:00Z",
    };

    function mockMitmFetch(): jest.Mock {
      return jest.fn().mockImplementation((url: string) => {
        if (typeof url === "string" && url.endsWith("/launcher/enroll")) {
          return Promise.resolve({
            ok: true,
            status: 201,
            headers: { get: () => "application/json" },
            json: () => Promise.resolve(ENROLL),
            text: () => Promise.resolve(JSON.stringify(ENROLL)),
          });
        }
        if (typeof url === "string" && url.endsWith("/gateway/ca-cert")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: { get: () => "application/x-pem-file" },
            text: () => Promise.resolve(PEM),
          });
        }
        return Promise.reject(new Error(`unexpected url ${url}`));
      });
    }

    // Sandbox env mutations so tests don't leak into each other.
    const ENV_KEYS = ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"];
    const envSnapshot: Record<string, string | undefined> = {};
    beforeEach(() => {
      for (const k of ENV_KEYS) envSnapshot[k] = process.env[k];
    });
    afterEach(() => {
      for (const k of ENV_KEYS) {
        if (envSnapshot[k] === undefined) delete process.env[k];
        else process.env[k] = envSnapshot[k];
      }
    });

    it("enrolls, downloads the CA, and returns the resolved config", async () => {
      const f = mockMitmFetch();
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const { tmpdir } = await import("os");
      const { join } = await import("path");
      const caPath = join(tmpdir(), `agentum-test-${Date.now()}.pem`);

      const cfg = await c.configureMitmProxy({ caPath, name: "bot", purpose: "test" });

      expect(cfg.agentId).toBe("ag-mitm-1");
      expect(cfg.sessionId).toBe("sess-mitm-1");
      expect(cfg.sessionJwt).toBe("mitm.session.jwt");
      expect(cfg.proxyToken).toBe("proxy-token-xyz");
      expect(cfg.caPath).toBe(caPath);
      // proxyUrl inherits host from baseUrl, port 7070, token as basic auth.
      expect(cfg.proxyUrl).toBe("http://proxy-token-xyz:x@localhost:7070");

      const fs = await import("fs");
      expect(fs.readFileSync(caPath, "utf-8")).toContain("BEGIN CERTIFICATE");
      fs.unlinkSync(caPath);
    });

    it("sets process.env.HTTPS_PROXY and NODE_EXTRA_CA_CERTS by default", async () => {
      const f = mockMitmFetch();
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const { tmpdir } = await import("os");
      const { join } = await import("path");
      const caPath = join(tmpdir(), `agentum-test-env-${Date.now()}.pem`);

      const cfg = await c.configureMitmProxy({ caPath });

      expect(process.env.HTTPS_PROXY).toBe(cfg.proxyUrl);
      expect(process.env.HTTP_PROXY).toBe(cfg.proxyUrl);
      expect(process.env.NODE_EXTRA_CA_CERTS).toBe(caPath);
      expect(process.env.SSL_CERT_FILE).toBe(caPath);

      const fs = await import("fs");
      fs.unlinkSync(caPath);
    });

    it("respects setProcessEnv=false", async () => {
      delete process.env.HTTPS_PROXY;
      const f = mockMitmFetch();
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const { tmpdir } = await import("os");
      const { join } = await import("path");
      const caPath = join(tmpdir(), `agentum-test-noenv-${Date.now()}.pem`);

      await c.configureMitmProxy({ caPath, setProcessEnv: false });

      expect(process.env.HTTPS_PROXY).toBeUndefined();

      const fs = await import("fs");
      fs.unlinkSync(caPath);
    });

    it("honours an explicit proxyUrl and injects the token as basic-auth", async () => {
      const f = mockMitmFetch();
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const { tmpdir } = await import("os");
      const { join } = await import("path");
      const caPath = join(tmpdir(), `agentum-test-explicit-${Date.now()}.pem`);

      const cfg = await c.configureMitmProxy({ proxyUrl: "http://proxy.internal:9000", caPath });

      const u = new URL(cfg.proxyUrl);
      expect(u.hostname).toBe("proxy.internal");
      expect(u.port).toBe("9000");
      expect(u.username).toBe("proxy-token-xyz");
      expect(u.password).toBe("x");

      const fs = await import("fs");
      fs.unlinkSync(caPath);
    });

    it("falls back to env-only when installCa=system is requested", async () => {
      const f = mockMitmFetch();
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "sk-key", fetch: f as unknown as typeof fetch });
      const { tmpdir } = await import("os");
      const { join } = await import("path");
      const caPath = join(tmpdir(), `agentum-test-system-${Date.now()}.pem`);
      const warn = jest.spyOn(console, "warn").mockImplementation(() => {});

      try {
        const cfg = await c.configureMitmProxy({ caPath, installCa: "system" });
        expect(cfg.caPath).toBe(caPath);
        expect(warn).toHaveBeenCalled();
        expect(process.env.HTTPS_PROXY).toBe(cfg.proxyUrl);
      } finally {
        warn.mockRestore();
      }

      const fs = await import("fs");
      fs.unlinkSync(caPath);
    });

    it("throws AgentumError when no API key is configured", async () => {
      const f = jest.fn();
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
      await expect(c.configureMitmProxy()).rejects.toThrow(/API key/i);
      expect(f).not.toHaveBeenCalled();
    });

    it("surfaces a 403 from enrollment as AgentumAuthError", async () => {
      const f = jest.fn().mockResolvedValue({
        ok: false,
        status: 403,
        headers: { get: () => "text/plain" },
        text: () => Promise.resolve("invalid api_key"),
      });
      const c = new AgentumClient({ baseUrl: BASE, apiKey: "bad", fetch: f as unknown as typeof fetch });
      await expect(c.configureMitmProxy({ caPath: "/tmp/_nope.pem" })).rejects.toThrow(AgentumAuthError);
    });
  });
});
