/**
 * Unit tests for AgentumAdminClient (Sprint 1.3.2).
 *
 * Uses a mock fetch so no live server is required. Mirrors the
 * `mockFetch` pattern used by `client.test.ts`.
 */

import {
  AgentumAdminClient,
  AgentumError,
  AgentumNotFoundError,
  AgentumPermissionError,
  AgentumRoleInsufficientError,
} from "../src/index";

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

describe("AgentumAdminClient", () => {
  describe("constructor / config", () => {
    it("accepts a plain baseUrl string", () => {
      const admin = new AgentumAdminClient(BASE);
      expect(admin).toBeInstanceOf(AgentumAdminClient);
    });

    it("sends X-API-Key on every admin call", async () => {
      const f = mockFetch({ agent_id: "a1", name: "x" });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak_test",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.agents.get("a1");
      const init = (f.mock.calls[0] as unknown[])[1] as {
        headers: Record<string, string>;
      };
      expect(init.headers["X-API-Key"]).toBe("ak_test");
    });

    it("omits audit buffer tuning from the config type surface", () => {
      // Compile-time assertion: these keys are not on AgentumAdminClientConfig.
      // Runtime check: passing them to the constructor is harmless (they
      // live in the shared AgentumClientConfig and are ignored by the
      // admin HTTP helper).
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
      });
      expect(admin).toBeInstanceOf(AgentumAdminClient);
    });

    it("close() is a no-op that resolves", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(admin.close()).resolves.toBeUndefined();
    });
  });

  describe("agents", () => {
    it("register() POSTs /agents with defaults filled in", async () => {
      const f = mockFetch({
        agent_id: "a1",
        name: "bot",
        status: "active",
        public_key_pem: "-----",
        session_jwt: "jwt",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.agents.register({
        name: "bot",
        owner_email: "o@example.com",
        purpose: "demo",
      });
      expect(r.agent_id).toBe("a1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string; method: string };
      expect(url).toBe(`${BASE}/api/v1/agents`);
      expect(init.method).toBe("POST");
      const body = JSON.parse(init.body);
      expect(body.framework).toBe("agentum-ts-sdk");
      expect(body.declared_tools).toEqual([]);
      expect(body.data_classes).toEqual([]);
    });

    it("list() normalises server shapes (array, {agents}, paginated)", async () => {
      const cases: Array<{ body: unknown; expected: number }> = [
        { body: [{ agent_id: "a1" }], expected: 1 },
        { body: { agents: [{ agent_id: "a1" }, { agent_id: "a2" }] }, expected: 2 },
        { body: { items: [{ agent_id: "a1" }], total: 1, limit: 10, offset: 0 }, expected: 1 },
      ];
      for (const c of cases) {
        const f = mockFetch(c.body);
        const admin = new AgentumAdminClient({
          baseUrl: BASE,
          apiKey: "ak",
          fetch: f as unknown as typeof fetch,
          retries: 0,
        });
        const rows = await admin.agents.list();
        expect(rows.length).toBe(c.expected);
      }
    });

    it("kill() / quarantine() / restore() hit the expected paths", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.agents.kill("a1");
      await admin.agents.quarantine("a1");
      await admin.agents.restore("a1");
      const urls = f.mock.calls.map((c) => (c as unknown[])[0]);
      expect(urls).toEqual([
        `${BASE}/api/v1/agents/a1/kill`,
        `${BASE}/api/v1/agents/a1/quarantine`,
        `${BASE}/api/v1/agents/a1/activate`,
      ]);
    });
  });

  describe("policies", () => {
    it("put() PUTs body { policy: cedarSource } to /policies/:agent_id", async () => {
      const f = mockFetch({ written: true });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.put("a1", "permit(principal, action, resource);");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string; method: string };
      expect(init.method).toBe("PUT");
      expect(url).toBe(`${BASE}/api/v1/policies/a1`);
      expect(JSON.parse(init.body)).toEqual({
        policy: "permit(principal, action, resource);",
      });
    });

    it("get() maps server {policy, note?} → {source, note?}", async () => {
      const f = mockFetch({ agent_id: "a1", policy: "permit(principal, action, resource);" });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await admin.policies.get("a1");
      expect(rec.source).toBe("permit(principal, action, resource);");
      expect(rec.note).toBeUndefined();
    });

    it("get() surfaces the server's 'no policy' note", async () => {
      const f = mockFetch({
        agent_id: "a1",
        policy: null,
        note: "No policy file found for this agent",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await admin.policies.get("a1");
      expect(rec.source).toBeNull();
      expect(rec.note).toBe("No policy file found for this agent");
    });

    it("delete() throws AgentumError with a 'not implemented' message", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(admin.policies.delete("a1")).rejects.toThrow(AgentumError);
      await expect(admin.policies.delete("a1")).rejects.toThrow(/not implemented/i);
    });

    it("applyDeclarative() POSTs to /policies/declarative/:agent_id and camelCases the response", async () => {
      const f = mockFetch({
        compiled_cedar: "permit(principal, action, resource);",
        applied_at: "2026-04-18T12:00:00Z",
        policy_id: "a1",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.applyDeclarative("a1", {
        agent_id: "a1",
        rules: [
          {
            kind: "http",
            permit: true,
            method: "GET",
            host: "api.example.com",
            path_like: "/orders/*",
          },
        ],
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/declarative/a1`);
      expect(init.method).toBe("POST");
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.agent_id).toBe("a1");
      expect(res.compiledCedar).toMatch(/permit/);
      expect(res.appliedAt).toBe("2026-04-18T12:00:00Z");
      expect(res.policyId).toBe("a1");
    });

    it("applyDeclarative() rejects path/body agent_id mismatch client-side", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(
        admin.policies.applyDeclarative("a1", { agent_id: "a2", rules: [] }),
      ).rejects.toThrow(/does not match/);
    });

    it("applyDeclarative() surfaces 400 compile errors", async () => {
      const f = mockFetch(
        { error: "policy parse error: rule #0: http rule: host is empty" },
        400,
      );
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(
        admin.policies.applyDeclarative("a1", {
          agent_id: "a1",
          rules: [{ kind: "http", permit: true, method: "GET", host: "" }],
        }),
      ).rejects.toThrow(/host is empty/);
    });

    it("simulateWithSource() POSTs /policies/simulate with policy_source and agent_id", async () => {
      const f = mockFetch({
        outcome: "Allow",
        rule_id: "policy0",
        reason: null,
        compiled: true,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.simulateWithSource(
        "a1",
        "permit(principal, action, resource);",
        { action: "http.get", resource: "api.example.com" },
      );
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/simulate`);
      expect(init.method).toBe("POST");
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.agent_id).toBe("a1");
      expect(sent.action).toBe("http.get");
      expect(sent.resource).toBe("api.example.com");
      expect(sent.policy_source).toBe("permit(principal, action, resource);");
      expect(res.outcome).toBe("Allow");
      expect(res.compiled).toBe(true);
    });

    it("simulateWithSource() forwards context and user overrides", async () => {
      const f = mockFetch({
        outcome: "Deny",
        rule_id: null,
        reason: "policy0 forbids",
        compiled: true,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.simulateWithSource(
        "a1",
        'forbid(principal, action, resource == Agentum::Resource::"api.example.com");',
        {
          action: "http.delete",
          resource: "api.example.com",
          context: { path: "/orders/1" },
          user: { id: "u1", email: "alice@corp.example", trust: "verified" },
        },
      );
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.context).toEqual({ path: "/orders/1" });
      expect(sent.user).toEqual({
        id: "u1",
        email: "alice@corp.example",
        trust: "verified",
      });
    });

    it("simulateWithSource() rejects empty cedarSource client-side", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(
        admin.policies.simulateWithSource("a1", "   ", {
          action: "http.get",
          resource: "api.example.com",
        }),
      ).rejects.toThrow(/non-empty/i);
    });

    it("simulateWithSource() surfaces 400 parse errors from the server", async () => {
      const f = mockFetch({ error: "policy parse error: unexpected token" }, 400);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(
        admin.policies.simulateWithSource("a1", "not cedar", {
          action: "http.get",
          resource: "api.example.com",
        }),
      ).rejects.toThrow(/unexpected token/);
    });

    it("reload() POSTs /policies/reload", async () => {
      const f = mockFetch({ reloaded: true });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.reload();
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/policies/reload`);
      expect(init.method).toBe("POST");
    });

    it("importFromOpenAPI() POSTs /policies/import-openapi with inline spec", async () => {
      const f = mockFetch({
        rules: [
          {
            kind: "http",
            permit: true,
            method: "GET",
            host: "api.example.com",
            path_like: "/v1/orders/*",
          },
        ],
        compiled_cedar: "permit(principal, action == Agentum::Action::\"http.get\", resource);",
        endpoint_count: 5,
        dry_run: true,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.importFromOpenAPI({
        agentId: "a1",
        spec: '{"openapi": "3.0.0", "paths": {}}',
        defaultEffect: "permit",
        hostOverride: "api.example.com",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/import-openapi`);
      expect(init.method).toBe("POST");
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.agent_id).toBe("a1");
      expect(sent.dry_run).toBe(true); // default
      expect(sent.spec).toBeDefined();
      expect(sent.spec_url).toBeUndefined();
      expect(sent.host_override).toBe("api.example.com");
      expect(res.endpointCount).toBe(5);
      expect(res.rules).toHaveLength(1);
      expect(res.compiledCedar).toMatch(/permit/);
      expect(res.dryRun).toBe(true);
    });

    it("importFromOpenAPI() rejects when neither spec nor specUrl set", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(
        admin.policies.importFromOpenAPI({ agentId: "a1" }),
      ).rejects.toThrow(/exactly one of `spec` or `specUrl`/);
    });

    it("importFromOpenAPI() rejects when both spec and specUrl set", async () => {
      const admin = new AgentumAdminClient(BASE);
      await expect(
        admin.policies.importFromOpenAPI({
          agentId: "a1",
          spec: "x",
          specUrl: "https://example.com/openapi.json",
        }),
      ).rejects.toThrow(/exactly one of `spec` or `specUrl`/);
    });

    it("importFromOpenAPI() serialises camelCase overrides to snake_case", async () => {
      const f = mockFetch({
        rules: [],
        compiled_cedar: "",
        endpoint_count: 0,
        dry_run: true,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.importFromOpenAPI({
        agentId: "a1",
        specUrl: "https://example.com/openapi.json",
        overrides: [
          { pathPattern: "/admin/*", effect: "forbid" },
          { pathPattern: "/**", effect: "forbid", method: "DELETE" },
        ],
      });
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      const sent = JSON.parse(init.body) as { overrides: Array<Record<string, unknown>> };
      expect(sent.overrides).toEqual([
        { path_pattern: "/admin/*", effect: "forbid" },
        { path_pattern: "/**", effect: "forbid", method: "DELETE" },
      ]);
    });

    // ── Proposals (Sprint 2.1.5) ───────────────────────────────────────────

    it("proposeProposal() POSTs to /policies/proposals and returns the created row", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        tenant_id: "t1",
        agent_id: "a1",
        proposed_by: "ops@example.com",
        proposed_at: "2026-04-19T12:00:00Z",
        status: "pending",
        author_mode: "manual",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.proposeProposal({
        agent_id: "a1",
        cedar_source: "permit(principal, action, resource);",
        note: "tighten scope",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/proposals`);
      expect(init.method).toBe("POST");
      const sent = JSON.parse(init.body) as Record<string, unknown>;
      expect(sent.agent_id).toBe("a1");
      expect(sent.cedar_source).toMatch(/permit/);
      expect(sent.note).toBe("tighten scope");
      expect(res.proposal_id).toBe("p1");
      expect(res.author_mode).toBe("manual");
      expect(res.status).toBe("pending");
    });

    it("listProposals() forwards status + agent_id as query params", async () => {
      const f = mockFetch({ proposals: [], total: 0 });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.listProposals({ status: "pending", agent_id: "a1" });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toContain(`${BASE}/api/v1/policies/proposals?`);
      expect(url).toContain("status=pending");
      expect(url).toContain("agent_id=a1");
    });

    it("getProposal() GETs /policies/proposals/:id", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        tenant_id: "t1",
        agent_id: "a1",
        proposed_by: "ops@example.com",
        proposed_at: "2026-04-19T12:00:00Z",
        status: "pending",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await admin.policies.getProposal("p1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1`);
      expect(rec.proposal_id).toBe("p1");
      expect(rec.status).toBe("pending");
    });

    it("approveProposal() POSTs with reviewer_note and camelCase-free response", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        status: "approved",
        reviewed_by: "admin@example.com",
        reviewed_at: "2026-04-19T12:10:00Z",
        applied_path: "/var/agentum/policies/a1.cedar",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.approveProposal("p1", {
        reviewer_note: "LGTM",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string; body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1/approve`);
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({ reviewer_note: "LGTM" });
      expect(res.status).toBe("approved");
      expect(res.applied_path).toContain("a1.cedar");
    });

    it("approveProposal() sends {} body when no reviewer_note supplied", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        status: "approved",
        reviewed_by: "admin@example.com",
        reviewed_at: "2026-04-19T12:10:00Z",
        applied_path: "/a1.cedar",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policies.approveProposal("p1");
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      expect(JSON.parse(init.body)).toEqual({});
    });

    it("approveProposal() surfaces 403 self-approval as AgentumPermissionError", async () => {
      const f = mockFetch(
        { error: "proposer cannot approve their own policy proposal" },
        403,
      );
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.policies.approveProposal("p1")).rejects.toThrow(
        AgentumPermissionError,
      );
    });

    it("rejectProposal() POSTs to /reject with optional note", async () => {
      const f = mockFetch({
        proposal_id: "p1",
        status: "rejected",
        reviewed_by: "admin@example.com",
        reviewed_at: "2026-04-19T12:20:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.rejectProposal("p1", {
        reviewer_note: "scope too broad",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1/reject`);
      expect(res.status).toBe("rejected");
    });

    it("withdrawProposal() POSTs empty body to /withdraw and returns withdrawn", async () => {
      const f = mockFetch({ proposal_id: "p1", status: "withdrawn" });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const res = await admin.policies.withdrawProposal("p1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      expect(url).toBe(`${BASE}/api/v1/policies/proposals/p1/withdraw`);
      expect(JSON.parse(init.body)).toEqual({});
      expect(res.status).toBe("withdrawn");
    });

    it("getProposal() surfaces 404 as AgentumNotFoundError", async () => {
      const f = mockFetch({ error: "policy_proposal not found: zz" }, 404);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.policies.getProposal("zz")).rejects.toThrow(
        AgentumNotFoundError,
      );
    });
  });

  describe("mcp", () => {
    it("registerServer() POSTs to /mcp/servers", async () => {
      const f = mockFetch({
        server_id: "s1",
        name: "stripe-mcp",
        url: "https://mcp.example.com",
        auth_type: "bearer",
        status: "active",
        has_api_key: true,
        created_at: "2026-01-01T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.mcp.registerServer({
        name: "stripe-mcp",
        url: "https://mcp.example.com",
        auth_type: "bearer",
        api_key: "key",
      });
      expect(r.server_id).toBe("s1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/mcp/servers`);
    });

    it("grantAccess() sends agent_id and allowed_tools", async () => {
      const f = mockFetch({
        server_id: "s1",
        agent_id: "a1",
        allowed_tools: ["charge"],
        created_at: "2026-01-01T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.mcp.grantAccess("s1", "a1", ["charge"]);
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string; method: string };
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({
        agent_id: "a1",
        allowed_tools: ["charge"],
      });
    });

    it("revokeAccess() DELETEs /mcp/servers/:id/access/:agent_id", async () => {
      const f = mockFetch({ revoked: true });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.mcp.revokeAccess("s1", "a1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/mcp/servers/s1/access/a1`);
      expect(init.method).toBe("DELETE");
    });

    it("deleteServer() hits DELETE /mcp/servers/:id", async () => {
      const f = mockFetch({ deleted: true });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.mcp.deleteServer("s1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/mcp/servers/s1`);
      expect(init.method).toBe("DELETE");
    });

    // ── Sprint 2.4.6 (G47) — external secrets manager binding ──

    it("registerWithExternalCredential() flattens credential.{source,ref} onto the wire body", async () => {
      const f = mockFetch({
        server_id: "s-ext-1",
        name: "ext-aws",
        url: "https://mcp.example.com/api",
        auth_type: "bearer",
        status: "active",
        has_api_key: false,
        credential_source: "aws_sm",
        credential_ref:
          "arn:aws:secretsmanager:us-east-1:123:secret:my-key-AbCdEf",
        credential_cache_ttl_seconds: 60,
        has_external_credential: true,
        created_at: "2026-04-20T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.mcp.registerWithExternalCredential({
        name: "ext-aws",
        url: "https://mcp.example.com/api",
        credential: {
          source: "aws_sm",
          ref: "arn:aws:secretsmanager:us-east-1:123:secret:my-key-AbCdEf",
          cache_ttl_seconds: 60,
        },
      });
      expect(r.has_external_credential).toBe(true);
      expect(r.credential_source).toBe("aws_sm");
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      const body = JSON.parse(init.body);
      expect(body).toEqual({
        name: "ext-aws",
        url: "https://mcp.example.com/api",
        auth_type: "bearer",
        credential_source: "aws_sm",
        credential_ref:
          "arn:aws:secretsmanager:us-east-1:123:secret:my-key-AbCdEf",
        credential_cache_ttl_seconds: 60,
      });
    });

    it("registerWithExternalCredential() rejects empty credential.ref before the network call", () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      expect(() =>
        admin.mcp.registerWithExternalCredential({
          name: "x",
          url: "https://example.com",
          credential: { source: "aws_sm", ref: "  " },
        }),
      ).toThrow(/credential\.ref/);
      expect(f).not.toHaveBeenCalled();
    });

    it("registerWithExternalCredential() defaults auth_type to 'bearer' when omitted", async () => {
      const f = mockFetch({
        server_id: "s-ext-2",
        name: "ext-vault",
        url: "https://mcp.example.com/api",
        auth_type: "bearer",
        status: "active",
        has_api_key: false,
        credential_source: "hashicorp",
        credential_ref: "secret/data/myapp/api-key",
        has_external_credential: true,
        created_at: "2026-04-20T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.mcp.registerWithExternalCredential({
        name: "ext-vault",
        url: "https://mcp.example.com/api",
        credential: {
          source: "hashicorp",
          ref: "secret/data/myapp/api-key",
        },
      });
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      const body = JSON.parse(init.body);
      expect(body.auth_type).toBe("bearer");
      expect(body.credential_source).toBe("hashicorp");
      expect(body.credential_cache_ttl_seconds).toBeUndefined();
    });
  });

  describe("apiKeys", () => {
    it("mint() maps server plaintext_key → plaintext", async () => {
      const f = mockFetch({
        id: "k1",
        tenant_id: "t1",
        email: "ops@x.com",
        role: "admin",
        agent_scope: null,
        expires_at: null,
        created_at: "2026-01-01T00:00:00Z",
        plaintext_key: "ak_abc",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.apiKeys.mint({
        email: "ops@x.com",
        role: "admin",
      });
      expect(r.id).toBe("k1");
      expect(r.plaintext).toBe("ak_abc");
      // Ensure we did not leak snake-case on the SDK surface.
      expect((r as unknown as Record<string, unknown>).plaintext_key).toBeUndefined();
    });

    it("list() reads {keys, total} envelope", async () => {
      const f = mockFetch({
        keys: [
          {
            id: "k1",
            tenant_id: "t1",
            email: "ops@x.com",
            role: "admin",
            created_by: null,
            created_at: "2026-01-01T00:00:00Z",
            revoked_at: null,
            last_used_at: null,
            agent_scope: null,
            expires_at: null,
            ip_allow_cidrs: null,
            scope_features: null,
            rotated_to_id: null,
            grace_until: null,
          },
        ],
        total: 1,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rows = await admin.apiKeys.list();
      expect(rows).toHaveLength(1);
      expect(rows[0]?.id).toBe("k1");
    });

    it("rotate() normalises snake-case to camelCase contract", async () => {
      const f = mockFetch({
        new_key_id: "k2",
        new_key_plaintext: "ak_new",
        old_key_id: "k1",
        old_key_grace_until: "2026-01-02T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.apiKeys.rotate("k1", 3600);
      expect(r).toEqual({
        newKeyId: "k2",
        newPlaintext: "ak_new",
        oldKeyId: "k1",
        oldGraceUntil: "2026-01-02T00:00:00Z",
      });
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      expect(JSON.parse(init.body)).toEqual({ grace_seconds: 3600 });
    });

    it("rotate() omits grace_seconds when undefined", async () => {
      const f = mockFetch({
        new_key_id: "k2",
        new_key_plaintext: "ak_new",
        old_key_id: "k1",
        old_key_grace_until: "2026-01-02T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.apiKeys.rotate("k1");
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      expect(JSON.parse(init.body)).toEqual({});
    });

    it("revoke() hits DELETE /tenant/api-keys/:id", async () => {
      const f = mockFetch({ id: "k1", revoked: true, revoked_at: "2026-01-01T00:00:00Z" });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.apiKeys.revoke("k1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/tenant/api-keys/k1`);
      expect(init.method).toBe("DELETE");
    });
  });

  describe("tenantAuditKeys", () => {
    it("rotate() posts to /admin/tenant-audit-keys/:tenant/rotate and normalises snake_case", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        dek_version: 2,
        rotated_at: "2026-04-20T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.tenantAuditKeys.rotate("t1");
      expect(r).toEqual({
        tenantId: "t1",
        dekVersion: 2,
        rotatedAt: "2026-04-20T00:00:00Z",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/admin/tenant-audit-keys/t1/rotate`);
      expect(init.method).toBe("POST");
    });

    it("rotate() rejects empty tenantId before any network call", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.tenantAuditKeys.rotate("")).rejects.toThrow(
        "tenantId is required",
      );
      expect(f).not.toHaveBeenCalled();
    });
  });

  describe("policyBundle (Sprint 3.1)", () => {
    it("sync() POSTs to /admin/policy-bundle/sync/:tenant and normalises snake_case", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        commit_sha: "abc123",
        bundle_sha256: "deadbeef",
        url: "https://bundles.example.com/t1.tar.gz",
        agents_updated: 2,
        agents_unchanged: 1,
        agents_removed: 0,
        mcp_servers_updated: 1,
        duration_ms: 142,
        trigger: "manual",
        no_change: false,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.policyBundle.sync("t1");
      expect(r).toEqual({
        tenantId: "t1",
        commitSha: "abc123",
        bundleSha256: "deadbeef",
        url: "https://bundles.example.com/t1.tar.gz",
        agentsUpdated: 2,
        agentsUnchanged: 1,
        agentsRemoved: 0,
        mcpServersUpdated: 1,
        durationMs: 142,
        trigger: "manual",
        noChange: false,
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/admin/policy-bundle/sync/t1`);
      expect(init.method).toBe("POST");
    });

    it("sync() appends ?force=true when opts.force is set", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        commit_sha: "abc",
        bundle_sha256: "x",
        url: "",
        agents_updated: 0,
        agents_unchanged: 0,
        agents_removed: 0,
        mcp_servers_updated: 0,
        duration_ms: 10,
        trigger: "manual",
        no_change: false,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.policyBundle.sync("t1", { force: true });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/admin/policy-bundle/sync/t1?force=true`);
    });

    it("sync() rejects empty tenantId before any network call", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.policyBundle.sync("")).rejects.toThrow(
        "tenantId is required",
      );
      expect(f).not.toHaveBeenCalled();
    });
  });

  describe("tenantClassifications (Sprint 2.5.2.2)", () => {
    it("create() posts snake_case body and normalises response", async () => {
      const f = mockFetch({
        id: "r1",
        tenant_id: "t1",
        label: "PHI:MRN",
        pattern: "\\bMRN-\\d{8}\\b",
        field_paths: [],
        sensitivity: "phi",
        created_at: "2026-04-20T00:00:00Z",
        updated_at: "2026-04-20T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await admin.tenantClassifications.create("t1", {
        label: "PHI:MRN",
        pattern: "\\bMRN-\\d{8}\\b",
        sensitivity: "phi",
      });
      expect(rec.fieldPaths).toEqual([]);
      expect(rec.tenantId).toBe("t1");
      expect(rec.sensitivity).toBe("phi");

      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as {
        method: string;
        body: string;
      };
      expect(url).toBe(`${BASE}/api/v1/admin/tenant-classifications/t1`);
      expect(init.method).toBe("POST");
      const body = JSON.parse(init.body);
      expect(body).toEqual({
        label: "PHI:MRN",
        pattern: "\\bMRN-\\d{8}\\b",
        sensitivity: "phi",
      });
    });

    it("create() rejects a no-op rule (no pattern AND no fieldPaths) before the network call", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(
        admin.tenantClassifications.create("t1", { label: "BAD" }),
      ).rejects.toThrow(/pattern.*fieldPaths/);
      expect(f).not.toHaveBeenCalled();
    });

    it("create() accepts a path-only rule (no pattern)", async () => {
      const f = mockFetch({
        id: "r2",
        tenant_id: "t1",
        label: "LEGAL:PRIV",
        pattern: null,
        field_paths: ["detail.legal_memo"],
        sensitivity: "secret",
        created_at: "2026-04-20T00:00:00Z",
        updated_at: "2026-04-20T00:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const rec = await admin.tenantClassifications.create("t1", {
        label: "LEGAL:PRIV",
        fieldPaths: ["detail.legal_memo"],
        sensitivity: "secret",
      });
      expect(rec.pattern).toBeNull();
      expect(rec.fieldPaths).toEqual(["detail.legal_memo"]);
    });

    it("list() normalises each record", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        count: 1,
        classifications: [
          {
            id: "r1",
            tenant_id: "t1",
            label: "PCI:ROUTING",
            pattern: "\\b\\d{9}\\b",
            field_paths: ["detail.routing_number"],
            sensitivity: "pci",
            created_at: "2026-04-20T00:00:00Z",
            updated_at: "2026-04-20T00:00:00Z",
          },
        ],
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.tenantClassifications.list("t1");
      expect(r.count).toBe(1);
      const first = r.classifications[0]!;
      expect(first.fieldPaths).toEqual(["detail.routing_number"]);
      expect(first.tenantId).toBe("t1");
    });

    it("update() sends PATCH-like partial body", async () => {
      const f = mockFetch({
        id: "r1",
        tenant_id: "t1",
        label: "PHI:MRN",
        pattern: null,
        field_paths: ["detail.mrn"],
        sensitivity: "phi",
        created_at: "2026-04-20T00:00:00Z",
        updated_at: "2026-04-20T00:00:01Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.tenantClassifications.update("t1", "r1", {
        pattern: null,
        fieldPaths: ["detail.mrn"],
      });
      const init = (f.mock.calls[0] as unknown[])[1] as {
        method: string;
        body: string;
      };
      expect(init.method).toBe("PUT");
      const body = JSON.parse(init.body);
      expect(body).toEqual({
        pattern: null,
        field_paths: ["detail.mrn"],
      });
      // label/sensitivity omitted because the caller didn't set them.
      expect(body).not.toHaveProperty("label");
      expect(body).not.toHaveProperty("sensitivity");
    });

    it("delete() calls DELETE on the rule URL", async () => {
      const f = mockFetch({}, 204);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.tenantClassifications.delete("t1", "r1");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/admin/tenant-classifications/t1/r1`);
      expect(init.method).toBe("DELETE");
    });

    it("test() runs a dry-run and normalises matches", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        matches: [
          {
            field_path: "detail.patient",
            labels: ["PHI:MRN"],
            sensitivity: "phi",
          },
        ],
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.tenantClassifications.test("t1", {
        detail: { patient: "MRN-12345678" },
      });
      expect(r.matches).toEqual([
        {
          fieldPath: "detail.patient",
          labels: ["PHI:MRN"],
          sensitivity: "phi",
        },
      ]);
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/admin/tenant-classifications/t1/test`);
    });

    it("rejects empty tenantId before any network call", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.tenantClassifications.list("")).rejects.toThrow(
        "tenantId is required",
      );
      expect(f).not.toHaveBeenCalled();
    });
  });

  describe("bootstrap", () => {
    it("marshals camelCase spec → snake_case wire, decodes response to camelCase", async () => {
      const wireResponse = {
        agent: { agent_id: "a-uuid", name: "bot", created: true },
        mcp_servers: [
          { server_id: "s1", name: "mcp-a", created: true },
        ],
        grants: [
          {
            mcp_server_name: "mcp-a",
            server_id: "s1",
            allowed_tools: ["*"],
            created: true,
          },
        ],
        policy: { policy_id: "a-uuid", applied: true, rule_count: 1 },
        api_keys: [
          {
            id: "k1",
            label: "ci",
            role: "operator",
            agent_scope: "a-uuid",
            created: true,
            plaintext_key: "ak_deadbeef",
          },
        ],
      };
      const f = mockFetch(wireResponse);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const result = await admin.bootstrap({
        agent: {
          name: "bot",
          ownerEmail: "o@x.com",
          purpose: "p",
          framework: "custom",
          declaredTools: ["greet"],
        },
        mcpServers: [
          {
            name: "mcp-a",
            url: "https://mcp-a.example.com",
            auth: { type: "bearer", token: "t", headerName: "Authorization" },
          },
        ],
        grants: [{ mcpServerName: "mcp-a", allowedTools: ["*"] }],
        apiKeys: [
          { role: "operator", label: "ci", agentScope: "__SELF__" },
        ],
      });

      const [url, init] = f.mock.calls[0] as [string, { method: string; body: string }];
      expect(url).toBe(`${BASE}/api/v1/admin/bootstrap`);
      expect(init.method).toBe("POST");
      const wire = JSON.parse(init.body);
      expect(wire.agent.owner_email).toBe("o@x.com");
      expect(wire.agent.declared_tools).toEqual(["greet"]);
      expect(wire.mcp_servers[0].auth.header_name).toBe("Authorization");
      expect(wire.grants[0].mcp_server_name).toBe("mcp-a");
      expect(wire.api_keys[0].agent_scope).toBe("__SELF__");

      expect(result.agent.agentId).toBe("a-uuid");
      expect(result.agent.created).toBe(true);
      expect(result.mcpServers[0]!.serverId).toBe("s1");
      expect(result.grants[0]!.allowedTools).toEqual(["*"]);
      expect(result.policy?.ruleCount).toBe(1);
      expect(result.apiKeys[0]!.plaintextKey).toBe("ak_deadbeef");
      expect(result.apiKeys[0]!.agentScope).toBe("a-uuid");
    });

    it("second run without plaintext surfaces created: false", async () => {
      const wireResponse = {
        agent: { agent_id: "a-uuid", name: "bot", created: false },
        mcp_servers: [],
        grants: [],
        api_keys: [
          { id: "k1", label: "ci", role: "operator", agent_scope: null, created: false },
        ],
      };
      const f = mockFetch(wireResponse);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const result = await admin.bootstrap({
        agent: {
          name: "bot",
          ownerEmail: "o@x.com",
          purpose: "p",
          framework: "custom",
        },
        apiKeys: [{ role: "operator", label: "ci" }],
      });
      expect(result.agent.created).toBe(false);
      expect(result.apiKeys[0]!.created).toBe(false);
      expect(result.apiKeys[0]!.plaintextKey).toBeUndefined();
      expect(result.apiKeys[0]!.agentScope).toBeUndefined();
    });
  });

  describe("error mapping + retries", () => {
    it("maps 404 to AgentumNotFoundError", async () => {
      const f = mockFetch({ error: "not found" }, 404);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.agents.get("missing")).rejects.toThrow(AgentumNotFoundError);
    });

    it("maps 403 to AgentumPermissionError", async () => {
      const f = mockFetch({ error: "forbidden" }, 403);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(admin.apiKeys.mint({ email: "x@y.com", role: "admin" })).rejects.toThrow(
        AgentumPermissionError,
      );
    });

    it("maps 403 role_insufficient body to AgentumRoleInsufficientError", async () => {
      const f = mockFetch(
        {
          error: "requires admin role, caller has operator",
          code: "role_insufficient",
          required: "admin",
          actual: "operator",
        },
        403,
      );
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      // Promise rejection — capture for field inspection, not just instanceof.
      await expect(
        admin.apiKeys.mint({ email: "x@y.com", role: "admin" }),
      ).rejects.toBeInstanceOf(AgentumRoleInsufficientError);

      // Role-insufficient is a subclass of AgentumPermissionError — generic
      // permission-error callers still match.
      let caught: unknown = null;
      try {
        await admin.apiKeys.mint({ email: "x@y.com", role: "admin" });
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(AgentumRoleInsufficientError);
      expect(caught).toBeInstanceOf(AgentumPermissionError);
      const e = caught as AgentumRoleInsufficientError;
      expect(e.required).toBe("admin");
      expect(e.actual).toBe("operator");
      expect(e.statusCode).toBe(403);
    });

    it("retries on 503 then succeeds", async () => {
      const f = mockSequenceFetch([
        { body: { error: "busy" }, status: 503 },
        { body: { agents: [] } },
      ]);
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 3,
        retryDelayMs: 1,
      });
      const rows = await admin.agents.list();
      expect(rows).toEqual([]);
      expect(f).toHaveBeenCalledTimes(2);
    });
  });

  describe("retention (Sprint 2.5.3.1)", () => {
    it("status() GETs /retention/status and normalises snake_case", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        effective_hot_days: 365,
        effective_cold_days: 2555,
        hot_event_count: 42,
        cold_file_count: 3,
        cold_bytes_on_disk: 12345,
        cold_dir: "/retention/t1",
        next_run_at: "2026-04-21T02:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const s = await admin.retention.status();
      expect(s).toEqual({
        tenantId: "t1",
        effectiveHotDays: 365,
        effectiveColdDays: 2555,
        hotEventCount: 42,
        coldFileCount: 3,
        coldBytesOnDisk: 12345,
        coldDir: "/retention/t1",
        nextRunAt: "2026-04-21T02:00:00Z",
      });
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(url).toBe(`${BASE}/api/v1/retention/status`);
      expect(init.method).toBe("GET");
    });

    it("status(tenantId) appends the query param for SuperAdmin cross-tenant reads", async () => {
      const f = mockFetch({
        tenant_id: "t2",
        effective_hot_days: 90,
        effective_cold_days: 90,
        hot_event_count: 0,
        cold_file_count: 0,
        cold_bytes_on_disk: 0,
        cold_dir: "/retention/t2",
        next_run_at: "2026-04-21T02:00:00Z",
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.retention.status("t2");
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toBe(`${BASE}/api/v1/retention/status?tenant_id=t2`);
    });

    it("runNow() POSTs /retention/run-now and returns the outcome", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        hot_to_cold_events: 100,
        hot_to_cold_bytes: 5000,
        hot_to_cold_files: 2,
        cold_deleted_files: 1,
        cold_deleted_bytes: 300,
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const o = await admin.retention.runNow();
      expect(o).toEqual({
        tenantId: "t1",
        hotToColdEvents: 100,
        hotToColdBytes: 5000,
        hotToColdFiles: 2,
        coldDeletedFiles: 1,
        coldDeletedBytes: 300,
      });
      const init = (f.mock.calls[0] as unknown[])[1] as { method: string };
      expect(init.method).toBe("POST");
    });

    it("scanCold() encodes from/to/limit and surfaces the events payload", async () => {
      const f = mockFetch({
        tenant_id: "t1",
        from: "2025-01-01T00:00:00Z",
        to: "2025-12-31T23:59:59Z",
        limit: 100,
        count: 1,
        events: [{ event_id: "e1", event_type: "policy_allow" }],
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const r = await admin.retention.scanCold({
        from: new Date("2025-01-01T00:00:00Z"),
        to: new Date("2025-12-31T23:59:59Z"),
        limit: 100,
      });
      expect(r.count).toBe(1);
      expect(r.events).toHaveLength(1);
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      expect(url).toContain("/api/v1/audit/cold");
      expect(url).toContain("from=2025-01-01T00%3A00%3A00.000Z");
      expect(url).toContain("limit=100");
    });
  });

  describe("dataSubjects (Sprint 2.5.3.2)", () => {
    it("export() posts snake_case body and normalises response to camelCase", async () => {
      const f = mockFetch({
        subject_type: "user",
        subject_hmac: "hmac-sha256:deadbeefcafefeed",
        tenant_id: "t1",
        exported_at: "2026-04-20T10:00:00Z",
        audit_events: [{ event_id: "e1" }],
        sessions: [
          {
            session_id: "s1",
            agent_id: "a1",
            source_ip: "10.0.0.1",
            started_at: "2026-04-20T09:00:00Z",
            ended_at: null,
            status: "active",
          },
        ],
        hitl_requests: [
          {
            request_id: "h1",
            agent_id: "a1",
            session_id: null,
            tool: "release_report",
            resource: "report.pdf",
            reason: null,
            requested_at: "2026-04-20T08:00:00Z",
            timeout_at: "2026-04-20T09:00:00Z",
            status: "approved",
            decided_by: "alice@example.com",
            decided_at: "2026-04-20T08:30:00Z",
            comment: "lgtm",
          },
        ],
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      const bundle = await admin.dataSubjects.export({
        subjectType: "user",
        subjectId: "alice@example.com",
      });
      expect(bundle.subjectType).toBe("user");
      expect(bundle.subjectHmac).toBe("hmac-sha256:deadbeefcafefeed");
      expect(bundle.tenantId).toBe("t1");
      expect(bundle.sessions).toHaveLength(1);
      expect(bundle.sessions[0]).toEqual({
        sessionId: "s1",
        agentId: "a1",
        sourceIp: "10.0.0.1",
        startedAt: "2026-04-20T09:00:00Z",
        status: "active",
      });
      const hitl = bundle.hitlRequests[0]!;
      expect(hitl.decidedBy).toBe("alice@example.com");
      expect(hitl.reason).toBeUndefined();
      const url = (f.mock.calls[0] as unknown[])[0] as string;
      const init = (f.mock.calls[0] as unknown[])[1] as {
        method: string;
        body: string;
      };
      expect(url).toBe(`${BASE}/api/v1/data-subjects/export`);
      expect(init.method).toBe("POST");
      expect(JSON.parse(init.body)).toEqual({
        subject_type: "user",
        subject_id: "alice@example.com",
      });
    });

    it("export() includes tenant_id in wire body when set (SuperAdmin)", async () => {
      const f = mockFetch({
        subject_type: "agent",
        subject_hmac: "hmac-sha256:cafe",
        tenant_id: "t-other",
        exported_at: "2026-04-20T10:00:00Z",
        audit_events: [],
        sessions: [],
        hitl_requests: [],
      });
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await admin.dataSubjects.export({
        subjectType: "agent",
        subjectId: "agent-uuid",
        tenantId: "t-other",
      });
      const init = (f.mock.calls[0] as unknown[])[1] as { body: string };
      expect(JSON.parse(init.body)).toEqual({
        subject_type: "agent",
        subject_id: "agent-uuid",
        tenant_id: "t-other",
      });
    });

    it("export() rejects empty subjectId before any network call", async () => {
      const f = mockFetch({});
      const admin = new AgentumAdminClient({
        baseUrl: BASE,
        apiKey: "ak",
        fetch: f as unknown as typeof fetch,
        retries: 0,
      });
      await expect(
        admin.dataSubjects.export({
          subjectType: "user",
          subjectId: "",
        }),
      ).rejects.toThrow("subjectId is required");
      expect(f).not.toHaveBeenCalled();
    });
  });
});
