/**
 * Tests for the enhanced AgentumSession class (Tasks 2.2.1, 2.3.1).
 */

import { AgentumClient, AgentumSession } from "../src/index";
import { hashArgsCanonical } from "../src/evaluation/cedar-client";

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

// ── JWT helpers ───────────────────────────────────────────────────────────────

/** Build a minimal JWT with the given exp (seconds since epoch). */
function makeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `${header}.${payload}.fakesig`;
}

const FUTURE_JWT = makeJwt(Math.floor(Date.now() / 1000) + 3600);  // expires in 1h
const EXPIRED_JWT = makeJwt(Math.floor(Date.now() / 1000) - 3600); // expired 1h ago
const NEAR_EXPIRY_JWT = makeJwt(Math.floor(Date.now() / 1000) + 30); // expires in 30s (within 60s threshold)
const NO_EXP_JWT = "header.e30K.sig"; // payload = {}

// ── isExpired() ───────────────────────────────────────────────────────────────

describe("AgentumSession.isExpired()", () => {
  it("returns false for a JWT with a future exp", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    expect(session.isExpired()).toBe(false);
  });

  it("returns true for a JWT with a past exp", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", EXPIRED_JWT);
    expect(session.isExpired()).toBe(true);
  });

  it("returns false (never-expiring) when JWT has no exp claim", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", NO_EXP_JWT);
    expect(session.isExpired()).toBe(false);
  });

  it("exposes expiresAt as a Date", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });
});

// ── isAllowed() ───────────────────────────────────────────────────────────────

describe("AgentumSession.isAllowed()", () => {
  it("calls simulatePolicy with the session agentId injected automatically", async () => {
    const policyResp = { outcome: "Allow", rule_id: null, reason: null };
    const f = mockFetch(policyResp);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-auto", "s-1", FUTURE_JWT);

    const allowed = await session.isAllowed("http.get", "https://api.example.com");

    expect(allowed).toBe(true);
    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as Record<string, unknown>;
    expect(body["agent_id"]).toBe("ag-auto");
    expect(body["action"]).toBe("http.get");
    expect(body["resource"]).toBe("https://api.example.com");
  });

  it("returns false when policy outcome is Deny", async () => {
    const f = mockFetch({ outcome: "Deny", rule_id: null, reason: "blocked" });
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    const allowed = await session.isAllowed("http.delete", "https://api.example.com");
    expect(allowed).toBe(false);
  });
});

// ── ingestAuditEvent() ────────────────────────────────────────────────────────

describe("AgentumSession.ingestAuditEvent()", () => {
  it("auto-injects agent_id and session_id", async () => {
    const f = mockFetch({});
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, disableAuditBuffer: true });
    const session = new AgentumSession(c, "ag-inject", "sess-inject", FUTURE_JWT);

    await session.ingestAuditEvent({ event_type: "tool_call" });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as Record<string, unknown>;
    expect(body["agent_id"]).toBe("ag-inject");
    expect(body["session_id"]).toBe("sess-inject");
    expect(body["event_type"]).toBe("tool_call");
  });

  it("passes optional fields through unchanged", async () => {
    const f = mockFetch({});
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, disableAuditBuffer: true });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.ingestAuditEvent({ event_type: "llm_start", tool: "search", outcome: "ok" });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as Record<string, unknown>;
    expect(body["tool"]).toBe("search");
    expect(body["outcome"]).toBe("ok");
  });

  it("never throws even when the network fails", async () => {
    const f = jest.fn().mockRejectedValue(new Error("network down"));
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, disableAuditBuffer: true });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    await expect(session.ingestAuditEvent({ event_type: "tool_call" })).resolves.toBeUndefined();
  });
});

// ── close() ───────────────────────────────────────────────────────────────────

describe("AgentumSession.close()", () => {
  it("calls endSession with the correct sessionId", async () => {
    const endFetch = mockNoContentFetch(204);
    const c = new AgentumClient({ baseUrl: BASE, fetch: endFetch as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "sess-close", FUTURE_JWT);

    await session.close();

    const [url] = endFetch.mock.calls[0] as [string];
    expect(url).toContain("sessions/sess-close/end");
  });

  it("clears the Bearer token on the client after close", async () => {
    const f = mockNoContentFetch(204);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, token: FUTURE_JWT });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.close();

    expect(c.getToken()).toBeNull();
  });

  it("is idempotent — second close() is a no-op", async () => {
    const f = mockNoContentFetch(204);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.close();
    await session.close(); // second call must not fire another HTTP request

    expect(f).toHaveBeenCalledTimes(1);
  });

  it("concurrent close() calls coalesce — endSession called exactly once", async () => {
    let resolveEnd!: () => void;
    const stalled = new Promise<void>((res) => { resolveEnd = res; });
    // endSession stalls until we release it
    const stalledFetch = jest.fn().mockImplementation(() =>
      stalled.then(() => ({ ok: true, status: 204, headers: { get: () => null }, json: async () => ({}) }))
    );
    const c = new AgentumClient({ baseUrl: BASE, fetch: stalledFetch as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-concurrent", FUTURE_JWT);

    // Fire 5 concurrent close() calls while endSession is stalled
    const promises = Array.from({ length: 5 }, () => session.close());
    resolveEnd(); // release endSession
    await Promise.all(promises);

    // endSession must have been called exactly once
    expect(stalledFetch).toHaveBeenCalledTimes(1);
    expect(c.getToken()).toBeNull();
  });

  it("clearToken runs even when endSession rejects", async () => {
    const f = mockNoContentFetch(204);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, token: FUTURE_JWT });
    jest.spyOn(c, "endSession").mockRejectedValue(new Error("network down"));
    const session = new AgentumSession(c, "ag-1", "s-fail", FUTURE_JWT);

    await expect(session.close()).rejects.toThrow("network down");

    // Token must be cleared even on failure
    expect(c.getToken()).toBeNull();
  });
});

// ── Symbol.asyncDispose ───────────────────────────────────────────────────────

describe("AgentumSession[Symbol.asyncDispose]()", () => {
  it("is defined on the session", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    expect(typeof session[Symbol.asyncDispose]).toBe("function");
  });

  it("delegates to close()", async () => {
    const f = mockNoContentFetch(204);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-dispose", FUTURE_JWT);

    await session[Symbol.asyncDispose]();

    const [url] = f.mock.calls[0] as [string];
    expect(url).toContain("sessions/s-dispose/end");
  });
});

// ── AgentumClient.connect() → AgentumSession ─────────────────────────────────

const REG = {
  agent_id: "ag-connect",
  name: "connect-bot",
  status: "active",
  public_key_pem: "---PEM---",
  session_jwt: "initial.jwt",
};
const SESS = {
  session_id: "sess-connect",
  agent_id: "ag-connect",
  jwt: FUTURE_JWT,
  started_at: "2024-01-01T00:00:00Z",
};

function makeConnectFetch(reg = REG, sess = SESS): jest.Mock {
  let call = 0;
  return jest.fn().mockImplementation(() => {
    call++;
    const body = call === 1 ? reg : sess;
    return Promise.resolve({
      ok: true,
      status: 200,
      headers: { get: () => "application/json" },
      json: () => Promise.resolve(body),
      text: () => Promise.resolve(JSON.stringify(body)),
    });
  });
}

describe("AgentumClient.connect() → AgentumSession", () => {
  it("returns an AgentumSession instance", async () => {
    const f = makeConnectFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    const session = await c.connect({ name: "bot", owner_email: "o@e.com", purpose: "test" });
    expect(session).toBeInstanceOf(AgentumSession);
  });

  it("session has correct agentId, sessionId, jwt", async () => {
    const f = makeConnectFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    const session = await c.connect({ name: "bot", owner_email: "o@e.com", purpose: "test" });
    expect(session.agentId).toBe("ag-connect");
    expect(session.sessionId).toBe("sess-connect");
    expect(session.jwt).toBe(FUTURE_JWT);
  });

  it("session.expiresAt is a Date in the future for a valid JWT", async () => {
    const f = makeConnectFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    const session = await c.connect({ name: "bot", owner_email: "o@e.com", purpose: "test" });
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("does not mutate the outer client token", async () => {
    const f = makeConnectFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    await c.connect({ name: "bot", owner_email: "o@e.com", purpose: "test" });
    expect(c.getToken()).toBeNull();
  });
});

// ── AgentumClient.connectExisting() ──────────────────────────────────────────

describe("AgentumClient.connectExisting()", () => {
  it("returns an AgentumSession without calling registerAgent", async () => {
    const f = mockFetch(SESS);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    const session = await c.connectExisting("ag-existing", { skipPolicyCheck: true });

    expect(session).toBeInstanceOf(AgentumSession);
    expect(session.agentId).toBe("ag-existing");
    expect(session.sessionId).toBe("sess-connect");
    // Only one POST (startSession) — no registerAgent call
    expect(f).toHaveBeenCalledTimes(1);
    const [url] = f.mock.calls[0] as [string];
    expect(url).toContain("/api/v1/sessions");
  });

  it("session client carries the session JWT", async () => {
    const f = mockFetch(SESS);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    const session = await c.connectExisting("ag-existing");
    expect(session.client.getToken()).toBe(FUTURE_JWT);
  });

  it("does not mutate the outer client token", async () => {
    const f = mockFetch(SESS);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch, apiKey: "sk" });
    await c.connectExisting("ag-existing");
    expect(c.getToken()).toBeNull();
  });
});

// ── AgentumSession.refresh() ──────────────────────────────────────────────────

const REFRESHED_JWT = makeJwt(Math.floor(Date.now() / 1000) + 7200); // new JWT, expires in 2h

describe("AgentumSession.refresh()", () => {
  it("updates jwt, sessionId, expiresAt and the client token", async () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const refreshFn = jest.fn().mockResolvedValue({ jwt: REFRESHED_JWT, session_id: "sess-new" });
    const session = new AgentumSession(c, "ag-1", "sess-old", FUTURE_JWT, { refreshFn });

    await session.refresh();

    expect(refreshFn).toHaveBeenCalledTimes(1);
    expect(session.jwt).toBe(REFRESHED_JWT);
    expect(session.sessionId).toBe("sess-new");
    expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now() + 3600_000);
    expect(c.getToken()).toBe(REFRESHED_JWT);
  });

  it("throws when no refreshFn is configured", async () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await expect(session.refresh()).rejects.toThrow("no refreshFn configured");
  });

  it("coalesces concurrent refresh() calls into a single network request", async () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    let resolveRefresh!: (v: { jwt: string; session_id: string }) => void;
    const refreshFn = jest.fn().mockReturnValue(
      new Promise<{ jwt: string; session_id: string }>((res) => { resolveRefresh = res; }),
    );
    const session = new AgentumSession(c, "ag-1", "sess-coalesce", FUTURE_JWT, { refreshFn });

    // Fire two refresh calls concurrently
    const p1 = session.refresh();
    const p2 = session.refresh();

    resolveRefresh({ jwt: REFRESHED_JWT, session_id: "sess-new" });
    await Promise.all([p1, p2]);

    // refreshFn must have been called exactly once
    expect(refreshFn).toHaveBeenCalledTimes(1);
    expect(session.jwt).toBe(REFRESHED_JWT);
  });

  it("isNearExpiry() returns true when JWT expires within threshold", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", NEAR_EXPIRY_JWT);
    expect(session.isNearExpiry()).toBe(true);
  });

  it("isNearExpiry() returns false when JWT has ample lifetime remaining", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    expect(session.isNearExpiry()).toBe(false);
  });

  it("respects a custom refreshThresholdMs", () => {
    const f = mockNoContentFetch();
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    // JWT expires in 30s; threshold is 10s — should NOT be near expiry yet
    const session = new AgentumSession(c, "ag-1", "s-1", NEAR_EXPIRY_JWT, {
      refreshThresholdMs: 10_000,
    });
    expect(session.isNearExpiry()).toBe(false);
  });
});

// ── Auto-refresh in isAllowed / ingestAuditEvent ──────────────────────────────

describe("AgentumSession auto-refresh", () => {
  it("isAllowed() triggers refresh when JWT is near expiry", async () => {
    const policyResp = { outcome: "Allow", rule_id: null, reason: null };
    const f = mockFetch(policyResp);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const refreshFn = jest.fn().mockResolvedValue({ jwt: REFRESHED_JWT, session_id: "sess-new" });
    const session = new AgentumSession(c, "ag-1", "s-1", NEAR_EXPIRY_JWT, { refreshFn });

    await session.isAllowed("http.get", "https://api.example.com");

    expect(refreshFn).toHaveBeenCalledTimes(1);
    expect(c.getToken()).toBe(REFRESHED_JWT);
  });

  it("isAllowed() does NOT refresh when JWT is not near expiry", async () => {
    const policyResp = { outcome: "Allow", rule_id: null, reason: null };
    const f = mockFetch(policyResp);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const refreshFn = jest.fn().mockResolvedValue({ jwt: REFRESHED_JWT, session_id: "sess-new" });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT, { refreshFn });

    await session.isAllowed("http.get", "https://api.example.com");

    expect(refreshFn).not.toHaveBeenCalled();
  });

  it("ingestAuditEvent() triggers refresh when JWT is near expiry", async () => {
    const f = mockFetch({});
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const refreshFn = jest.fn().mockResolvedValue({ jwt: REFRESHED_JWT, session_id: "sess-new" });
    const session = new AgentumSession(c, "ag-1", "sess-audit", NEAR_EXPIRY_JWT, { refreshFn });

    await session.ingestAuditEvent({ event_type: "tool_call" });

    expect(refreshFn).toHaveBeenCalledTimes(1);
    expect(c.getToken()).toBe(REFRESHED_JWT);
  });

  it("ingestAuditEvent() never throws even when refresh fails", async () => {
    const f = mockFetch({});
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const refreshFn = jest.fn().mockRejectedValue(new Error("refresh failed"));
    const session = new AgentumSession(c, "ag-1", "sess-audit", NEAR_EXPIRY_JWT, { refreshFn });

    await expect(session.ingestAuditEvent({ event_type: "tool_call" })).resolves.toBeUndefined();
  });
});

// ── requestApproval() — Sprint 1.5.6 ─────────────────────────────────────────

import {
  AgentumHitlDeniedError,
  AgentumHitlTimeoutError,
} from "../src/types";

/** Create a fetch mock whose responses are queued in order of consumption. */
function queuedFetch(responses: Array<{ status?: number; body: unknown }>): jest.Mock {
  const f = jest.fn();
  for (const r of responses) {
    f.mockResolvedValueOnce({
      ok: (r.status ?? 200) < 400,
      status: r.status ?? 200,
      headers: { get: () => "application/json" },
      json: () => Promise.resolve(r.body),
      text: () => Promise.resolve(JSON.stringify(r.body)),
    });
  }
  return f;
}

describe("AgentumSession.requestApproval()", () => {
  it("creates request, polls, and resolves on approval", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-1", status: "pending" } },
      {
        body: {
          request_id: "req-1",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: "ok",
          action: "http.post",
          resource: "api.example.com",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    const result = await session.requestApproval({
      action: "http.post",
      resource: "api.example.com",
      timeout: 5000,
      pollIntervalMs: 250,
    });

    expect(result.status).toBe("approved");
    expect(result.decided_by).toEqual(["op@example.com"]);
    expect(result.reason).toBe("ok");
    expect(result.request_id).toBe("req-1");
    // Two HTTP calls: create + one poll.
    expect(f).toHaveBeenCalledTimes(2);
    const [createUrl] = f.mock.calls[0] as [string];
    expect(createUrl).toContain("/hitl/agent/requests");
  });

  it("throws AgentumHitlDeniedError on denial with reviewer reason", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-2", status: "pending" } },
      {
        body: {
          request_id: "req-2",
          agent_id: "ag-1",
          status: "denied",
          decided_by: ["admin@example.com"],
          reason: "too risky",
          action: "http.delete",
          resource: "prod-db",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await expect(
      session.requestApproval({
        action: "http.delete",
        resource: "prod-db",
        timeout: 5000,
        pollIntervalMs: 250,
      }),
    ).rejects.toMatchObject({
      name: "AgentumHitlDeniedError",
      requestId: "req-2",
      decidedBy: ["admin@example.com"],
      reason: "too risky",
    });
  });

  it("throws AgentumHitlTimeoutError when client deadline elapses while pending", async () => {
    const pendingBody = {
      request_id: "req-3",
      agent_id: "ag-1",
      status: "pending",
      decided_by: [],
      reason: null,
      action: "http.post",
      resource: "api.example.com",
      context: null,
      created_at: "2026-04-19T00:00:00Z",
      decided_at: null,
    };
    // Create + many polls — all pending.
    const responses: Array<{ status?: number; body: unknown }> = [
      { status: 201, body: { request_id: "req-3", status: "pending" } },
    ];
    for (let i = 0; i < 50; i++) responses.push({ body: pendingBody });
    const f = queuedFetch(responses);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await expect(
      session.requestApproval({
        action: "http.post",
        resource: "api.example.com",
        timeout: 600, // 0.6s — deliberately short to keep the test fast
        pollIntervalMs: 250,
      }),
    ).rejects.toBeInstanceOf(AgentumHitlTimeoutError);
  });

  it("validates action/resource", async () => {
    const f = mockFetch({});
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);
    await expect(
      session.requestApproval({ action: "", resource: "x" }),
    ).rejects.toThrow(/action and resource/);
    await expect(
      session.requestApproval({ action: "x", resource: "" }),
    ).rejects.toThrow(/action and resource/);
    expect(f).not.toHaveBeenCalled();
  });

  it("forwards reason and required_approvals into the create body", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-4", status: "pending" } },
      {
        body: {
          request_id: "req-4",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: null,
          action: "http.post",
          resource: "api.example.com",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.requestApproval({
      action: "http.post",
      resource: "api.example.com",
      reason: "Agent wants to merge PR #42",
      requiredApprovals: 2,
      timeout: 5000,
      pollIntervalMs: 250,
    });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as Record<string, unknown>;
    expect(body["action"]).toBe("http.post");
    expect(body["resource"]).toBe("api.example.com");
    expect(body["reason"]).toBe("Agent wants to merge PR #42");
    expect(body["required_approvals"]).toBe(2);
    expect(body["timeout_seconds"]).toBe(10); // 5000ms→5s, max(10, 5+5)=10
  });

  // L02b — when the caller threads `toolName` into requestApproval, a
  // successful approval registers a grant on the per-agent evaluator so
  // the next identical evaluateToolCall short-circuits without
  // contacting PDP / central / re-prompting.
  it("L02b: approval with toolName records a grant; next evaluateToolCall short-circuits", async () => {
    const f = queuedFetch([
      // 1. createHitlAgentRequest
      { status: 201, body: { request_id: "req-grant-1", status: "pending" } },
      // 2. first getHitlAgentRequest poll → approved
      {
        body: {
          request_id: "req-grant-1",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: null,
          action: "tool:search",
          resource: "search",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
      // 3. audit/ingest from the short-circuited evaluateToolCall —
      //    fire-and-forget, but the mock queue needs an entry so the
      //    detached POST doesn't pull a `mockResolvedValue undefined`
      //    later in the test.
      { status: 200, body: {} },
    ]);
    const c = new AgentumClient({
      baseUrl: BASE,
      apiKey: "k", // required for recordApprovalGrant / evaluateToolCall
      fetch: f as unknown as typeof fetch,
    });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    const result = await session.requestApproval({
      action: "tool:search",
      resource: "search",
      timeout: 5000,
      pollIntervalMs: 250,
      toolName: "search",
      toolArgs: { q: "hello" },
      advice: ["require_hitl:approvals=1,timeout=120"],
    });
    expect(result.status).toBe("approved");

    // After approval, the next evaluateToolCall for the same tool must
    // short-circuit: NO additional /sdk/evaluate-tool-call request, NO
    // additional /v1/authorize request, NO repeat /hitl/agent/requests
    // round trip. The cedar-client.ts audit POST is fire-and-forget so
    // we don't assert on its presence here.
    const callsBeforeEval = f.mock.calls.length;
    const evalResult = await c.evaluateToolCall("ag-1", {
      toolName: "search",
      arguments: { q: "hello" },
    });
    expect(evalResult.decision).toBe("allow");

    // Only audit-ingest fetches (if any) should have fired — definitely
    // no /sdk/evaluate-tool-call or /v1/authorize call.
    const newCalls = f.mock.calls.slice(callsBeforeEval);
    for (const call of newCalls) {
      const url = String(call[0]);
      expect(url).not.toContain("/sdk/evaluate-tool-call");
      expect(url).not.toContain("/v1/authorize");
      expect(url).not.toContain("/hitl/agent/requests");
    }
  });

  // GR-07 follow-up — when the caller threads `toolArgs`, the create body must
  // carry them under `context.arguments` so central derives its PDP grant from
  // the real args_hash (not hash(null)).
  it("GR-07: toolArgs are sent in the create body under context.arguments", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-ctx-1", status: "pending" } },
      {
        body: {
          request_id: "req-ctx-1",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: null,
          action: "tool:search",
          resource: "search",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
      { status: 200, body: {} }, // fire-and-forget audit ingest from the grant path
    ]);
    const c = new AgentumClient({
      baseUrl: BASE,
      apiKey: "k",
      fetch: f as unknown as typeof fetch,
    });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.requestApproval({
      action: "tool:search",
      resource: "search",
      context: { reasonHint: "user asked" },
      timeout: 5000,
      pollIntervalMs: 250,
      toolName: "search",
      toolArgs: { q: "hello" },
    });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as {
      context?: Record<string, unknown>;
    };
    expect(body.context).toEqual({
      reasonHint: "user asked",
      arguments: { q: "hello" },
    });
  });

  // GR-07 follow-up — when no toolArgs are present, the create body must NOT
  // carry an `arguments` key. This matches central's hash(null) semantics: the
  // derived grant only ever covers argument-less calls.
  it("GR-07: absent toolArgs → no arguments key in create-body context", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-ctx-2", status: "pending" } },
      {
        body: {
          request_id: "req-ctx-2",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: null,
          action: "tool:search",
          resource: "search",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
      { status: 200, body: {} },
    ]);
    const c = new AgentumClient({
      baseUrl: BASE,
      apiKey: "k",
      fetch: f as unknown as typeof fetch,
    });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.requestApproval({
      action: "tool:search",
      resource: "search",
      context: { reasonHint: "user asked" },
      timeout: 5000,
      pollIntervalMs: 250,
      toolName: "search",
      // no toolArgs
    });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as {
      context?: Record<string, unknown>;
    };
    // Original context survives unchanged; no `arguments` key injected.
    expect(body.context).toEqual({ reasonHint: "user asked" });
    expect(body.context).not.toHaveProperty("arguments");
  });

  // GR-07 follow-up — cross-tree consistency: the args payload the SDK sends in
  // `context.arguments` hashes (via the shared canonical-JSON SHA-256) to the
  // SAME digest central computes from that field, which is the SAME digest the
  // SDK's local grant key uses. Pinned vectors mirror hitl.rs hash_args + the
  // GR-08 cedar-client tests.
  it("GR-07: context.arguments hashes to the pinned cross-tree args_hash", async () => {
    const f = queuedFetch([
      { status: 201, body: { request_id: "req-ctx-3", status: "pending" } },
      {
        body: {
          request_id: "req-ctx-3",
          agent_id: "ag-1",
          status: "approved",
          decided_by: ["op@example.com"],
          reason: null,
          action: "tool:exec",
          resource: "exec",
          context: null,
          created_at: "2026-04-19T00:00:00Z",
          decided_at: "2026-04-19T00:00:01Z",
        },
      },
      { status: 200, body: {} },
    ]);
    const c = new AgentumClient({
      baseUrl: BASE,
      apiKey: "k",
      fetch: f as unknown as typeof fetch,
    });
    const session = new AgentumSession(c, "ag-1", "s-1", FUTURE_JWT);

    await session.requestApproval({
      action: "tool:exec",
      resource: "exec",
      timeout: 5000,
      pollIntervalMs: 250,
      toolName: "exec",
      toolArgs: { cmd: "ls" },
    });

    const [, init] = f.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((init as { body: string }).body) as {
      context?: { arguments?: unknown };
    };
    const sentArgs = body.context?.arguments;
    expect(sentArgs).toEqual({ cmd: "ls" });
    // sha256('{"cmd":"ls"}') — identical to hitl.rs hash_args(json!({"cmd":"ls"}))
    // and the GR-08 cedar-client pinned vector. Central computes the grant
    // args_hash from exactly this payload, so the two planes agree.
    await expect(hashArgsCanonical(sentArgs)).resolves.toBe(
      "a908494c958996ec8cebfa2e10728536e84904384b2497a4fbba9f48d99215ba",
    );
  });
});
