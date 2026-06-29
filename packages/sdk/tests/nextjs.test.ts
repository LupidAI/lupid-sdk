/**
 * Tests for the Next.js Agentum framework integration.
 *
 * `AgentumClient` is mocked — no network traffic. Covers:
 *
 *   - agentumMiddleware: user resolution, default derivation, allow/deny/error paths
 *   - createAgentumRuntime + withAgentumGuard: cache hit/miss, fail-mode, breaker,
 *     health-down short-circuit, custom onDeny
 *   - withAgentumServerAction: allow runs the action, deny returns a tagged error
 */
import {
  agentumMiddleware,
  createAgentumRuntime,
  withAgentumServerAction,
  DecisionCache,
  hashContext,
} from "../src/frameworks/nextjs";
import type {
  NextRequestLike,
  AgentumUser,
} from "../src/frameworks/nextjs";

// ── Test doubles ──────────────────────────────────────────────────────────────

function makeClient(
  overrides: {
    outcome?: "Allow" | "Deny";
    ruleId?: string | null;
    reason?: string | null;
    throws?: Error | null;
    policyHash?: string;
    decisionSource?:
      | "central_evaluated"
      | "central_cache_hit"
      | "local_pdp_evaluated"
      | "local_pdp_cache_hit";
  } = {},
) {
  const {
    outcome = "Allow",
    ruleId = null,
    reason = null,
    throws = null,
    policyHash,
    decisionSource,
  } = overrides;
  const simulatePolicy = jest.fn(async () => {
    if (throws) throw throws;
    return {
      outcome,
      rule_id: ruleId,
      reason,
      ...(policyHash !== undefined ? { policy_hash: policyHash } : {}),
      ...(decisionSource !== undefined ? { decision_source: decisionSource } : {}),
    };
  });
  const health = jest.fn(async () => ({ ok: true }));
  // L05c — guards now emit a best-effort request_denied audit on deny.
  // The mock is shaped as a stub jest.fn so tests can assert on calls.
  const ingestAuditEvent = jest.fn(async () => {});
  return {
    simulatePolicy,
    health,
    ingestAuditEvent,
  } as unknown as import("../src/client.js").AgentumClient;
}

function makeReq(
  opts: { method?: string; url?: string; headers?: Record<string, string> } = {},
): NextRequestLike {
  const { method = "GET", url = "https://app.example.com/api/orders", headers = {} } = opts;
  const headerMap = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    method,
    url,
    headers: { get: (name: string) => headerMap.get(name.toLowerCase()) ?? null },
    nextUrl: { pathname: new URL(url).pathname, search: new URL(url).search },
  };
}

function makeUser(overrides: Partial<AgentumUser> = {}): AgentumUser {
  return { id: "u_alice", email: "alice@example.com", trust: "trusted", ...overrides };
}

// ── agentumMiddleware ─────────────────────────────────────────────────────────

describe("agentumMiddleware — wiring", () => {
  it("throws if `runtime` is missing", () => {
    expect(() =>
      agentumMiddleware({
        // @ts-expect-error intentionally invalid
        runtime: null,
        agentId: "ag-1",
        userFromRequest: () => null,
      }),
    ).toThrow(/runtime/);
  });

  it("throws if `agentId` is missing", () => {
    expect(() =>
      agentumMiddleware({
        runtime: makeClient(),
        // @ts-expect-error intentionally invalid
        agentId: undefined,
        userFromRequest: () => null,
      }),
    ).toThrow(/agentId/);
  });

  it("throws if `userFromRequest` is not a function", () => {
    expect(() =>
      agentumMiddleware({
        runtime: makeClient(),
        agentId: "ag-1",
        // @ts-expect-error intentionally invalid
        userFromRequest: "not-a-function",
      }),
    ).toThrow(/userFromRequest/);
  });
});

describe("agentumMiddleware — request flow", () => {
  it("returns 401 when userFromRequest returns null", async () => {
    const client = makeClient();
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => null,
    });
    const res = await mw(makeReq());
    expect(res?.status).toBe(401);
    const body = JSON.parse(await res!.text());
    expect(body.error).toBe("unauthenticated");
  });

  it("invokes a custom onUnauthenticated", async () => {
    const mw = agentumMiddleware({
      runtime: makeClient(),
      agentId: "ag-1",
      userFromRequest: () => null,
      onUnauthenticated: () => new Response("nope", { status: 418 }),
    });
    const res = await mw(makeReq());
    expect(res?.status).toBe(418);
    expect(await res!.text()).toBe("nope");
  });

  it("passes through (undefined) on Allow", async () => {
    const client = makeClient({ outcome: "Allow" });
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const res = await mw(makeReq());
    expect(res).toBeUndefined();
    expect(client.simulatePolicy).toHaveBeenCalledTimes(1);
  });

  it("default-derives action, resource, context from the request", async () => {
    const client = makeClient({ outcome: "Allow" });
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    await mw(makeReq({ method: "POST", url: "https://example.com/api/orders/42" }));
    expect(client.simulatePolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        agent_id: "ag-1",
        action: "http.post",
        resource: "example.com",
        context: { path: "/api/orders/42" },
        user: { id: "u_alice", email: "alice@example.com", trust: "trusted" },
      }),
    );
  });

  it("returns 403 on Deny with the default onDeny body", async () => {
    const client = makeClient({ outcome: "Deny", ruleId: "r1", reason: "not allowed" });
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const res = await mw(makeReq());
    expect(res?.status).toBe(403);
    const body = JSON.parse(await res!.text());
    expect(body).toEqual({
      error: "forbidden",
      rule_id: "r1",
      reason: "not allowed",
      source: "network",
    });
  });

  it("calls custom onDeny with the decision", async () => {
    const onDeny = jest.fn((_req, _decision) => new Response("denied", { status: 451 }));
    const mw = agentumMiddleware({
      runtime: makeClient({ outcome: "Deny", ruleId: "r2", reason: "nope" }),
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      onDeny,
    });
    const res = await mw(makeReq());
    expect(res?.status).toBe(451);
    expect(onDeny).toHaveBeenCalledTimes(1);
    const decision = onDeny.mock.calls[0]![1];
    expect(decision).toMatchObject({ outcome: "Deny", rule_id: "r2", reason: "nope" });
  });

  it("fails closed (503) when simulatePolicy throws", async () => {
    const mw = agentumMiddleware({
      runtime: makeClient({ throws: new Error("boom") }),
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const res = await mw(makeReq());
    expect(res?.status).toBe(503);
    const body = JSON.parse(await res!.text());
    expect(body.fallback).toBe("closed");
  });

  it("skips authorization when deriveRequest returns null", async () => {
    const client = makeClient({ outcome: "Deny" });
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      deriveRequest: () => null,
    });
    const res = await mw(makeReq());
    expect(res).toBeUndefined();
    expect(client.simulatePolicy).not.toHaveBeenCalled();
  });

  it("honours a custom deriveRequest", async () => {
    const client = makeClient({ outcome: "Allow" });
    const mw = agentumMiddleware({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      deriveRequest: () => ({
        action: "mcp.tool.call",
        resource: "gmail.send",
        context: { extra: "x" },
      }),
    });
    await mw(makeReq());
    expect(client.simulatePolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "mcp.tool.call",
        resource: "gmail.send",
        context: { extra: "x" },
      }),
    );
  });
});

// ── createAgentumRuntime + withAgentumGuard ──────────────────────────────────

describe("createAgentumRuntime", () => {
  it("throws if `runtime` is missing", () => {
    expect(() =>
      // @ts-expect-error intentionally invalid
      createAgentumRuntime({ agentId: "ag-1" }),
    ).toThrow(/runtime/);
  });

  it("throws if `agentId` is missing", () => {
    expect(() =>
      // @ts-expect-error intentionally invalid
      createAgentumRuntime({ runtime: makeClient() }),
    ).toThrow(/agentId/);
  });

  it("exposes resilience primitives on `_internals`", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient(),
      agentId: "ag-1",
      healthCheck: { enabled: false }, // avoid background timer in tests
    });
    expect(rt._internals.decisionCache).not.toBeNull();
    expect(rt._internals.circuitBreaker).not.toBeNull();
    expect(rt._internals.healthMonitor).toBeNull();
    await rt.close();
  });
});

describe("withAgentumGuard — allow / deny", () => {
  it("runs the handler when policy allows", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ outcome: "Allow" }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      handler,
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
    await rt.close();
  });

  it("returns 403 on Deny without calling the handler", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ outcome: "Deny", ruleId: "r3", reason: "blocked" }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      handler,
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    const body = JSON.parse(await res.text());
    expect(body.rule_id).toBe("r3");
    await rt.close();
  });

  it("returns 401 when userFromRequest returns null", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient(),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => null,
      },
      handler,
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
    await rt.close();
  });

  it("calls custom onDeny", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ outcome: "Deny" }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const onDeny = jest.fn(() => new Response("custom", { status: 418 }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
        onDeny,
      },
      async () => Response.json({ ok: true }),
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(418);
    expect(onDeny).toHaveBeenCalled();
    await rt.close();
  });

  it("L05c: emits request_denied audit with policy_hash + decision_source threaded from simulatePolicy", async () => {
    const policyHash = "ab".repeat(32);
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_forbid",
      reason: "policy_says_no",
      policyHash,
      decisionSource: "central_evaluated",
    });
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-7",
      healthCheck: { enabled: false },
    });
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.delete",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      async () => Response.json({ ok: true }),
    );
    const res = await wrapped(makeReq({ method: "DELETE" }), { params: {} });
    expect(res.status).toBe(403);
    // Defer past the void-promise emit.
    await Promise.resolve();
    const ingest = (client as unknown as { ingestAuditEvent: jest.Mock }).ingestAuditEvent;
    expect(ingest).toHaveBeenCalledTimes(1);
    const payload = ingest.mock.calls[0]![0] as {
      event_type: string;
      outcome?: string;
      agent_id: string;
      session_id: string;
      policy_hash?: string;
      decision_source?: string;
      detail: Record<string, unknown>;
    };
    expect(payload.event_type).toBe("request_denied");
    expect(payload.outcome).toBe("deny");
    expect(payload.agent_id).toBe("ag-7");
    // Q3 (deferred): session_id is empty until AgentumNextRuntimeOptions
    // widens to carry sessionId.
    expect(payload.session_id).toBe("");
    expect(payload.policy_hash).toBe(policyHash);
    expect(payload.decision_source).toBe("central_evaluated");
    expect(payload.detail).toMatchObject({
      action: "http.delete",
      resource: "api.example.com",
      framework: "nextjs.route-handler",
      rule_id: "r_forbid",
      reason: "policy_says_no",
      source: "network",
    });
    expect(payload.detail["policy_hash"]).toBeUndefined();
    expect(payload.detail["decision_source"]).toBeUndefined();
    await rt.close();
  });
});

describe("withAgentumGuard — decision cache", () => {
  it("serves a cache hit without calling simulatePolicy", async () => {
    const client = makeClient({ outcome: "Allow" });
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      handler,
    );
    await wrapped(makeReq(), { params: {} });
    await wrapped(makeReq(), { params: {} });
    expect(client.simulatePolicy).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledTimes(2);
    await rt.close();
  });

  it("skipCache=true forces a fresh network call every time", async () => {
    const client = makeClient({ outcome: "Allow" });
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
        skipCache: true,
      },
      async () => Response.json({ ok: true }),
    );
    await wrapped(makeReq(), { params: {} });
    await wrapped(makeReq(), { params: {} });
    expect(client.simulatePolicy).toHaveBeenCalledTimes(2);
    await rt.close();
  });
});

describe("withAgentumGuard — fail-mode", () => {
  it("defaults to fail-closed (403) when simulatePolicy throws", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ throws: new Error("down") }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      async () => Response.json({ ok: true }),
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(403);
    const body = JSON.parse(await res.text());
    expect(body.source).toBe("fail-closed");
    await rt.close();
  });

  it("fail-mode `open` allows the request through when simulatePolicy throws", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ throws: new Error("down") }),
      agentId: "ag-1",
      failMode: "open",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      handler,
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    await rt.close();
  });

  it("fail-mode `cached` serves the last-known-good Allow", async () => {
    // First call: success + cache populated. Second call: fail → stale hit.
    const simulatePolicy = jest
      .fn()
      .mockResolvedValueOnce({ outcome: "Allow", rule_id: "r-good", reason: null })
      .mockRejectedValueOnce(new Error("down"));
    const client = {
      simulatePolicy,
      ingestAuditEvent: jest.fn(async () => {}),
    } as unknown as import("../src/client.js").AgentumClient;
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      failMode: "cached",
      decisionCache: { ttlMs: 1 }, // so the 2nd call misses the *fresh* cache
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      handler,
    );
    await wrapped(makeReq(), { params: {} });
    // Force fresh cache expiry by waiting past TTL.
    await new Promise((r) => setTimeout(r, 5));
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(2);
    await rt.close();
  });

  it("failModeOverride on the guard beats the runtime default", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ throws: new Error("down") }),
      agentId: "ag-1",
      failMode: "closed",
      healthCheck: { enabled: false },
    });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
        failModeOverride: "open",
      },
      handler,
    );
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    await rt.close();
  });
});

describe("withAgentumGuard — breaker & health short-circuit", () => {
  it("short-circuits to fail-mode when the breaker is open", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ throws: new Error("down") }),
      agentId: "ag-1",
      circuitBreaker: { failureThreshold: 2, resetTimeoutMs: 60_000 },
      healthCheck: { enabled: false },
    });
    const wrapped = rt.withAgentumGuard(
      {
        action: "http.get",
        resource: "api.example.com",
        userFromRequest: () => makeUser(),
      },
      async () => Response.json({ ok: true }),
    );
    // Two failures → breaker opens.
    await wrapped(makeReq(), { params: {} });
    await wrapped(makeReq(), { params: {} });
    // Third call: breaker is open, should short-circuit.
    const res = await wrapped(makeReq(), { params: {} });
    expect(res.status).toBe(403);
    const body = JSON.parse(await res.text());
    expect(body.source).toBe("breaker-open");
    await rt.close();
  });
});

// ── withAgentumServerAction ──────────────────────────────────────────────────

describe("withAgentumServerAction", () => {
  it("runs the action on Allow and returns ok=true with data", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ outcome: "Allow" }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const action = jest.fn(async ({ x }: { x: number }) => ({ doubled: x * 2 }));
    const wrapped = withAgentumServerAction(
      rt,
      {
        action: "http.post",
        resource: "api.example.com",
        getUser: () => makeUser(),
      },
      action,
    );
    const result = await wrapped({ x: 21 });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toEqual({ doubled: 42 });
    expect(action).toHaveBeenCalledTimes(1);
    await rt.close();
  });

  it("returns ok=false / error=forbidden on Deny without invoking the action", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient({ outcome: "Deny", ruleId: "r1", reason: "no" }),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const action = jest.fn(async () => ({ data: "sensitive" }));
    const wrapped = withAgentumServerAction(
      rt,
      {
        action: "http.post",
        resource: "api.example.com",
        getUser: () => makeUser(),
      },
      action,
    );
    const result = await wrapped();
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("forbidden");
      expect(result.decision?.rule_id).toBe("r1");
    }
    expect(action).not.toHaveBeenCalled();
    await rt.close();
  });

  it("L05c: emits request_denied audit with policy_hash + decision_source on Deny", async () => {
    const policyHash = "ab".repeat(32);
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_forbid",
      reason: "policy_says_no",
      policyHash,
      decisionSource: "central_evaluated",
    });
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-9",
      healthCheck: { enabled: false },
    });
    const action = jest.fn(async () => ({ ok: true }));
    const wrapped = withAgentumServerAction(
      rt,
      {
        action: "http.delete",
        resource: "api.example.com",
        getUser: () => makeUser(),
      },
      action,
    );
    const result = await wrapped();
    expect(result.ok).toBe(false);
    await Promise.resolve();
    const ingest = (client as unknown as { ingestAuditEvent: jest.Mock }).ingestAuditEvent;
    expect(ingest).toHaveBeenCalledTimes(1);
    const payload = ingest.mock.calls[0]![0] as {
      event_type: string;
      outcome?: string;
      agent_id: string;
      session_id: string;
      policy_hash?: string;
      decision_source?: string;
      detail: Record<string, unknown>;
    };
    expect(payload.event_type).toBe("request_denied");
    expect(payload.outcome).toBe("deny");
    expect(payload.agent_id).toBe("ag-9");
    expect(payload.session_id).toBe("");
    expect(payload.policy_hash).toBe(policyHash);
    expect(payload.decision_source).toBe("central_evaluated");
    expect(payload.detail).toMatchObject({
      action: "http.delete",
      resource: "api.example.com",
      framework: "nextjs.server-action",
      rule_id: "r_forbid",
      reason: "policy_says_no",
      source: "network",
    });
    expect(payload.detail["policy_hash"]).toBeUndefined();
    expect(payload.detail["decision_source"]).toBeUndefined();
    expect(action).not.toHaveBeenCalled();
    await rt.close();
  });

  it("returns ok=false / error=unauthenticated when getUser returns null", async () => {
    const rt = createAgentumRuntime({
      runtime: makeClient(),
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const action = jest.fn();
    const wrapped = withAgentumServerAction(
      rt,
      {
        action: "http.post",
        resource: "api.example.com",
        getUser: () => null,
      },
      action,
    );
    const result = await wrapped();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("unauthenticated");
    expect(action).not.toHaveBeenCalled();
    await rt.close();
  });

  it("derives `context.path` from the first argument via pathLike", async () => {
    const client = makeClient({ outcome: "Allow" });
    const rt = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      healthCheck: { enabled: false },
    });
    const wrapped = withAgentumServerAction(
      rt,
      {
        action: "http.delete",
        resource: "api.example.com",
        pathLike: (arg) => `/orders/${(arg as { id: string }).id}`,
        getUser: () => makeUser(),
      },
      async ({ id }: { id: string }) => ({ deleted: id }),
    );
    await wrapped({ id: "ord_42" });
    expect(client.simulatePolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        context: { path: "/orders/ord_42" },
      }),
    );
    await rt.close();
  });
});

// ── Shared primitives re-exports ──────────────────────────────────────────────

describe("nextjs re-exports express primitives", () => {
  it("exports DecisionCache + hashContext (same semantics as express)", () => {
    const c = new DecisionCache({ maxSize: 5, ttlMs: 1_000 });
    const k = DecisionCache.key("u", "a", "r", hashContext({ x: 1 }));
    c.put(k, { outcome: "Allow", rule_id: null, reason: null });
    expect(c.get(k)?.outcome).toBe("Allow");
  });

  it("hashContext is stable regardless of key order", () => {
    expect(hashContext({ a: 1, b: 2 })).toBe(hashContext({ b: 2, a: 1 }));
  });
});
