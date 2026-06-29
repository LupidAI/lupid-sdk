/**
 * Tests for the Express.js Agentum middleware.
 *
 * All dependencies (AgentumClient, AgentumSession) are mocked so no network
 * calls are made. Tests cover:
 *
 *  - req.agentum injection (session, agentId, sessionId, tenantId)
 *  - Session pool reuse (same key → same session object)
 *  - Session pool invalidation on expiry
 *  - enforce mode: 403 on denied
 *  - observe mode: never blocks
 *  - resolveAgent error propagation
 *  - connect() vs connectExisting() path
 *  - audit events (request_start, request_end, request_denied)
 *  - custom onDeny handler
 *  - LRU eviction calls close() on evicted session
 */

import {
  agentumMiddleware,
  agentumGuard,
  DecisionCache,
  CircuitBreaker,
  HealthMonitor,
  hashContext,
} from "../src/frameworks/express";
import type {
  AgentumRequest,
  AgentumResponse,
  AgentumNext,
  AgentumUser,
  GuardDecision,
} from "../src/frameworks/express";

// ── Mock helpers ──────────────────────────────────────────────────────────────

function makeSession(overrides: Partial<{
  agentId: string;
  sessionId: string;
  expired: boolean;
  allowed: boolean;
}> = {}) {
  const { agentId = "ag-1", sessionId = "sess-1", expired = false, allowed = true } = overrides;
  return {
    agentId,
    sessionId,
    isExpired: jest.fn(() => expired),
    isAllowed: jest.fn(async () => allowed),
    ingestAuditEvent: jest.fn(async () => {}),
    close: jest.fn(async () => {}),
  };
}

function makeClient(session = makeSession()) {
  return {
    connectExisting: jest.fn(async () => session),
    connect: jest.fn(async () => session),
  };
}

function makeReq(overrides: Partial<AgentumRequest> = {}): AgentumRequest {
  return {
    headers: {},
    method: "GET",
    path: "/api/data",
    ...overrides,
  };
}

function makeRes(opts: { statusCode?: number } = {}): AgentumResponse & { _statusCode: number; _body: unknown; _finishListeners: (() => void)[] } {
  const res = {
    _statusCode: opts.statusCode ?? 200,
    _body: undefined as unknown,
    _finishListeners: [] as (() => void)[],
    get statusCode() { return res._statusCode; },
    status(code: number) { res._statusCode = code; return res; },
    json(body: unknown) { res._body = body; },
    end() {},
    on(event: string, listener: () => void) {
      if (event === "finish") res._finishListeners.push(listener);
    },
  };
  return res;
}

function flushFinish(res: ReturnType<typeof makeRes>) {
  res._finishListeners.forEach((fn) => fn());
}

function makeNext(): AgentumNext & { called: boolean; err: unknown } {
  const fn = Object.assign(
    (err?: unknown) => { fn.called = true; fn.err = err; },
    { called: false, err: undefined as unknown },
  );
  return fn;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("agentumMiddleware — req.agentum injection", () => {
  it("injects session, agentId, sessionId into req.agentum", async () => {
    const session = makeSession({ agentId: "ag-42", sessionId: "sess-99" });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ agentId: "ag-42" }),
      mode: "observe",
    });
    const req = makeReq();
    await mw(req, makeRes(), makeNext());
    expect(req.agentum?.agentId).toBe("ag-42");
    expect(req.agentum?.sessionId).toBe("sess-99");
    expect(req.agentum?.session).toBe(session);
  });

  it("injects tenantId when resolveAgent provides it", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ agentId: "ag-1", tenantId: "tenant-abc" }),
      mode: "observe",
    });
    const req = makeReq();
    await mw(req, makeRes(), makeNext());
    expect(req.agentum?.tenantId).toBe("tenant-abc");
  });

  it("calls next() to pass control downstream", async () => {
    const client = makeClient() as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    const next = makeNext();
    await mw(makeReq(), makeRes(), next);
    expect(next.called).toBe(true);
    expect(next.err).toBeUndefined();
  });
});

describe("agentumMiddleware — session pool reuse", () => {
  it("reuses the same session for the same pool key", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });

    await mw(makeReq(), makeRes(), makeNext());
    await mw(makeReq(), makeRes(), makeNext());

    // connectExisting called only once; second request reused pool
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
  });

  it("creates a new session when the pooled one is expired", async () => {
    const expiredSession = makeSession({ expired: true });
    const freshSession = makeSession({ agentId: "ag-fresh", sessionId: "sess-fresh" });
    const client = {
      connectExisting: jest.fn()
        .mockResolvedValueOnce(expiredSession)
        .mockResolvedValueOnce(freshSession),
    } as any;

    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });

    // First request: gets expiredSession
    const req1 = makeReq();
    await mw(req1, makeRes(), makeNext());

    // Second request: expired → fetches fresh
    const req2 = makeReq();
    await mw(req2, makeRes(), makeNext());

    expect(client.connectExisting).toHaveBeenCalledTimes(2);
    expect(req2.agentum?.agentId).toBe("ag-fresh");
  });

  it("uses connect() when no agentId provided (auto-register path)", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ name: "new-bot", ownerEmail: "o@example.com", purpose: "test" }),
      mode: "observe",
    });
    await mw(makeReq(), makeRes(), makeNext());
    expect(client.connect).toHaveBeenCalledTimes(1);
    expect(client.connectExisting).not.toHaveBeenCalled();
  });

  // G-F regression: when the middleware is mounted on nested routers
  // (LibreChat does this for `agents/index.js` outer + inner v1 router),
  // it gets invoked multiple times in the same request chain. Pre-fix,
  // each invocation minted a fresh `request_start` audit event and
  // re-ran `isAllowed`, producing 3+ DB writes per logical request.
  // The req.agentum guard now short-circuits subsequent calls.
  it("is idempotent across multiple middleware passes on the same request", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ agentId: "ag-1" }),
      mode: "observe",
    });

    // Same `req` object reused — simulates two nested router middlewares
    // both invoking the handler in the same request chain.
    const req = makeReq();
    const next1 = makeNext();
    const next2 = makeNext();

    await mw(req, makeRes(), next1);
    expect(req.agentum).toBeDefined();
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
    expect(session.ingestAuditEvent).toHaveBeenCalledTimes(1);

    // Second pass: must reuse the attached context and not call the
    // client or audit emitter again.
    await mw(req, makeRes(), next2);
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
    expect(session.ingestAuditEvent).toHaveBeenCalledTimes(1);
    expect(next2.called).toBe(true);
    expect(next2.err).toBeUndefined();
  });
});

describe("agentumMiddleware — enforce mode", () => {
  it("calls next() when isAllowed returns true", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "enforce" });
    const next = makeNext();
    await mw(makeReq({ method: "GET", path: "/data" }), makeRes(), next);
    expect(next.called).toBe(true);
    expect(next.err).toBeUndefined();
  });

  it("responds 403 when isAllowed returns false", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "enforce" });
    const res = makeRes();
    const next = makeNext();
    await mw(makeReq({ method: "DELETE", path: "/secret" }), res, next);
    expect(res._statusCode).toBe(403);
    expect(next.called).toBe(false);
  });

  it("passes the correct Cedar action derived from HTTP method", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "enforce" });
    await mw(makeReq({ method: "POST", path: "/submit" }), makeRes(), makeNext());
    expect(session.isAllowed).toHaveBeenCalledWith("http.post", "/submit");
  });

  it("uses custom onDeny handler when provided", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session) as any;
    const onDeny = jest.fn();
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ agentId: "ag-1" }),
      mode: "enforce",
      onDeny,
    });
    await mw(makeReq(), makeRes(), makeNext());
    expect(onDeny).toHaveBeenCalledTimes(1);
  });
});

describe("agentumMiddleware — observe mode", () => {
  it("never blocks requests even when isAllowed returns false", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    const next = makeNext();
    const res = makeRes();
    await mw(makeReq(), res, next);
    expect(next.called).toBe(true);
    expect(res._statusCode).toBe(200); // unchanged
  });

  it("does not call isAllowed in observe mode", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    await mw(makeReq(), makeRes(), makeNext());
    expect(session.isAllowed).not.toHaveBeenCalled();
  });
});

describe("agentumMiddleware — audit events", () => {
  it("emits request_start audit event", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    await mw(makeReq({ method: "GET", path: "/foo" }), makeRes(), makeNext());
    // Wait for microtasks (void async calls)
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const startCall = calls.find((c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_start");
    expect(startCall).toBeDefined();
    expect(startCall![0].detail).toMatchObject({ method: "GET", path: "/foo" });
  });

  it("emits request_end after the response finishes (res.on('finish'))", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    const res = makeRes({ statusCode: 200 });
    await mw(makeReq({ method: "GET", path: "/bar" }), res, makeNext());
    await Promise.resolve();

    // Before flush: request_end must NOT have fired yet
    const callsBefore = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const endBefore = callsBefore.find((c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_end");
    expect(endBefore).toBeUndefined();

    // After flush: request_end must fire with status_code
    flushFinish(res);
    await Promise.resolve();
    const callsAfter = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const endCall = callsAfter.find((c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_end");
    expect(endCall).toBeDefined();
    expect(endCall![0].detail).toMatchObject({ method: "GET", path: "/bar", status_code: 200 });
  });

  it("emits request_denied when enforce mode denies", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "enforce" });
    await mw(makeReq({ method: "DELETE", path: "/protected" }), makeRes(), makeNext());
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const deniedCall = calls.find((c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_denied");
    expect(deniedCall).toBeDefined();
  });
});

describe("agentumMiddleware — error handling", () => {
  it("calls next(err) when resolveAgent throws", async () => {
    const client = makeClient() as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => { throw new Error("resolve failed"); },
      mode: "observe",
    });
    const next = makeNext();
    await mw(makeReq(), makeRes(), next);
    expect(next.err).toBeInstanceOf(Error);
  });

  it("calls next(err) when connect() rejects", async () => {
    const client = { connectExisting: jest.fn().mockRejectedValue(new Error("network down")) } as any;
    const mw = agentumMiddleware({ client, resolveAgent: () => ({ agentId: "ag-1" }), mode: "observe" });
    const next = makeNext();
    await mw(makeReq(), makeRes(), next);
    expect(next.err).toBeInstanceOf(Error);
    expect((next.err as Error).message).toBe("network down");
  });
});

describe("agentumMiddleware — LRU pool eviction", () => {
  it("evicts oldest session and calls close() when pool is full", async () => {
    const sessions = Array.from({ length: 3 }, (_, i) =>
      makeSession({ agentId: `ag-${i}`, sessionId: `sess-${i}` }),
    );
    let callCount = 0;
    const client = {
      connectExisting: jest.fn(async () => sessions[callCount++]),
    } as any;

    // maxPoolSize=2 so third entry evicts the first
    const mw = agentumMiddleware({
      client,
      resolveAgent: (req) => ({ agentId: req.headers["x-agent-id"] as string }),
      mode: "observe",
      maxPoolSize: 2,
    });

    await mw(makeReq({ headers: { "x-agent-id": "ag-0" } }), makeRes(), makeNext());
    await mw(makeReq({ headers: { "x-agent-id": "ag-1" } }), makeRes(), makeNext());
    await mw(makeReq({ headers: { "x-agent-id": "ag-2" } }), makeRes(), makeNext());

    // ag-0's session should have been evicted and closed
    await Promise.resolve(); // flush microtasks
    expect(sessions[0]!.close).toHaveBeenCalled();
  });

  it("concurrent requests for the same agentId create only one session", async () => {
    const session = makeSession({ agentId: "ag-shared" });
    let resolveConnect!: (s: typeof session) => void;
    const stalled = new Promise<typeof session>((res) => { resolveConnect = res; });
    const connectExisting = jest.fn(() => stalled);
    const client = { connectExisting } as any;
    const mw = agentumMiddleware({
      client,
      resolveAgent: () => ({ agentId: "ag-shared" }),
      mode: "observe",
    });

    // Fire 5 concurrent requests before the first connect resolves
    const p1 = mw(makeReq(), makeRes(), makeNext());
    const p2 = mw(makeReq(), makeRes(), makeNext());
    const p3 = mw(makeReq(), makeRes(), makeNext());

    resolveConnect(session); // release the stalled connect
    await Promise.all([p1, p2, p3]);

    // connectExisting must have been called exactly once
    expect(connectExisting).toHaveBeenCalledTimes(1);
  });
});

describe("agentumMiddleware — tokenFromRequest (verified mode)", () => {
  it("mints a session with user:{token} when tokenFromRequest resolves a string", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      tokenFromRequest: () => "eyJhbGciOiJIUzI1NiJ9.payload.sig",
      mode: "observe",
    });
    await mw(makeReq(), makeRes(), makeNext());
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
    const [passedAgentId, passedOpts] = client.connectExisting.mock.calls[0];
    expect(passedAgentId).toBe("ag-1");
    expect(passedOpts.user).toEqual({ token: "eyJhbGciOiJIUzI1NiJ9.payload.sig" });
    expect(passedOpts.skipPolicyCheck).toBe(true);
  });

  it("calls onUnauthenticated when tokenFromRequest returns null", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const onUnauth = jest.fn((_req, res, _next) => { res.status(401).json({ e: "no" }); });
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      tokenFromRequest: () => null,
      onUnauthenticated: onUnauth,
      mode: "observe",
    });
    const res = makeRes();
    await mw(makeReq(), res, makeNext());
    expect(onUnauth).toHaveBeenCalledTimes(1);
    expect(client.connectExisting).not.toHaveBeenCalled();
    expect(res._statusCode).toBe(401);
  });

  it("distinct tokens produce distinct pool entries", async () => {
    const sessionA = makeSession({ agentId: "ag-1", sessionId: "sess-a" });
    const sessionB = makeSession({ agentId: "ag-1", sessionId: "sess-b" });
    const client = {
      connectExisting: jest.fn()
        .mockResolvedValueOnce(sessionA)
        .mockResolvedValueOnce(sessionB),
    } as any;
    let whichToken = 0;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      tokenFromRequest: () => (whichToken++ === 0 ? "token.for.alice" : "token.for.bob"),
      mode: "observe",
    });

    await mw(makeReq(), makeRes(), makeNext());
    await mw(makeReq(), makeRes(), makeNext());

    expect(client.connectExisting).toHaveBeenCalledTimes(2);
  });

  it("repeated requests with the same token reuse the pooled session", async () => {
    const session = makeSession();
    const client = makeClient(session) as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      tokenFromRequest: () => "same.token.everywhere",
      mode: "observe",
    });

    await mw(makeReq(), makeRes(), makeNext());
    await mw(makeReq(), makeRes(), makeNext());

    expect(client.connectExisting).toHaveBeenCalledTimes(1);
  });

  it("throws when both userFromRequest and tokenFromRequest are supplied", () => {
    const client = makeClient() as any;
    expect(() =>
      agentumMiddleware({
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        tokenFromRequest: () => "t",
      }),
    ).toThrow(/mutually exclusive/);
  });

  it("propagates errors thrown by tokenFromRequest via next(err)", async () => {
    const client = makeClient() as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      tokenFromRequest: () => { throw new Error("cookie parse failed"); },
      mode: "observe",
    });
    const next = makeNext();
    await mw(makeReq(), makeRes(), next);
    expect(next.err).toBeInstanceOf(Error);
    expect((next.err as Error).message).toBe("cookie parse failed");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Sprint 1.5.1 additions — decision cache, fail-mode, circuit breaker, health
// check, and the per-route `agentumGuard()` helper.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Helpers for the new surface ─────────────────────────────────────────────────

function makeGuardSession(
  overrides: {
    agentId?: string;
    sessionId?: string;
    outcome?: "Allow" | "Deny";
    ruleId?: string | null;
    reason?: string | null;
    advice?: string[];
    simulateThrows?: Error | null;
    requestApproval?: jest.Mock;
    policyHash?: string;
    /** R45b — `addon.policy.hitl` enablement. Defaults to `true`
     *  (fail-OPEN), matching the runtime's cold-start posture. */
    hitlAddonEnabled?: boolean;
    decisionSource?:
      | "central_evaluated"
      | "central_cache_hit"
      | "local_pdp_evaluated"
      | "local_pdp_cache_hit";
  } = {},
) {
  const {
    agentId = "ag-1",
    sessionId = "sess-1",
    outcome = "Allow",
    ruleId = null,
    reason = null,
    advice,
    simulateThrows = null,
    requestApproval = jest.fn(async () => ({
      status: "approved",
      decided_by: "reviewer@example.com",
      request_id: "req-1",
    })),
    policyHash,
    hitlAddonEnabled = true,
    decisionSource,
  } = overrides;
  const simulatePolicy = jest.fn(async () => {
    if (simulateThrows) throw simulateThrows;
    return {
      outcome,
      rule_id: ruleId,
      reason,
      ...(advice ? { advice } : {}),
      ...(policyHash !== undefined ? { policy_hash: policyHash } : {}),
      ...(decisionSource !== undefined ? { decision_source: decisionSource } : {}),
    };
  });
  return {
    agentId,
    sessionId,
    isExpired: jest.fn(() => false),
    isAllowed: jest.fn(async () => outcome === "Allow"),
    ingestAuditEvent: jest.fn(async () => {}),
    requestApproval,
    isHitlAddonEnabled: jest.fn(() => hitlAddonEnabled),
    close: jest.fn(async () => {}),
    client: { simulatePolicy },
  };
}

function makeUser(id = "u_alice", email = "alice@example.com"): AgentumUser {
  return { id, email, trust: "trusted" };
}

// Run the middleware + a guard against one request. Returns everything tests
// typically want to assert on.
async function runWithGuard(
  mwOpts: Parameters<typeof agentumMiddleware>[0],
  guardOpts: Parameters<typeof agentumGuard>[0],
  reqOverrides: Partial<AgentumRequest> = {},
) {
  const mw = agentumMiddleware(mwOpts);
  const guard = agentumGuard(guardOpts);
  const req = makeReq(reqOverrides);
  const res = makeRes();
  const mwNext = makeNext();
  await mw(req, res, mwNext);
  const guardNext = makeNext();
  await guard(req, res, guardNext);
  return { req, res, mwNext, guardNext, mw };
}

// ── DecisionCache unit tests ───────────────────────────────────────────────────

describe("DecisionCache", () => {
  it("returns fresh entries before TTL expires", () => {
    const cache = new DecisionCache({ maxSize: 10, ttlMs: 10_000 });
    const key = DecisionCache.key("u1", "http.get", "api.example.com", "ctx");
    cache.put(key, { outcome: "Allow", rule_id: "r1", reason: null });
    expect(cache.get(key)?.outcome).toBe("Allow");
  });

  it("evicts expired entries on get (but retains them as stale)", () => {
    jest.useFakeTimers();
    try {
      const cache = new DecisionCache({ maxSize: 10, ttlMs: 1_000 });
      const key = DecisionCache.key("u1", "a", "r", "");
      cache.put(key, { outcome: "Allow", rule_id: null, reason: null });
      jest.advanceTimersByTime(2_000);
      expect(cache.get(key)).toBeUndefined();
      expect(cache.getStale(key)?.outcome).toBe("Allow");
    } finally {
      jest.useRealTimers();
    }
  });

  it("evicts the oldest fresh entry when at capacity", () => {
    const cache = new DecisionCache({ maxSize: 2, ttlMs: 60_000 });
    const k1 = DecisionCache.key("u1", "a", "r", "");
    const k2 = DecisionCache.key("u2", "a", "r", "");
    const k3 = DecisionCache.key("u3", "a", "r", "");
    cache.put(k1, { outcome: "Allow", rule_id: null, reason: null });
    cache.put(k2, { outcome: "Allow", rule_id: null, reason: null });
    cache.put(k3, { outcome: "Allow", rule_id: null, reason: null });
    expect(cache.get(k1)).toBeUndefined(); // oldest fresh entry evicted
    expect(cache.get(k2)?.outcome).toBe("Allow");
    expect(cache.get(k3)?.outcome).toBe("Allow");
  });

  it("invalidateAll() drops both fresh and stale stores", () => {
    const cache = new DecisionCache({ maxSize: 10, ttlMs: 1 });
    const k = DecisionCache.key("u", "a", "r", "");
    cache.put(k, { outcome: "Allow", rule_id: null, reason: null });
    cache.invalidateAll();
    expect(cache.get(k)).toBeUndefined();
    expect(cache.getStale(k)).toBeUndefined();
  });

  it("hashContext() is deterministic regardless of key insertion order", () => {
    const a = hashContext({ a: 1, b: 2, nested: { y: 2, x: 1 } });
    const b = hashContext({ b: 2, nested: { x: 1, y: 2 }, a: 1 });
    expect(a).toBe(b);
  });
});

// ── CircuitBreaker unit tests ──────────────────────────────────────────────────

describe("CircuitBreaker", () => {
  it("stays closed until the failure threshold is crossed", () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 1_000 });
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.shouldSkip()).toBe(false);
    cb.recordFailure();
    expect(cb.shouldSkip()).toBe(true);
    expect(cb.state).toBe("open");
  });

  it("transitions to half-open after resetTimeoutMs, then closed on probe success", () => {
    jest.useFakeTimers();
    try {
      const cb = new CircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 500 });
      cb.recordFailure();
      expect(cb.state).toBe("open");
      jest.advanceTimersByTime(600);

      // First caller probes; subsequent callers still see open-equivalent.
      expect(cb.shouldSkip()).toBe(false); // this caller is the probe
      expect(cb.state).toBe("half-open");
      expect(cb.shouldSkip()).toBe(true); // subsequent caller short-circuits

      cb.recordSuccess();
      expect(cb.state).toBe("closed");
      expect(cb.shouldSkip()).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });

  it("re-opens when the half-open probe fails", () => {
    jest.useFakeTimers();
    try {
      const cb = new CircuitBreaker({ failureThreshold: 1, resetTimeoutMs: 200 });
      cb.recordFailure();
      jest.advanceTimersByTime(300);
      cb.shouldSkip(); // enters half-open
      cb.recordFailure(); // probe fails
      expect(cb.state).toBe("open");
      expect(cb.shouldSkip()).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  it("recordSuccess() resets the failure counter", () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 1_000 });
    cb.recordFailure();
    cb.recordFailure();
    cb.recordSuccess();
    expect(cb.failures).toBe(0);
  });
});

// ── HealthMonitor unit tests ───────────────────────────────────────────────────

describe("HealthMonitor", () => {
  it("flips reachable=false when a probe fails", async () => {
    const probe = jest.fn().mockRejectedValue(new Error("econnrefused"));
    const hm = new HealthMonitor({
      client: {} as any,
      intervalMs: 10_000,
      probe,
      start: false,
    });
    expect(hm.reachable).toBe(true); // optimistic default
    await hm.probe();
    expect(hm.reachable).toBe(false);
  });

  it("recovers to reachable=true when the probe succeeds", async () => {
    let shouldFail = true;
    const probe = jest.fn(async () => {
      if (shouldFail) throw new Error("down");
    });
    const hm = new HealthMonitor({
      client: {} as any,
      intervalMs: 10_000,
      probe,
      start: false,
    });
    await hm.probe();
    expect(hm.reachable).toBe(false);
    shouldFail = false;
    await hm.probe();
    expect(hm.reachable).toBe(true);
  });

  it("stop() clears the interval so Node can exit", () => {
    const hm = new HealthMonitor({
      client: {} as any,
      intervalMs: 10_000,
      probe: jest.fn(async () => {}),
      start: true,
    });
    hm.stop();
    // Calling stop() twice is a no-op
    hm.stop();
    expect(hm.reachable).toBe(true);
  });
});

// ── agentumGuard — happy path + decision cache ─────────────────────────────────

describe("agentumGuard — allow path", () => {
  it("calls next() when simulatePolicy returns Allow", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const user = makeUser();
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => user,
        healthCheck: { enabled: false },
      },
      { action: "http.get", resource: "api.example.com" },
      { path: "/orders" },
    );
    expect(guardNext.called).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(session.client.simulatePolicy).toHaveBeenCalledTimes(1);
  });

  it("responds 403 with rule_id + reason when Cedar returns Deny", async () => {
    const session = makeGuardSession({
      outcome: "Deny",
      ruleId: "r_forbid_delete",
      reason: "http.delete forbidden",
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
      },
      { action: "http.delete", resource: "api.example.com" },
      { method: "DELETE", path: "/orders/42" },
    );
    expect(res._statusCode).toBe(403);
    expect(res._body).toMatchObject({
      error: "forbidden",
      rule_id: "r_forbid_delete",
      source: "network",
    });
    expect(guardNext.called).toBe(false);
  });

  it("returns 500 when agentumGuard runs without agentumMiddleware", async () => {
    const guard = agentumGuard({ action: "http.get", resource: "r" });
    const req = makeReq();
    const res = makeRes();
    const next = makeNext();
    await guard(req, res, next);
    expect(res._statusCode).toBe(500);
    expect(next.called).toBe(false);
  });

  it("invokes the custom onDeny handler when provided", async () => {
    const session = makeGuardSession({ outcome: "Deny" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const onDeny = jest.fn<void, [GuardDecision, AgentumRequest, AgentumResponse]>();
    await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
      },
      { action: "http.post", resource: "r", onDeny },
    );
    expect(onDeny).toHaveBeenCalledTimes(1);
    expect(onDeny.mock.calls[0]![0].outcome).toBe("Deny");
  });

  it("L05c: threads policy_hash + decision_source from simulatePolicy into the request_denied audit", async () => {
    const policyHash = "ab".repeat(32);
    const session = makeGuardSession({
      outcome: "Deny",
      ruleId: "r_forbid",
      reason: "policy_says_no",
      policyHash,
      decisionSource: "central_evaluated",
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        // Disable the legacy mode-enforce middleware deny emit (it would
        // also write a request_denied row that does not carry the new
        // L05c fields). The per-route agentumGuard is what we're testing
        // here.
        mode: "observe",
        healthCheck: { enabled: false },
      },
      { action: "http.delete", resource: "api.example.com" },
      { method: "DELETE", path: "/orders/42" },
    );
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const deniedCall = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_denied",
    );
    expect(deniedCall).toBeDefined();
    const payload = deniedCall![0] as {
      event_type: string;
      outcome?: string;
      policy_hash?: string;
      decision_source?: string;
      detail: Record<string, unknown>;
    };
    // Top-level: policy_hash + decision_source (joinable with LocalPdpDecision)
    expect(payload.outcome).toBe("deny");
    expect(payload.policy_hash).toBe(policyHash);
    expect(payload.decision_source).toBe("central_evaluated");
    // Detail: rule_id + reason (via pdpObservabilityDetailRaw); plus the
    // guard-internal `source` (breaker/cache trace) — NOT the wire
    // `decision_source` field.
    expect(payload.detail).toMatchObject({
      action: "http.delete",
      resource: "api.example.com",
      rule_id: "r_forbid",
      reason: "policy_says_no",
      source: "network",
    });
    // policy_hash / decision_source must NOT leak into `detail`.
    expect(payload.detail["policy_hash"]).toBeUndefined();
    expect(payload.detail["decision_source"]).toBeUndefined();
  });
});

describe("agentumGuard — decision cache", () => {
  it("serves a cached Allow without a network call on the second request", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      decisionCache: { maxSize: 100, ttlMs: 60_000 },
      healthCheck: { enabled: false },
    });
    const guard = agentumGuard({ action: "http.get", resource: "api.example.com" });

    const req1 = makeReq({ path: "/orders" });
    await mw(req1, makeRes(), makeNext());
    await guard(req1, makeRes(), makeNext());

    const req2 = makeReq({ path: "/orders" });
    await mw(req2, makeRes(), makeNext());
    await guard(req2, makeRes(), makeNext());

    expect(session.client.simulatePolicy).toHaveBeenCalledTimes(1);
  });

  it("skipCache=true bypasses the cache on every call", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      healthCheck: { enabled: false },
    });
    const guard = agentumGuard({
      action: "http.post",
      resource: "api.example.com",
      skipCache: true,
    });
    for (let i = 0; i < 3; i++) {
      const req = makeReq({ method: "POST", path: "/submit" });
      await mw(req, makeRes(), makeNext());
      await guard(req, makeRes(), makeNext());
    }
    expect(session.client.simulatePolicy).toHaveBeenCalledTimes(3);
  });

  it("different users get separate cache entries", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    let whichUser = 0;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => (whichUser === 0 ? makeUser("u1", "a@x") : makeUser("u2", "b@x")),
      healthCheck: { enabled: false },
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    whichUser = 0;
    const r1 = makeReq({ path: "/p" });
    await mw(r1, makeRes(), makeNext());
    await guard(r1, makeRes(), makeNext());

    whichUser = 1;
    const r2 = makeReq({ path: "/p" });
    await mw(r2, makeRes(), makeNext());
    await guard(r2, makeRes(), makeNext());

    expect(session.client.simulatePolicy).toHaveBeenCalledTimes(2);
  });
});

// ── agentumGuard — fail-mode ───────────────────────────────────────────────────

describe("agentumGuard — fail-mode", () => {
  it("closed: returns 403 when simulatePolicy throws", async () => {
    const session = makeGuardSession({ simulateThrows: new Error("boom") });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        failMode: "closed",
        healthCheck: { enabled: false },
        circuitBreaker: { enabled: false },
      },
      { action: "http.get", resource: "r" },
    );
    expect(res._statusCode).toBe(403);
    expect(guardNext.called).toBe(false);
  });

  it("open: allows the request and emits policy_check_degraded audit", async () => {
    const session = makeGuardSession({ simulateThrows: new Error("boom") });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        failMode: "open",
        healthCheck: { enabled: false },
        circuitBreaker: { enabled: false },
      },
      { action: "http.get", resource: "r" },
    );
    expect(guardNext.called).toBe(true);
    expect(res._statusCode).toBe(200);
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const degraded = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "policy_check_degraded",
    );
    expect(degraded).toBeDefined();
  });

  it("cached: serves last-known-good decision when simulatePolicy fails", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "cached",
      decisionCache: { maxSize: 10, ttlMs: 1 },
      healthCheck: { enabled: false },
      circuitBreaker: { enabled: false },
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    // First request: populate cache with Allow
    const r1 = makeReq({ path: "/p" });
    await mw(r1, makeRes(), makeNext());
    await guard(r1, makeRes(), makeNext());

    // Flip the mock to throw, then wait past TTL so cache is stale (not fresh)
    (session.client.simulatePolicy as jest.Mock).mockRejectedValueOnce(new Error("down"));
    await new Promise((r) => setTimeout(r, 5));

    const r2 = makeReq({ path: "/p" });
    const r2Res = makeRes();
    const r2Next = makeNext();
    await mw(r2, makeRes(), makeNext());
    await guard(r2, r2Res, r2Next);

    // Second request should be allowed from stale cache
    expect(r2Next.called).toBe(true);
    expect(r2Res._statusCode).toBe(200);
  });

  it("cached: falls back to closed when no stale value exists", async () => {
    const session = makeGuardSession({ simulateThrows: new Error("boom") });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        failMode: "cached",
        decisionCache: { maxSize: 10, ttlMs: 60_000 },
        healthCheck: { enabled: false },
        circuitBreaker: { enabled: false },
      },
      { action: "http.get", resource: "r" },
    );
    expect(res._statusCode).toBe(403);
  });

  it("failModeOverride on the guard takes precedence over middleware default", async () => {
    const session = makeGuardSession({ simulateThrows: new Error("boom") });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        failMode: "closed",
        healthCheck: { enabled: false },
        circuitBreaker: { enabled: false },
      },
      { action: "http.get", resource: "r", failModeOverride: "open" },
    );
    expect(guardNext.called).toBe(true);
    expect(res._statusCode).toBe(200);
  });
});

// ── agentumGuard — circuit breaker ─────────────────────────────────────────────

describe("agentumGuard — circuit breaker", () => {
  it("opens after N consecutive failures, skipping the network while open", async () => {
    const session = makeGuardSession({ simulateThrows: new Error("boom") });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "closed",
      healthCheck: { enabled: false },
      circuitBreaker: { failureThreshold: 3, resetTimeoutMs: 10_000 },
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    // Fire enough requests to trip the breaker
    for (let i = 0; i < 5; i++) {
      const r = makeReq();
      await mw(r, makeRes(), makeNext());
      await guard(r, makeRes(), makeNext());
    }
    // After 3 failures simulatePolicy should stop being called
    expect(session.client.simulatePolicy).toHaveBeenCalledTimes(3);
  });

  it("closes after reset + probe success, resuming normal operation", async () => {
    jest.useFakeTimers({ now: 1_700_000_000_000 });
    try {
      const simulatePolicy = jest
        .fn()
        .mockRejectedValueOnce(new Error("boom"))
        .mockRejectedValueOnce(new Error("boom"))
        .mockRejectedValueOnce(new Error("boom"))
        .mockResolvedValueOnce({ outcome: "Allow", rule_id: null, reason: null })
        .mockResolvedValueOnce({ outcome: "Allow", rule_id: null, reason: null });
      const session = {
        agentId: "ag-1",
        sessionId: "sess-1",
        isExpired: () => false,
        isAllowed: async () => true,
        ingestAuditEvent: jest.fn(async () => {}),
        isHitlAddonEnabled: () => true,
        close: jest.fn(async () => {}),
        client: { simulatePolicy },
      };
      const client = { connectExisting: jest.fn(async () => session) } as any;
      const mw = agentumMiddleware({
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        failMode: "closed",
        healthCheck: { enabled: false },
        circuitBreaker: { failureThreshold: 3, resetTimeoutMs: 500 },
      });
      const guard = agentumGuard({ action: "http.get", resource: "r" });

      // 3 failures → breaker opens
      for (let i = 0; i < 3; i++) {
        const r = makeReq({ path: `/p${i}` });
        await mw(r, makeRes(), makeNext());
        await guard(r, makeRes(), makeNext());
      }
      // While open, simulatePolicy is not called
      const r4 = makeReq({ path: "/p4" });
      await mw(r4, makeRes(), makeNext());
      await guard(r4, makeRes(), makeNext());
      expect(simulatePolicy).toHaveBeenCalledTimes(3);

      // Advance time past reset; next call probes and succeeds
      jest.advanceTimersByTime(600);
      const r5 = makeReq({ path: "/p5" });
      await mw(r5, makeRes(), makeNext());
      await guard(r5, makeRes(), makeNext());
      expect(simulatePolicy).toHaveBeenCalledTimes(4); // probe fired

      // Breaker closed, subsequent calls go through
      const r6 = makeReq({ path: "/p6" });
      await mw(r6, makeRes(), makeNext());
      await guard(r6, makeRes(), makeNext());
      expect(simulatePolicy).toHaveBeenCalledTimes(5);
    } finally {
      jest.useRealTimers();
    }
  });
});

// ── agentumGuard — health check ────────────────────────────────────────────────

describe("agentumGuard — health check short-circuit", () => {
  it("serves fail-mode directly when health monitor reports unreachable", async () => {
    const session = makeGuardSession({ outcome: "Allow" });
    const client = {
      connectExisting: jest.fn(async () => session),
      health: jest.fn().mockRejectedValue(new Error("down")),
    } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "closed",
      healthCheck: { intervalMs: 60_000 },
      circuitBreaker: { enabled: false },
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    // Wait for the initial probe to resolve (health monitor fires one on start).
    await new Promise((r) => setTimeout(r, 10));

    const req = makeReq();
    const res = makeRes();
    await mw(req, res, makeNext());
    const gRes = makeRes();
    await guard(req, gRes, makeNext());

    // Deny (fail-closed) without touching simulatePolicy
    expect(gRes._statusCode).toBe(403);
    expect(session.client.simulatePolicy).not.toHaveBeenCalled();

    await mw.close();
  });
});

// ── Task 1.5.9 (G37) — auto-HITL escalation ───────────────────────────────────

describe("agentumGuard — auto-HITL (G37)", () => {
  it("escalates Deny+require_hitl to session.requestApproval and reverses to Allow", async () => {
    const approve = jest.fn(async () => ({
      status: "approved",
      decided_by: "physician@med.example",
      request_id: "req-42",
    }));
    const session = makeGuardSession({
      outcome: "Deny",
      ruleId: "r_lab_order",
      reason: "require physician approval",
      advice: ["require_hitl:approvals=1,timeout=300"],
      requestApproval: approve,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
      { method: "POST", path: "/orders/new" },
    );
    expect(approve).toHaveBeenCalledTimes(1);
    expect((approve.mock.calls[0] as any[])[0]).toMatchObject({
      action: "http.post",
      resource: "lab-api",
      timeout: 300_000,
      requiredApprovals: 1,
    });
    expect(guardNext.called).toBe(true);
    expect(res.statusCode).toBe(200);
  });

  it("HITL denial by reviewer falls through to 403 with hitl reason", async () => {
    const { AgentumHitlDeniedError } = await import("../src/types");
    const deny = jest.fn(async () => {
      throw new AgentumHitlDeniedError("req-42", ["reviewer@example.com"], "not authorized");
    });
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl"],
      requestApproval: deny,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
    );
    expect(deny).toHaveBeenCalledTimes(1);
    expect(guardNext.called).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body).toMatchObject({
      error: "forbidden",
      source: "hitl-denied",
    });
    expect((res._body as { reason: string }).reason).toMatch(/hitl_denied_by:reviewer@example.com/);
  });

  it("HITL timeout falls through to 403 with hitl-timeout source", async () => {
    const { AgentumHitlTimeoutError } = await import("../src/types");
    const timeout = jest.fn(async () => {
      throw new AgentumHitlTimeoutError("req-42", 60_000);
    });
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl"],
      requestApproval: timeout,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
    );
    expect(res._statusCode).toBe(403);
    expect((res._body as { source: string }).source).toBe("hitl-timeout");
  });

  it("autoEscalateHitl=false keeps plain Deny even when advice carries require_hitl", async () => {
    const approve = jest.fn();
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl"],
      requestApproval: approve,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api", autoEscalateHitl: false },
    );
    expect(approve).not.toHaveBeenCalled();
    expect(res._statusCode).toBe(403);
    expect((res._body as { source: string }).source).toBe("network");
  });

  it("R45b: skips HITL escalation when addon.policy.hitl is disabled", async () => {
    const approve = jest.fn();
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl:approvals=1,timeout=300"],
      requestApproval: approve,
      hitlAddonEnabled: false,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
    );
    // Addon off → escalation skipped, the require_hitl Deny stands.
    expect(session.isHitlAddonEnabled).toHaveBeenCalled();
    expect(approve).not.toHaveBeenCalled();
    expect(res._statusCode).toBe(403);
    expect((res._body as { source: string }).source).toBe("network");
  });

  it("R45b: still escalates when addon.policy.hitl is enabled (fail-OPEN default)", async () => {
    const approve = jest.fn(async () => ({
      status: "approved",
      decided_by: "reviewer@example.com",
      request_id: "req-1",
    }));
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl:approvals=1,timeout=300"],
      requestApproval: approve,
      hitlAddonEnabled: true,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res, guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
    );
    expect(approve).toHaveBeenCalledTimes(1);
    // Approved → guard calls next(), no 403.
    expect(guardNext.called).toBe(true);
    expect(res._statusCode).not.toBe(403);
  });

  it("Deny without require_hitl advice stays plain Deny", async () => {
    const approve = jest.fn();
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["some_other_directive"],
      requestApproval: approve,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const { res } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api" },
    );
    expect(approve).not.toHaveBeenCalled();
    expect(res._statusCode).toBe(403);
    expect((res._body as { source: string }).source).toBe("network");
  });

  it("onHitlRequested hook can override timeout and inject a reason", async () => {
    const approve = jest.fn(async () => ({
      status: "approved",
      decided_by: "admin@example.com",
      request_id: "r",
    }));
    const session = makeGuardSession({
      outcome: "Deny",
      advice: ["require_hitl:approvals=1,timeout=300"],
      requestApproval: approve,
    });
    const client = { connectExisting: jest.fn(async () => session) } as any;
    const onHitlRequested = jest.fn(async () => ({
      reason: "Lab order #42 requested by alice",
      timeoutMs: 5_000,
    }));
    const { guardNext } = await runWithGuard(
      {
        client,
        agentId: "ag-1",
        userFromRequest: () => makeUser(),
        healthCheck: { enabled: false },
        mode: "observe",
      },
      { action: "http.post", resource: "lab-api", onHitlRequested },
    );
    expect(onHitlRequested).toHaveBeenCalledTimes(1);
    expect((approve.mock.calls[0] as any[])[0]).toMatchObject({
      reason: "Lab order #42 requested by alice",
      timeout: 5_000,
    });
    expect(guardNext.called).toBe(true);
  });

  it("parseHitlAdvice extracts bare and parameterised forms", async () => {
    const { parseHitlAdvice } = await import("../src/types");
    expect(parseHitlAdvice(undefined)).toBeNull();
    expect(parseHitlAdvice([])).toBeNull();
    expect(parseHitlAdvice(["log_reason"])).toBeNull();
    expect(parseHitlAdvice(["require_hitl"])).toEqual({});
    expect(parseHitlAdvice(["require_hitl:approvals=2,timeout=600"])).toEqual({
      requiredApprovals: 2,
      timeoutSeconds: 600,
    });
    expect(parseHitlAdvice(["other", "require_hitl:timeout=60"])).toEqual({
      timeoutSeconds: 60,
    });
  });
});

// ── Middleware-level teardown ──────────────────────────────────────────────────

describe("agentumMiddleware — close()", () => {
  it("stops the health monitor and closes pooled sessions", async () => {
    const session = makeGuardSession();
    const client = {
      connectExisting: jest.fn(async () => session),
      health: jest.fn().mockResolvedValue({}),
    } as any;
    const mw = agentumMiddleware({
      client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      healthCheck: { intervalMs: 1_000 },
    });
    const r = makeReq();
    await mw(r, makeRes(), makeNext());
    await mw.close();
    expect(session.close).toHaveBeenCalled();
  });

  it("throws at construction when neither runtime/client nor agent source is set", () => {
    expect(() => agentumMiddleware({ agentId: "ag-1" })).toThrow(/runtime/);
    expect(() => agentumMiddleware({ client: {} as any })).toThrow(/resolveAgent/);
  });
});
