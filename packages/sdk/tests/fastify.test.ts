/**
 * Tests for the Fastify Agentum plugin + agentumGuard.
 *
 * AgentumClient + AgentumSession are mocked; no network calls.
 */

import { agentumPlugin, agentumGuard } from "../src/frameworks/fastify";
import type {
  FastifyInstanceLike,
  FastifyRequestLike,
  FastifyReplyLike,
  AgentumUser,
  GuardDecision,
} from "../src/frameworks/fastify";

// ── Mock helpers ──────────────────────────────────────────────────────────────

function makeSession(
  overrides: Partial<{
    agentId: string;
    sessionId: string;
    expired: boolean;
    /** R45b — `addon.policy.hitl` enablement; defaults to `true`
     *  (fail-OPEN), matching the runtime cold-start posture. */
    hitlAddonEnabled: boolean;
  }> = {},
) {
  const {
    agentId = "ag-1",
    sessionId = "sess-1",
    expired = false,
    hitlAddonEnabled = true,
  } = overrides;
  return {
    agentId,
    sessionId,
    isExpired: jest.fn(() => expired),
    ingestAuditEvent: jest.fn(async () => {}),
    isHitlAddonEnabled: jest.fn(() => hitlAddonEnabled),
    close: jest.fn(async () => {}),
    client: undefined as unknown, // populated per test below if needed
  };
}

function makeClient(
  session = makeSession(),
  simulateOverrides: {
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
  } = simulateOverrides;
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
  // The guard reads `ctx.session.client.simulatePolicy`; wire the session's
  // `.client` accessor to this mock client.
  (session as { client: unknown }).client = { simulatePolicy };
  return {
    simulatePolicy,
    health,
    connectExisting: jest.fn(async () => session),
    connect: jest.fn(async () => session),
  };
}

function makeFastify(): FastifyInstanceLike & { _preHandler: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void> } {
  const self: {
    addHook: jest.Mock;
    decorateRequest: jest.Mock;
    _preHandler: (req: FastifyRequestLike, reply: FastifyReplyLike) => Promise<void>;
  } = {
    addHook: jest.fn(),
    decorateRequest: jest.fn(),
    _preHandler: async () => {},
  };
  self.addHook.mockImplementation((name: string, handler: typeof self._preHandler) => {
    if (name === "preHandler") self._preHandler = handler;
  });
  return self as unknown as FastifyInstanceLike & { _preHandler: typeof self._preHandler };
}

function makeReq(
  overrides: Partial<FastifyRequestLike> & { headers?: Record<string, string> } = {},
): FastifyRequestLike {
  return {
    method: "GET",
    url: "/api/data",
    headers: {},
    ...overrides,
  };
}

function makeReply(): FastifyReplyLike & { _statusCode: number; _body: unknown; _sent: boolean } {
  const reply: {
    _statusCode: number;
    _body: unknown;
    _sent: boolean;
    code(code: number): typeof reply;
    status(code: number): typeof reply;
    send(body?: unknown): typeof reply;
  } = {
    _statusCode: 200,
    _body: undefined as unknown,
    _sent: false,
    code(code: number) {
      reply._statusCode = code;
      return reply;
    },
    status(code: number) {
      reply._statusCode = code;
      return reply;
    },
    send(body?: unknown) {
      reply._body = body;
      reply._sent = true;
      return reply;
    },
  };
  return reply as unknown as FastifyReplyLike & { _statusCode: number; _body: unknown; _sent: boolean };
}

function makeUser(overrides: Partial<AgentumUser> = {}): AgentumUser {
  return { id: "u_alice", email: "alice@example.com", trust: "trusted", ...overrides };
}

// ── agentumPlugin — wiring ────────────────────────────────────────────────────

describe("agentumPlugin — wiring", () => {
  it("throws when neither runtime nor client is provided", async () => {
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await expect(
      plugin(fastify, { agentId: "ag-1" } as never),
    ).rejects.toThrow(/runtime/);
  });

  it("throws when agentId and resolveAgent are both absent", async () => {
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    const client = makeClient() as unknown;
    await expect(
      plugin(fastify, { runtime: client as never } as never),
    ).rejects.toThrow(/agentId/);
  });

  it("registers a preHandler hook and decorates request", async () => {
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    const client = makeClient() as unknown;
    await plugin(fastify, { runtime: client as never, agentId: "ag-1" });
    expect((fastify as unknown as { addHook: jest.Mock }).addHook).toHaveBeenCalledWith(
      "preHandler",
      expect.any(Function),
    );
    expect((fastify as unknown as { decorateRequest: jest.Mock }).decorateRequest).toHaveBeenCalledWith(
      "agentum",
      null,
    );
    await plugin.close();
  });
});

// ── Request flow: user binding, session pool, context injection ───────────────

describe("agentumPlugin — request flow", () => {
  it("injects session into request.agentum on success", async () => {
    const session = makeSession({ agentId: "ag-42", sessionId: "sess-99" });
    const client = makeClient(session) as unknown;
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as never,
      agentId: "ag-42",
      userFromRequest: () => makeUser(),
    });

    const req = makeReq();
    const reply = makeReply();
    await fastify._preHandler(req, reply);
    expect(req.agentum?.agentId).toBe("ag-42");
    expect(req.agentum?.sessionId).toBe("sess-99");
    expect(req.agentum?.session).toBe(session);
    expect(req.agentum?.user?.email).toBe("alice@example.com");
    await plugin.close();
  });

  it("returns 401 when userFromRequest resolves to null", async () => {
    const client = makeClient() as unknown;
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as never,
      agentId: "ag-1",
      userFromRequest: () => null,
    });
    const reply = makeReply() as unknown as { _statusCode: number; _body: { error: string } };
    await fastify._preHandler(makeReq(), reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(401);
    expect(reply._body.error).toBe("unauthenticated");
    await plugin.close();
  });

  it("reuses the pooled session for the same user key", async () => {
    const session = makeSession();
    const client = makeClient(session);
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });

    await fastify._preHandler(makeReq(), makeReply());
    await fastify._preHandler(makeReq(), makeReply());

    expect(client.connectExisting).toHaveBeenCalledTimes(1);
    await plugin.close();
  });

  it("uses connect() when resolveAgent has no agentId (auto-register)", async () => {
    const session = makeSession();
    const client = makeClient(session);
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      resolveAgent: () => ({ name: "fastify-bot", ownerEmail: "o@example.com", purpose: "test" }),
      userFromRequest: () => makeUser(),
    });
    await fastify._preHandler(makeReq(), makeReply());
    expect(client.connect).toHaveBeenCalledTimes(1);
    expect(client.connectExisting).not.toHaveBeenCalled();
    await plugin.close();
  });

  it("500s when userFromRequest throws", async () => {
    const client = makeClient() as unknown;
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as never,
      agentId: "ag-1",
      userFromRequest: () => {
        throw new Error("token expired");
      },
    });
    const reply = makeReply() as unknown as { _statusCode: number; _body: { error: string } };
    await fastify._preHandler(makeReq(), reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(500);
    expect(reply._body.error).toBe("user_resolution_failed");
    await plugin.close();
  });

  it("502s by default when session mint throws", async () => {
    const client = {
      connectExisting: jest.fn().mockRejectedValue(new Error("agentum down")),
      connect: jest.fn(),
      health: jest.fn(async () => ({ ok: true })),
    };
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const reply = makeReply() as unknown as { _statusCode: number; _body: { error: string } };
    await fastify._preHandler(makeReq(), reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(502);
    expect(reply._body.error).toBe("agentum_session_mint_failed");
    await plugin.close();
  });

  it("emits a best-effort request_start audit event", async () => {
    const session = makeSession();
    const client = makeClient(session) as unknown;
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    await fastify._preHandler(makeReq({ method: "GET", url: "/foo?bar=1" }), makeReply());
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const startCall = calls.find((c) => (c[0] as { event_type: string }).event_type === "request_start");
    expect(startCall).toBeDefined();
    expect(startCall![0].detail).toMatchObject({ method: "GET", path: "/foo" });
    await plugin.close();
  });
});

// ── agentumGuard — per-route enforcement ──────────────────────────────────────

describe("agentumGuard — allow/deny flow", () => {
  it("500s when the plugin hasn't set up req.agentum", async () => {
    const guard = agentumGuard({ action: "http.get", resource: "api.example.com" });
    const reply = makeReply() as unknown as { _statusCode: number; _body: { error: string } };
    await guard(makeReq(), reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(500);
    expect(reply._body.error).toBe("agentum_plugin_missing");
  });

  it("allows the request to continue when simulatePolicy returns Allow", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Allow" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.get", resource: "api.example.com" });

    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    const reply = makeReply() as unknown as { _statusCode: number; _body: unknown; _sent: boolean };
    await guard(req, reply as unknown as FastifyReplyLike);
    expect(reply._sent).toBe(false);
    await plugin.close();
  });

  it("returns 403 JSON when simulatePolicy returns Deny", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Deny", ruleId: "r-7", reason: "forbidden-path" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.post", resource: "api.example.com" });

    const req = makeReq({ method: "POST", url: "/orders" });
    await fastify._preHandler(req, makeReply());
    const reply = makeReply() as unknown as { _statusCode: number; _body: { rule_id: string; reason: string } };
    await guard(req, reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(403);
    expect(reply._body.rule_id).toBe("r-7");
    expect(reply._body.reason).toBe("forbidden-path");
    await plugin.close();
  });

  it("uses custom onDeny when provided", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Deny", ruleId: "r-x", reason: "nope" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const onDeny = jest.fn((_d: GuardDecision, _req, reply: FastifyReplyLike) => {
      reply.code(418).send({ custom: true });
    });
    const guard = agentumGuard({ action: "http.get", resource: "r", onDeny });

    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    const reply = makeReply() as unknown as { _statusCode: number; _body: { custom: boolean } };
    await guard(req, reply as unknown as FastifyReplyLike);
    expect(onDeny).toHaveBeenCalledTimes(1);
    expect(reply._statusCode).toBe(418);
    expect(reply._body.custom).toBe(true);
    await plugin.close();
  });

  it("L05c: threads policy_hash + decision_source from simulatePolicy into the request_denied audit", async () => {
    const policyHash = "ab".repeat(32);
    const session = makeSession();
    const client = makeClient(session, {
      outcome: "Deny",
      ruleId: "r_forbid",
      reason: "policy_says_no",
      policyHash,
      decisionSource: "central_evaluated",
    });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.delete", resource: "api.example.com" });

    const req = makeReq({ method: "DELETE", url: "/orders/42" });
    await fastify._preHandler(req, makeReply());
    await guard(req, makeReply() as unknown as FastifyReplyLike);
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
    // Top-level: policy_hash + decision_source.
    expect(payload.outcome).toBe("deny");
    expect(payload.policy_hash).toBe(policyHash);
    expect(payload.decision_source).toBe("central_evaluated");
    // Detail: rule_id + reason; guard-internal `source` stays in detail.
    expect(payload.detail).toMatchObject({
      action: "http.delete",
      resource: "api.example.com",
      rule_id: "r_forbid",
      reason: "policy_says_no",
      source: "network",
    });
    expect(payload.detail["policy_hash"]).toBeUndefined();
    expect(payload.detail["decision_source"]).toBeUndefined();
    await plugin.close();
  });

  it("fail-closed — simulatePolicy throws → 403", async () => {
    const session = makeSession();
    const client = makeClient(session, { throws: new Error("timeout") });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "closed",
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });
    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    const reply = makeReply() as unknown as { _statusCode: number; _body: { source: string } };
    await guard(req, reply as unknown as FastifyReplyLike);
    expect(reply._statusCode).toBe(403);
    expect(reply._body.source).toBe("fail-closed");
    await plugin.close();
  });

  it("fail-open — simulatePolicy throws → allowed to continue", async () => {
    const session = makeSession();
    const client = makeClient(session, { throws: new Error("timeout") });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "open",
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });
    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    const reply = makeReply() as unknown as { _sent: boolean };
    await guard(req, reply as unknown as FastifyReplyLike);
    expect(reply._sent).toBe(false);
    await plugin.close();
  });

  it("caches decisions — second call does not hit the network", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Allow" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    await guard(req, makeReply());
    await guard(req, makeReply());
    expect(client.simulatePolicy).toHaveBeenCalledTimes(1);
    await plugin.close();
  });

  it("respects skipCache — always hits the network", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Allow" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.get", resource: "r", skipCache: true });

    const req = makeReq();
    await fastify._preHandler(req, makeReply());
    await guard(req, makeReply());
    await guard(req, makeReply());
    expect(client.simulatePolicy).toHaveBeenCalledTimes(2);
    await plugin.close();
  });

  it("uses routerPath as default cedar path when available", async () => {
    const session = makeSession();
    const client = makeClient(session, { outcome: "Allow" });
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as unknown as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const guard = agentumGuard({ action: "http.get", resource: "r" });

    const req = makeReq({ url: "/orders/42", routerPath: "/orders/:id" });
    await fastify._preHandler(req, makeReply());
    await guard(req, makeReply());
    expect(client.simulatePolicy).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ path: "/orders/:id" }),
      }),
    );
    await plugin.close();
  });
});

// ── Cleanup ────────────────────────────────────────────────────────────────────

describe("agentumPlugin — lifecycle", () => {
  it("close() stops the health monitor and closes pooled sessions", async () => {
    const session = makeSession();
    const client = makeClient(session) as unknown;
    const plugin = agentumPlugin();
    const fastify = makeFastify();
    await plugin(fastify, {
      runtime: client as never,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    await fastify._preHandler(makeReq(), makeReply());
    await plugin.close();
    expect((session.close as jest.Mock)).toHaveBeenCalled();
  });
});
