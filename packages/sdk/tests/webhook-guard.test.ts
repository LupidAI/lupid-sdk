/**
 * Tests for `agentumWebhookGuard` (Express) and `withAgentumWebhookGuard`
 * (Next.js) — Sprint 1.5.7 / G28.
 *
 * All network / session mints are mocked. Covers:
 *   - Allow path: downstream handler invoked + audit event emitted
 *   - Deny path: 403 + request_denied audit event + handler NOT invoked
 *   - Error path: 503 + handler NOT invoked
 *   - Service-session pool reuse + invalidation on expiry
 *   - Cedar call shape: action="webhook.receive", resource=<source>
 *   - Validation: throws on missing agentId / source / serviceIdentity
 */

import {
  agentumWebhookGuard,
} from "../src/frameworks/express";
import type {
  AgentumRequest,
  AgentumResponse,
  AgentumNext,
} from "../src/frameworks/express";
import { createAgentumWebhookRuntime } from "../src/frameworks/nextjs";
import type { NextRequestLike, RouteHandlerContext } from "../src/frameworks/nextjs";

// ── Shared mocks ──────────────────────────────────────────────────────────────

function makeSession(overrides: Partial<{
  agentId: string;
  sessionId: string;
  expired: boolean;
  allowed: boolean;
  isAllowedThrows: Error | null;
}> = {}) {
  const {
    agentId = "ag-1",
    sessionId = "sess-1",
    expired = false,
    allowed = true,
    isAllowedThrows = null,
  } = overrides;
  return {
    agentId,
    sessionId,
    isExpired: jest.fn(() => expired),
    isAllowed: jest.fn(async () => {
      if (isAllowedThrows) throw isAllowedThrows;
      return allowed;
    }),
    ingestAuditEvent: jest.fn(async () => {}),
    close: jest.fn(async () => {}),
  };
}

function makeClient(session = makeSession(), connectThrows: Error | null = null) {
  return {
    connectExisting: jest.fn(async (_agentId: string, _opts: unknown) => {
      if (connectThrows) throw connectThrows;
      return session;
    }),
  };
}

// ── Express-side helpers ──────────────────────────────────────────────────────

function makeReq(overrides: Partial<AgentumRequest> = {}): AgentumRequest {
  return {
    headers: {},
    method: "POST",
    path: "/webhooks/github",
    ...overrides,
  };
}

function makeRes(): AgentumResponse & { _statusCode: number; _body: unknown } {
  const res = {
    _statusCode: 200,
    _body: undefined as unknown,
    get statusCode() { return res._statusCode; },
    status(code: number) { res._statusCode = code; return res; },
    json(body: unknown) { res._body = body; },
    end() {},
    on(_event: string, _listener: () => void) {},
  };
  return res;
}

function makeNext(): AgentumNext & { called: boolean; err: unknown } {
  const fn = Object.assign(
    (err?: unknown) => { fn.called = true; fn.err = err; },
    { called: false, err: undefined as unknown },
  );
  return fn;
}

// ── Express: validation ───────────────────────────────────────────────────────

describe("agentumWebhookGuard (express) — validation", () => {
  // Use `any`-typed option bags so runtime validation is exercised without
  // fighting `exactOptionalPropertyTypes`.
  it("throws when `runtime`/`client` is missing", () => {
    expect(() =>
      agentumWebhookGuard({
        agentId: "ag-1",
        source: "github",
        serviceIdentity: "github-webhook",
      } as any),
    ).toThrow(/runtime/);
  });

  it("throws when `agentId` is missing", () => {
    expect(() =>
      agentumWebhookGuard({
        runtime: makeClient() as any,
        source: "github",
        serviceIdentity: "github-webhook",
      } as any),
    ).toThrow(/agentId/);
  });

  it("throws when `source` is missing", () => {
    expect(() =>
      agentumWebhookGuard({
        runtime: makeClient() as any,
        agentId: "ag-1",
        serviceIdentity: "github-webhook",
      } as any),
    ).toThrow(/source/);
  });

  it("throws when `serviceIdentity` is missing", () => {
    expect(() =>
      agentumWebhookGuard({
        runtime: makeClient() as any,
        agentId: "ag-1",
        source: "github",
      } as any),
    ).toThrow(/serviceIdentity/);
  });
});

// ── Express: allow path ───────────────────────────────────────────────────────

describe("agentumWebhookGuard (express) — allow path", () => {
  it("mints a service session with {service, source} and calls next()", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-codeforge",
      source: "github",
      serviceIdentity: "github-webhook",
      serviceSource: "main",
    });
    const req = makeReq();
    const res = makeRes();
    const next = makeNext();

    await guard(req, res, next);

    expect(next.called).toBe(true);
    expect(next.err).toBeUndefined();

    // Service-session mint shape: user: {service, source}
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
    const [agentArg, optsArg] = client.connectExisting.mock.calls[0]!;
    expect(agentArg).toBe("ag-codeforge");
    expect(optsArg).toMatchObject({
      skipPolicyCheck: true,
      user: { service: "github-webhook", source: "main" },
    });
  });

  it("gates on action=webhook.receive, resource=<source>", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    await guard(makeReq(), makeRes(), makeNext());
    expect(session.isAllowed).toHaveBeenCalledWith("webhook.receive", "github");
  });

  it("honours a custom `action` override", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
      action: "webhook.github.push",
    });
    await guard(makeReq(), makeRes(), makeNext());
    expect(session.isAllowed).toHaveBeenCalledWith("webhook.github.push", "github");
  });

  it("attaches req.agentum with session and service identity", async () => {
    const session = makeSession({ agentId: "ag-7", sessionId: "sess-99", allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-7",
      source: "github",
      serviceIdentity: "github-webhook",
      tenantId: "tenant-abc",
    });
    const req = makeReq();
    await guard(req, makeRes(), makeNext());

    expect(req.agentum?.session).toBe(session);
    expect(req.agentum?.agentId).toBe("ag-7");
    expect(req.agentum?.sessionId).toBe("sess-99");
    expect(req.agentum?.service).toBe("github-webhook");
    expect(req.agentum?.tenantId).toBe("tenant-abc");
    // Service sessions have no user binding
    expect(req.agentum?.user).toBeUndefined();
  });

  it("emits a webhook_receive audit event on allow", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
      serviceSource: "main",
    });
    await guard(makeReq({ method: "POST", path: "/webhooks/github" }), makeRes(), makeNext());
    await Promise.resolve(); // flush void promise

    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const accepted = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "webhook_receive",
    );
    expect(accepted).toBeDefined();
    expect(accepted![0].detail).toMatchObject({
      source: "github",
      service: "github-webhook",
      service_source: "main",
      method: "POST",
      path: "/webhooks/github",
    });
  });
});

// ── Express: deny path ────────────────────────────────────────────────────────

describe("agentumWebhookGuard (express) — deny path", () => {
  it("responds 403 and does NOT call next() when Cedar denies", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    const res = makeRes();
    const next = makeNext();

    await guard(makeReq(), res, next);

    expect(res._statusCode).toBe(403);
    expect(next.called).toBe(false);
  });

  it("emits request_denied audit event with webhook source tag", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    await guard(makeReq(), makeRes(), makeNext());
    await Promise.resolve();

    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const denied = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_denied",
    );
    expect(denied).toBeDefined();
    expect(denied![0].detail).toMatchObject({
      action: "webhook.receive",
      resource: "github",
      source: "webhook",
      service: "github-webhook",
    });
  });

  it("invokes a custom onDeny handler instead of the default 403", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const onDeny = jest.fn(
      (_req: AgentumRequest, res: AgentumResponse, _reason: string) => {
        res.status(418).json({ teapot: true });
      },
    );
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
      onDeny,
    });
    const res = makeRes();
    await guard(makeReq(), res, makeNext());
    expect(onDeny).toHaveBeenCalledTimes(1);
    expect(res._statusCode).toBe(418);
  });
});

// ── Express: error path ───────────────────────────────────────────────────────

describe("agentumWebhookGuard (express) — error path", () => {
  it("responds 503 when session mint throws", async () => {
    const client = makeClient(makeSession(), new Error("network down"));
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    const res = makeRes();
    const next = makeNext();
    await guard(makeReq(), res, next);
    expect(res._statusCode).toBe(503);
    expect(next.called).toBe(false);
  });

  it("responds 503 when isAllowed throws", async () => {
    const session = makeSession({ isAllowedThrows: new Error("cedar 500") });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    const res = makeRes();
    const next = makeNext();
    await guard(makeReq(), res, next);
    expect(res._statusCode).toBe(503);
    expect(next.called).toBe(false);
  });
});

// ── Express: pool behaviour ───────────────────────────────────────────────────

describe("agentumWebhookGuard (express) — service-session pool", () => {
  it("reuses the same pooled session across requests", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    await guard(makeReq(), makeRes(), makeNext());
    await guard(makeReq(), makeRes(), makeNext());
    await guard(makeReq(), makeRes(), makeNext());
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
  });

  it("replaces a pooled session when it has expired", async () => {
    const expired = makeSession({ expired: true, allowed: true });
    const fresh = makeSession({ expired: false, allowed: true, sessionId: "sess-fresh" });
    const client = {
      connectExisting: jest.fn()
        .mockResolvedValueOnce(expired)
        .mockResolvedValueOnce(fresh),
    };
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    await guard(makeReq(), makeRes(), makeNext());
    const req2 = makeReq();
    await guard(req2, makeRes(), makeNext());
    expect(client.connectExisting).toHaveBeenCalledTimes(2);
    expect(req2.agentum?.sessionId).toBe("sess-fresh");
  });

  it("close() drains pooled sessions", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const guard = agentumWebhookGuard({
      runtime: client as any,
      agentId: "ag-1",
      source: "github",
      serviceIdentity: "github-webhook",
    });
    await guard(makeReq(), makeRes(), makeNext());
    await guard.close();
    expect(session.close).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Next.js — withAgentumWebhookGuard
// ═══════════════════════════════════════════════════════════════════════════════

function makeNextReq(method = "POST", url = "https://example.com/api/webhooks/github"): NextRequestLike {
  return {
    method,
    url,
    headers: { get: () => null },
    nextUrl: { pathname: new URL(url).pathname, search: "" },
  };
}

const emptyCtx: RouteHandlerContext = { params: Promise.resolve({}) };

describe("createAgentumWebhookRuntime — validation", () => {
  it("throws when `runtime` is missing", () => {
    expect(() =>
      createAgentumWebhookRuntime({ agentId: "ag-1" } as any),
    ).toThrow(/runtime/);
  });

  it("throws when `agentId` is missing", () => {
    expect(() =>
      createAgentumWebhookRuntime({ runtime: makeClient() as any } as any),
    ).toThrow(/agentId/);
  });
});

describe("withAgentumWebhookGuard (nextjs) — allow path", () => {
  it("invokes the wrapped handler with webhook context on Allow", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({
      runtime: client as any,
      agentId: "ag-1",
    });
    const handler = jest.fn(async (_req: NextRequestLike, _ctx: any) =>
      Response.json({ ok: true }),
    );
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      handler,
    );
    const res = await guarded(makeNextReq(), emptyCtx);
    expect(res.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    const [, ctx] = handler.mock.calls[0]!;
    expect(ctx.agentum.session).toBe(session);
    expect(ctx.agentum.service).toBe("github-webhook");
  });

  it("gates on action=webhook.receive, resource=<source>", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "stripe", serviceIdentity: "stripe-webhook" },
      async () => Response.json({ ok: true }),
    );
    await guarded(makeNextReq(), emptyCtx);
    expect(session.isAllowed).toHaveBeenCalledWith("webhook.receive", "stripe");
  });

  it("emits webhook_receive audit event on allow", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook", serviceSource: "main" },
      async () => Response.json({ ok: true }),
    );
    await guarded(makeNextReq(), emptyCtx);
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const accepted = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "webhook_receive",
    );
    expect(accepted).toBeDefined();
    expect(accepted![0].detail).toMatchObject({
      source: "github",
      service: "github-webhook",
      service_source: "main",
    });
  });
});

describe("withAgentumWebhookGuard (nextjs) — deny path", () => {
  it("returns 403 and does NOT invoke the handler on Deny", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      handler,
    );
    const res = await guarded(makeNextReq(), emptyCtx);
    expect(res.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
  });

  it("emits request_denied audit event with webhook tag", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      async () => Response.json({ ok: true }),
    );
    await guarded(makeNextReq(), emptyCtx);
    await Promise.resolve();
    const calls = (session.ingestAuditEvent as jest.Mock).mock.calls;
    const denied = calls.find(
      (c: unknown[]) => (c[0] as { event_type: string }).event_type === "request_denied",
    );
    expect(denied).toBeDefined();
    expect(denied![0].detail).toMatchObject({
      source: "webhook",
      resource: "github",
    });
  });

  it("invokes custom onDeny instead of default 403", async () => {
    const session = makeSession({ allowed: false });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const onDeny = jest.fn(() => new Response("teapot", { status: 418 }));
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook", onDeny },
      async () => Response.json({ ok: true }),
    );
    const res = await guarded(makeNextReq(), emptyCtx);
    expect(res.status).toBe(418);
    expect(onDeny).toHaveBeenCalledTimes(1);
  });
});

describe("withAgentumWebhookGuard (nextjs) — error path", () => {
  it("returns 503 when session mint throws", async () => {
    const client = makeClient(makeSession(), new Error("network down"));
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const handler = jest.fn(async () => Response.json({ ok: true }));
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      handler,
    );
    const res = await guarded(makeNextReq(), emptyCtx);
    expect(res.status).toBe(503);
    expect(handler).not.toHaveBeenCalled();
  });

  it("returns 503 when isAllowed throws", async () => {
    const session = makeSession({ isAllowedThrows: new Error("cedar 500") });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      async () => Response.json({ ok: true }),
    );
    const res = await guarded(makeNextReq(), emptyCtx);
    expect(res.status).toBe(503);
  });
});

describe("withAgentumWebhookGuard (nextjs) — pool", () => {
  it("reuses the same pooled session across requests", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      async () => Response.json({ ok: true }),
    );
    await guarded(makeNextReq(), emptyCtx);
    await guarded(makeNextReq(), emptyCtx);
    expect(client.connectExisting).toHaveBeenCalledTimes(1);
  });

  it("close() drains pooled sessions", async () => {
    const session = makeSession({ allowed: true });
    const client = makeClient(session);
    const rt = createAgentumWebhookRuntime({ runtime: client as any, agentId: "ag-1" });
    const guarded = rt.withAgentumWebhookGuard(
      { source: "github", serviceIdentity: "github-webhook" },
      async () => Response.json({ ok: true }),
    );
    await guarded(makeNextReq(), emptyCtx);
    await rt.close();
    expect(session.close).toHaveBeenCalled();
  });
});
