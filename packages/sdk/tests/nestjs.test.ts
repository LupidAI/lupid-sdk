/**
 * Tests for the NestJS Agentum guard + decorator + runtime.
 *
 * AgentumClient is mocked; no network. We fabricate a minimal
 * `ExecutionContextLike` so `@nestjs/common` is NOT required at test time.
 */

import {
  AgentumGuard,
  AgentumGuardFor,
  agentumGuardClass,
  createAgentumRuntime,
  createAgentumRuntimeAsync,
  setAgentumRuntime,
  getAgentumRuntime,
} from "../src/frameworks/nestjs";
import { AgentumSession } from "../src/session";
import type {
  AgentumNestRuntime,
  AgentumUser,
  ExecutionContextLike,
  NestHttpRequestLike,
  NestHttpResponseLike,
} from "../src/frameworks/nestjs";

// ── Mock helpers ──────────────────────────────────────────────────────────────

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
    advice?: string[];
    hitlPending?: boolean;
    // HITL-6: addon snapshot state the live getter reads. `enabled` permits
    // escalation; `disabled` / `unknown` (the default) must not.
    hitlAddon?: "enabled" | "disabled" | "unknown";
    // HITL-6: terminal status the polled approval resolves to.
    hitlStatus?: "approved" | "denied" | "timeout";
    hitlDecidedBy?: string[];
  } = {},
) {
  const {
    outcome = "Allow",
    ruleId = null,
    reason = null,
    throws = null,
    policyHash,
    decisionSource,
    advice,
    hitlPending,
    hitlAddon = "unknown",
    hitlStatus = "approved",
    hitlDecidedBy = ["approver@example.com"],
  } = overrides;
  const simulatePolicy = jest.fn(async () => {
    if (throws) throw throws;
    return {
      outcome,
      rule_id: ruleId,
      reason,
      ...(policyHash !== undefined ? { policy_hash: policyHash } : {}),
      ...(decisionSource !== undefined ? { decision_source: decisionSource } : {}),
      ...(advice !== undefined ? { advice } : {}),
      ...(hitlPending !== undefined ? { hitl_pending: hitlPending } : {}),
    };
  });
  const health = jest.fn(async () => ({ ok: true }));
  // L05c — guards now emit a best-effort request_denied audit on deny.
  // The mock is shaped as a stub jest.fn so tests can assert on calls.
  const ingestAuditEvent = jest.fn(async () => {});
  // HITL-6: the live addon getter the runtime factory wires.
  const isHitlAddonEnabled = jest.fn(() => hitlAddon === "enabled");
  // HITL-6: the primitives `session.requestApproval` drives. The guard does
  // not thread `toolName`, so `recordApprovalGrant` is never reached.
  const createHitlAgentRequest = jest.fn(async () => ({ request_id: "req-1" }));
  const getHitlAgentRequest = jest.fn(async () => ({
    status: hitlStatus,
    decided_by: hitlDecidedBy,
    reason: null as string | null,
  }));
  return {
    simulatePolicy,
    health,
    ingestAuditEvent,
    isHitlAddonEnabled,
    createHitlAgentRequest,
    getHitlAgentRequest,
  } as unknown as import("../src/client.js").AgentumClient;
}

function makeReq(
  overrides: Partial<NestHttpRequestLike> & { headers?: Record<string, string> } = {},
): NestHttpRequestLike {
  const { headers = {} } = overrides;
  return {
    method: "GET",
    url: "/api/data",
    path: "/api/data",
    headers,
    ...overrides,
  };
}

function makeRes(): NestHttpResponseLike & {
  _statusCode: number;
  _body: unknown;
} {
  const res: {
    _statusCode: number;
    _body: unknown;
    status(code: number): typeof res;
    json(body: unknown): typeof res;
  } = {
    _statusCode: 200,
    _body: undefined as unknown,
    status(code: number) {
      res._statusCode = code;
      return res;
    },
    json(body: unknown) {
      res._body = body;
      return res;
    },
  };
  return res as unknown as NestHttpResponseLike & { _statusCode: number; _body: unknown };
}

function makeCtx(
  handler: (...args: unknown[]) => unknown,
  req: NestHttpRequestLike,
  res: NestHttpResponseLike,
): ExecutionContextLike {
  return {
    switchToHttp: () => ({
      getRequest: () => req as never,
      getResponse: () => res as never,
    }),
    getHandler: () => handler,
    getClass: () => class StubController {},
  };
}

function makeUser(overrides: Partial<AgentumUser> = {}): AgentumUser {
  return { id: "u_alice", email: "alice@example.com", trust: "trusted", ...overrides };
}

// Helpers for attaching AgentumGuardFor metadata to a freshly-defined method.
function defineHandlerWithGuardFor(
  opts: Parameters<typeof AgentumGuardFor>[0],
): (...args: unknown[]) => unknown {
  class Tmp {
    handler(): string {
      return "ok";
    }
  }
  const descriptor = Object.getOwnPropertyDescriptor(Tmp.prototype, "handler")!;
  AgentumGuardFor(opts)(Tmp.prototype, "handler", descriptor as never);
  return descriptor.value as (...args: unknown[]) => unknown;
}

// ── Runtime factory ───────────────────────────────────────────────────────────

describe("createAgentumRuntime", () => {
  it("throws when runtime is missing", () => {
    expect(() =>
      createAgentumRuntime({
        // @ts-expect-error intentionally invalid
        runtime: null,
        agentId: "ag-1",
        userFromRequest: () => null,
      }),
    ).toThrow(/runtime/);
  });

  it("throws when agentId is missing", () => {
    expect(() =>
      createAgentumRuntime({
        runtime: makeClient(),
        // @ts-expect-error intentionally invalid
        agentId: undefined,
        userFromRequest: () => null,
      }),
    ).toThrow(/agentId/);
  });

  it("throws when userFromRequest is not a function", () => {
    expect(() =>
      createAgentumRuntime({
        runtime: makeClient(),
        agentId: "ag-1",
        // @ts-expect-error intentionally invalid
        userFromRequest: "not-a-function",
      }),
    ).toThrow(/userFromRequest/);
  });
});

// ── AgentumGuardFor decorator ─────────────────────────────────────────────────

describe("AgentumGuardFor decorator", () => {
  it("rejects missing action", () => {
    expect(() =>
      AgentumGuardFor({ action: "" as string, resource: "r" }),
    ).toThrow(/action/);
  });

  it("rejects missing resource", () => {
    expect(() =>
      AgentumGuardFor({ action: "http.get", resource: "" as string }),
    ).toThrow(/resource/);
  });

  it("attaches options discoverable by guard", async () => {
    const handler = defineHandlerWithGuardFor({
      action: "http.post",
      resource: "api.example.com",
    });
    const client = makeClient({ outcome: "Allow" });
    const runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    const GuardClass = agentumGuardClass(runtime);
    const guard = new GuardClass();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(ok).toBe(true);
    const simulatePolicy = (client as unknown as {
      simulatePolicy: jest.Mock;
    }).simulatePolicy;
    expect(simulatePolicy).toHaveBeenCalledWith(
      expect.objectContaining({ action: "http.post", resource: "api.example.com" }),
    );
    await runtime.close();
  });
});

// ── AgentumGuard (singleton path) ─────────────────────────────────────────────

describe("AgentumGuard — singleton runtime", () => {
  let runtime: AgentumNestRuntime | null = null;

  afterEach(async () => {
    if (runtime) await runtime.close();
    runtime = null;
    setAgentumRuntime(null);
  });

  it("throws at canActivate when no runtime is registered", async () => {
    setAgentumRuntime(null);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    await expect(
      guard.canActivate(makeCtx(handler, makeReq(), makeRes())),
    ).rejects.toThrow(/no runtime registered/);
  });

  it("setAgentumRuntime + getAgentumRuntime roundtrip", () => {
    const client = makeClient();
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    expect(getAgentumRuntime()).toBe(runtime);
  });

  it("500s on missing @AgentumGuardFor metadata", async () => {
    const client = makeClient();
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handlerWithoutMeta = function anonymous() {
      return null;
    } as (...args: unknown[]) => unknown;
    const res = makeRes() as unknown as { _statusCode: number; _body: { error: string } };
    const guard = new AgentumGuard();
    const ok = await guard.canActivate(makeCtx(handlerWithoutMeta, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(500);
    expect(res._body.error).toBe("agentum_guard_missing_metadata");
  });

  it("401s on unauthenticated user", async () => {
    const client = makeClient();
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => null,
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const res = makeRes() as unknown as { _statusCode: number; _body: { error: string } };
    const guard = new AgentumGuard();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(401);
    expect(res._body.error).toBe("unauthenticated");
  });

  it("allows when simulatePolicy returns Allow", async () => {
    const client = makeClient({ outcome: "Allow" });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    const res = makeRes();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res));
    expect(ok).toBe(true);
  });

  it("denies when simulatePolicy returns Deny + writes 403 JSON", async () => {
    const client = makeClient({ outcome: "Deny", ruleId: "r-7", reason: "forbidden-path" });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "r" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { rule_id: string; reason: string } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body.rule_id).toBe("r-7");
    expect(res._body.reason).toBe("forbidden-path");
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
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-8",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({
      action: "http.delete",
      resource: "api.example.com",
    });
    const guard = new AgentumGuard();
    const res = makeRes();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res));
    expect(ok).toBe(false);
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
    expect(payload.agent_id).toBe("ag-8");
    expect(payload.session_id).toBe("");
    expect(payload.policy_hash).toBe(policyHash);
    expect(payload.decision_source).toBe("central_evaluated");
    expect(payload.detail).toMatchObject({
      action: "http.delete",
      resource: "api.example.com",
      framework: "nestjs",
      rule_id: "r_forbid",
      reason: "policy_says_no",
      source: "network",
    });
    expect(payload.detail["policy_hash"]).toBeUndefined();
    expect(payload.detail["decision_source"]).toBeUndefined();
  });

  it("uses custom onDeny when provided in the decorator", async () => {
    const client = makeClient({ outcome: "Deny" });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const onDeny = jest.fn((_d, _req, res: NestHttpResponseLike) => {
      (res.status as (c: number) => NestHttpResponseLike).call(res, 418);
      (res.json as (b: unknown) => unknown).call(res, { custom: true });
    });
    const handler = defineHandlerWithGuardFor({
      action: "http.get",
      resource: "r",
      onDeny: onDeny as never,
    });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { custom: boolean } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(onDeny).toHaveBeenCalledTimes(1);
    expect(res._statusCode).toBe(418);
    expect(res._body.custom).toBe(true);
  });

  it("fail-closed: simulatePolicy throws → 403", async () => {
    const client = makeClient({ throws: new Error("network down") });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "closed",
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { source: string } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body.source).toBe("fail-closed");
  });

  it("fail-open: simulatePolicy throws → allowed", async () => {
    const client = makeClient({ throws: new Error("network down") });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
      failMode: "open",
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    const res = makeRes();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res));
    expect(ok).toBe(true);
  });

  it("caches decisions — second call does not hit the network", async () => {
    const client = makeClient({ outcome: "Allow" });
    const simulateMock = (client as unknown as { simulatePolicy: jest.Mock }).simulatePolicy;
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(simulateMock).toHaveBeenCalledTimes(1);
  });

  it("skipCache on the decorator forces a network call every time", async () => {
    const client = makeClient({ outcome: "Allow" });
    const simulateMock = (client as unknown as { simulatePolicy: jest.Mock }).simulatePolicy;
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({
      action: "http.get",
      resource: "r",
      skipCache: true,
    });
    const guard = new AgentumGuard();
    await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(simulateMock).toHaveBeenCalledTimes(2);
  });

  it("uses routerPath as default cedar path when set", async () => {
    const client = makeClient({ outcome: "Allow" });
    const simulateMock = (client as unknown as { simulatePolicy: jest.Mock }).simulatePolicy;
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-1",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    const guard = new AgentumGuard();
    const req = makeReq({ routerPath: "/orders/:id", path: "/orders/42", url: "/orders/42" });
    await guard.canActivate(makeCtx(handler, req, makeRes()));
    expect(simulateMock).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ path: "/orders/:id" }),
      }),
    );
  });
});

// ── agentumGuardClass (DI factory path) ───────────────────────────────────────

describe("agentumGuardClass — bound factory", () => {
  it("returns an independent guard class per runtime", async () => {
    const clientA = makeClient({ outcome: "Allow" });
    const clientB = makeClient({ outcome: "Deny" });
    const runtimeA = createAgentumRuntime({
      runtime: clientA,
      agentId: "ag-a",
      userFromRequest: () => makeUser(),
    });
    const runtimeB = createAgentumRuntime({
      runtime: clientB,
      agentId: "ag-b",
      userFromRequest: () => makeUser(),
    });
    const GuardA = agentumGuardClass(runtimeA);
    const GuardB = agentumGuardClass(runtimeB);
    const handler = defineHandlerWithGuardFor({ action: "http.get", resource: "r" });
    expect(await new GuardA().canActivate(makeCtx(handler, makeReq(), makeRes()))).toBe(true);
    expect(await new GuardB().canActivate(makeCtx(handler, makeReq(), makeRes()))).toBe(false);
    await runtimeA.close();
    await runtimeB.close();
  });

  it("throws when runtime is null", () => {
    expect(() => agentumGuardClass(null as never)).toThrow(/runtime/);
  });
});

// ── HITL escalation (HITL-6) ──────────────────────────────────────────────────

describe("AgentumGuard — HITL escalation", () => {
  let runtime: AgentumNestRuntime | null = null;

  afterEach(async () => {
    if (runtime) await runtime.close();
    runtime = null;
    setAgentumRuntime(null);
  });

  it("addon enabled + Deny w/ require_hitl + approval → calls requestApproval and ALLOWS", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "enabled",
      hitlStatus: "approved",
      hitlDecidedBy: ["boss@example.com"],
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(ok).toBe(true);
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    const poll = (client as unknown as { getHitlAgentRequest: jest.Mock }).getHitlAgentRequest;
    expect(create).toHaveBeenCalledTimes(1);
    expect(poll).toHaveBeenCalled();
    const isEnabled = (client as unknown as { isHitlAddonEnabled: jest.Mock }).isHitlAddonEnabled;
    expect(isEnabled).toHaveBeenCalledWith("ag-hitl");
  });

  it("addon DISABLED + Deny w/ require_hitl → NO escalation, plain 403 deny", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "disabled",
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { rule_id: string } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body.rule_id).toBe("r_hitl");
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).not.toHaveBeenCalled();
  });

  it("addon UNKNOWN (cold start) + Deny w/ require_hitl → NO escalation (INC-B safe default)", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "unknown",
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).not.toHaveBeenCalled();
  });

  it("addon enabled + reviewer DENIES → deny stands (no allow)", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "enabled",
      hitlStatus: "denied",
      hitlDecidedBy: ["boss@example.com"],
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { source: string } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body.source).toBe("hitl-denied");
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).toHaveBeenCalledTimes(1);
  });

  it("addon enabled but Deny has NO require_hitl advice → plain deny, no escalation", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_plain",
      reason: "forbidden",
      hitlAddon: "enabled",
      // no advice, no hitl_pending
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).not.toHaveBeenCalled();
  });

  it("autoEscalateHitl: false on the decorator → escalation skipped even when enabled", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "enabled",
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({
      action: "http.post",
      resource: "api.example.com",
      autoEscalateHitl: false,
    });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).not.toHaveBeenCalled();
  });

  it("falls back to parseHitlAdvice when hitl_pending is absent (older API)", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl:timeout=30"],
      // hitl_pending omitted — older API
      hitlAddon: "enabled",
      hitlStatus: "approved",
    });
    runtime = createAgentumRuntime({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(ok).toBe(true);
    const create = (client as unknown as { createHitlAgentRequest: jest.Mock }).createHitlAgentRequest;
    expect(create).toHaveBeenCalledTimes(1);
  });
});

// ── SDK-HITL-A: createAgentumRuntimeAsync mints a Bearer agent session ─────────
//
// The server's HITL agent endpoints authenticate via `Authorization: Bearer`
// (the agent session JWT) ONLY — they never read `X-API-Key`. The sync
// `createAgentumRuntime` builds the approval session over the shared API-key
// client with an empty JWT, so on an API-key-only runtime the approval
// round-trip 401s. `createAgentumRuntimeAsync` mints a real agent session via
// `client.connectExisting(agentId)` whose forked client carries a Bearer JWT
// (plus a refreshFn), fixing the 401.
//
// NOTE on patched-marker reset: the NestJS guard/runtime installs no
// `Symbol.for("agentum.*.patched")` autopatch markers (those belong to the
// openai/anthropic/fetch/http/undici instrumentation plane), so there is
// nothing to reset between these tests.

/** Build a non-expiring (far-future `exp`) unsigned JWT for the minted session. */
function farFutureJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const payload = Buffer.from(
    JSON.stringify({ sub: "ag-hitl", tenant_id: "t-1", exp }),
  ).toString("base64url");
  return `${header}.${payload}.`;
}

/**
 * Build a Bearer-authenticated mock client (carries a session JWT, NO api key)
 * plus an `AgentumSession` over it — the shape `connectExisting` returns. The
 * HITL primitives are jest stubs so the test can assert the approval flow ran
 * through THIS session (the Bearer one), not the shared API-key client.
 */
function makeBearerApprovalSession(
  agentId: string,
  opts: { hitlStatus?: "approved" | "denied" | "timeout"; hitlDecidedBy?: string[] } = {},
): { session: AgentumSession; createMock: jest.Mock; pollMock: jest.Mock; jwt: string } {
  const { hitlStatus = "approved", hitlDecidedBy = ["boss@example.com"] } = opts;
  const jwt = farFutureJwt();
  const createMock = jest.fn(async () => ({ request_id: "req-async-1", status: "pending" }));
  const pollMock = jest.fn(async () => ({
    request_id: "req-async-1",
    status: hitlStatus,
    decided_by: hitlDecidedBy,
    reason: null as string | null,
  }));
  // Minimal Bearer client surface: it has a token (JWT) and exposes the HITL
  // primitives. `setTokenRefreshFn` is invoked by the AgentumSession ctor when a
  // refreshFn is supplied; `endSession`/`clearToken`/`close` are called on close.
  const bearerClient = {
    token: jwt,
    setTokenRefreshFn: jest.fn(),
    setToken: jest.fn(),
    clearToken: jest.fn(),
    endSession: jest.fn(async () => {}),
    close: jest.fn(async () => {}),
    createHitlAgentRequest: createMock,
    getHitlAgentRequest: pollMock,
  } as unknown as import("../src/client.js").AgentumClient;
  // Supply a refreshFn so the session re-mints its JWT before expiry (the
  // production `connectExisting` does the same) — proves the long-run refresh
  // story rather than a session that silently expires.
  const session = new AgentumSession(bearerClient, agentId, "sess-async-1", jwt, {
    refreshFn: async () => ({ jwt: farFutureJwt(), session_id: "sess-async-1" }),
    ownsClient: true,
  });
  return { session, createMock, pollMock, jwt };
}

describe("createAgentumRuntimeAsync — SDK-HITL-A", () => {
  let runtime: AgentumNestRuntime | null = null;

  afterEach(async () => {
    if (runtime) await runtime.close();
    runtime = null;
    setAgentumRuntime(null);
  });

  it("validates options like the sync constructor", async () => {
    const client = makeClient();
    await expect(
      createAgentumRuntimeAsync({
        runtime: client,
        // @ts-expect-error intentionally invalid
        agentId: undefined,
        userFromRequest: () => null,
      }),
    ).rejects.toThrow(/agentId/);
  });

  it("mints the approval session via connectExisting (Bearer JWT, not the api-key client)", async () => {
    const { session, jwt } = makeBearerApprovalSession("ag-hitl");
    const client = makeClient({ outcome: "Allow" });
    const connectExisting = jest.fn(async () => session);
    (client as unknown as { connectExisting: jest.Mock }).connectExisting = connectExisting;

    runtime = await createAgentumRuntimeAsync({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });

    // connectExisting was called for the agent, skipping the policy probe.
    expect(connectExisting).toHaveBeenCalledWith("ag-hitl", { skipPolicyCheck: true });
    // The runtime's approval session is the Bearer-authenticated minted one,
    // whose underlying client carries `Authorization: Bearer <jwt>`, NOT the
    // shared API-key client.
    const approval = runtime._internals.approvalSession;
    expect(approval).toBeDefined();
    expect((approval!.client as unknown as { token: string }).token).toBe(jwt);
    expect(approval!.client).not.toBe(client);
  });

  it("addon enabled + Deny w/ require_hitl + approval → escalates via the Bearer session and ALLOWS", async () => {
    const { session, createMock, pollMock } = makeBearerApprovalSession("ag-hitl", {
      hitlStatus: "approved",
    });
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "enabled",
    });
    (client as unknown as { connectExisting: jest.Mock }).connectExisting = jest.fn(
      async () => session,
    );

    runtime = await createAgentumRuntimeAsync({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), makeRes()));
    expect(ok).toBe(true);
    // The create + poll fired on the BEARER session's client, proving the
    // approval round-trip uses the agent JWT, not X-API-Key.
    expect(createMock).toHaveBeenCalledTimes(1);
    expect(pollMock).toHaveBeenCalled();
    // The shared API-key client's HITL primitives were NOT used.
    const sharedCreate = (client as unknown as { createHitlAgentRequest: jest.Mock })
      .createHitlAgentRequest;
    expect(sharedCreate).not.toHaveBeenCalled();
  });

  it("addon DISABLED + Deny w/ require_hitl → no escalation, plain 403", async () => {
    const { session, createMock } = makeBearerApprovalSession("ag-hitl");
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "disabled",
    });
    (client as unknown as { connectExisting: jest.Mock }).connectExisting = jest.fn(
      async () => session,
    );

    runtime = await createAgentumRuntimeAsync({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number; _body: { rule_id: string } };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    expect(res._body.rule_id).toBe("r_hitl");
    expect(createMock).not.toHaveBeenCalled();
  });

  it("central unreachable at bootstrap → HITL disabled (no crash), require_hitl Deny stands", async () => {
    const client = makeClient({
      outcome: "Deny",
      ruleId: "r_hitl",
      reason: "needs_approval",
      advice: ["require_hitl"],
      hitlPending: true,
      hitlAddon: "enabled",
    });
    (client as unknown as { connectExisting: jest.Mock }).connectExisting = jest.fn(async () => {
      throw new Error("ECONNREFUSED central");
    });
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    // Construction must not throw even though connectExisting failed.
    runtime = await createAgentumRuntimeAsync({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    // No approval session minted → escalation cleanly disabled.
    expect(runtime._internals.approvalSession).toBeUndefined();
    expect(warnSpy).toHaveBeenCalled();
    warnSpy.mockRestore();

    setAgentumRuntime(runtime);
    const handler = defineHandlerWithGuardFor({ action: "http.post", resource: "api.example.com" });
    const guard = new AgentumGuard();
    const res = makeRes() as unknown as { _statusCode: number };
    const ok = await guard.canActivate(makeCtx(handler, makeReq(), res as unknown as NestHttpResponseLike));
    // The Deny stands (fail-CLOSED) — no escalation, no 401, no crash.
    expect(ok).toBe(false);
    expect(res._statusCode).toBe(403);
    const sharedCreate = (client as unknown as { createHitlAgentRequest: jest.Mock })
      .createHitlAgentRequest;
    expect(sharedCreate).not.toHaveBeenCalled();
  });

  it("close() closes the minted approval session", async () => {
    const { session } = makeBearerApprovalSession("ag-hitl");
    const closeSpy = jest.spyOn(session, "close");
    const client = makeClient({ outcome: "Allow" });
    (client as unknown as { connectExisting: jest.Mock }).connectExisting = jest.fn(
      async () => session,
    );
    const r = await createAgentumRuntimeAsync({
      runtime: client,
      agentId: "ag-hitl",
      userFromRequest: () => makeUser(),
    });
    await r.close();
    expect(closeSpy).toHaveBeenCalledTimes(1);
  });
});
