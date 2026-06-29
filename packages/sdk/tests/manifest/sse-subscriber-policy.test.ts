/**
 * W05 — SchemaSubscriber policy/capability invalidation tests.
 *
 * Asserts the tenant-wide `/api/v1/policy/stream` subscriber wires
 * `policy`, `capability_effective_set_changed`,
 * `capability_set_invalidate_all_scopes`, and `lagged` events through
 * to `CedarToolCallClient.invalidate{Policy,Capability}Cache`, and that
 * the next `evaluateToolCall` re-fetches from the wire.
 *
 * Event names verified against
 * `crates/agentum-api/src/routes/policy_distribution.rs::live_stream`
 * (variant → SSE label mapping at lines 458-466).
 */

import nock from "nock";

import {
  SchemaSubscriber,
  __resetSchemaSubscriberForTest,
} from "../../src/manifest/sse-subscriber";
import { _setActiveSchema } from "../../src/manifest/state";
import { AdminHttpClient } from "../../src/admin/http";
import {
  CedarToolCallClient,
  hashArgsCanonical,
} from "../../src/evaluation/cedar-client";
import type { TenantSchema } from "../../src/manifest/types";

// --- jest.mock for the `eventsource` polyfill ------------------------------

type Listener = (ev: { data: string }) => void;

class MockEventSource {
  static instances: MockEventSource[] = [];

  url: string;
  listeners: Map<string, Listener[]> = new Map();
  onerror: ((ev: unknown) => void) | null = null;
  closed = false;

  constructor(url: string, _init?: { fetch?: unknown }) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: Listener): void {
    const arr = this.listeners.get(type) ?? [];
    arr.push(listener);
    this.listeners.set(type, arr);
  }

  close(): void {
    this.closed = true;
  }

  __emit(event: string, data: string): void {
    const arr = this.listeners.get(event) ?? [];
    for (const l of arr) {
      l({ data });
    }
  }
}

jest.mock("eventsource", () => ({
  EventSource: MockEventSource,
}));

// --- helpers ---------------------------------------------------------------

function silentLogger(): { log: jest.Mock; warn: jest.Mock; error: jest.Mock } {
  return { log: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await new Promise((r) => setImmediate(r));
  }
  await new Promise((r) => setTimeout(r, 10));
}

function mkSchema(version: number): TenantSchema {
  return {
    version,
    scoping_dimension: "account_id",
    dimensions: [
      {
        name: "account_id",
        source: {
          kind: "request_header",
          header: "x-account",
          when_missing: "reject",
        },
        scoping: true,
        required: true,
        cedar: { attribute: "account", type: "String" },
        clickhouse: { column: "dim_account_id", codec: "LowCardinality(String)" },
        pii: "none",
      },
    ],
  } as unknown as TenantSchema;
}

const TENANT_ID = "tenant-uuid-1";
const AGENT_ID = "agent-uuid-1";
const BASE_URL = "http://gateway.example:7071";
const API_KEY = "ak_test";

function buildAdminHttp(): AdminHttpClient {
  return new AdminHttpClient({ baseUrl: BASE_URL, apiKey: API_KEY });
}

interface EvalFetchRecord {
  url: string;
  init: RequestInit | undefined;
}

/**
 * Build a fetch impl that returns a canned `evaluate-tool-call` allow
 * response on every call, recording each invocation. Audit POSTs are
 * accepted with a no-op 200 so the fire-and-forget audit path settles.
 */
function makeEvalFetch(
  records: EvalFetchRecord[],
): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    records.push({ url: u, init });
    if (u.endsWith("/api/v1/audit/ingest")) {
      return new Response("{}", { status: 200 });
    }
    if (u.endsWith("/api/v1/sdk/evaluate-tool-call")) {
      return new Response(
        JSON.stringify({
          decision: "allow",
          ttl_ms: 60_000,
          policy_hash: "hash-a",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    throw new Error(`unrouted fetch in test: ${u}`);
  }) as typeof fetch;
}

function countEvalCalls(records: EvalFetchRecord[]): number {
  return records.filter((r) =>
    r.url.endsWith("/api/v1/sdk/evaluate-tool-call"),
  ).length;
}

function findPolicyEventSource(): MockEventSource {
  const policyEs = MockEventSource.instances.find((es) =>
    es.url.endsWith("/api/v1/policy/stream"),
  );
  if (!policyEs) throw new Error("policy EventSource was not opened");
  return policyEs;
}

// --- tests -----------------------------------------------------------------

describe("SchemaSubscriber W05 policy + capability invalidation", () => {
  beforeEach(() => {
    MockEventSource.instances = [];
    nock.cleanAll();
    nock.disableNetConnect();
    __resetSchemaSubscriberForTest();
    _setActiveSchema(mkSchema(1));
  });

  afterEach(async () => {
    __resetSchemaSubscriberForTest();
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it("opens a second EventSource against /api/v1/policy/stream when cedarClient is supplied", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });

    expect(MockEventSource.instances).toHaveLength(2);
    const schemaEs = MockEventSource.instances.find((es) =>
      es.url.endsWith(`/api/v1/agents/${AGENT_ID}/schema/stream`),
    );
    const policyEs = MockEventSource.instances.find((es) =>
      es.url.endsWith("/api/v1/policy/stream"),
    );
    expect(schemaEs).toBeDefined();
    expect(policyEs).toBeDefined();

    await evaluator.flushPendingAudits();
  });

  it("does NOT open the policy stream when cedarClient is omitted", async () => {
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
    });

    expect(MockEventSource.instances).toHaveLength(1);
    expect(
      MockEventSource.instances[0]!.url.endsWith(
        `/api/v1/agents/${AGENT_ID}/schema/stream`,
      ),
    ).toBe(true);
  });

  it("clears the decision cache on a `policy` event and re-fetches on next evaluate", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });

    // First evaluation populates the cache.
    const r1 = await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(r1.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(1);

    // Second evaluation with same args hits the cache, no new fetch.
    const r2 = await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(r2.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(1);

    // Fire a tenant-wide policy event — payload mirrors UrgentEvent::Policy.
    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "policy",
      JSON.stringify({
        kind: "policy",
        version: 7,
        bundle_hash_hex: "deadbeef".repeat(8),
        reason: "new_version",
      }),
    );
    await flush();

    // Third evaluation: cache cleared, must hit the wire again.
    const r3 = await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(r3.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(2);

    await evaluator.flushPendingAudits();
  });

  it("clears the decision cache on a `capability_effective_set_changed` event", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);
    // Cached.
    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);

    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "capability_effective_set_changed",
      JSON.stringify({
        kind: "capability_effective_set_changed",
        scope_value: "tenant-abc",
        capability_set_hash: "feedface".repeat(8),
      }),
    );
    await flush();

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(2);

    await evaluator.flushPendingAudits();
  });

  it("clears the decision cache on `capability_set_invalidate_all_scopes`", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);

    const policyEs = findPolicyEventSource();
    policyEs.__emit("capability_set_invalidate_all_scopes", "");
    await flush();

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(2);

    await evaluator.flushPendingAudits();
  });

  it("invalidates conservatively on a `lagged` event from the policy stream", async () => {
    const records: EvalFetchRecord[] = [];
    const logger = silentLogger();
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
      cedarClient: evaluator,
    });

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);
    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);

    const policyEs = findPolicyEventSource();
    policyEs.__emit("lagged", "subscriber_lagged");
    await flush();

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(2);
    expect(
      logger.warn.mock.calls.some((c) =>
        /policy subscriber: lagged event/.test(String(c[0])),
      ),
    ).toBe(true);

    await evaluator.flushPendingAudits();
  });

  it("close() shuts down both EventSources", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });

    expect(MockEventSource.instances).toHaveLength(2);
    sub.close();
    for (const es of MockEventSource.instances) {
      expect(es.closed).toBe(true);
    }
    // Idempotent.
    expect(() => sub.close()).not.toThrow();
  });

  // ── PASS2-SDK-01 Item C — lifecycle SSE fast-paths ─────────────────────────

  function buildEvaluator(records: EvalFetchRecord[]): CedarToolCallClient {
    return new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
  }

  async function startSub(evaluator: CedarToolCallClient): Promise<SchemaSubscriber> {
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger: silentLogger(),
      cedarClient: evaluator,
    });
    return sub;
  }

  it("agent_suspended populates the local fail-CLOSED deny-set; next evaluate denies in-process", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = buildEvaluator(records);
    await startSub(evaluator);

    expect(evaluator.isSuspended(AGENT_ID)).toBe(false);

    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "agent_suspended",
      JSON.stringify({ kind: "agent_suspended", tenant_id: TENANT_ID, agent_id: AGENT_ID }),
    );
    await flush();

    expect(evaluator.isSuspended(AGENT_ID)).toBe(true);

    // Suspended → deny WITHOUT a wire round-trip.
    const r = await evaluator.evaluateToolCall({ toolName: "search", arguments: { q: "x" } });
    expect(r.decision).toBe("deny");
    expect(r.reason).toBe("agent suspended");
    expect(countEvalCalls(records)).toBe(0);

    await evaluator.flushPendingAudits();
  });

  it("agent_activated clears the deny-set; evaluate resumes hitting the wire", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = buildEvaluator(records);
    await startSub(evaluator);

    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "agent_suspended",
      JSON.stringify({ kind: "agent_suspended", tenant_id: TENANT_ID, agent_id: AGENT_ID }),
    );
    await flush();
    expect(evaluator.isSuspended(AGENT_ID)).toBe(true);

    policyEs.__emit(
      "agent_activated",
      JSON.stringify({ kind: "agent_activated", tenant_id: TENANT_ID, agent_id: AGENT_ID }),
    );
    await flush();
    expect(evaluator.isSuspended(AGENT_ID)).toBe(false);

    const r = await evaluator.evaluateToolCall({ toolName: "search", arguments: { q: "x" } });
    expect(r.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(1);

    await evaluator.flushPendingAudits();
  });

  it("drops a cross-tenant agent_suspended event (tenant-guard)", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = buildEvaluator(records);
    await startSub(evaluator);

    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "agent_suspended",
      JSON.stringify({ kind: "agent_suspended", tenant_id: "other-tenant", agent_id: AGENT_ID }),
    );
    await flush();

    expect(evaluator.isSuspended(AGENT_ID)).toBe(false);

    await evaluator.flushPendingAudits();
  });

  it("hitl_grant pre-populates the ApprovalGrantCache keyed on args_hash; identical call short-circuits", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = buildEvaluator(records);
    await startSub(evaluator);

    const toolArgs = { city: "Paris" };
    const argsHash = await hashArgsCanonical(toolArgs);
    expect(argsHash).toBeDefined();

    const expiresAt = new Date(Date.now() + 300_000).toISOString();
    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "hitl_grant",
      JSON.stringify({
        kind: "hitl_grant",
        tenant_id: TENANT_ID,
        agent_id: AGENT_ID,
        tool: "get_weather",
        args_hash: argsHash,
        granted_by: "operator@example.com",
        expires_at: expiresAt,
        request_id: "11111111-1111-1111-1111-111111111111",
      }),
    );
    await flush();

    // The grant is now findable under the SAME canonical args_hash.
    const grant = await evaluator.findApprovalGrant({
      agentId: AGENT_ID,
      toolName: "get_weather",
      toolArgs,
    });
    expect(grant).toBeDefined();
    expect(grant?.requestId).toBe("11111111-1111-1111-1111-111111111111");

    // The next identical tool call short-circuits to allow WITHOUT a wire call.
    const r = await evaluator.evaluateToolCall({ toolName: "get_weather", arguments: toolArgs });
    expect(r.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(0);

    // A DIFFERENT args shape misses the grant key (args_hash differs) and falls
    // through to the wire.
    const r2 = await evaluator.evaluateToolCall({
      toolName: "get_weather",
      arguments: { city: "London" },
    });
    expect(r2.decision).toBe("allow");
    expect(countEvalCalls(records)).toBe(1);

    await evaluator.flushPendingAudits();
  });

  it("drops a cross-tenant hitl_grant event (tenant-guard)", async () => {
    const records: EvalFetchRecord[] = [];
    const evaluator = buildEvaluator(records);
    await startSub(evaluator);

    const toolArgs = { city: "Paris" };
    const argsHash = await hashArgsCanonical(toolArgs);
    const policyEs = findPolicyEventSource();
    policyEs.__emit(
      "hitl_grant",
      JSON.stringify({
        kind: "hitl_grant",
        tenant_id: "other-tenant",
        agent_id: AGENT_ID,
        tool: "get_weather",
        args_hash: argsHash,
        granted_by: "operator@example.com",
        expires_at: new Date(Date.now() + 300_000).toISOString(),
        request_id: "22222222-2222-2222-2222-222222222222",
      }),
    );
    await flush();

    const grant = await evaluator.findApprovalGrant({
      agentId: AGENT_ID,
      toolName: "get_weather",
      toolArgs,
    });
    expect(grant).toBeUndefined();

    await evaluator.flushPendingAudits();
  });

  it("invalidates the cache even on a malformed `policy` payload (fail-CLOSED)", async () => {
    const records: EvalFetchRecord[] = [];
    const logger = silentLogger();
    const evaluator = new CedarToolCallClient({
      baseUrl: BASE_URL,
      apiKey: API_KEY,
      agentId: AGENT_ID,
      fetchImpl: makeEvalFetch(records),
      logger: silentLogger(),
    });
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
      cedarClient: evaluator,
    });

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(1);

    const policyEs = findPolicyEventSource();
    policyEs.__emit("policy", "not-json-at-all{");
    await flush();

    await evaluator.evaluateToolCall({
      toolName: "search",
      arguments: { q: "foo" },
    });
    expect(countEvalCalls(records)).toBe(2);
    expect(
      logger.warn.mock.calls.some((c) =>
        /malformed policy payload/.test(String(c[0])),
      ),
    ).toBe(true);

    await evaluator.flushPendingAudits();
  });
});
