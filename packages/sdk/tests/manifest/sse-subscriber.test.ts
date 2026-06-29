/**
 * S1-16 — SchemaSubscriber unit tests.
 *
 * The `eventsource` polyfill is jest-mocked so tests never open a real
 * socket. The mock exposes a `__emit(event, data)` hook so each test can
 * deterministically simulate `schema_installed` / `lagged` / error
 * arrivals.
 */

import nock from "nock";

import {
  SchemaSubscriber,
  __resetSchemaSubscriberForTest,
} from "../../src/manifest/sse-subscriber";
import { _setActiveSchema, getActiveSchema } from "../../src/manifest/state";
import { AdminHttpClient } from "../../src/admin/http";
import type { TenantSchema } from "../../src/manifest/types";

// --- jest.mock for the `eventsource` polyfill ------------------------------

type Listener = (ev: { data: string }) => void;

class MockEventSource {
  static instances: MockEventSource[] = [];

  url: string;
  init?: { fetch?: unknown };
  listeners: Map<string, Listener[]> = new Map();
  onerror: ((ev: unknown) => void) | null = null;
  closed = false;

  constructor(url: string, init?: { fetch?: unknown }) {
    this.url = url;
    if (init !== undefined) this.init = init;
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

  // Test-only hook
  __emit(event: string, data: string): void {
    const arr = this.listeners.get(event) ?? [];
    for (const l of arr) {
      l({ data });
    }
  }

  __triggerError(err: unknown = new Error("connection lost")): void {
    if (this.onerror) this.onerror(err);
  }
}

jest.mock("eventsource", () => ({
  EventSource: MockEventSource,
}));

// --- helpers ---------------------------------------------------------------

function silentLogger(): { log: jest.Mock; warn: jest.Mock; error: jest.Mock } {
  return { log: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

/** Drain pending microtasks + timers so async refresh paths complete. */
async function flush(): Promise<void> {
  // Yield enough times to clear: handleEvent → refreshSchema → adminHttp.get
  // → fetch → response.json() → reconcile → _setActiveSchema. Each await
  // is at least one microtask; a real network roundtrip via nock can also
  // schedule a setImmediate/setTimeout(0). 50 ticks + a 10ms real timer
  // is generous and still <100ms per test.
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

// Wire shape mirror — see SchemaInstalledWire in sse-subscriber.ts.
function wireEvent(opts: {
  tenantId?: string;
  agentId?: string;
  version: number;
  previous?: number | null;
}): string {
  return JSON.stringify({
    tenant_id: opts.tenantId ?? TENANT_ID,
    agent_id: opts.agentId ?? AGENT_ID,
    version: opts.version,
    previous_version: opts.previous ?? null,
    added_columns: [],
    manifest_revision_id: null,
    installed_at: new Date().toISOString(),
  });
}

// --- tests -----------------------------------------------------------------

describe("SchemaSubscriber", () => {
  beforeEach(() => {
    MockEventSource.instances = [];
    nock.cleanAll();
    nock.disableNetConnect();
    __resetSchemaSubscriberForTest();
    _setActiveSchema(mkSchema(1));
  });

  afterEach(() => {
    __resetSchemaSubscriberForTest();
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it("applies a new schema on schema_installed for the matching tenant", async () => {
    // Server returns v2 on the live-fetch path.
    nock(BASE_URL)
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(200, {
        tenant_id: TENANT_ID,
        version: 2,
        definition: mkSchema(2),
      });

    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
    });

    expect(MockEventSource.instances).toHaveLength(1);
    const es = MockEventSource.instances[0]!;
    expect(es.url).toBe(`${BASE_URL}/api/v1/agents/${AGENT_ID}/schema/stream`);

    // Simulate server push.
    es.__emit("schema_installed", wireEvent({ version: 2, previous: 1 }));
    // The handler is async (refreshSchema awaits a fetch). Yield twice to
    // let the promise chain settle.
    await flush();
    await flush();

    expect(getActiveSchema().version).toBe(2);
    expect(
      logger.log.mock.calls.some((c) =>
        /schema subscriber: applied v2/.test(String(c[0])),
      ),
    ).toBe(true);
  });

  it("drops cross-agent events without calling getLiveSchema (defence in depth)", async () => {
    // No nock scope set up — if we accidentally call getLiveSchema, the
    // request will throw `Nock: Disallowed net connect` and the test fails
    // loudly.
    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
    });

    const es = MockEventSource.instances[0]!;
    es.__emit(
      "schema_installed",
      wireEvent({ agentId: "other-agent-xx", version: 99 }),
    );
    await flush();
    await flush();

    // Schema must not change.
    expect(getActiveSchema().version).toBe(1);
    expect(
      logger.warn.mock.calls.some((c) =>
        /dropping cross-agent event/.test(String(c[0])),
      ),
    ).toBe(true);
  });

  it("triggers a refresh on a 'lagged' event", async () => {
    nock(BASE_URL)
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(200, {
        tenant_id: TENANT_ID,
        version: 5,
        definition: mkSchema(5),
      });

    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
    });

    const es = MockEventSource.instances[0]!;
    es.__emit("lagged", "subscriber_lagged");
    await flush();
    await flush();

    expect(getActiveSchema().version).toBe(5);
    expect(
      logger.log.mock.calls.some((c) =>
        /schema subscriber: applied v5 \(lagged\)/.test(String(c[0])),
      ),
    ).toBe(true);
  });

  it("logs a warning but keeps listening when getLiveSchema fails", async () => {
    // First refresh: 500. Second refresh (after a follow-up event): 200.
    nock(BASE_URL)
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(500, { error: "boom" })
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(500, { error: "boom" })
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(500, { error: "boom" })
      .get(`/api/v1/agents/${AGENT_ID}/schema`)
      .reply(500, { error: "boom" });

    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: new AdminHttpClient({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        // Disable retries to keep the test fast.
        retries: 0,
        retryDelayMs: 1,
      }),
      localSchema: mkSchema(1),
      logger,
    });

    const es = MockEventSource.instances[0]!;
    es.__emit("schema_installed", wireEvent({ version: 2 }));
    await flush();
    await flush();

    // Schema unchanged.
    expect(getActiveSchema().version).toBe(1);
    expect(
      logger.warn.mock.calls.some((c) =>
        /schema subscriber: refresh failed/.test(String(c[0])),
      ),
    ).toBe(true);

    // Subscriber should still be alive and ready to receive the next event.
    expect(es.closed).toBe(false);
  });

  it("close() is idempotent and stops listening", async () => {
    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
    });
    const es = MockEventSource.instances[0]!;

    sub.close();
    expect(es.closed).toBe(true);
    // Idempotent — second close must not throw.
    expect(() => sub.close()).not.toThrow();

    // After close, an in-flight event must not advance the active schema.
    es.__emit("schema_installed", wireEvent({ version: 99 }));
    await flush();
    expect(getActiveSchema().version).toBe(1);
  });

  it("onerror increments reconnect counter without crashing", async () => {
    const logger = silentLogger();
    const sub = new SchemaSubscriber();
    await sub.start({
      baseUrl: BASE_URL,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      adminHttp: buildAdminHttp(),
      localSchema: mkSchema(1),
      logger,
    });
    const es = MockEventSource.instances[0]!;

    es.__triggerError();
    es.__triggerError();

    expect(
      logger.log.mock.calls.filter((c) =>
        /connection error \(attempt \d+\)/.test(String(c[0])),
      ),
    ).toHaveLength(2);
  });
});
