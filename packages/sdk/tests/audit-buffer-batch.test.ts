/**
 * L05 — audit-buffer batch flusher.
 *
 * Asserts the new batched flush contract:
 *   - Single POST per slice against `/api/v1/audit/ingest/batch` with body
 *     shape `{ events: AuditIngestRequest[] }` (NOT a bare array).
 *   - Slice size honours `auditFlushBatchSize` (default 100).
 *   - 5xx / transport: whole batch re-prepended (server is all-or-nothing),
 *     exponential backoff observed.
 *   - 401: batch dropped, `onAuditError` fired with reason `ingest_failed`.
 *   - 422 (or any other 4xx): batch dropped — don't infinite-retry against
 *     a permanent payload error.
 */

import { AgentumClient } from "../src/index";

const BASE = "http://localhost:7071";

interface RequestInitWithBody extends RequestInit {
  body?: string;
}

interface MockResponseSpec {
  status: number;
  body?: unknown;
}

function makeFetch(responses: MockResponseSpec[]): jest.Mock {
  let i = 0;
  return jest.fn().mockImplementation(() => {
    const idx = Math.min(i, responses.length - 1);
    i += 1;
    const r = responses[idx] as MockResponseSpec;
    return Promise.resolve({
      ok: r.status < 400,
      status: r.status,
      headers: { get: () => "application/json" },
      json: () => Promise.resolve(r.body ?? {}),
      text: () => Promise.resolve(JSON.stringify(r.body ?? {})),
    });
  });
}

function batchCalls(f: jest.Mock): Array<{ url: string; events: Array<{ event_type: string }> }> {
  return f.mock.calls
    .filter((call) => (call as [string, RequestInit])[0].includes("audit/ingest/batch"))
    .map((call) => {
      const [url, init] = call as [string, RequestInitWithBody];
      const parsed = JSON.parse(init.body ?? "{}") as { events: Array<{ event_type: string }> };
      return { url, events: parsed.events };
    });
}

describe("audit buffer batch flusher (L05)", () => {
  it("posts a single batch to /audit/ingest/batch with body shape { events: [...] }", async () => {
    const f = makeFetch([{ status: 200, body: { ingested: 3 } }]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "e1" });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "e2" });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "e3" });
    await c.flushAuditBuffer();
    const calls = batchCalls(f);
    expect(calls.length).toBe(1);
    const first = calls[0]!;
    expect(first.url).toMatch(/\/api\/v1\/audit\/ingest\/batch$/);
    expect(first.events.map((e) => e.event_type)).toEqual(["e1", "e2", "e3"]);
    await c.close();
  });

  it("respects auditFlushBatchSize: ceil(N / batchSize) POSTs", async () => {
    // 250 events at batchSize 100 → 3 POSTs of sizes 100, 100, 50.
    const f = makeFetch([{ status: 200, body: { ingested: 100 } }]);
    const c = new AgentumClient({
      baseUrl: BASE,
      fetch: f as unknown as typeof fetch,
      auditBufferSize: 1000, // big enough to hold them all
      auditFlushBatchSize: 100,
    });
    for (let i = 0; i < 250; i++) {
      await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: `e${i}` });
    }
    // close() drains to completion (ignoreBackoff = true).
    await c.close();
    const calls = batchCalls(f);
    expect(calls.length).toBe(3);
    expect(calls[0]!.events.length).toBe(100);
    expect(calls[1]!.events.length).toBe(100);
    expect(calls[2]!.events.length).toBe(50);
    // Order preserved across batches.
    const eventTypes = calls.flatMap((c0) => c0.events.map((e) => e.event_type));
    expect(eventTypes).toEqual(Array.from({ length: 250 }, (_, i) => `e${i}`));
  });

  it("on 503: re-prepends the whole batch and observes backoff", async () => {
    const onAuditError = jest.fn();
    // First call: 503 (5xx). Subsequent calls: 200.
    let i = 0;
    const f = jest.fn().mockImplementation(() => {
      i += 1;
      const status = i === 1 ? 503 : 200;
      return Promise.resolve({
        ok: status < 400,
        status,
        headers: { get: () => "application/json" },
        json: () => Promise.resolve(status === 200 ? { ingested: 2 } : { error: "down" }),
        text: () => Promise.resolve("{}"),
      });
    });
    const c = new AgentumClient({
      baseUrl: BASE,
      fetch: f as unknown as typeof fetch,
      onAuditError,
      retries: 0, // surface 5xx immediately
      auditMaxBackoffMs: 50,
      auditFlushIntervalMs: 100,
    });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "ev-1" });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "ev-2" });
    await c.flushAuditBuffer();
    // Batch came back 503 → re-prepend whole batch, fire onAuditError.
    expect(onAuditError).toHaveBeenCalledWith(
      expect.objectContaining({ reason: "ingest_failed", attempt: 1 }),
    );
    expect(c.auditBufferLength()).toBe(2);
    // close() ignores backoff and retries → second POST succeeds.
    await c.close();
    expect(c.auditBufferLength()).toBe(0);
    const calls = batchCalls(f);
    expect(calls.length).toBe(2);
    expect(calls[0]!.events.map((e) => e.event_type)).toEqual(["ev-1", "ev-2"]);
    expect(calls[1]!.events.map((e) => e.event_type)).toEqual(["ev-1", "ev-2"]);
  });

  it("on 401: drops the batch and emits onAuditError with reason ingest_failed", async () => {
    const onAuditError = jest.fn();
    const f = makeFetch([{ status: 401, body: { error: "unauthorized" } }]);
    const c = new AgentumClient({
      baseUrl: BASE,
      fetch: f as unknown as typeof fetch,
      onAuditError,
      retries: 0,
    });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "x1" });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "x2" });
    await c.flushAuditBuffer();
    expect(onAuditError).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: "ingest_failed",
        dropped: 2,
      }),
    );
    // Batch dropped — buffer is empty after the failed flush.
    expect(c.auditBufferLength()).toBe(0);
    // Exactly one POST attempted (no per-event fallback).
    expect(batchCalls(f).length).toBe(1);
    await c.close();
  });

  it("on 422: drops the batch (no infinite-retry against malformed payload)", async () => {
    const onAuditError = jest.fn();
    const f = makeFetch([{ status: 422, body: { error: "agent_id required" } }]);
    const c = new AgentumClient({
      baseUrl: BASE,
      fetch: f as unknown as typeof fetch,
      onAuditError,
      retries: 0,
    });
    await c.ingestAuditEvent({ agent_id: "a", session_id: "s", event_type: "y1" });
    await c.flushAuditBuffer();
    expect(onAuditError).toHaveBeenCalledWith(
      expect.objectContaining({
        reason: "ingest_failed",
        dropped: 1,
      }),
    );
    expect(c.auditBufferLength()).toBe(0);
    // Even on close() we don't re-attempt — the error was permanent.
    await c.close();
    expect(batchCalls(f).length).toBe(1);
  });
});
