/**
 * Sprint 3.3 — W3C Trace Context propagation tests.
 *
 * These tests assert that (a) the tracing helper mints/parses the
 * W3C header correctly and (b) the runtime + admin clients attach a
 * `traceparent` on every outbound request without any OTel dep.
 */

import { describe, expect, it, jest } from "@jest/globals";

import { AgentumClient } from "../src/client.js";
import { AgentumAdminClient } from "../src/admin/index.js";
import {
  formatTraceparent,
  mintTraceContext,
  parseTraceparent,
  resolveTraceContext,
  type TraceContext,
} from "../src/tracing.js";

describe("tracing helpers", () => {
  it("mintTraceContext produces valid W3C shapes", () => {
    const ctx = mintTraceContext();
    expect(ctx.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(ctx.spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(ctx.flags).toBe("01");
    expect(/^0+$/.test(ctx.traceId)).toBe(false);
    expect(/^0+$/.test(ctx.spanId)).toBe(false);
  });

  it("formatTraceparent + parseTraceparent round-trip", () => {
    const ctx = mintTraceContext();
    const header = formatTraceparent(ctx);
    expect(header).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/);
    const parsed = parseTraceparent(header)!;
    expect(parsed.traceId).toBe(ctx.traceId);
    expect(parsed.spanId).toBe(ctx.spanId);
    expect(parsed.flags).toBe(ctx.flags);
  });

  it("parseTraceparent rejects malformed inputs", () => {
    expect(parseTraceparent(null)).toBeNull();
    expect(parseTraceparent("")).toBeNull();
    expect(parseTraceparent("garbage")).toBeNull();
    expect(parseTraceparent("00-short-b7ad6b7169203331-01")).toBeNull();
    expect(
      parseTraceparent(
        "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
      ),
    ).toBeNull();
    expect(
      parseTraceparent(
        "00-00000000000000000000000000000000-b7ad6b7169203331-01",
      ),
    ).toBeNull();
    expect(
      parseTraceparent(
        "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
      ),
    ).toBeNull();
  });

  it("resolveTraceContext prefers a caller-supplied provider", () => {
    const provider = {
      getActiveContext(): TraceContext {
        return {
          traceId: "feedface00000000000000000000dead",
          spanId: "1111222233334444",
          flags: "01",
        };
      },
    };
    expect(resolveTraceContext(provider).traceId).toBe(
      "feedface00000000000000000000dead",
    );
  });

  it("resolveTraceContext falls back to a minted id when provider returns null", () => {
    const provider = { getActiveContext: () => null };
    const ctx = resolveTraceContext(provider);
    expect(ctx.traceId).toMatch(/^[0-9a-f]{32}$/);
  });
});

function capturingFetch() {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, init: init ?? {} });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  return { calls, fetch: fetchImpl as unknown as typeof globalThis.fetch };
}

describe("AgentumClient — traceparent injection", () => {
  it("attaches a traceparent on outbound requests when no provider is set", async () => {
    const { calls, fetch } = capturingFetch();
    const client = new AgentumClient({
      baseUrl: "http://localhost:7071",
      apiKey: "ak_test",
      fetch,
    });
    await client.health();
    expect(calls.length).toBe(1);
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["traceparent"]).toBeDefined();
    expect(headers["traceparent"]).toMatch(
      /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/,
    );
  });

  it("caller-supplied tracingProvider wins over the minter", async () => {
    const { calls, fetch } = capturingFetch();
    const fixed: TraceContext = {
      traceId: "0af7651916cd43dd8448eb211c80319c",
      spanId: "b7ad6b7169203331",
      flags: "01",
    };
    const client = new AgentumClient({
      baseUrl: "http://localhost:7071",
      apiKey: "ak_test",
      fetch,
      tracingProvider: { getActiveContext: () => fixed },
    });
    await client.health();
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["traceparent"]).toBe(formatTraceparent(fixed));
  });

  it("retries reuse the same traceparent (one logical operation)", async () => {
    const calls: Array<Record<string, unknown>> = [];
    let n = 0;
    const fetch = jest.fn(async (_input: unknown, init?: RequestInit) => {
      calls.push((init?.headers as Record<string, unknown>) ?? {});
      n++;
      if (n === 1) {
        return new Response("", { status: 503 });
      }
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const client = new AgentumClient({
      baseUrl: "http://localhost:7071",
      apiKey: "ak_test",
      fetch: fetch as unknown as typeof globalThis.fetch,
      retries: 2,
      retryDelayMs: 1,
    });
    await client.health();
    expect(calls.length).toBe(2);
    expect((calls[0] as Record<string, string>)["traceparent"]).toBe(
      (calls[1] as Record<string, string>)["traceparent"],
    );
  });

  it("ingestAuditEvent stamps trace_id at emit time", async () => {
    const { calls, fetch } = capturingFetch();
    const provider = {
      getActiveContext: (): TraceContext => ({
        traceId: "11111111111111111111111111111111",
        spanId: "2222222222222222",
        flags: "01",
      }),
    };
    const client = new AgentumClient({
      baseUrl: "http://localhost:7071",
      apiKey: "ak_test",
      fetch,
      disableAuditBuffer: true,
      tracingProvider: provider,
    });
    await client.ingestAuditEvent({
      agent_id: "agent-a",
      session_id: "sess-a",
      event_type: "tool_call",
    });
    expect(calls.length).toBe(1);
    const body = JSON.parse((calls[0]!.init.body as string) ?? "{}");
    expect(body.trace_id).toBe("11111111111111111111111111111111");
  });
});

describe("AgentumAdminClient — traceparent injection", () => {
  it("attaches a traceparent on admin requests", async () => {
    const { calls, fetch } = capturingFetch();
    const admin = new AgentumAdminClient({
      baseUrl: "http://localhost:7071",
      apiKey: "ak_test",
      fetch,
    });
    await admin.agents.list();
    expect(calls.length).toBeGreaterThan(0);
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers["traceparent"]).toMatch(
      /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/,
    );
  });
});
