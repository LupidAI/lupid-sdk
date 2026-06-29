/**
 * Tests for the `agentum.init()` drop-in.
 *
 * Coverage:
 *   - Idempotency (concurrent + serial)
 *   - Required-env validation
 *   - Cedar evaluator client (allow / deny / cache / timeout fail-closed)
 *   - Streaming + non-streaming OpenAI parsers (via the patched `create`)
 *   - Anthropic parsers (non-streaming + streaming)
 *
 * The OpenAI / Anthropic packages are not installed in this repo, so we
 * test the patch + parser machinery by directly exercising the parsers
 * and the `CedarToolCallClient`. End-to-end installation is verified via
 * a separate integration script (see `examples/init_e2e.ts`).
 */

import {
  init,
  _resetForTests,
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "../src/index";
import {
  ingestOpenAIChunk,
  newOpenAIStreamState,
  extractOpenAIToolCalls,
  ingestAnthropicEvent,
  newAnthropicStreamState,
  extractAnthropicToolUses,
} from "../src/instrumentation/_parsers";

function mockFetch(handler: (input: unknown, init?: unknown) => unknown): jest.Mock {
  return jest.fn().mockImplementation(async (input, opts) => {
    // S1-12 — short-circuit the manifest pipeline's live-schema fetch
    // for legacy tests that don't differentiate URLs in their handler.
    // The schema URL is routed BEFORE the handler runs so a passthrough
    // catch-all handler can't accidentally return a non-schema envelope
    // (which would fail TenantSchema validation downstream).
    //
    // Tests that NEED real schema-fetch behaviour use
    // `tests/manifest/init-integration.test.ts` (nock-backed, no shared
    // mockFetch). If a future test in this file wants its own schema
    // envelope, it can switch to nock or add a dedicated mock branch
    // — do not loosen the URL match below.
    const url = typeof input === "string" ? input : String(input);
    // The manifest client fetches the per-agent schema route
    // (`agents/{agentId}/schema`, see client.ts:53 — moved from the legacy
    // per-tenant route in PRE-S2-08). Match both so the short-circuit keeps
    // intercepting the schema fetch regardless of which form a caller uses.
    const schemaMatch = url.match(/\/api\/v1\/(?:tenants|agents)\/([^/]+)\/schema$/);
    if (schemaMatch) {
      const envelope = {
        tenant_id: schemaMatch[1], // echo from URL so tests aren't lied to
        version: 1,
        definition: { version: 1, dimensions: [] },
      };
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve(envelope),
        text: () => Promise.resolve(JSON.stringify(envelope)),
        headers: { get: () => "application/json" },
      };
    }
    const result = await handler(input, opts);
    if (result instanceof Error) throw result;
    const body = result as { status?: number; json?: unknown };
    return {
      ok:     (body.status ?? 200) < 400,
      status: body.status ?? 200,
      json:   () => Promise.resolve(body.json ?? {}),
      text:   () => Promise.resolve(JSON.stringify(body.json ?? {})),
      headers: { get: () => "application/json" },
    };
  });
}

const ENV_BASE = {
  AGENTUM_BASE_URL:   "http://agentum:7071",
  AGENTUM_API_KEY:    "ak_test",
  AGENTUM_AGENT_NAME: "init-test-agent",
};

describe("agentum.init()", () => {
  beforeEach(async () => {
    await _resetForTests();
  });

  it("validates required env", async () => {
    await expect(
      init({ env: {}, logger: silentLogger() }),
    ).rejects.toThrow(/AGENTUM_BASE_URL/);
    await expect(
      init({ env: { AGENTUM_BASE_URL: "x" }, logger: silentLogger() }),
    ).rejects.toThrow(/AGENTUM_API_KEY/);
    await expect(
      init({ env: { AGENTUM_BASE_URL: "x", AGENTUM_API_KEY: "y" }, logger: silentLogger() }),
    ).rejects.toThrow(/AGENTUM_AGENT_NAME/);
  });

  test.each([
    ["AGENTUM_BASE_URL",   {}],
    ["AGENTUM_API_KEY",    { AGENTUM_BASE_URL: "http://x" }],
    ["AGENTUM_AGENT_NAME", { AGENTUM_BASE_URL: "http://x", AGENTUM_API_KEY: "k" }],
  ])("init() throws actionable hint for %s", async (name, env) => {
    await expect(
      init({ env, logger: silentLogger() }),
    ).rejects.toThrow(name);
    await expect(
      init({ env, logger: silentLogger() }),
    ).rejects.toThrow(/github\.com\/lupidai\/lupid-sdk/);
  });

  it("is idempotent across serial and concurrent calls", async () => {
    const f = mockFetch(() => ({
      json: { agent_id: "a-1", tenant_id: "t-1", created: true },
    }));
    const opts = {
      env:       ENV_BASE,
      fetchImpl: f as unknown as typeof fetch,
      logger:    silentLogger(),
      disableAutoPatch: true,
    };
    const r1 = await init(opts);
    const [r2, r3] = await Promise.all([init(opts), init(opts)]);
    expect(r1).toBe(r2);
    expect(r2).toBe(r3);
    // Only one /sdk/register call across all three init()s.
    const registerCalls = f.mock.calls.filter((c) =>
      String(c[0]).includes("/sdk/register"),
    );
    expect(registerCalls).toHaveLength(1);
  });

  it("does not auto-patch when disableAutoPatch is true", async () => {
    const f = mockFetch(() => ({
      json: { agent_id: "a-1", tenant_id: "t-1", created: true },
    }));
    const rt = await init({
      env: ENV_BASE,
      fetchImpl: f as unknown as typeof fetch,
      logger: silentLogger(),
      disableAutoPatch: true,
    });
    expect(rt.patchedOpenAI).toBe(false);
    expect(rt.patchedAnthropic).toBe(false);
  });

  // A3 / ADR-0017 — PDP is opt-in via AGENTUM_PDP_URL presence.
  // The zero-config path must produce no PDP wiring AND no
  // service-token-missing warn (the warn is gated on
  // `pdpUrl && !pdpServiceToken && !pdpUrl.startsWith("unix://")` at
  // init.ts:318, so with the default flipped to "" the warn block is
  // unreachable in Mode A). The init complete log line must report
  // `pdp=disabled` so operators get positive confirmation.
  it("Mode A: zero-config defaults to PDP disabled with no service-token warn", async () => {
    const f = mockFetch(() => ({
      json: { agent_id: "a-1", tenant_id: "t-1", created: true },
    }));
    const log = jest.fn();
    const warn = jest.fn();
    const rt = await init({
      env: ENV_BASE,
      fetchImpl: f as unknown as typeof fetch,
      logger: { log, warn, error: () => {} },
      disableAutoPatch: true,
    });
    // PDP wiring is absent on the resolved evaluator.
    expect(
      (rt.evaluator as unknown as { pdpUrl: string | undefined }).pdpUrl,
    ).toBeUndefined();
    // No service-token warn (it would mention AGENTUM_PDP_SERVICE_TOKEN).
    for (const call of warn.mock.calls) {
      expect(String(call[0])).not.toMatch(/AGENTUM_PDP_SERVICE_TOKEN/);
    }
    // Init complete log line reports `pdp=disabled`.
    const initLogged = log.mock.calls
      .map((c) => String(c[0]))
      .filter((s) => s.includes("[agentum] init complete"));
    expect(initLogged.length).toBeGreaterThan(0);
    expect(initLogged[0]).toMatch(/pdp=disabled/);
  });

  it("Mode B: explicit AGENTUM_PDP_URL wires PDP and logs the url", async () => {
    const f = mockFetch(() => ({
      json: { agent_id: "a-1", tenant_id: "t-1", created: true },
    }));
    const log = jest.fn();
    const rt = await init({
      env: {
        ...ENV_BASE,
        AGENTUM_PDP_URL: "http://127.0.0.1:7080",
        AGENTUM_PDP_SERVICE_TOKEN: "svc_tok",
      },
      fetchImpl: f as unknown as typeof fetch,
      logger: { log, warn: () => {}, error: () => {} },
      disableAutoPatch: true,
    });
    expect(
      (rt.evaluator as unknown as { pdpUrl: string | undefined }).pdpUrl,
    ).toBe("http://127.0.0.1:7080");
    const initLogged = log.mock.calls
      .map((c) => String(c[0]))
      .filter((s) => s.includes("[agentum] init complete"));
    expect(initLogged.length).toBeGreaterThan(0);
    expect(initLogged[0]).toMatch(/pdp=http:\/\/127\.0\.0\.1:7080/);
  });
});

describe("CedarToolCallClient", () => {
  function client(handler: Parameters<typeof mockFetch>[0]): {
    c: CedarToolCallClient;
    f: jest.Mock;
  } {
    const f = mockFetch(handler);
    const c = new CedarToolCallClient({
      baseUrl: "http://agentum:7071",
      apiKey:  "ak_test",
      agentId: "agent-1",
      fetchImpl: f as unknown as typeof fetch,
      logger:  silentLogger(),
    });
    return { c, f };
  }

  it("returns allow on a permissive policy", async () => {
    const { c } = client(() => ({
      json: { decision: "allow", ttl_ms: 15_000 },
    }));
    const r = await c.evaluateToolCall({ toolName: "web_search", arguments: { q: "x" } });
    expect(r.decision).toBe("allow");
    expect(r.ttlMs).toBe(15_000);
  });

  it("returns deny with rule_id and reason", async () => {
    const { c } = client(() => ({
      json: { decision: "deny", ttl_ms: 5_000, rule_id: "rule-7", reason: "no_pii", advice: ["redact"] },
    }));
    const r = await c.evaluateToolCall({ toolName: "send_email", arguments: { to: "a@b.com" } });
    expect(r).toEqual<ToolCallEvaluation>({
      decision: "deny",
      ttlMs:    5_000,
      ruleId:   "rule-7",
      reason:   "no_pii",
      advice:   ["redact"],
      decisionSource: "central",
    });
  });

  it("caches by (tool, arguments) for the server-supplied ttl", async () => {
    const { c, f } = client(() => ({
      json: { decision: "allow", ttl_ms: 60_000 },
    }));
    // L06 — every evaluate also fires a fire-and-forget audit POST, so we
    // scope the call-count assertion to the evaluate-tool-call URL rather
    // than the raw fetch counter.
    const evaluateCalls = (): number =>
      f.mock.calls.filter((args: unknown[]) =>
        String(args[0]).includes("/api/v1/sdk/evaluate-tool-call"),
      ).length;
    await c.evaluateToolCall({ toolName: "tool_a", arguments: { x: 1 } });
    await c.evaluateToolCall({ toolName: "tool_a", arguments: { x: 1 } });
    expect(evaluateCalls()).toBe(1);
    // Different arguments → different cache key → second call.
    await c.evaluateToolCall({ toolName: "tool_a", arguments: { x: 2 } });
    expect(evaluateCalls()).toBe(2);
  });

  it("fails closed (deny) on transport errors", async () => {
    const { c } = client(() => new Error("ECONNREFUSED"));
    const r = await c.evaluateToolCall({ toolName: "tool_a" });
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/fail-closed/);
  });

  it("fails closed on timeout", async () => {
    const c = new CedarToolCallClient({
      baseUrl: "http://agentum:7071",
      apiKey:  "ak_test",
      agentId: "agent-1",
      timeoutMs: 5,
      logger:    silentLogger(),
      fetchImpl: ((_url: unknown, opts?: { signal?: AbortSignal }) =>
        new Promise((_, reject) => {
          opts?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        })) as unknown as typeof fetch,
    });
    const r = await c.evaluateToolCall({ toolName: "slow_tool" });
    expect(r.decision).toBe("deny");
    expect(r.reason).toMatch(/timeout/);
  });

  it("can be configured to fail open in dev mode", async () => {
    const c = new CedarToolCallClient({
      baseUrl: "http://agentum:7071",
      apiKey:  "ak_test",
      agentId: "agent-1",
      failMode: "allow",
      logger:    silentLogger(),
      fetchImpl: (() => Promise.reject(new Error("nope"))) as unknown as typeof fetch,
    });
    const r = await c.evaluateToolCall({ toolName: "tool_a" });
    expect(r.decision).toBe("allow");
  });
});

describe("OpenAI parsers", () => {
  it("aggregates streaming tool_calls by index", () => {
    const state = newOpenAIStreamState();
    const chunks = [
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "web_", arguments: "" } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { name: "search", arguments: "{\"q\":" } }] } }] },
      { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: "\"x\"}" } }] } }] },
      { choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] },
    ];
    for (const c of chunks) ingestOpenAIChunk(state, c);
    expect(state.toolCalls.size).toBe(1);
    const tc = state.toolCalls.get(0)!;
    expect(tc.id).toBe("c1");
    expect(tc.function.name).toBe("web_search");
    expect(tc.function.arguments).toBe("{\"q\":\"x\"}");
    expect(state.finishReason).toBe("tool_calls");
  });

  it("extracts non-streaming tool_calls from a completion response", () => {
    const resp = {
      choices: [{
        message: {
          tool_calls: [
            { id: "c1", type: "function", function: { name: "f", arguments: "{}" } },
          ],
        },
      }],
    };
    const tcs = extractOpenAIToolCalls(resp);
    expect(tcs).toHaveLength(1);
    expect(tcs[0]!.function.name).toBe("f");
  });
});

describe("Anthropic parsers", () => {
  it("aggregates streaming tool_use input_json_delta", () => {
    const state = newAnthropicStreamState();
    const events = [
      { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "tu_1", name: "weather", input: {} } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: "{\"city\":" } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: "\"sf\"}" } },
      { type: "content_block_stop",  index: 0 },
      { type: "message_delta", delta: { stop_reason: "tool_use" } },
    ];
    for (const e of events) ingestAnthropicEvent(state, e);
    expect(state.toolUses.size).toBe(1);
    const tu = state.toolUses.get(0)!;
    expect(tu.id).toBe("tu_1");
    expect(tu.name).toBe("weather");
    expect(tu.partialJson).toBe("{\"city\":\"sf\"}");
    expect(state.stopReason).toBe("tool_use");
  });

  it("extracts non-streaming tool_use blocks", () => {
    const resp = {
      content: [
        { type: "text", text: "ok" },
        { type: "tool_use", id: "tu_1", name: "weather", input: { city: "sf" } },
      ],
      stop_reason: "tool_use",
    };
    const tus = extractAnthropicToolUses(resp);
    expect(tus).toHaveLength(1);
    expect(tus[0]!.index).toBe(1);
    expect(tus[0]!.input).toEqual({ city: "sf" });
  });
});

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}
