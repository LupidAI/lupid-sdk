/**
 * L01 — PDP-first SDK wiring.
 *
 * Mirrors the `fetchImpl`-injection style of `cedar-client-timeout.test.ts`
 * and `cedar-client-plaintext.test.ts`. No nock — those tests don't use it
 * either. We assert the SDK:
 *   - probes PDP `/v1/health` and routes `/v1/authorize` traffic when alive
 *   - falls back to central exactly once on transport / 5xx
 *   - fails closed on 401 (no fallback) and logs an error
 *   - caches the unhealthy verdict for `pdpDiscoveryTtlMs`
 *   - sends `Authorization: Bearer <token>` when configured
 *   - surfaces `policy_hash` and tags `decisionSource`
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

interface FetchOutcome {
  status?: number;
  body?: string;
  throwErr?: Error;
  /** Resolve after this many ms. Default 0 (synchronous). */
  delayMs?: number;
}

/**
 * Build a `fetch`-shaped function that dispatches by URL path. Pass a map
 * of `{ "/v1/health": {…}, "/v1/authorize": {…}, "/api/v1/sdk/evaluate-tool-call": {…} }`.
 * Records every call into `capture`. Each route may also be a function
 * that picks the outcome based on call count, for the 5xx-then-200 cases.
 */
function makeRoutedFetch(
  routes: Record<string, FetchOutcome | ((callIdx: number) => FetchOutcome)>,
  capture: CapturedCall[] = [],
): typeof fetch {
  const counts: Record<string, number> = {};
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    capture.push({ url: u, init });
    const matchKey = Object.keys(routes).find((k) => u.endsWith(k));
    if (!matchKey) throw new Error(`unrouted URL in test fetch: ${u}`);
    counts[matchKey] = (counts[matchKey] ?? 0) + 1;
    const route = routes[matchKey]!;
    const outcome = typeof route === "function" ? route(counts[matchKey]! - 1) : route;
    // Honour aborts during the synthetic delay.
    if (outcome.delayMs && outcome.delayMs > 0) {
      const signal = init?.signal as AbortSignal | undefined;
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, outcome.delayMs);
        signal?.addEventListener("abort", () => {
          clearTimeout(t);
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    }
    if (outcome.throwErr) throw outcome.throwErr;
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

const HEALTH_OK: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    status: "ok",
    agent_id: "agent-1",
    policy_hash: "abc123",
    synced_at: new Date().toISOString(),
    uptime_secs: 1,
  }),
};

const PDP_PERMIT: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "permit-everything",
    policy_hash: "abc123",
    evaluated_locally: true,
    latency_us: 250,
  }),
};

const CENTRAL_PERMIT: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "central-fallback",
    ttl_ms: 5_000,
    policy_hash: "central-hash",
  }),
};

describe("CedarToolCallClient — PDP routing (L01)", () => {
  test("routes to PDP when /v1/health is up", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_PERMIT,
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });

    const result = await client.evaluateToolCall({
      toolName: "search",
      arguments: { q: "hi" },
    });

    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("pdp");
    expect(result.policyHash).toBe("abc123");
    // Both PDP routes hit, central never.
    const urls = captured.map((c) => c.url);
    expect(urls).toContain("http://127.0.0.1:7080/v1/health");
    expect(urls).toContain("http://127.0.0.1:7080/v1/authorize");
    expect(urls.find((u) => u.includes("/api/v1/sdk/evaluate-tool-call"))).toBeUndefined();
  });

  test("falls back to central exactly once on PDP transport error", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": { throwErr: new Error("ECONNRESET") },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const warn = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn, error: () => {} },
    });

    const r1 = await client.evaluateToolCall({ toolName: "search" });
    expect(r1.decision).toBe("allow");
    expect(r1.decisionSource).toBe("central");

    const centralCalls1 = captured.filter((c) =>
      c.url.includes("/api/v1/sdk/evaluate-tool-call"),
    ).length;
    expect(centralCalls1).toBe(1);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("PDP /v1/authorize transport error"),
    );

    // Second call — PDP marked unhealthy, no /v1/health re-probe, straight
    // to central. We cleared no caches so the response *would* be cached;
    // call a different tool to bypass the LRU.
    const r2 = await client.evaluateToolCall({ toolName: "other-tool" });
    expect(r2.decisionSource).toBe("central");
    const healthCalls = captured.filter((c) => c.url.endsWith("/v1/health")).length;
    expect(healthCalls).toBe(1);
    const authorizeCalls = captured.filter((c) =>
      c.url.endsWith("/v1/authorize"),
    ).length;
    // Only the original authorize attempt; no second attempt because
    // PDP is cached unhealthy.
    expect(authorizeCalls).toBe(1);
  });

  test("falls back to central on PDP 5xx", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": { status: 503, body: "{}" },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const warn = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn, error: () => {} },
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("central");
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("PDP /v1/authorize HTTP 503"),
    );
    const centralCalls = captured.filter((c) =>
      c.url.includes("/api/v1/sdk/evaluate-tool-call"),
    ).length;
    expect(centralCalls).toBe(1);
  });

  test("does NOT fall back on PDP 401 — fails closed and logs error", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": { status: 401, body: "" },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const error = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "wrong-token",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error },
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decision).toBe("deny");
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining("PDP returned 401"),
    );
    const centralCalls = captured.filter((c) =>
      c.url.includes("/api/v1/sdk/evaluate-tool-call"),
    ).length;
    expect(centralCalls).toBe(0);
  });

  test("caches PDP unhealthy for pdpDiscoveryTtlMs (no probe storm)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        // Health fails — PDP not running.
        "/v1/health": { status: 503, body: "{}" },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpDiscoveryTtlMs: 60_000,
      fetchImpl,
      logger: silentLogger(),
    });

    await client.evaluateToolCall({ toolName: "tool-a" });
    await client.evaluateToolCall({ toolName: "tool-b" });
    await client.evaluateToolCall({ toolName: "tool-c" });

    const healthCalls = captured.filter((c) => c.url.endsWith("/v1/health")).length;
    expect(healthCalls).toBe(1);
  });

  test("sends Authorization: Bearer header when token configured", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_PERMIT,
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });
    await client.evaluateToolCall({ toolName: "search" });

    const authorizeCall = captured.find((c) => c.url.endsWith("/v1/authorize"));
    expect(authorizeCall).toBeDefined();
    const headers = authorizeCall!.init?.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer s3cret");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  test("surfaces policy_hash on ToolCallEvaluation", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": {
          status: 200,
          body: JSON.stringify({
            decision: "deny",
            rule_id: "block-search",
            reason: "tool not allowed",
            policy_hash: "deadbeef-policy",
            evaluated_locally: true,
            latency_us: 120,
          }),
        },
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });
    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.policyHash).toBe("deadbeef-policy");
    expect(result.decisionSource).toBe("pdp");
    expect(result.ruleId).toBe("block-search");
    expect(result.decision).toBe("deny");
  });

  test("tags decisionSource=central when pdpUrl unset", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      // No pdpUrl — discoverPdp returns false immediately.
      fetchImpl,
      logger: silentLogger(),
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decisionSource).toBe("central");
    expect(result.policyHash).toBe("central-hash");
    // Should never have probed health or authorize.
    expect(captured.find((c) => c.url.endsWith("/v1/health"))).toBeUndefined();
    expect(captured.find((c) => c.url.endsWith("/v1/authorize"))).toBeUndefined();
  });

  // ── L08 ─────────────────────────────────────────────────────────────
  test("L08 — fetchImpl is invoked when pdpUrl uses unix://", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_PERMIT,
      },
      captured,
    );
    const globalFetchSpy = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(() => {
        throw new Error("global fetch must not be called on unix:// path");
      });
    try {
      const client = new CedarToolCallClient({
        baseUrl: "http://api.example",
        apiKey: "k",
        agentId: "agent-1",
        pdpUrl: "unix:///run/agentum/pdp.sock",
        fetchImpl,
        logger: silentLogger(),
      });

      const result = await client.evaluateToolCall({ toolName: "search" });

      expect(result.decision).toBe("allow");
      expect(result.decisionSource).toBe("pdp");
      // The injected fetchImpl must have received unix:// URLs — both health
      // and authorize routed through it.
      const urls = captured.map((c) => c.url);
      expect(urls).toContain("unix:///run/agentum/pdp.sock/v1/health");
      expect(urls).toContain("unix:///run/agentum/pdp.sock/v1/authorize");
      // globalThis.fetch must NOT have been called — this is the whole
      // point of the fetchImpl injection.
      expect(globalFetchSpy).not.toHaveBeenCalled();
    } finally {
      globalFetchSpy.mockRestore();
    }
  });

  test("L08 — PDP health.agent_id mismatch fails closed, no central fallback in TTL", async () => {
    const captured: CapturedCall[] = [];
    const MISMATCH_HEALTH: FetchOutcome = {
      status: 200,
      body: JSON.stringify({
        status: "ok",
        agent_id: "wrong-agent",
        policy_hash: "abc123",
        synced_at: new Date().toISOString(),
        uptime_secs: 1,
      }),
    };
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": MISMATCH_HEALTH,
        "/v1/authorize": PDP_PERMIT,
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const error = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      pdpDiscoveryTtlMs: 60_000,
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error },
    });

    // First call: discoverPdp probes /v1/health, sees mismatch, fails closed.
    // The contract is that `pdpAlive=false` and central is used. No fallback
    // to PDP on subsequent calls within the discovery TTL.
    const r1 = await client.evaluateToolCall({ toolName: "search" });
    expect(r1.decisionSource).toBe("central");
    expect(r1.decision).toBe("allow");

    // The mismatch must have been logged once at error level.
    expect(error).toHaveBeenCalledTimes(1);
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining("PDP /v1/health agent_id mismatch"),
    );

    // /v1/authorize must never have been hit — discoverPdp returned false.
    expect(captured.find((c) => c.url.endsWith("/v1/authorize"))).toBeUndefined();

    // Second call: PDP is cached unhealthy for the TTL. No re-probe, no
    // re-log; central serves directly.
    const r2 = await client.evaluateToolCall({ toolName: "other-tool" });
    expect(r2.decisionSource).toBe("central");
    const healthCalls = captured.filter((c) => c.url.endsWith("/v1/health")).length;
    expect(healthCalls).toBe(1);
    // Still only one error log — TTL caching suppresses re-emission.
    expect(error).toHaveBeenCalledTimes(1);
  });

  test("L08 — PDP health.agent_id match passes through (regression)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK, // agent_id: "agent-1"
        "/v1/authorize": PDP_PERMIT,
      },
      captured,
    );
    const error = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error },
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("pdp");
    expect(error).not.toHaveBeenCalled();
  });

  test("L08 — PDP health body fails to parse → fail closed", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": { status: 200, body: "not-json-at-all" },
        "/v1/authorize": PDP_PERMIT,
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const error = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error },
    });
    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decisionSource).toBe("central");
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining("did not parse as JSON"),
    );
    expect(captured.find((c) => c.url.endsWith("/v1/authorize"))).toBeUndefined();
  });

  // ── L02a ─────────────────────────────────────────────────────────────
  test("L02a — PDP advice strings pass through verbatim (matches central)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": {
          status: 200,
          body: JSON.stringify({
            decision: "allow",
            rule_id: "permit-with-hitl",
            policy_hash: "abc123",
            evaluated_locally: true,
            latency_us: 250,
            // L02a: PDP now returns Vec<String>, byte-identical to central.
            advice: ["require_hitl:approvals=2,timeout=600"],
          }),
        },
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });
    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.decisionSource).toBe("pdp");
    expect(result.advice).toBeDefined();
    expect(result.advice).toHaveLength(1);
    expect(result.advice![0]).toBe("require_hitl:approvals=2,timeout=600");
  });

  test("L02a — PDP advice with non-string entries filtered out (defensive)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": {
          status: 200,
          body: JSON.stringify({
            decision: "allow",
            rule_id: "permit-mixed-advice",
            policy_hash: "abc123",
            evaluated_locally: true,
            latency_us: 250,
            // Defensive: even though the post-L02a PDP wire shape is Vec<String>,
            // the SDK should still narrow safely if a future variant slips through.
            advice: ["require_hitl:approvals=1", 42, null, { rule_id: "x" }],
          }),
        },
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });
    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.advice).toEqual(["require_hitl:approvals=1"]);
  });

  test("L02a — PDP advice absent → advice field unset", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_PERMIT, // no advice field
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });
    const result = await client.evaluateToolCall({ toolName: "search" });
    expect(result.advice).toBeUndefined();
  });

  test("discoverPdp respects pdpProbeTimeoutMs", async () => {
    const captured: CapturedCall[] = [];
    // Health takes 200ms but we probe with a 10ms abort — should fall back.
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": { ...HEALTH_OK, delayMs: 200 },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
      },
      captured,
    );
    const warn = jest.fn();
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      pdpProbeTimeoutMs: 10,
      fetchImpl,
      logger: { log: () => {}, warn, error: () => {} },
    });

    const start = Date.now();
    const result = await client.evaluateToolCall({ toolName: "search" });
    const elapsed = Date.now() - start;

    expect(result.decisionSource).toBe("central");
    // Probe must have aborted well under the 200ms upstream delay.
    expect(elapsed).toBeLessThan(150);
    // Authorize should never have been attempted because health probe
    // failed (aborted).
    expect(captured.find((c) => c.url.endsWith("/v1/authorize"))).toBeUndefined();
  });
});
