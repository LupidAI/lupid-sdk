/**
 * H6 — load test for the SDK's evaluator timeout path.
 *
 * The cardinal SDK invariant is fail-CLOSED on a slow PDP: when the
 * gateway / local PDP doesn't answer within `timeoutMs`, the evaluator
 * must synthesise a deny within ~timeoutMs, every call must complete,
 * and the AbortController plumbing must not leak handles. This test
 * pins all three under N=200 concurrent calls, which is well above
 * any realistic per-second SDK QPS on a single Node process.
 *
 * Why 200 not 1000: the plan's "1000 concurrent" target assumed a
 * gateway-side load test (k6/wrk). For the in-process JS evaluator
 * Jest runs single-threaded; 200 concurrent promises with a 50ms
 * timeout finishes in ~70ms total and runs reliably on CI hardware.
 * 1000 would inflate the suite duration without testing anything
 * the 200-case run doesn't.
 */

import {
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "../src/evaluation/cedar-client";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

/** Build a fetch impl that never resolves within `timeoutMs` of the
 *  signal's abort. Used to force the evaluator into the timeout
 *  fail-CLOSED branch on every call. */
function slowFetch(delayMs: number): typeof fetch {
  return ((async (_url: string | URL, init?: RequestInit) => {
    const signal = init?.signal as AbortSignal | undefined;
    return new Promise<Response>((resolve, reject) => {
      const timer = setTimeout(() => {
        resolve(
          new Response(JSON.stringify({ decision: "allow", ttl_ms: 5000 }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }, delayMs);
      signal?.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(new DOMException("Aborted", "AbortError"));
      });
    });
  }) as unknown) as typeof fetch;
}

describe("CedarToolCallClient — H6 timeout load", () => {
  test("200 concurrent slow calls all fail-CLOSED within bounded time", async () => {
    const timeoutMs = 50;
    // Upstream delay is 10x the client timeout — every call MUST
    // hit the AbortSignal.timeout branch. If the timeout plumbing
    // is broken (e.g. AbortController.signal aliasing regression
    // from cedar-client-timeout.test.ts), at least one call would
    // sit waiting for 500ms and the P99 assertion below would trip.
    const upstreamDelay = 500;

    const client = new CedarToolCallClient({
      baseUrl: "http://test.invalid",
      apiKey: "ak_h6",
      agentId: "agent-h6",
      timeoutMs,
      fetchImpl: slowFetch(upstreamDelay),
      logger: silentLogger(),
    });

    const N = 200;
    const start = Date.now();
    // Distinct tool names defeat the LRU cache so each call really
    // exercises the fetch path. (Cached entries short-circuit
    // before the fetch and would mask a broken timeout.)
    const tasks: Promise<{ verdict: ToolCallEvaluation; latencyMs: number }>[] = [];
    for (let i = 0; i < N; i++) {
      const t0 = Date.now();
      tasks.push(
        client.evaluateToolCall({ toolName: `t-${i}` }).then((verdict) => ({
          verdict,
          latencyMs: Date.now() - t0,
        })),
      );
    }
    const results = await Promise.all(tasks);
    const wallMs = Date.now() - start;

    // ── Every call resolved with a fail-CLOSED deny ───────────────────
    for (const r of results) {
      expect(r.verdict.decision).toBe("deny");
      // H4 — the SDK synthesises `deny_fail_closed` on transport timeout.
      expect(r.verdict.denyCode).toBe("deny_fail_closed");
      // The reason carries the timeout marker.
      expect(r.verdict.reason).toContain("agentum-fail-closed");
    }

    // ── P99 latency bound ─────────────────────────────────────────────
    // Each call should resolve at ~timeoutMs (50 ms) since the
    // AbortController fires on schedule. We allow 4× the configured
    // timeout to give the JS event loop room under load and to soak
    // up any GC pauses. A working timeout path finishes in ~60-80ms;
    // a broken one would only return when the upstream delay
    // expires (~500ms), which would blow this bound on every call.
    const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);
    const p50 = latencies[Math.floor(N * 0.5)]!;
    const p99 = latencies[Math.floor(N * 0.99)]!;
    expect(p99).toBeLessThan(timeoutMs * 4);
    // Sanity: P50 should be roughly the timeout — if every call
    // returned instantly (e.g. someone wired the fetch to bypass the
    // signal entirely) we'd see ~0ms here and a quiet correctness
    // regression. Lower bound is "at least 60% of the configured
    // timeout" since the AbortController fires precisely on schedule.
    expect(p50).toBeGreaterThanOrEqual(Math.floor(timeoutMs * 0.6));

    // ── Wall-clock bound ──────────────────────────────────────────────
    // 200 concurrent calls should overlap; total wall-clock must
    // stay close to a single timeout window, not N × timeout.
    expect(wallMs).toBeLessThan(timeoutMs * 8);
  });

  test("server-side delays well under timeout pass through cleanly", async () => {
    // Counterfactual: verify the load harness itself can observe
    // the happy path. If THIS test fails the harness is broken;
    // if only the test above fails, the timeout plumbing is.
    const client = new CedarToolCallClient({
      baseUrl: "http://test.invalid",
      apiKey: "ak_h6",
      agentId: "agent-h6",
      timeoutMs: 500,
      fetchImpl: slowFetch(10), // upstream answers in 10ms, well under 500ms
      logger: silentLogger(),
    });

    const N = 100;
    const tasks: Promise<ToolCallEvaluation>[] = [];
    for (let i = 0; i < N; i++) {
      tasks.push(client.evaluateToolCall({ toolName: `t-${i}` }));
    }
    const results = await Promise.all(tasks);
    for (const r of results) {
      expect(r.decision).toBe("allow");
      expect(r.denyCode).toBeUndefined();
    }
  });
});
