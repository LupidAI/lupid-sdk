/**
 * L06 — `LocalPdpDecision` + `LocalPdpStale` audit emission from
 * `CedarToolCallClient`.
 *
 * The Rust gateway commit `3e1fa6b1` added the matching `AuditEventType`
 * variants and the `policy_hash` / `decision_source` columns. This suite
 * verifies the SDK side of L06:
 *
 *   1. PDP-served decision emits `LocalPdpDecision` with
 *      `decision_source: "local_pdp"` and the response's `policy_hash`.
 *   2. Central-served decision emits `decision_source: "central"`.
 *   3. Cache hit emits `decision_source: "cache"` (and does NOT hit the
 *      decision wire a second time).
 *   4. PDP returning a different `policy_hash` than the last-observed one
 *      emits a separate `LocalPdpStale` event whose `detail` carries both
 *      the expected and observed hashes.
 *
 * The audit POST is fire-and-forget so we flush microtasks before
 * asserting the captured calls.
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
}

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
    if (outcome.throwErr) throw outcome.throwErr;
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function flushMicrotasks(): Promise<void> {
  // Two queue flushes settle the detached `void fire()` audit POST.
  return new Promise((resolve) => setImmediate(resolve));
}

// L08 — `/v1/health` must surface `agent_id` and the SDK now enforces
// `agent_id === this.agentId` before considering the PDP alive. These tests
// all use `agent_id: "agent-1"` to match the client's `agentId`.
const HEALTH_OK: FetchOutcome = {
  status: 200,
  body: JSON.stringify({ status: "ok", agent_id: "agent-1" }),
};

const PDP_PERMIT_HASH_A: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "permit-everything",
    policy_hash: "hash-A",
    evaluated_locally: true,
    latency_us: 250,
  }),
};

const PDP_PERMIT_HASH_B: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "permit-everything",
    policy_hash: "hash-B",
    evaluated_locally: true,
    latency_us: 300,
  }),
};

const CENTRAL_PERMIT: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "central-rule",
    ttl_ms: 5_000,
    policy_hash: "central-hash",
  }),
};

interface AuditEnvelope {
  agent_id: string;
  session_id: string;
  event_type: string;
  outcome?: string;
  tool?: string;
  policy_hash?: string;
  decision_source?: "local_pdp" | "central" | "cache";
  detail?: Record<string, unknown>;
}

function auditPosts(captured: CapturedCall[]): AuditEnvelope[] {
  const out: AuditEnvelope[] = [];
  for (const c of captured) {
    if (!c.url.endsWith("/api/v1/audit/ingest")) continue;
    const body = (c.init?.body as string | undefined) ?? "{}";
    out.push(JSON.parse(body) as AuditEnvelope);
  }
  return out;
}

describe("CedarToolCallClient — L06 audit emission", () => {
  test("PDP-served decision emits LocalPdpDecision with decision_source=local_pdp and policy_hash", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_PERMIT_HASH_A,
        "/api/v1/audit/ingest": { status: 200 },
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
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter((a) => a.event_type === "local_pdp_decision");
    expect(decisionEvents).toHaveLength(1);
    const ev = decisionEvents[0]!;
    expect(ev.decision_source).toBe("local_pdp");
    expect(ev.policy_hash).toBe("hash-A");
    expect(ev.tool).toBe("search");
    expect(ev.outcome).toBe("allow");
    expect(ev.detail?.["evaluated_locally"]).toBe(true);
    expect(ev.detail?.["pdp_latency_us"]).toBe(250);
    // No stale event on first decision.
    expect(audits.find((a) => a.event_type === "local_pdp_stale")).toBeUndefined();
  });

  test("central-served decision emits LocalPdpDecision with decision_source=central", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        // Health probe fails so the SDK skips PDP entirely.
        "/v1/health": { status: 503, body: "{}" },
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_PERMIT,
        "/api/v1/audit/ingest": { status: 200 },
      },
      captured,
    );
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      pdpUrl: "http://127.0.0.1:7080",
      fetchImpl,
      logger: silentLogger(),
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("central");
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter((a) => a.event_type === "local_pdp_decision");
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("central");
    expect(decisionEvents[0]!.policy_hash).toBe("central-hash");
  });

  test("cache hit emits LocalPdpDecision with decision_source=cache and skips the wire", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        // PDP returns ttl_ms via the central path; PDP itself uses the
        // 1_000ms default in cedar-client. First call seeds the cache.
        "/v1/authorize": PDP_PERMIT_HASH_A,
        "/api/v1/audit/ingest": { status: 200 },
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

    // First call: PDP, seeds the cache (ttlMs=1000 default for PDP path).
    await client.evaluateToolCall({ toolName: "search", arguments: { q: "x" } });
    // Second call: same args, cache hit.
    const result2 = await client.evaluateToolCall({
      toolName: "search",
      arguments: { q: "x" },
    });
    await flushMicrotasks();

    expect(result2.decision).toBe("allow");
    // Only ONE /v1/authorize call — the second was served from cache.
    const authorizeCalls = captured.filter((c) => c.url.endsWith("/v1/authorize"));
    expect(authorizeCalls).toHaveLength(1);

    const audits = auditPosts(captured);
    const decisionEvents = audits.filter((a) => a.event_type === "local_pdp_decision");
    // Two LocalPdpDecision events: one for the PDP serve, one for the cache hit.
    expect(decisionEvents).toHaveLength(2);
    expect(decisionEvents[0]!.decision_source).toBe("local_pdp");
    expect(decisionEvents[1]!.decision_source).toBe("cache");
    // Cache-hit event still carries the original policy_hash.
    expect(decisionEvents[1]!.policy_hash).toBe("hash-A");
  });

  test("hash mismatch on PDP response emits LocalPdpStale with both hashes in detail", async () => {
    const captured: CapturedCall[] = [];
    let callIdx = 0;
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        // First call returns hash-A, second returns hash-B (a policy push
        // happened between them and our last-observed hash is now stale).
        "/v1/authorize": () => {
          const out = callIdx === 0 ? PDP_PERMIT_HASH_A : PDP_PERMIT_HASH_B;
          callIdx += 1;
          return out;
        },
        "/api/v1/audit/ingest": { status: 200 },
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

    // First decision: lastPolicyHash is undefined, no stale signal.
    await client.evaluateToolCall({ toolName: "tool-a" });
    // Second decision (different tool to bypass the LRU): PDP returns
    // hash-B vs the last-observed hash-A — should emit LocalPdpStale.
    await client.evaluateToolCall({ toolName: "tool-b" });
    await flushMicrotasks();

    const audits = auditPosts(captured);
    const staleEvents = audits.filter((a) => a.event_type === "local_pdp_stale");
    expect(staleEvents).toHaveLength(1);
    const stale = staleEvents[0]!;
    expect(stale.detail?.["expected_policy_hash"]).toBe("hash-A");
    expect(stale.detail?.["observed_policy_hash"]).toBe("hash-B");
    expect(stale.policy_hash).toBe("hash-B");
    expect(stale.decision_source).toBe("local_pdp");
    expect(stale.tool).toBe("tool-b");

    // Two LocalPdpDecision events overall (one per call).
    const decisionEvents = audits.filter((a) => a.event_type === "local_pdp_decision");
    expect(decisionEvents).toHaveLength(2);
  });
});
