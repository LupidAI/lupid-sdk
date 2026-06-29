/**
 * L02b — HITL post-approval grant cache on `CedarToolCallClient`.
 *
 * After an operator approves a HITL-gated tool call, the SDK records a
 * grant entry keyed on `(agent_id, tool_name)`. The next identical tool
 * call within the grant TTL short-circuits — no PDP or central round
 * trip, no second approval prompt, and the cache hit is audited with
 * `decision_source: "approval_grant"`.
 *
 * Cases (per spec §Verification):
 *   1. Recorded grant short-circuits the next identical call within TTL.
 *   2. After TTL expires the next call re-escalates (no short-circuit).
 *   3. Different `tool_name` does not match an existing grant.
 *   4. Different `agent_id` (multi-agent process) does not match.
 *   5. LRU evicts the oldest entry on overflow without erroring.
 */

import {
  ApprovalGrantCache,
  CedarToolCallClient,
  canonicalJsonStringify,
  hashArgsCanonical,
} from "../src/evaluation/cedar-client";

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
    const outcome =
      typeof route === "function" ? route(counts[matchKey]! - 1) : route;
    if (outcome.throwErr) throw outcome.throwErr;
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

const HEALTH_OK = (agentId: string): FetchOutcome => ({
  status: 200,
  body: JSON.stringify({ status: "ok", agent_id: agentId }),
});

const PDP_PERMIT: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    decision: "allow",
    rule_id: "permit-everything",
    policy_hash: "hash-A",
    evaluated_locally: true,
    latency_us: 250,
  }),
};

interface AuditEnvelope {
  agent_id: string;
  session_id: string;
  event_type: string;
  outcome?: string;
  tool?: string;
  decision_source?: string;
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

describe("CedarToolCallClient — L02b approval-grant short-circuit", () => {
  test("recorded grant short-circuits the next identical tool call within TTL", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    // Record a grant simulating a just-approved HITL request.
    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 10_000,
      requestId: "req-abc",
    });

    const result = await client.evaluateToolCall({ toolName: "search" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    // No PDP or central hit — grant short-circuited.
    expect(captured.filter((c) => c.url.endsWith("/v1/authorize"))).toHaveLength(
      0,
    );
    expect(
      captured.filter((c) => c.url.endsWith("/v1/health")),
    ).toHaveLength(0);
    expect(
      captured.filter((c) => c.url.endsWith("/api/v1/sdk/evaluate-tool-call")),
    ).toHaveLength(0);

    // Audit row carries decision_source=approval_grant + request_id.
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("approval_grant");
    expect(decisionEvents[0]!.tool).toBe("search");
    expect(decisionEvents[0]!.outcome).toBe("allow");
    expect(decisionEvents[0]!.detail?.["approval_request_id"]).toBe("req-abc");
  });

  test("after TTL expires the next call re-escalates (no short-circuit)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    // 1 ms TTL — guaranteed-expired by the time we eval.
    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 1,
      requestId: "req-expired",
    });
    // Wait so the entry is unambiguously past its expiry.
    await new Promise((r) => setTimeout(r, 5));

    const result = await client.evaluateToolCall({ toolName: "search" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    // PDP WAS consulted — grant expired so the short-circuit did not fire.
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(1);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    // PDP-served, not approval-grant.
    expect(decisionEvents[0]!.decision_source).toBe("local_pdp");
  });

  test("different tool_name does not match an existing grant", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 60_000,
      requestId: "req-1",
    });

    const result = await client.evaluateToolCall({ toolName: "delete-file" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    // PDP hit because the grant key was (agent-1, "search"), not
    // (agent-1, "delete-file").
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(1);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("local_pdp");
  });

  test("different agent_id does not match (multi-agent process)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-2"),
        "/v1/authorize": PDP_PERMIT,
        "/api/v1/audit/ingest": { status: 200 },
      },
      captured,
    );
    // Client is for agent-2.
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-2",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: silentLogger(),
    });

    // Attempt to record a grant for a different agent — must be rejected
    // by the evaluator's `agentId` guard.
    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 60_000,
      requestId: "req-1",
    });
    expect(
      await client.findApprovalGrant({ agentId: "agent-1", toolName: "search" }),
    ).toBeUndefined();
    expect(
      await client.findApprovalGrant({ agentId: "agent-2", toolName: "search" }),
    ).toBeUndefined();

    const result = await client.evaluateToolCall({ toolName: "search" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    // PDP hit — no cross-agent grant leakage.
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(1);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("local_pdp");
  });

  test("LRU evicts oldest entry on overflow without erroring", () => {
    // Direct LRU test: avoid the network for the eviction proof.
    // A fixed args_hash ("h1") keeps the eviction proof orthogonal to the
    // canonicalisation — every entry shares the same third key component.
    const cache = new ApprovalGrantCache(3);
    cache.put("a", "t1", "h1", 60_000, "r1");
    cache.put("a", "t2", "h1", 60_000, "r2");
    cache.put("a", "t3", "h1", 60_000, "r3");
    expect(cache.size).toBe(3);

    // Overflow: insertion order is [t1, t2, t3]; inserting t4 at capacity
    // evicts t1 (the oldest), leaves [t2, t3, t4].
    cache.put("a", "t4", "h1", 60_000, "r4");
    expect(cache.size).toBe(3);
    expect(cache.find("a", "t1", "h1")).toBeUndefined();
    // Re-bind without bumping (use direct map peek via re-insertion of
    // same value would change order, so use a separate cache to test the
    // post-eviction state independent of LRU bump-on-find).
    const peek = new ApprovalGrantCache(3);
    peek.put("a", "t1", "h1", 60_000, "r1");
    peek.put("a", "t2", "h1", 60_000, "r2");
    peek.put("a", "t3", "h1", 60_000, "r3");
    peek.put("a", "t4", "h1", 60_000, "r4");
    expect(peek.size).toBe(3);
    // After eviction, t1 is gone; t2/t3/t4 survive.
    expect(peek.find("a", "t1", "h1")).toBeUndefined();
    expect(peek.find("a", "t2", "h1")?.requestId).toBe("r2");
    expect(peek.find("a", "t3", "h1")?.requestId).toBe("r3");
    expect(peek.find("a", "t4", "h1")?.requestId).toBe("r4");

    // LRU bump-on-find: after the three finds above the order is
    // [t2, t3, t4] (each find bumped its key to the tail in that order).
    // Inserting t5 at capacity evicts the new head, which is t2.
    peek.put("a", "t5", "h1", 60_000, "r5");
    expect(peek.size).toBe(3);
    expect(peek.find("a", "t2", "h1")).toBeUndefined();
    expect(peek.find("a", "t3", "h1")?.requestId).toBe("r3");
    expect(peek.find("a", "t4", "h1")?.requestId).toBe("r4");
    expect(peek.find("a", "t5", "h1")?.requestId).toBe("r5");
  });

  // GR-08 — the grant key now includes a canonical-JSON SHA-256 of the
  // call's args, so an approval for one args shape cannot unlock different
  // args for the same tool.
  test("same tool, different args → cache miss (re-escalates)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    // Approve a benign invocation.
    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "bash",
      ttlMs: 60_000,
      requestId: "req-ls",
      toolArgs: { cmd: "ls" },
    });

    // A dangerous invocation of the same tool must NOT short-circuit.
    const result = await client.evaluateToolCall({
      toolName: "bash",
      arguments: { cmd: "rm -rf /" },
    });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(1);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("local_pdp");
  });

  test("identical args, different key insertion order → same hash → hit", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 60_000,
      requestId: "req-order",
      toolArgs: { b: [2, 3], a: 1 },
    });

    const result = await client.evaluateToolCall({
      toolName: "search",
      arguments: { a: 1, b: [2, 3] },
    });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    // Canonicalisation makes the two arg objects hash equal → short-circuit.
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(0);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("approval_grant");
  });

  test("Rust cross-check vectors (hardcoded hex) pin the TS impl to the PDP", async () => {
    expect(canonicalJsonStringify({ b: [2, 3], a: 1 })).toBe('{"a":1,"b":[2,3]}');
    // sha256('{"a":1,"b":[2,3]}') — mirrors hitl.rs hash_args(json!({"b":[2,3],"a":1}))
    await expect(hashArgsCanonical({ b: [2, 3], a: 1 })).resolves.toBe(
      "efbd0040190fb0871831e606c581f8a66db79d8e2bb836745a70051306956070",
    );
    // sha256('{"cmd":"ls"}')
    await expect(hashArgsCanonical({ cmd: "ls" })).resolves.toBe(
      "a908494c958996ec8cebfa2e10728536e84904384b2497a4fbba9f48d99215ba",
    );
    // sha256('null') — undefined and null MUST agree (matches hash_args(&Value::Null))
    await expect(hashArgsCanonical(undefined)).resolves.toBe(
      "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    );
    await expect(hashArgsCanonical(null)).resolves.toBe(
      "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b",
    );
    // sha256('{}') — null vs {} must differ (hitl.rs test
    // hash_args_null_vs_empty_object_differ)
    await expect(hashArgsCanonical({})).resolves.toBe(
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    );
  });

  test("no-args back-compat round-trip → short-circuit fires", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK("agent-1"),
        "/v1/authorize": PDP_PERMIT,
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

    // Record with no toolArgs (hashes JSON null)…
    await client.recordApprovalGrant({
      agentId: "agent-1",
      toolName: "search",
      ttlMs: 60_000,
      requestId: "req-noargs",
    });

    // …and evaluate with no arguments (also hashes JSON null) → HIT.
    const result = await client.evaluateToolCall({ toolName: "search" });
    await flushMicrotasks();

    expect(result.decision).toBe("allow");
    expect(
      captured.filter((c) => c.url.endsWith("/v1/authorize")),
    ).toHaveLength(0);
    const audits = auditPosts(captured);
    const decisionEvents = audits.filter(
      (a) => a.event_type === "local_pdp_decision",
    );
    expect(decisionEvents).toHaveLength(1);
    expect(decisionEvents[0]!.decision_source).toBe("approval_grant");
  });

  test("integer-like keys sort byte-wise, not numerically", () => {
    // Byte-wise sort: "10" < "2" (compares '1'=0x31 vs '2'=0x32). A naive
    // sorted-object-then-JSON.stringify or Object.keys() iteration would
    // emit the JS numeric order '{"2":2,"10":1}'.
    expect(canonicalJsonStringify({ "10": 1, "2": 2 })).toBe(
      '{"10":1,"2":2}',
    );
  });
});
