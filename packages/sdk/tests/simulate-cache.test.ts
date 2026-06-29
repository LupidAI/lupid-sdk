/**
 * Sprint 3.4 — client-side Cedar decision cache + invalidatePolicyCache.
 *
 * Uses a mock fetch that returns deterministic `Headers` so we can test
 * TTL, advice-bypass, generation-change invalidation, and explicit
 * `invalidatePolicyCache()`. The server-emitted headers are the contract
 * pinned by `crates/agentum-api/src/lib.rs::simulate_response_carries_*`.
 */

import {
  AgentumClient,
  SimulateDecisionCache,
  parseMaxAgeMs,
  stableStringify,
} from "../src/index";

const BASE = "http://localhost:7071";

/**
 * Build a `fetch` mock that returns a distinct Headers instance per call
 * driven by `queue` entries (response body + optional header overrides).
 */
function headeredFetch(
  queue: Array<{
    body: unknown;
    status?: number;
    maxAge?: number;
    generation?: string;
    advice?: string[];
    noStore?: boolean;
  }>,
): jest.Mock {
  return jest.fn().mockImplementation(async () => {
    const next = queue.shift();
    if (!next) throw new Error("fetch called beyond queued responses");
    const headers = new Headers();
    headers.set("content-type", "application/json");
    if (next.noStore) {
      headers.set("cache-control", "no-store");
      headers.set("x-agentum-cache-max-age", "0");
    } else if (next.maxAge !== undefined) {
      headers.set("cache-control", `public, max-age=${next.maxAge}`);
      headers.set("x-agentum-cache-max-age", String(next.maxAge));
    }
    if (next.generation !== undefined) {
      headers.set("x-agentum-policy-generation", next.generation);
    }
    const body = next.advice
      ? { ...(next.body as object), advice: next.advice }
      : next.body;
    return {
      ok: (next.status ?? 200) < 400,
      status: next.status ?? 200,
      headers,
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  });
}

describe("SimulateDecisionCache", () => {
  it("round-trips a value within TTL and evicts after expiry", () => {
    const cache = new SimulateDecisionCache<string>({ maxSize: 4 });
    const key = SimulateDecisionCache.key("a", "b", "c", "", "");
    cache.put(key, "hit", 50);
    expect(cache.get(key)).toBe("hit");
    // Fake expiry by walking `Date.now`.
    const realNow = Date.now;
    Date.now = () => realNow() + 100;
    try {
      expect(cache.get(key)).toBeUndefined();
    } finally {
      Date.now = realNow;
    }
  });

  it("is a no-op when disabled", () => {
    const cache = new SimulateDecisionCache<string>({ enabled: false });
    const key = SimulateDecisionCache.key("a", "b", "c", "", "");
    cache.put(key, "x", 10_000);
    expect(cache.get(key)).toBeUndefined();
  });

  it("LRU-evicts the oldest insert when at capacity", () => {
    const cache = new SimulateDecisionCache<string>({ maxSize: 2 });
    cache.put("k1", "a", 10_000);
    cache.put("k2", "b", 10_000);
    cache.put("k3", "c", 10_000);
    expect(cache.get("k1")).toBeUndefined();
    expect(cache.get("k2")).toBe("b");
    expect(cache.get("k3")).toBe("c");
  });

  it("observeGeneration blows away the cache when the header bumps", () => {
    const cache = new SimulateDecisionCache<string>({});
    cache.observeGeneration("5"); // first observation — no drop.
    cache.put("k", "v", 10_000);
    cache.observeGeneration("5"); // unchanged — still present.
    expect(cache.get("k")).toBe("v");
    cache.put("k2", "v2", 10_000);
    cache.observeGeneration("6"); // bumped — drop everything.
    expect(cache.get("k")).toBeUndefined();
    expect(cache.get("k2")).toBeUndefined();
  });

  it("observeGeneration ignores missing / malformed headers", () => {
    const cache = new SimulateDecisionCache<string>({});
    cache.observeGeneration("7");
    cache.put("k", "v", 10_000);
    cache.observeGeneration(null);
    cache.observeGeneration("not-a-number");
    cache.observeGeneration("-5");
    expect(cache.get("k")).toBe("v");
  });

  it("stableStringify is key-order-independent", () => {
    expect(stableStringify({ b: 1, a: 2 })).toBe(stableStringify({ a: 2, b: 1 }));
    expect(stableStringify([3, 1, 2])).toBe("[3,1,2]"); // arrays keep order.
    expect(stableStringify(null)).toBe("null");
    expect(stableStringify(undefined)).toBe(undefined);
  });

  it("parseMaxAgeMs prefers the vendor header over Cache-Control", () => {
    const h = new Headers();
    h.set("cache-control", "max-age=30");
    h.set("x-agentum-cache-max-age", "15");
    expect(parseMaxAgeMs(h)).toBe(15_000);
  });

  it("parseMaxAgeMs reads max-age from Cache-Control when vendor missing", () => {
    const h = new Headers();
    h.set("cache-control", "public, max-age=7");
    expect(parseMaxAgeMs(h)).toBe(7_000);
  });

  it("parseMaxAgeMs returns 0 for no-store", () => {
    const h = new Headers();
    h.set("cache-control", "no-store");
    expect(parseMaxAgeMs(h)).toBe(0);
  });

  it("parseMaxAgeMs returns null when no hint is present", () => {
    expect(parseMaxAgeMs(new Headers())).toBeNull();
  });
});

describe("AgentumClient.simulatePolicy caching", () => {
  it("serves the second identical call from cache (no fetch)", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Allow", rule_id: null, reason: null },
        maxAge: 30,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const req = { agent_id: "a1", action: "http.get", resource: "/x" };
    const first = await c.simulatePolicy(req);
    const second = await c.simulatePolicy(req);
    expect(first).toEqual(second);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("re-fetches when the server generation header bumps", async () => {
    const fetch = headeredFetch([
      // Call 1: warm cache for req A at generation 1.
      {
        body: { outcome: "Allow", rule_id: null, reason: "initial" },
        maxAge: 30,
        generation: "1",
      },
      // Call 2: req B arrives with bumped generation → evicts A from cache.
      {
        body: { outcome: "Deny", rule_id: null, reason: "req B" },
        maxAge: 30,
        generation: "2",
      },
      // Call 3: req A re-fetched since its cache entry was wiped.
      {
        body: { outcome: "Deny", rule_id: "r", reason: "updated" },
        maxAge: 30,
        generation: "2",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const reqA = { agent_id: "a1", action: "http.get", resource: "/x" };
    const reqB = { agent_id: "a1", action: "http.get", resource: "/y" };
    const first = await c.simulatePolicy(reqA);
    expect(first.outcome).toBe("Allow");
    const second = await c.simulatePolicy(reqB);
    expect(second.outcome).toBe("Deny");
    const third = await c.simulatePolicy(reqA);
    expect(third.outcome).toBe("Deny");
    expect(third.reason).toBe("updated");
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("bypasses cache when server sends Cache-Control: no-store", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Allow", rule_id: null, reason: null },
        noStore: true,
        generation: "1",
      },
      {
        body: { outcome: "Deny", rule_id: "r", reason: "not cached" },
        noStore: true,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const req = { agent_id: "a1", action: "http.get", resource: "/x" };
    const a = await c.simulatePolicy(req);
    const b = await c.simulatePolicy(req);
    expect(a.outcome).toBe("Allow");
    expect(b.outcome).toBe("Deny");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("bypasses cache when the decision carries HITL advice", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Deny", rule_id: "r", reason: "need approval" },
        advice: ["require_hitl"],
        noStore: true, // server should pair advice with no-store
        generation: "1",
      },
      {
        body: { outcome: "Allow", rule_id: null, reason: "post-hitl" },
        maxAge: 30,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const req = { agent_id: "a1", action: "http.post", resource: "/sensitive" };
    const first = await c.simulatePolicy(req);
    expect(first.advice).toEqual(["require_hitl"]);
    const second = await c.simulatePolicy(req);
    expect(second.outcome).toBe("Allow");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("invalidatePolicyCache() drops every cached entry", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Allow", rule_id: null, reason: null },
        maxAge: 30,
        generation: "1",
      },
      {
        body: { outcome: "Deny", rule_id: "r", reason: "post-invalidate" },
        maxAge: 30,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const req = { agent_id: "a1", action: "http.get", resource: "/x" };
    const first = await c.simulatePolicy(req);
    expect(first.outcome).toBe("Allow");
    c.invalidatePolicyCache();
    const second = await c.simulatePolicy(req);
    expect(second.outcome).toBe("Deny");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("keys cache entries by user identity — no cross-user contamination", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Allow", rule_id: null, reason: "alice allowed" },
        maxAge: 30,
        generation: "1",
      },
      {
        body: { outcome: "Deny", rule_id: null, reason: "bob denied" },
        maxAge: 30,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({ baseUrl: BASE, fetch: fetch as unknown as typeof globalThis.fetch, retries: 0 });
    const base = { agent_id: "a1", action: "http.get", resource: "/x" };
    const alice = await c.simulatePolicy({ ...base, user: { id: "u-alice", email: "a@x" } });
    const bob = await c.simulatePolicy({ ...base, user: { id: "u-bob", email: "b@x" } });
    expect(alice.outcome).toBe("Allow");
    expect(bob.outcome).toBe("Deny");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("disables caching entirely when policyCache.enabled === false", async () => {
    const fetch = headeredFetch([
      {
        body: { outcome: "Allow", rule_id: null, reason: null },
        maxAge: 30,
        generation: "1",
      },
      {
        body: { outcome: "Deny", rule_id: "r", reason: "second call" },
        maxAge: 30,
        generation: "1",
      },
    ]);
    const c = new AgentumClient({
      baseUrl: BASE,
      fetch: fetch as unknown as typeof globalThis.fetch,
      retries: 0,
      policyCache: { enabled: false },
    });
    const req = { agent_id: "a1", action: "http.get", resource: "/x" };
    await c.simulatePolicy(req);
    await c.simulatePolicy(req);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
