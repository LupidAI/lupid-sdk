/**
 * S1-14 — Cache module unit tests.
 *
 * Covers:
 *   - `buildCacheKey` uses the RS sentinel and tolerates null inputs
 *   - per-ref registry keeps separate caches for separate refs
 *   - LRU evicts past `max_entries`
 *   - per-entry TTL is honoured on `set({ttl})`
 */

import {
  __resetEnrichmentCacheForTest,
  buildCacheKey,
  getOrCreateCache,
  type EnrichmentResult,
} from "../../src/enrichment/cache";
import type { EnrichmentDefFull } from "../../src/enrichment/types";

function fullDef(over: Partial<EnrichmentDefFull> = {}): EnrichmentDefFull {
  return {
    kind: "webhook",
    url: "https://example.test/x",
    cache: { key: ["a", "b"], ttl_ms: 1000 },
    auth: { secret_ref: "env:UNUSED" },
    request: { include_dimensions: [] },
    response: { shape: { ref: "string" } },
    ...over,
  };
}

beforeEach(() => {
  __resetEnrichmentCacheForTest();
});

describe("enrichment/cache", () => {
  test("buildCacheKey joins with the RS sentinel", () => {
    const def = fullDef();
    const key = buildCacheKey(def, { a: "acme", b: "u_42" });
    expect(key).toBe("acme\x1fu_42");
  });

  test("buildCacheKey substitutes empty string for nulls/missing", () => {
    const def = fullDef();
    const key = buildCacheKey(def, { a: "acme" });
    expect(key).toBe("acme\x1f");
  });

  test("separate refs get separate caches", () => {
    const def1 = fullDef();
    const def2 = fullDef();
    const c1 = getOrCreateCache("ref1", def1);
    const c2 = getOrCreateCache("ref2", def2);
    expect(c1).not.toBe(c2);
  });

  test("same ref returns the same cache instance", () => {
    const def = fullDef();
    const c1 = getOrCreateCache("ref1", def);
    const c2 = getOrCreateCache("ref1", def);
    expect(c1).toBe(c2);
  });

  test("LRU evicts past max_entries", () => {
    const def = fullDef({ cache: { key: ["a"], ttl_ms: 60_000, max_entries: 2 } });
    const c = getOrCreateCache("ref1", def);
    const mk = (n: number): EnrichmentResult => ({
      values: { ref1: String(n) },
      cachedAt: Date.now(),
      isNegative: false,
    });
    c.set("k1", mk(1));
    c.set("k2", mk(2));
    c.set("k3", mk(3));
    expect(c.get("k1")).toBeUndefined();
    expect(c.get("k2")).toBeDefined();
    expect(c.get("k3")).toBeDefined();
  });

  test("per-entry ttl honoured on set", async () => {
    const def = fullDef({ cache: { key: ["a"], ttl_ms: 1000 } });
    const c = getOrCreateCache("ref1", def);
    c.set(
      "k1",
      {
        values: { ref1: "v" },
        cachedAt: Date.now(),
        isNegative: false,
      },
      { ttl: 50 },
    );
    expect(c.get("k1")).toBeDefined();
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(c.get("k1")).toBeUndefined();
  });
});
