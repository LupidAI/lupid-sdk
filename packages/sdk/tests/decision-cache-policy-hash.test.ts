/**
 * L05 — DecisionCache.key() gains an optional 5th `policyHash` arg so a
 * policy churn during the cache TTL window cannot serve a stale decision.
 *
 * Asserts:
 *   - Same (userId, action, resource, ctxHash) with two different
 *     policyHash values → two distinct keys.
 *   - Missing policyHash arg yields the legacy 4-component key (back-compat).
 *   - Same policyHash twice → same key (cache hit on second call).
 */

import { DecisionCache } from "../src/frameworks/express/decision-cache";

describe("DecisionCache.key() policyHash dimension (L05)", () => {
  it("different policyHash values produce different keys", () => {
    const a = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashA");
    const b = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashB");
    expect(a).not.toBe(b);
    expect(a).toBe("u1|tool:foo|*|ctx|hashA");
    expect(b).toBe("u1|tool:foo|*|ctx|hashB");
  });

  it("omitting policyHash keeps the legacy 4-component key shape", () => {
    const k = DecisionCache.key("u1", "tool:foo", "*", "ctx");
    expect(k).toBe("u1|tool:foo|*|ctx");
    // Explicit undefined matches the no-arg form (back-compat).
    const k2 = DecisionCache.key("u1", "tool:foo", "*", "ctx", undefined);
    expect(k2).toBe(k);
  });

  it("same policyHash twice yields the same key (cache hit on second call)", () => {
    const a = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashA");
    const b = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashA");
    expect(a).toBe(b);
  });

  it("end-to-end: putting under hashA does not satisfy a get under hashB", () => {
    const cache = new DecisionCache({ maxSize: 16, ttlMs: 60_000 });
    const keyA = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashA");
    const keyB = DecisionCache.key("u1", "tool:foo", "*", "ctx", "hashB");
    // Smuggle an opaque value through the cache (matches cedar-client usage).
    cache.put(keyA, { decision: "allow" } as unknown as never);
    expect(cache.get(keyA)).toBeDefined();
    expect(cache.get(keyB)).toBeUndefined();
  });
});
