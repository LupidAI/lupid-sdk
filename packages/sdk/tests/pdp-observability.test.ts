/**
 * PASS2-SDK-01 Item B — `_pdp-observability.ts` decision_source mapping.
 *
 * ADR-0014 §80: the SDK autopatch plane always intercepts in-process, so the
 * legacy short-form `decision_source` values (`pdp` / `central` / `cache`) all
 * collapse onto the single ADR-0010 plane id `"inproc"`. The cache semantic
 * that the old `"cache"` value smeared into `decision_source` now travels on a
 * separate `cache_hit: true` wire field.
 */

import {
  mapDecisionSourceToAudit,
  pdpTopLevelFields,
} from "../src/frameworks/_pdp-observability";
import type { ToolCallEvaluation } from "../src/evaluation/cedar-client";

describe("_pdp-observability — mapDecisionSourceToAudit (ADR-0014 §80)", () => {
  it("maps PDP-served decisions to inproc", () => {
    expect(mapDecisionSourceToAudit("pdp")).toBe("inproc");
  });

  it("maps central decisions to inproc", () => {
    expect(mapDecisionSourceToAudit("central")).toBe("inproc");
  });

  it("maps a (future) cache value to inproc", () => {
    expect(
      mapDecisionSourceToAudit("cache" as ToolCallEvaluation["decisionSource"]),
    ).toBe("inproc");
  });

  it("never emits the legacy local_pdp / central / cache strings", () => {
    for (const src of ["pdp", "central", "cache"] as Array<
      ToolCallEvaluation["decisionSource"]
    >) {
      const out = mapDecisionSourceToAudit(src);
      expect(out).not.toBe("local_pdp");
      expect(out).not.toBe("central");
      expect(out).not.toBe("cache");
    }
  });

  it("returns undefined for an unknown / missing value", () => {
    expect(
      mapDecisionSourceToAudit(undefined as ToolCallEvaluation["decisionSource"]),
    ).toBeUndefined();
    expect(
      mapDecisionSourceToAudit("garbage" as ToolCallEvaluation["decisionSource"]),
    ).toBeUndefined();
  });
});

describe("_pdp-observability — pdpTopLevelFields cache_hit hoist (ADR-0014 §5)", () => {
  it("emits decision_source=inproc with no cache_hit for a PDP decision", () => {
    const e: ToolCallEvaluation = {
      decision: "allow",
      ttlMs: 0,
      decisionSource: "pdp",
      policyHash: "ph-1",
    };
    const out = pdpTopLevelFields(e);
    expect(out.decision_source).toBe("inproc");
    expect(out.cache_hit).toBeUndefined();
    expect(out.policy_hash).toBe("ph-1");
  });

  it("hoists the cache semantic to cache_hit:true while still emitting inproc", () => {
    const e = {
      decision: "allow",
      ttlMs: 0,
      decisionSource: "cache",
    } as unknown as ToolCallEvaluation;
    const out = pdpTopLevelFields(e);
    expect(out.decision_source).toBe("inproc");
    expect(out.cache_hit).toBe(true);
  });

  it("omits decision_source entirely when the source is unknown", () => {
    const e = { decision: "deny", ttlMs: 0 } as ToolCallEvaluation;
    const out = pdpTopLevelFields(e);
    expect(out.decision_source).toBeUndefined();
    expect(out.cache_hit).toBeUndefined();
  });
});
