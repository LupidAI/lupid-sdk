/**
 * HITL-8 — Autopatch / NextJS HITL honesty.
 *
 * The autopatch interceptors and the NextJS middleware have no session
 * context to suspend, so a `require_hitl` deny cannot escalate to human
 * approval on these planes. The contract this suite locks in:
 *
 *   - warn ONCE per plane (a second identical deny does NOT warn again);
 *   - the warning fires only for a `require_hitl` DENY — never for an allow,
 *     never for a plain deny;
 *   - the helper is pure: it never throws, never retries, never re-invokes —
 *     fail-CLOSED is preserved by the caller's existing deny path.
 */

import {
  warnHitlUnsupportedOnce,
  isHitlPending,
  __resetHitlUnsupportedWarnings,
  type HitlUnsupportedPlane,
} from "../../src/instrumentation/hitl-unsupported";

function fakeLogger(): { warn: jest.Mock } {
  return { warn: jest.fn() };
}

beforeEach(() => {
  // Reset the per-plane dedup set so each test observes first-warning
  // behavior (the set is a process-singleton in production).
  __resetHitlUnsupportedWarnings();
});

describe("isHitlPending", () => {
  it("is true for a deny carrying a bare require_hitl advice", () => {
    expect(isHitlPending({ decision: "deny", advice: ["require_hitl"] })).toBe(true);
  });

  it("is true for a deny carrying a parameterized require_hitl advice", () => {
    expect(
      isHitlPending({ decision: "deny", advice: ["require_hitl:timeout=60"] }),
    ).toBe(true);
  });

  it("is true for a deny carrying the derived hitlPending flag", () => {
    expect(isHitlPending({ decision: "deny", hitlPending: true })).toBe(true);
  });

  it("is false for a plain deny with no require_hitl signal", () => {
    expect(isHitlPending({ decision: "deny", advice: ["mask_pii"] })).toBe(false);
    expect(isHitlPending({ decision: "deny" })).toBe(false);
  });

  it("is false for an allow even when require_hitl advice is present", () => {
    // A live grant short-circuit produces decision=allow; it must NOT warn.
    expect(
      isHitlPending({ decision: "allow", advice: ["require_hitl"], hitlPending: true }),
    ).toBe(false);
  });
});

describe("warnHitlUnsupportedOnce", () => {
  it("warns once on the first require_hitl deny and dedups thereafter", () => {
    const logger = fakeLogger();
    const deny = { decision: "deny" as const, advice: ["require_hitl"] };

    // First identical deny → warns once.
    expect(warnHitlUnsupportedOnce("fetch", deny, logger)).toBe(true);
    // Second identical deny → does NOT warn again (dedup).
    expect(warnHitlUnsupportedOnce("fetch", deny, logger)).toBe(false);
    // Third → still silent.
    expect(warnHitlUnsupportedOnce("fetch", deny, logger)).toBe(false);

    expect(logger.warn).toHaveBeenCalledTimes(1);
    const msg = String(logger.warn.mock.calls[0]![0]);
    expect(msg).toContain("autopatch HITL unsupported in v1");
    expect(msg).toContain("Express/Fastify/NestJS");
    expect(msg).toContain("R22");
  });

  it("dedups independently per plane", () => {
    const logger = fakeLogger();
    const deny = { decision: "deny" as const, advice: ["require_hitl"] };
    const planes: HitlUnsupportedPlane[] = [
      "openai",
      "anthropic",
      "fetch",
      "node-http",
      "mcp-stdio",
      "nextjs",
    ];
    for (const p of planes) {
      expect(warnHitlUnsupportedOnce(p, deny, logger)).toBe(true);
      // Immediate repeat on the same plane is silent.
      expect(warnHitlUnsupportedOnce(p, deny, logger)).toBe(false);
    }
    expect(logger.warn).toHaveBeenCalledTimes(planes.length);
  });

  it("never warns for an allow (live-grant short-circuit)", () => {
    const logger = fakeLogger();
    expect(
      warnHitlUnsupportedOnce(
        "openai",
        { decision: "allow", advice: ["require_hitl"] },
        logger,
      ),
    ).toBe(false);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("never warns for a plain deny without require_hitl", () => {
    const logger = fakeLogger();
    expect(
      warnHitlUnsupportedOnce("anthropic", { decision: "deny", advice: ["mask_pii"] }, logger),
    ).toBe(false);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("is pure: returns synchronously without throwing, retrying, or mutating", () => {
    const logger = fakeLogger();
    const deny = Object.freeze({ decision: "deny" as const, advice: ["require_hitl"] });
    // A frozen decision proves the helper does not mutate the decision object
    // (no auto-retry shape rewrite). Throwing on a frozen mutation would fail.
    expect(() => warnHitlUnsupportedOnce("fetch", deny, logger)).not.toThrow();
    expect(deny).toEqual({ decision: "deny", advice: ["require_hitl"] });
  });
});
