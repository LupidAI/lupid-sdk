/**
 * S1-14 — Circuit breaker unit tests (Jest fake timers).
 *
 * Verifies:
 *   - closed → open after 5 consecutive failures within the window
 *   - open → half_open after the open duration elapses
 *   - half_open + success → closed
 *   - half_open + failure → open (re-trip immediately)
 *   - failures outside the 30s window do not accumulate toward the trip
 */

import {
  __resetEnrichmentBreakerForTest,
  checkBreaker,
  recordBreakerFailure,
  recordBreakerSuccess,
} from "../../src/enrichment/circuit-breaker";

beforeEach(() => {
  __resetEnrichmentBreakerForTest();
});

describe("enrichment/circuit-breaker", () => {
  test("starts closed", () => {
    expect(checkBreaker("ref1")).toBe("closed");
  });

  test("trips open after 5 consecutive failures within the window", () => {
    const t0 = 1_000_000;
    for (let i = 0; i < 4; i += 1) {
      recordBreakerFailure("ref1", t0 + i * 100);
      expect(checkBreaker("ref1", t0 + i * 100)).toBe("closed");
    }
    recordBreakerFailure("ref1", t0 + 500);
    expect(checkBreaker("ref1", t0 + 500)).toBe("open");
  });

  test("transitions to half_open after 60s elapsed since trip", () => {
    const t0 = 1_000_000;
    let tripAt = t0;
    for (let i = 0; i < 5; i += 1) {
      tripAt = t0 + i;
      recordBreakerFailure("ref1", tripAt);
    }
    expect(checkBreaker("ref1", tripAt)).toBe("open");
    expect(checkBreaker("ref1", tripAt + 59_999)).toBe("open");
    expect(checkBreaker("ref1", tripAt + 60_000)).toBe("half_open");
  });

  test("half_open + success closes the breaker", () => {
    const t0 = 1_000_000;
    let tripAt = t0;
    for (let i = 0; i < 5; i += 1) {
      tripAt = t0 + i;
      recordBreakerFailure("ref1", tripAt);
    }
    expect(checkBreaker("ref1", tripAt + 60_000)).toBe("half_open");
    recordBreakerSuccess("ref1");
    expect(checkBreaker("ref1", tripAt + 60_001)).toBe("closed");
  });

  test("half_open + failure re-opens the breaker", () => {
    const t0 = 1_000_000;
    let tripAt = t0;
    for (let i = 0; i < 5; i += 1) {
      tripAt = t0 + i;
      recordBreakerFailure("ref1", tripAt);
    }
    expect(checkBreaker("ref1", tripAt + 60_000)).toBe("half_open");
    const reTripAt = tripAt + 60_001;
    recordBreakerFailure("ref1", reTripAt);
    expect(checkBreaker("ref1", reTripAt)).toBe("open");
    // The new 60s window resets from the re-trip moment.
    expect(checkBreaker("ref1", reTripAt + 59_999)).toBe("open");
    expect(checkBreaker("ref1", reTripAt + 60_000)).toBe("half_open");
  });

  test("failures outside the 30s window do not accumulate", () => {
    const t0 = 1_000_000;
    recordBreakerFailure("ref1", t0); // 1
    recordBreakerFailure("ref1", t0 + 31_000); // first one drops; window = [1]
    recordBreakerFailure("ref1", t0 + 31_100);
    recordBreakerFailure("ref1", t0 + 31_200);
    recordBreakerFailure("ref1", t0 + 31_300);
    // After 5 calls total but only 4 within the window since t0+1000, still closed.
    expect(checkBreaker("ref1", t0 + 31_300)).toBe("closed");
    recordBreakerFailure("ref1", t0 + 31_400);
    expect(checkBreaker("ref1", t0 + 31_400)).toBe("open");
  });
});
