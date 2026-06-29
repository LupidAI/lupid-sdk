/**
 * Per-ref token-bucket rate limiter.
 *
 * Default: 1000 req/sec capacity, refill 1000 tokens/sec. Bucket exhaustion
 * is treated as a failure for the request's degradation path but does NOT
 * increment the circuit breaker's failure count — the bucket protects the
 * webhook from us, not the other way around.
 *
 * The bucket size/refill rate are mutable via `__configureRateLimitForTest()`
 * so tests can hit the limit without firing 1000 calls. Production never
 * calls the configure function.
 *
 * Single-tenant per-process today, so the state map is keyed by `ref`.
 */

interface Bucket {
  tokens: number;
  /** ms-epoch of the last refill computation. */
  lastRefillMs: number;
}

interface Config {
  capacity: number;
  refillPerSec: number;
}

let config: Config = { capacity: 1000, refillPerSec: 1000 };

const BUCKETS: Map<string, Bucket> = new Map();

/**
 * Try to take one token. Returns true on success (caller may proceed),
 * false on rate-limit exhaustion (caller treats as failure).
 */
export function tryAcquireToken(ref: string, now: number = Date.now()): boolean {
  let b = BUCKETS.get(ref);
  if (!b) {
    b = { tokens: config.capacity, lastRefillMs: now };
    BUCKETS.set(ref, b);
  }
  const elapsedSec = Math.max(0, (now - b.lastRefillMs) / 1000);
  if (elapsedSec > 0) {
    b.tokens = Math.min(config.capacity, b.tokens + elapsedSec * config.refillPerSec);
    b.lastRefillMs = now;
  }
  if (b.tokens >= 1) {
    b.tokens -= 1;
    return true;
  }
  return false;
}

/** Test-only — replace capacity/refill so the limit can be hit cheaply. */
export function __configureRateLimitForTest(capacity: number, refillPerSec: number): void {
  config = { capacity, refillPerSec };
  BUCKETS.clear();
}

/** Test-only — restore production defaults and drop all bucket state. */
export function __resetEnrichmentRateLimitForTest(): void {
  config = { capacity: 1000, refillPerSec: 1000 };
  BUCKETS.clear();
}
