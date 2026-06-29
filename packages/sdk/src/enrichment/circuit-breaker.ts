/**
 * Per-ref circuit breaker.
 *
 * State machine:
 *   closed → open (after 5 consecutive failures within 30 s)
 *   open → half-open (after 60 s)
 *   half-open → closed (on next success) | open (on failure)
 *
 * Single-tenant per-process today, so the state map is keyed by `ref`. If
 * the SDK ever fans out to multiple tenants in one process, the map key
 * must extend to `${tenant_id}\x1f${ref}`.
 */

export type BreakerState = "closed" | "open" | "half_open";

interface RefState {
  state: BreakerState;
  /** Times (ms-epoch) of consecutive failures, only relevant in `closed`. */
  failureTimes: number[];
  /** ms-epoch when the breaker tripped open. */
  openedAt: number;
}

const FAILURES_TO_OPEN = 5;
const WINDOW_MS = 30_000;
const OPEN_DURATION_MS = 60_000;

const STATE: Map<string, RefState> = new Map();

function get(ref: string): RefState {
  let s = STATE.get(ref);
  if (!s) {
    s = { state: "closed", failureTimes: [], openedAt: 0 };
    STATE.set(ref, s);
  }
  return s;
}

/**
 * Returns the breaker state at this instant, transitioning open→half_open
 * if the open duration has elapsed. Callers should treat `open` as "no
 * fetch"; `half_open` allows exactly one probe per transition.
 */
export function checkBreaker(ref: string, now: number = Date.now()): BreakerState {
  const s = get(ref);
  if (s.state === "open" && now - s.openedAt >= OPEN_DURATION_MS) {
    s.state = "half_open";
  }
  return s.state;
}

/** Record a successful fetch — drops failure history, closes the breaker. */
export function recordBreakerSuccess(ref: string): void {
  const s = get(ref);
  s.state = "closed";
  s.failureTimes = [];
  s.openedAt = 0;
}

/**
 * Record a failed fetch. In `half_open` this re-opens the breaker
 * immediately. In `closed`, we trip open after 5 failures within a 30 s
 * sliding window.
 */
export function recordBreakerFailure(ref: string, now: number = Date.now()): void {
  const s = get(ref);
  if (s.state === "half_open") {
    s.state = "open";
    s.openedAt = now;
    s.failureTimes = [];
    return;
  }
  // closed (or transitioning from open with a stale check; treat as closed).
  if (s.state === "open") return; // already open; nothing to record
  s.failureTimes.push(now);
  // Drop failures outside the window.
  const cutoff = now - WINDOW_MS;
  while (s.failureTimes.length > 0 && (s.failureTimes[0] as number) < cutoff) {
    s.failureTimes.shift();
  }
  if (s.failureTimes.length >= FAILURES_TO_OPEN) {
    s.state = "open";
    s.openedAt = now;
    s.failureTimes = [];
  }
}

/** Test-only — clear all breaker state. */
export function __resetEnrichmentBreakerForTest(): void {
  STATE.clear();
}
