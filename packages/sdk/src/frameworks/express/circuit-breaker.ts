/**
 * Circuit breaker for `simulatePolicy` calls (G50).
 *
 *   closed  ─── N consecutive failures ───▶ open
 *   open    ─── resetTimeoutMs elapsed  ───▶ half-open
 *   half-open ─── success ──▶ closed  │  ─── failure ──▶ open
 *
 * While in `open`, callers skip the network and serve fail-mode behaviour
 * directly — this prevents a downed Agentum server from adding per-request
 * retry-backoff latency.
 *
 * The half-open state is single-probe: only the first caller after
 * `resetTimeoutMs` attempts a real call; concurrent callers see `open` until
 * the probe settles.
 */

export type BreakerState = "closed" | "open" | "half-open";

export class CircuitBreaker {
  private _state: BreakerState = "closed";
  private _failures = 0;
  private _openedAt = 0;
  private _probing = false;
  private readonly _threshold: number;
  private readonly _resetTimeoutMs: number;

  constructor(opts: { failureThreshold: number; resetTimeoutMs: number }) {
    this._threshold = Math.max(1, opts.failureThreshold | 0);
    this._resetTimeoutMs = Math.max(0, opts.resetTimeoutMs | 0);
  }

  /**
   * True when the caller should skip the network and go straight to fail-mode
   * behaviour. False when it is safe to attempt a real call (which may be a
   * probe in `half-open` state).
   */
  shouldSkip(): boolean {
    if (this._state === "closed") return false;
    if (this._state === "open") {
      if (Date.now() - this._openedAt >= this._resetTimeoutMs) {
        // Transition to half-open — but only the first caller gets to probe.
        if (!this._probing) {
          this._state = "half-open";
          this._probing = true;
          return false;
        }
        return true;
      }
      return true;
    }
    // half-open: probe is in flight — everybody else short-circuits.
    return true;
  }

  /** Call when a simulatePolicy succeeds. */
  recordSuccess(): void {
    this._failures = 0;
    this._state = "closed";
    this._probing = false;
  }

  /** Call when a simulatePolicy fails. */
  recordFailure(): void {
    if (this._state === "half-open") {
      // Probe failed — re-open and reset the timer.
      this._state = "open";
      this._openedAt = Date.now();
      this._probing = false;
      return;
    }
    this._failures += 1;
    if (this._failures >= this._threshold) {
      this._state = "open";
      this._openedAt = Date.now();
    }
  }

  /** @internal — test hooks. */
  get state(): BreakerState {
    return this._state;
  }
  get failures(): number {
    return this._failures;
  }
}
