/**
 * Background health monitor for the Agentum server (G50).
 *
 * Polls `client.health()` on a fixed interval and exposes a `serverReachable`
 * flag that `agentumGuard()` consults before attempting a real `simulatePolicy`
 * call — eliminating the 30s-timeout wait on every request while the server is
 * down.
 *
 * Lifecycle: construct with `start: true` (default) or call `start()`; always
 * call `stop()` during shutdown or Node will keep the event loop alive via the
 * interval timer.
 */

import type { AgentumClient } from "../../client.js";

export interface HealthMonitorOptions {
  client: AgentumClient;
  intervalMs: number;
  /** If set, overrides `client.health()` with a custom probe. Used in tests. */
  probe?: () => Promise<unknown>;
  /** Auto-start on construction. Default: `true`. */
  start?: boolean;
}

export class HealthMonitor {
  private _reachable = true;
  private _timer: ReturnType<typeof setInterval> | null = null;
  private readonly _intervalMs: number;
  private readonly _probe: () => Promise<unknown>;

  constructor(opts: HealthMonitorOptions) {
    this._intervalMs = Math.max(100, opts.intervalMs | 0);
    this._probe = opts.probe ?? (() => opts.client.health());
    if (opts.start !== false) this.start();
  }

  start(): void {
    if (this._timer !== null) return;
    // Fire once immediately on start so the flag reflects current server state
    // before the first real request arrives. Failures are swallowed — the flag
    // flips on the caller's behalf.
    void this._tick();
    this._timer = setInterval(() => void this._tick(), this._intervalMs);
    // Don't keep the event loop alive on Node just for health polling.
    const t = this._timer as unknown as { unref?: () => void };
    if (typeof t.unref === "function") t.unref();
  }

  stop(): void {
    if (this._timer !== null) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** Server reachability flag — `true` until a probe fails. */
  get reachable(): boolean {
    return this._reachable;
  }

  /** Force an immediate probe. Returns the resulting reachability flag. */
  async probe(): Promise<boolean> {
    await this._tick();
    return this._reachable;
  }

  private async _tick(): Promise<void> {
    try {
      await this._probe();
      this._reachable = true;
    } catch {
      this._reachable = false;
    }
  }
}
