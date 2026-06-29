/**
 * LRU cache for `simulatePolicy` decisions.
 *
 * Keyed by `(user_id, action, resource, context_hash)`. On a fresh put the
 * decision is retained for `ttlMs`; after that it's evicted lazily on
 * `get()`. On overflow the oldest entry is evicted (standard Map-iteration-
 * order LRU — re-insert on hit to refresh).
 *
 * The cache retains the last-known-good decision for `fail-mode: "cached"`
 * via a parallel "stale" store that ignores TTL — callers can ask for either
 * a fresh hit (`get`) or a stale-but-any hit (`getStale`).
 */

import type { PolicySimulateResponse } from "../../types.js";

/** Stable serialisation of a context record — sorted keys, deterministic. */
export function hashContext(ctx: Record<string, unknown> | undefined): string {
  if (ctx === undefined || ctx === null) return "";
  return stableStringify(ctx);
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    parts.push(JSON.stringify(k) + ":" + stableStringify(obj[k]));
  }
  return "{" + parts.join(",") + "}";
}

interface CacheEntry {
  decision: PolicySimulateResponse;
  expiresAt: number;
}

export class DecisionCache {
  private readonly _maxSize: number;
  private readonly _ttlMs: number;
  private readonly _fresh = new Map<string, CacheEntry>();
  // Parallel stale store for fail-mode: "cached" — keeps the last-known-good
  // decision even after TTL expiry, until the key is evicted by capacity.
  private readonly _stale = new Map<string, PolicySimulateResponse>();

  constructor(opts: { maxSize: number; ttlMs: number }) {
    this._maxSize = Math.max(1, opts.maxSize | 0);
    this._ttlMs = Math.max(0, opts.ttlMs | 0);
  }

  /**
   * Build the cache key. `contextHash` is the output of `hashContext()`.
   *
   * `policyHash`: when provided, becomes a 5th key component. Two
   * decisions for the same `(userId, action, resource, contextHash)` taken
   * under different policy generations yield distinct keys, so a policy
   * churn inside the cache TTL window cannot serve a stale decision.
   * Omitting `policyHash` keeps the legacy 4-component key shape — this is
   * the path used by every framework adapter (Express/Fastify/NestJS/Next.js)
   * for `simulatePolicy`-backed decisions where no policy hash is exposed.
   */
  static key(
    userId: string,
    action: string,
    resource: string,
    contextHash: string,
    policyHash?: string,
  ): string {
    // userId goes first so one compromised user's denials don't fill the whole cache.
    return policyHash !== undefined
      ? `${userId}|${action}|${resource}|${contextHash}|${policyHash}`
      : `${userId}|${action}|${resource}|${contextHash}`;
  }

  /** Returns a fresh (non-expired) decision, or `undefined`. */
  get(key: string): PolicySimulateResponse | undefined {
    const entry = this._fresh.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      // Expired: drop from fresh, retain in stale for fail-mode: cached.
      this._fresh.delete(key);
      return undefined;
    }
    // LRU bump.
    this._fresh.delete(key);
    this._fresh.set(key, entry);
    return entry.decision;
  }

  /** Returns the last-known-good decision regardless of TTL, or `undefined`. */
  getStale(key: string): PolicySimulateResponse | undefined {
    return this._stale.get(key);
  }

  put(key: string, decision: PolicySimulateResponse): void {
    // Evict oldest fresh entry if at capacity.
    if (this._fresh.size >= this._maxSize && !this._fresh.has(key)) {
      const oldest = this._fresh.keys().next().value;
      if (oldest !== undefined) this._fresh.delete(oldest);
    }
    // Evict oldest stale entry if at (double) capacity — stale uses 2×fresh.
    if (this._stale.size >= this._maxSize * 2 && !this._stale.has(key)) {
      const oldest = this._stale.keys().next().value;
      if (oldest !== undefined) this._stale.delete(oldest);
    }
    this._fresh.set(key, { decision, expiresAt: Date.now() + this._ttlMs });
    this._stale.set(key, decision);
  }

  /** Drop everything. Called on `PolicyUpdated` webhook. */
  invalidateAll(): void {
    this._fresh.clear();
    this._stale.clear();
  }

  /** @internal used only by tests. */
  get size(): number {
    return this._fresh.size;
  }
}
