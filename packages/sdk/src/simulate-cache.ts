/**
 * Client-side Cedar decision cache for `AgentumClient.simulatePolicy`.
 *
 * Keyed by `(agent_id, action, resource, user_hash, context_hash)`. TTL
 * comes from the server-advertised `Cache-Control: max-age=N` header (with
 * `X-Agentum-Cache-Max-Age` as a fallback parse). The server sets
 * `max-age=0` / `Cache-Control: no-store` for decisions that carry HITL
 * advice or were produced by inline simulate; those are never cached.
 *
 * The cache is separately invalidated when the server's
 * `X-Agentum-Policy-Generation` header changes — that signal fans out on
 * every `/policies/*` write (reload, inline load, per-agent PUT/declarative,
 * proposal approval), giving the SDK a dead-simple eviction primitive.
 *
 * This is distinct from the middleware-layer `DecisionCache` in
 * `frameworks/express/decision-cache.ts` — that one keys on user session
 * + adds fail-mode "cached" semantics. The client-level cache here is a
 * lower-layer primitive shared by every caller of `client.simulatePolicy()`
 * and `client.isAllowed()`.
 */

/** Stable JSON stringify with sorted object keys (deterministic hash input). */
export function stableStringify(value: unknown): string {
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

export interface SimulateCacheOptions {
  /** Enable the cache. Default `true`. Set to `false` to disable globally. */
  enabled?: boolean;
  /** Maximum number of entries. Oldest-insert is evicted on overflow. Default 512. */
  maxSize?: number;
}

interface CacheEntry<V> {
  value: V;
  expiresAt: number;
}

/**
 * Minimal TTL + LRU-on-overflow cache. Deliberately small (~40 LOC of logic)
 * because the hot path is `get()` → compare `Date.now()` → return. We keep
 * the map iteration-order eviction (Map preserves insertion order; re-insert
 * on hit bumps).
 */
export class SimulateDecisionCache<V> {
  private readonly maxSize: number;
  private readonly entries = new Map<string, CacheEntry<V>>();
  private generation = 0;
  readonly enabled: boolean;

  constructor(opts: SimulateCacheOptions = {}) {
    this.enabled = opts.enabled ?? true;
    this.maxSize = Math.max(1, (opts.maxSize ?? 512) | 0);
  }

  static key(
    agentId: string,
    action: string,
    resource: string,
    userHash: string,
    contextHash: string,
  ): string {
    // agent_id | action | resource | user | context — separators chosen to
    // avoid collision with anything a Cedar action/resource string might
    // contain (`|` is the one ASCII char Cedar identifiers can't use).
    return `${agentId}|${action}|${resource}|${userHash}|${contextHash}`;
  }

  /**
   * Fetch the cached value if not expired. Bumps the LRU slot on hit.
   * Returns `undefined` on miss / expiry / disabled cache.
   */
  get(key: string): V | undefined {
    if (!this.enabled) return undefined;
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // LRU bump.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  /**
   * Insert with TTL.  `ttlMs <= 0` is a no-op (explicit non-cacheable
   * decisions like HITL-advice Denies short-circuit this path).
   */
  put(key: string, value: V, ttlMs: number): void {
    if (!this.enabled || ttlMs <= 0) return;
    if (this.entries.size >= this.maxSize && !this.entries.has(key)) {
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  /** Drop every entry.  Called by `invalidatePolicyCache()` + on generation bump. */
  invalidateAll(): void {
    this.entries.clear();
  }

  /**
   * If `newGeneration` differs from the last observed generation, drop
   * every entry and record the new value. No-op when the generation
   * is unchanged or the header was missing (legacy server).
   */
  observeGeneration(newGeneration: string | null): void {
    if (!newGeneration) return;
    const parsed = Number(newGeneration);
    if (!Number.isFinite(parsed) || parsed <= 0) return;
    if (parsed !== this.generation) {
      if (this.generation !== 0) this.invalidateAll();
      this.generation = parsed;
    }
  }

  /** @internal exposed for tests. */
  get size(): number {
    return this.entries.size;
  }
}

/**
 * Parse `Cache-Control: max-age=N` and `X-Agentum-Cache-Max-Age: N` headers.
 * Returns milliseconds. `0` means "do not cache" (e.g. `no-store` or
 * `max-age=0`). Missing headers return `null` so callers can fall back to
 * a library default.
 */
export function parseMaxAgeMs(headers: Headers): number | null {
  // Explicit vendor header wins — it's always in seconds, no parsing fuss.
  const vendor = headers.get("x-agentum-cache-max-age");
  if (vendor !== null) {
    const n = Number(vendor);
    if (Number.isFinite(n) && n >= 0) return Math.round(n * 1000);
  }
  const cc = headers.get("cache-control");
  if (!cc) return null;
  const lower = cc.toLowerCase();
  if (lower.includes("no-store") || lower.includes("no-cache")) return 0;
  const match = lower.match(/max-age\s*=\s*(\d+)/);
  if (match) {
    const n = Number(match[1]);
    if (Number.isFinite(n) && n >= 0) return Math.round(n * 1000);
  }
  return null;
}
