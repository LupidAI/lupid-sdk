/**
 * Per-ref LRU cache for enrichment results.
 *
 * Cache scoping: the TS SDK process is single-tenant by design
 * (`_setActiveSchema` installs exactly one active manifest per `init()`).
 * `TenantSchema` carries no `tenant_id` field, so we key the registry by
 * `ref` alone. If the SDK ever grows multi-tenant fan-out, this map's key
 * must extend to `${tenant_id}\x1f${ref}` and `getOrCreateCache` must accept
 * a tenant argument.
 *
 * Positive and negative results live in the same cache, distinguished by
 * `isNegative`. The LRU's per-entry `ttl` is set when we call `.set()` so
 * negative results expire on `cache.negative_ttl_ms` while positive ones
 * expire on `cache.ttl_ms`.
 */

import { LRUCache } from "lru-cache";

import type { EnrichmentDefFull } from "./types.js";

export interface EnrichmentResult {
  /**
   * The full response map from the webhook (already shape-validated). Keyed
   * by dimension name; values are `string | null` per the manifest's
   * `response.shape` declaration.
   */
  values: Record<string, string | null>;
  /** ms since epoch when this result was produced (positive or negative). */
  cachedAt: number;
  /** True when this is a recorded failure (per `on_failure: fail_open`). */
  isNegative: boolean;
}

const DEFAULT_MAX_ENTRIES = 10_000;

function envMax(): number {
  if (typeof process === "undefined") return DEFAULT_MAX_ENTRIES;
  const raw = process.env["LUPID_ENRICHMENT_CACHE_SIZE"];
  if (!raw) return DEFAULT_MAX_ENTRIES;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_MAX_ENTRIES;
}

const REGISTRY: Map<string, LRUCache<string, EnrichmentResult>> = new Map();

export function getOrCreateCache(
  ref: string,
  def: EnrichmentDefFull,
): LRUCache<string, EnrichmentResult> {
  const existing = REGISTRY.get(ref);
  if (existing) return existing;
  const max = def.cache.max_entries ?? envMax();
  // The LRU's `ttl` is the default per-entry; we always pass an explicit
  // `ttl` on `.set()` so negative_ttl_ms applies cleanly. `ttlAutopurge` is
  // off — we lazily check expiry on `.get()`, which is the LRU default.
  const cache = new LRUCache<string, EnrichmentResult>({
    max,
    ttl: def.cache.ttl_ms,
    allowStale: false,
    updateAgeOnGet: false,
  });
  REGISTRY.set(ref, cache);
  return cache;
}

/**
 * Build the cache lookup key from the resolved-so-far dimensions. The
 * sentinel `\x1f` (US, Unit Separator) avoids collision when a dimension
 * value contains `|` (a more obvious separator).
 */
export function buildCacheKey(
  def: EnrichmentDefFull,
  resolved: Record<string, string | null>,
): string {
  return def.cache.key.map((k) => resolved[k] ?? "").join("\x1f");
}

/** Test-only — clear every cache and drop them from the registry. */
export function __resetEnrichmentCacheForTest(): void {
  for (const c of REGISTRY.values()) c.clear();
  REGISTRY.clear();
}
