/**
 * Enrichment webhook client.
 *
 * Public surface:
 *   - `resolveEnrichment(ref, resolved, schema)` — called from
 *     `instrumentation/resolve-dimensions.ts:89` for any `kind: enrichment`
 *     dimension. Returns the resolved string value (or null per
 *     `on_failure: fail_open`).
 *   - Errors re-exported via `enrichment/index.ts`:
 *     `EnrichmentFailedError`, `EnrichmentConfigError`.
 *   - `getEnrichmentMetricsSnapshot()` for the future Prometheus exporter
 *     (not wired today).
 *
 * Composition: LRU cache (per-ref, positive + negative results) → in-flight
 * de-duplication → circuit breaker → token-bucket rate limit → HMAC-signed
 * POST → response-shape validation. Background refresh kicks in once the
 * cached entry crosses `ttl/2` so the next request after the half-life
 * pre-warms without blocking the caller.
 *
 * Edge-runtime contract: every `node:*` import in this module's dependency
 * graph (`hmac.ts`) is dynamic. The resolver only fires server-side today,
 * but the import-graph guard at `tests/edge-entry.test.ts` enforces this
 * against the built bundle.
 */

import type { TenantSchema, EnrichmentDef } from "../manifest/types.js";
import { EnrichmentConfigError, EnrichmentFailedError } from "./errors.js";
import {
  asFullDef,
  type EnrichmentDefFull,
  type ResponseBlock,
} from "./types.js";
import {
  buildCacheKey,
  getOrCreateCache,
  type EnrichmentResult,
} from "./cache.js";
import {
  checkBreaker,
  recordBreakerFailure,
  recordBreakerSuccess,
} from "./circuit-breaker.js";
import { tryAcquireToken } from "./rate-limit.js";
import { sign } from "./hmac.js";
import {
  recordCacheHit,
  recordCacheMiss,
  recordDuration,
  recordRequest,
  warnSendRawOnce,
} from "./metrics.js";

const DEFAULT_TIMEOUT_MS = 250;

/**
 * Coalesce concurrent callers waiting on the same `(ref, key)` so only one
 * HTTP fetch fires. Keyed by `${ref}\x1f${cacheKey}`. The entry is removed
 * in a `.finally()` so a failure does not block future retries.
 */
const IN_FLIGHT: Map<string, Promise<EnrichmentResult>> = new Map();

/**
 * Resolve a single enrichment dimension. Returns the string value the
 * dimension should take, or `null` per `on_failure: fail_open`. Throws
 * `EnrichmentFailedError` when `on_failure: fail_closed` and the call fails.
 *
 * The required-dimension post-pass at `resolve-dimensions.ts:128-138` will
 * still translate a returned `null` into `RequiredDimensionMissingError`
 * for `when_missing: reject` dimensions — that is correct: `on_failure:
 * fail_open` relaxes the webhook's contract, not the dimension's
 * required-ness.
 */
export async function resolveEnrichment(
  ref: string,
  resolved: Record<string, string | null>,
  schema: TenantSchema,
): Promise<string | null> {
  const raw: EnrichmentDef | undefined = schema.enrichments?.[ref];
  if (!raw) return null;
  const def = asFullDef(raw, ref);

  if (def.send_raw === true) {
    warnSendRawOnce(ref);
  }

  const key = buildCacheKey(def, resolved);
  const cache = getOrCreateCache(ref, def);

  const hit = cache.get(key);
  if (hit) {
    recordCacheHit(ref);
    maybeBackgroundRefresh(ref, def, resolved, key, hit);
    return extractValue(hit, ref, def.response);
  }
  recordCacheMiss(ref);

  const inflightKey = `${ref}\x1f${key}`;
  let p = IN_FLIGHT.get(inflightKey);
  if (!p) {
    p = fetchEnrichment(ref, def, resolved).finally(() => {
      IN_FLIGHT.delete(inflightKey);
    });
    IN_FLIGHT.set(inflightKey, p);
  }

  let result: EnrichmentResult;
  try {
    result = await p;
  } catch (err) {
    // fail_closed surfaces here.
    if (err instanceof EnrichmentFailedError) throw err;
    if (err instanceof EnrichmentConfigError) throw err;
    throw new EnrichmentFailedError(
      ref,
      `enrichment '${ref}' unexpected error`,
      err,
    );
  }

  const ttl = result.isNegative
    ? def.cache.negative_ttl_ms ?? def.cache.ttl_ms
    : def.cache.ttl_ms;
  cache.set(key, result, { ttl });
  return extractValue(result, ref, def.response);
}

function extractValue(
  result: EnrichmentResult,
  ref: string,
  _shape: ResponseBlock,
): string | null {
  const v = result.values[ref];
  return typeof v === "string" ? v : null;
}

/**
 * Build a failure-mode `EnrichmentResult`. Records the metrics and either
 * throws (`fail_closed`) or returns a negative-result placeholder
 * (`fail_open`). The caller is responsible for caching the negative result
 * with `negative_ttl_ms`.
 */
function failureResult(
  ref: string,
  def: EnrichmentDefFull,
  outcome: "failure" | "circuit_open" | "rate_limited",
): EnrichmentResult {
  recordRequest(ref, outcome);
  if (def.on_failure === "fail_closed") {
    throw new EnrichmentFailedError(
      ref,
      `enrichment '${ref}' failed (${outcome}) and on_failure is fail_closed`,
    );
  }
  return {
    values: { [ref]: null },
    cachedAt: Date.now(),
    isNegative: true,
  };
}

function getSecret(secretRef: string, ref: string): string {
  const m = /^env:(.+)$/.exec(secretRef);
  if (!m) {
    throw new EnrichmentConfigError(
      `unsupported secret_ref: '${secretRef}' (only 'env:VAR' is supported in v1)`,
      ref,
    );
  }
  const varName = m[1] as string;
  if (typeof process === "undefined" || !process.env) {
    throw new EnrichmentConfigError(
      `env var ${varName} unavailable (no process.env)`,
      ref,
    );
  }
  const v = process.env[varName];
  if (!v) {
    throw new EnrichmentConfigError(`env var ${varName} unset`, ref);
  }
  return v;
}

function buildRequestBody(
  def: EnrichmentDefFull,
  resolved: Record<string, string | null>,
): string {
  const body: Record<string, string | null> = {};
  for (const k of def.request.include_dimensions) {
    body[k] = resolved[k] ?? null;
  }
  return JSON.stringify(body);
}

function validateResponseShape(
  ref: string,
  shape: ResponseBlock,
  parsed: unknown,
): Record<string, string | null> {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new EnrichmentFailedError(
      ref,
      `enrichment '${ref}' response was not a JSON object`,
    );
  }
  const obj = parsed as Record<string, unknown>;
  const out: Record<string, string | null> = {};
  for (const [k, t] of Object.entries(shape.shape)) {
    const v = obj[k];
    if (t === "string") {
      if (typeof v !== "string") {
        throw new EnrichmentFailedError(
          ref,
          `enrichment '${ref}' response.shape['${k}'] expected string, got ${typeof v}`,
        );
      }
      out[k] = v;
    } else {
      // "string|null"
      if (v === null || v === undefined) {
        out[k] = null;
      } else if (typeof v === "string") {
        out[k] = v;
      } else {
        throw new EnrichmentFailedError(
          ref,
          `enrichment '${ref}' response.shape['${k}'] expected string|null, got ${typeof v}`,
        );
      }
    }
  }
  return out;
}

async function fetchEnrichment(
  ref: string,
  def: EnrichmentDefFull,
  resolved: Record<string, string | null>,
): Promise<EnrichmentResult> {
  // 1. Circuit breaker.
  const breakerState = checkBreaker(ref);
  if (breakerState === "open") {
    return failureResult(ref, def, "circuit_open");
  }

  // 2. Rate limiter.
  if (!tryAcquireToken(ref)) {
    return failureResult(ref, def, "rate_limited");
  }

  // 3. Build request body. Values are already PII-masked by the resolver
  // (resolve-dimensions.ts:121-126); `send_raw: true` is a no-op for v1.
  const body = buildRequestBody(def, resolved);

  // 4. HMAC-sign. Throws EnrichmentConfigError if node:crypto is unavailable
  // (edge runtime) or the secret env var is unset; both surface immediately.
  const secret = getSecret(def.auth.secret_ref, ref);
  const sig = await sign(body, secret, ref);

  // 5. Issue fetch with abort-on-timeout.
  const timeoutMs = def.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const ctrl = new AbortController();
  const timeoutHandle = setTimeout(() => ctrl.abort(), timeoutMs);
  const method = def.request.method ?? "POST";
  const start = Date.now();
  let response: Response;
  try {
    response = await fetch(def.url, {
      method,
      headers: {
        "content-type": "application/json",
        "x-lupid-signature": `sha256=${sig}`,
        "x-lupid-enrichment-ref": ref,
      },
      body,
      signal: ctrl.signal,
    });
  } catch (err) {
    clearTimeout(timeoutHandle);
    recordDuration(ref, (Date.now() - start) / 1000);
    recordBreakerFailure(ref);
    if (err instanceof EnrichmentConfigError) throw err;
    return failureResult(ref, def, "failure");
  }
  clearTimeout(timeoutHandle);
  recordDuration(ref, (Date.now() - start) / 1000);

  // 6. Non-2xx → failure.
  if (!response.ok) {
    recordBreakerFailure(ref);
    return failureResult(ref, def, "failure");
  }

  // 7. Parse + validate body.
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    recordBreakerFailure(ref);
    return failureResult(ref, def, "failure");
  }
  let values: Record<string, string | null>;
  try {
    values = validateResponseShape(ref, def.response, parsed);
  } catch (err) {
    recordBreakerFailure(ref);
    // `on_failure: fail_closed` should still surface validation failures
    // as EnrichmentFailedError; `fail_open` swallows them.
    if (def.on_failure === "fail_closed") {
      if (err instanceof EnrichmentFailedError) throw err;
      throw new EnrichmentFailedError(
        ref,
        err instanceof Error ? err.message : String(err),
      );
    }
    return failureResult(ref, def, "failure");
  }

  recordBreakerSuccess(ref);
  recordRequest(ref, "success");
  return {
    values,
    cachedAt: Date.now(),
    isNegative: false,
  };
}

/**
 * Kick off a background refresh if the cached result has aged past half its
 * TTL. The refresh shares the same `IN_FLIGHT` map so a foreground request
 * for the same key would coalesce. The promise is fire-and-forget; failures
 * are swallowed (the original cache entry survives until its own TTL).
 */
function maybeBackgroundRefresh(
  ref: string,
  def: EnrichmentDefFull,
  resolved: Record<string, string | null>,
  cacheKey: string,
  hit: EnrichmentResult,
): void {
  if (hit.isNegative) return; // negative entries are refreshed on natural TTL only
  const halfLife = def.cache.ttl_ms / 2;
  if (Date.now() - hit.cachedAt <= halfLife) return;

  const inflightKey = `${ref}\x1f${cacheKey}`;
  if (IN_FLIGHT.has(inflightKey)) return;

  const cache = getOrCreateCache(ref, def);
  const p: Promise<EnrichmentResult> = fetchEnrichment(ref, def, resolved)
    .then((result) => {
      const ttl = result.isNegative
        ? def.cache.negative_ttl_ms ?? def.cache.ttl_ms
        : def.cache.ttl_ms;
      cache.set(cacheKey, result, { ttl });
      return result;
    })
    .catch(() => {
      // Swallow — original cache entry remains valid until natural TTL.
      return hit;
    })
    .finally(() => {
      IN_FLIGHT.delete(inflightKey);
    });
  IN_FLIGHT.set(inflightKey, p);
}

/** Test-only — clear coalescing state. */
export function __resetEnrichmentInFlightForTest(): void {
  IN_FLIGHT.clear();
}
