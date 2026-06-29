/**
 * Public surface for the enrichment subsystem.
 *
 * `resolveEnrichment` is consumed by
 * `instrumentation/resolve-dimensions.ts:89`; everything else is exported for
 * the future Prometheus exporter and for tests.
 */

export { resolveEnrichment } from "./client.js";
export { EnrichmentFailedError, EnrichmentConfigError } from "./errors.js";
export {
  getEnrichmentMetricsSnapshot,
  type EnrichmentMetricsSnapshot,
} from "./metrics.js";

import { __resetEnrichmentCacheForTest } from "./cache.js";
import { __resetEnrichmentBreakerForTest } from "./circuit-breaker.js";
import { __resetEnrichmentRateLimitForTest } from "./rate-limit.js";
import { __resetEnrichmentMetricsForTest } from "./metrics.js";
import { __resetEnrichmentInFlightForTest } from "./client.js";

/**
 * Test-only — reset every piece of enrichment state in one call. Tests
 * should invoke this in `beforeEach` so leakage between cases never
 * masks regressions.
 */
export function __resetEnrichmentStateForTest(): void {
  __resetEnrichmentCacheForTest();
  __resetEnrichmentBreakerForTest();
  __resetEnrichmentRateLimitForTest();
  __resetEnrichmentMetricsForTest();
  __resetEnrichmentInFlightForTest();
}
