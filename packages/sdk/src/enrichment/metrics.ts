/**
 * In-process metrics for the enrichment client.
 *
 * Internal-only. No `prom-client` dependency. Names mirror the standard
 * Prometheus naming so a future exporter can map them 1:1 without rewriting
 * call sites.
 *
 * Histogram buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1] seconds.
 * We store cumulative bucket counts plus sum + count so the snapshot can be
 * reshaped into either Prometheus histogram or summary form later.
 */

export type Outcome = "success" | "failure" | "circuit_open" | "rate_limited";

const HIST_BUCKETS_S = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1] as const;

interface RefHist {
  buckets: number[]; // length = HIST_BUCKETS_S.length, cumulative counts
  sumSeconds: number;
  count: number;
}

interface State {
  requests: Map<string, Map<Outcome, number>>; // ref → outcome → count
  duration: Map<string, RefHist>;
  cacheHits: Map<string, number>;
  cacheMisses: Map<string, number>;
  /** One-shot per-(tenant,ref) warning state for `send_raw: true`. Tenant
   *  scoping is single-tenant per-process today, so the key is just the ref. */
  sendRawWarned: Set<string>;
  /** One-shot per-ref warning state for `allow_http: true`. */
  allowHttpWarned: Set<string>;
}

let state: State = freshState();

function freshState(): State {
  return {
    requests: new Map(),
    duration: new Map(),
    cacheHits: new Map(),
    cacheMisses: new Map(),
    sendRawWarned: new Set(),
    allowHttpWarned: new Set(),
  };
}

function incMap(m: Map<string, number>, k: string): void {
  m.set(k, (m.get(k) ?? 0) + 1);
}

export function recordRequest(ref: string, outcome: Outcome): void {
  let byOutcome = state.requests.get(ref);
  if (!byOutcome) {
    byOutcome = new Map();
    state.requests.set(ref, byOutcome);
  }
  byOutcome.set(outcome, (byOutcome.get(outcome) ?? 0) + 1);
}

export function recordDuration(ref: string, seconds: number): void {
  let h = state.duration.get(ref);
  if (!h) {
    h = { buckets: new Array(HIST_BUCKETS_S.length).fill(0), sumSeconds: 0, count: 0 };
    state.duration.set(ref, h);
  }
  for (let i = 0; i < HIST_BUCKETS_S.length; i += 1) {
    const upper = HIST_BUCKETS_S[i] as number;
    if (seconds <= upper) h.buckets[i] = (h.buckets[i] ?? 0) + 1;
  }
  h.sumSeconds += seconds;
  h.count += 1;
}

export function recordCacheHit(ref: string): void {
  incMap(state.cacheHits, ref);
}

export function recordCacheMiss(ref: string): void {
  incMap(state.cacheMisses, ref);
}

/**
 * One-shot warning for `send_raw: true`. The validator already warns at
 * install; this is a runtime warning per `(tenant, ref)` for operators who
 * push a manifest with `send_raw: true` while we still treat it as a no-op.
 */
export function warnSendRawOnce(ref: string): void {
  if (state.sendRawWarned.has(ref)) return;
  state.sendRawWarned.add(ref);
  // Logging policy: there is no centralised SDK logger.
  // We surface via process.stderr exactly once per ref.
  if (typeof process !== "undefined" && process.stderr) {
    process.stderr.write(
      `[agentum-sdk] enrichment '${ref}' declares send_raw: true; ` +
        `PII-masked values are sent regardless (v1 no-op).\n`,
    );
  }
}

/**
 * One-shot stderr warning when an enrichment is configured with
 * `allow_http: true` and a plain-http URL. Mirrors `warnSendRawOnce`'s
 * one-shot-per-ref shape so the warning is loud on first use but does not
 * spam every webhook call. DEV-ONLY: production manifests must keep the
 * default strict-HTTPS path.
 */
export function warnAllowHttpOnce(ref: string, url: string): void {
  if (state.allowHttpWarned.has(ref)) return;
  state.allowHttpWarned.add(ref);
  if (typeof process !== "undefined" && process.stderr) {
    process.stderr.write(
      `[agentum-sdk] enrichment '${ref}': insecure http:// URL accepted ` +
        `because allow_http=true — DEV ONLY, do not use in production ` +
        `(url=${url}).\n`,
    );
  }
}

export interface EnrichmentMetricsSnapshot {
  requests: Record<string, Partial<Record<Outcome, number>>>;
  duration: Record<
    string,
    {
      buckets: { le: number; count: number }[];
      sumSeconds: number;
      count: number;
    }
  >;
  cacheHits: Record<string, number>;
  cacheMisses: Record<string, number>;
}

export function getEnrichmentMetricsSnapshot(): EnrichmentMetricsSnapshot {
  const requests: EnrichmentMetricsSnapshot["requests"] = {};
  for (const [ref, byOutcome] of state.requests) {
    const inner: Partial<Record<Outcome, number>> = {};
    for (const [o, n] of byOutcome) inner[o] = n;
    requests[ref] = inner;
  }
  const duration: EnrichmentMetricsSnapshot["duration"] = {};
  for (const [ref, h] of state.duration) {
    duration[ref] = {
      buckets: HIST_BUCKETS_S.map((le, i) => ({ le, count: h.buckets[i] ?? 0 })),
      sumSeconds: h.sumSeconds,
      count: h.count,
    };
  }
  const cacheHits: Record<string, number> = {};
  for (const [k, v] of state.cacheHits) cacheHits[k] = v;
  const cacheMisses: Record<string, number> = {};
  for (const [k, v] of state.cacheMisses) cacheMisses[k] = v;
  return { requests, duration, cacheHits, cacheMisses };
}

/** Test-only — reset all metric state. Called from `__resetEnrichmentStateForTest`. */
export function __resetEnrichmentMetricsForTest(): void {
  state = freshState();
}
