/**
 * Replay-prevention freshness headers for `/audit/ingest` POSTs.
 *
 * The central API enforces a per-tenant nonce + timestamp gate on
 * audit-ingest requests (see `crates/agentum-api/src/routes/audit_ingest.rs`
 * `check_freshness_headers`). As of Q4, the tenant-settings default
 * `audit_ingest_require_freshness` flips to `TRUE`, so every audit POST
 * from the SDK must carry both headers — the legacy "opt-in" posture is
 * gone for net-new tenants.
 *
 * Both header values are generated client-side:
 * - `x-agentum-nonce` — UUIDv4, single-use within the server's replay
 *   window. The server caches the nonce per-tenant and rejects duplicates.
 * - `x-agentum-timestamp` — Unix milliseconds at request-build time. The
 *   server rejects timestamps outside its freshness window (default ±5min).
 *
 * Edge-safety: `crypto.randomUUID()` and `Date.now()` are globally
 * available in Node ≥ 14.17, Cloudflare Workers, Vercel Edge, Deno, and
 * the browser. No `node:*` import is required, so this helper is safe to
 * pull from any file reachable from `index.ts`.
 */
export function freshnessHeaders(): Record<string, string> {
  return {
    "x-agentum-nonce": crypto.randomUUID(),
    "x-agentum-timestamp": Date.now().toString(),
  };
}
