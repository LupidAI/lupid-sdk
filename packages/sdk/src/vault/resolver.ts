/**
 * Vault placeholder auto-resolver.
 *
 * Web agents using the SDK can put `agentum://SECRET/<lease_id>` in any
 * HTTP header (typically `Authorization`). The fetch interceptor scans
 * outgoing headers for the placeholder syntax and swaps it for the
 * underlying secret value by calling `POST /api/v1/vault/resolve` on
 * central.
 *
 * TRUST MODEL (VAULT-V6 — be precise): in THIS in-process path the agent
 * *code* never sees the secret (the interceptor resolves it transparently),
 * but the plaintext IS fetched into the agent process's memory and cached
 * here for the TTL. So this path buys "not in source / not in env", NOT
 * "never in process". The only deployment where the agent process truly
 * never holds plaintext is the R22 reverse-proxy plane (see PDPC-A4 below),
 * where resolution happens out-of-process. Do not describe the SDK-only
 * shape as "agent never holds plaintext".
 *
 * Resolution is cached in-memory by `lease_id` with a 5-minute TTL by
 * default; central's `VaultService::resolve_placeholder` is the source
 * of truth for expiry / revocation, so a short-lived cache here is the
 * standard hot-path optimization (Spec 2 §runtime hot path).
 *
 * Fail-CLOSED: if central is unreachable or returns an error, the
 * placeholder stays in the header and the upstream request fails
 * authentication. We never silently swap to an empty value — that
 * would silently downgrade auth for the agent's outbound call.
 *
 * PDPC-A4: this in-process resolver is BYPASSED for requests bound to the
 * R22 reverse proxy (`pdpProxyUrl` / `AGENTUM_PDP_PROXY_URL`) — R22 resolves
 * the placeholder out-of-process before forwarding upstream, so the SDK
 * forwards the placeholder verbatim and never pulls plaintext into the agent.
 *
 * Scope:
 *  - Header values only. Body resolution (JSON/form) is NOT supported.
 *    As of R50 a placeholder detected in a scannable request body
 *    (string / Uint8Array / Buffer / Request) is rejected fail-CLOSED by
 *    the fetch interceptor (`bodyContainsPlaceholder`) — the request never
 *    leaves the process, so the placeholder is never forwarded upstream
 *    verbatim. Non-scannable bodies (FormData / ReadableStream / Blob)
 *    cannot be inspected and pass through; put the secret in a header or
 *    pre-resolve it. Resolving inside arbitrary body shapes would require
 *    deeper parsing that we don't ship.
 *  - All HTTP methods. Idempotent on the resolver side.
 *
 * Pairs with backend route `POST /api/v1/vault/resolve` (vault.rs).
 */
export const VAULT_PLACEHOLDER_PREFIX = "agentum://SECRET/"
const PLACEHOLDER_REGEX = /agentum:\/\/SECRET\/([A-Za-z0-9_-]{1,128})/g

interface CacheEntry {
  value: string
  expiresAt: number
}

const DEFAULT_TTL_MS = 5 * 60_000
const cache: Map<string, CacheEntry> = new Map()

export interface VaultResolverOptions {
  /**
   * Central API base URL. Required. Typically the same `gatewayUrl`
   * passed to `installFetchInterceptor`. Example: `https://api.lupid.io`
   */
  apiBaseUrl: string
  /**
   * Tenant API key for the resolve endpoint. Required. Same key the
   * SDK uses for `/sdk/evaluate-tool-call`.
   */
  apiKey: string
  /**
   * Fetch implementation to use. Defaults to the global fetch. Pass
   * the ORIGINAL (unpatched) fetch to avoid recursing through our own
   * interceptor.
   */
  fetchImpl?: typeof fetch
  /**
   * Cache TTL in milliseconds. Defaults to 5 minutes.
   */
  cacheTtlMs?: number
}

/**
 * Resolve a single `agentum://SECRET/<lease_id>` placeholder to its
 * underlying secret. Caches the result by `lease_id` with TTL.
 *
 * @throws Error if central returns non-2xx or the response shape is
 * unexpected. Callers should propagate (fail-CLOSED).
 */
export async function resolvePlaceholder(
  placeholder: string,
  opts: VaultResolverOptions,
): Promise<string> {
  const m = placeholder.match(/^agentum:\/\/SECRET\/([A-Za-z0-9_-]+)$/)
  if (!m || !m[1]) throw new Error(`not an agentum:// SECRET placeholder: ${placeholder}`)
  const leaseId: string = m[1]
  const ttl = opts.cacheTtlMs ?? DEFAULT_TTL_MS
  const now = Date.now()
  const cached = cache.get(leaseId)
  if (cached && cached.expiresAt > now) return cached.value

  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  if (!fetchImpl) {
    throw new Error("agentum vault resolver: no fetch implementation available")
  }
  const url = `${opts.apiBaseUrl.replace(/\/$/, "")}/api/v1/vault/resolve`
  const res = await fetchImpl(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": opts.apiKey,
    },
    body: JSON.stringify({ placeholder }),
  })
  if (!res.ok) {
    throw new Error(
      `agentum vault resolve failed: ${res.status} ${res.statusText}`,
    )
  }
  const body = (await res.json()) as { value?: unknown }
  if (typeof body.value !== "string") {
    throw new Error("agentum vault resolve returned no value")
  }
  cache.set(leaseId, { value: body.value, expiresAt: now + ttl })
  return body.value
}

/**
 * Walk every header value in `init` and substitute every
 * `agentum://SECRET/<lease_id>` occurrence with the resolved secret.
 * Returns a new RequestInit; does not mutate the input.
 *
 * If no placeholders are found, returns the original `init` unchanged
 * (a cheap fast path for the common case of no vault placeholders).
 *
 * Fail-CLOSED: on any resolver error, this rejects. The fetch
 * interceptor should propagate the error so the request never goes
 * out with an unresolved placeholder.
 */
export async function resolveHeaderPlaceholders(
  init: RequestInit | undefined,
  opts: VaultResolverOptions,
): Promise<RequestInit | undefined> {
  if (!init?.headers) return init
  // Normalize headers to a plain Record<string, string>. Headers object,
  // 2D array, and plain object all coerce.
  const raw: Headers | string[][] | Record<string, string> = init.headers as
    | Headers
    | string[][]
    | Record<string, string>
  const entries: [string, string][] = []
  if (raw instanceof Headers) {
    raw.forEach((v, k) => entries.push([k, v]))
  } else if (Array.isArray(raw)) {
    for (const pair of raw) {
      if (pair.length >= 2 && pair[0] != null && pair[1] != null) {
        entries.push([pair[0], pair[1]])
      }
    }
  } else {
    for (const [k, v] of Object.entries(raw)) {
      entries.push([k, String(v)])
    }
  }

  let anyResolved = false
  const resolvedEntries: [string, string][] = []
  for (const [k, v] of entries) {
    if (!v.includes(VAULT_PLACEHOLDER_PREFIX)) {
      resolvedEntries.push([k, v])
      continue
    }
    // Resolve every placeholder in this header value. Multiple
    // placeholders in one header are supported (rare but possible).
    let resolved = v
    const matches = Array.from(v.matchAll(PLACEHOLDER_REGEX))
    for (const m of matches) {
      const ph: string = m[0]
      const secret = await resolvePlaceholder(ph, opts)
      resolved = resolved.split(ph).join(secret)
    }
    anyResolved = true
    resolvedEntries.push([k, resolved])
  }
  if (!anyResolved) return init
  return { ...init, headers: resolvedEntries }
}

/**
 * Test-only: clear the in-memory cache. Used by Jest tests so cache
 * state from one test doesn't bleed into the next.
 *
 * @internal
 */
export function _resetCacheForTests(): void {
  cache.clear()
}
