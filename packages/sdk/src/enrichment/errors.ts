/**
 * Error types for the enrichment client.
 *
 * `EnrichmentFailedError` — runtime failure surfaced through `on_failure:
 * fail_closed`. Resolver-side code at
 * `instrumentation/resolve-dimensions.ts:89` bubbles it to the caller.
 *
 * `EnrichmentConfigError` — manifest block malformed (cache/auth/request/
 * response missing or wrong shape, secret env var unset, non-HTTPS URL).
 * Never caught inside the client; surfaces immediately so misconfiguration
 * is loud.
 */

export class EnrichmentFailedError extends Error {
  public readonly ref: string;
  public readonly cause?: unknown;
  constructor(ref: string, message?: string, cause?: unknown) {
    super(message ?? `enrichment '${ref}' failed`);
    this.name = "EnrichmentFailedError";
    this.ref = ref;
    if (cause !== undefined) this.cause = cause;
  }
}

export class EnrichmentConfigError extends Error {
  public readonly ref: string;
  constructor(message: string, ref: string) {
    super(message);
    this.name = "EnrichmentConfigError";
    this.ref = ref;
  }
}
