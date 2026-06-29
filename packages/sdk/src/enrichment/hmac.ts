/**
 * HMAC-SHA256 signing for enrichment webhook payloads.
 *
 * Uses a dynamic `import("node:crypto")` so this module loads in edge runtimes
 * without throwing — the actual resolver paths today are Node-only, but the
 * SDK's universal entry must not break at module-load on Workers/Edge/browser.
 *
 * If `node:crypto` is unavailable (edge runtime, browser without polyfill),
 * `sign()` throws `EnrichmentConfigError("node-only")`.
 */

import { EnrichmentConfigError } from "./errors.js";

export async function sign(payload: string, secret: string, ref: string): Promise<string> {
  try {
    const { createHmac } = await import("node:crypto");
    return createHmac("sha256", secret).update(payload).digest("hex");
  } catch (err) {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' HMAC signing requires node:crypto (node-only): ${
        err instanceof Error ? err.message : String(err)
      }`,
      ref,
    );
  }
}
