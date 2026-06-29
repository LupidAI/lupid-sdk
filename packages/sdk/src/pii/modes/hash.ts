/**
 * HMAC-SHA256 hash mode.
 *
 * Output format: `h:<64 hex chars>`. Full-width by design — no truncation
 * knob. Consumers that need a shorter display form (dashboard, scanner)
 * truncate at the consumer side; canonical storage stays 64 hex chars.
 *
 * `node:crypto` is lazy-imported inside the function body; a top-level
 * static import would trip `tests/edge-entry.test.ts`.
 */

import type { PiiSecrets } from "../secrets.js";

export async function hash(value: string, secrets: PiiSecrets): Promise<string> {
  if (secrets.hashSecret === null) {
    throw new Error(
      "agentum.pii.hash: hashSecret not loaded; either " +
        "LUPID_PII_HASH_SECRET is unset or init() has not run",
    );
  }
  const { createHmac } = await import("node:crypto");
  const hex = createHmac("sha256", secrets.hashSecret)
    .update(value, "utf8")
    .digest("hex");
  return `h:${hex}`;
}
