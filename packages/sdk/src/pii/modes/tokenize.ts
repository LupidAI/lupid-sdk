/**
 * AES-256-GCM tokenize / reverseTokenize mode.
 *
 * Output format: `t:<base64url(nonce(12) || ciphertext || tag(16))>`.
 * Nonce is `randomBytes(12)` per NIST SP 800-38D recommendation for GCM;
 * a 96-bit random nonce keeps collision probability negligible for any
 * realistic per-process workload.
 *
 * `node:crypto` is lazy-imported inside the function bodies.
 */

import type { PiiSecrets } from "../secrets.js";

const PREFIX = "t:";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/**
 * Typed error so callers (e.g., the CLI reverse command) can
 * distinguish "wrong key / wrong version / corrupted token" from
 * unrelated failures.
 */
export class PiiReverseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PiiReverseError";
  }
}

export async function tokenize(value: string, secrets: PiiSecrets): Promise<string> {
  if (secrets.tokenizeKey === null) {
    throw new Error(
      "agentum.pii.tokenize: tokenizeKey not loaded; either " +
        "LUPID_PII_TOKENIZE_KEY is unset or init() has not run",
    );
  }
  const { createCipheriv, randomBytes } = await import("node:crypto");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", secrets.tokenizeKey, nonce);
  const ct = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([nonce, ct, tag]);
  return `${PREFIX}${blob.toString("base64url")}`;
}

export async function reverseTokenize(
  token: string,
  secrets: PiiSecrets,
): Promise<string> {
  if (secrets.tokenizeKey === null) {
    throw new PiiReverseError(
      "agentum.pii.reverseTokenize: tokenizeKey not loaded; either " +
        "LUPID_PII_TOKENIZE_KEY is unset or init() has not run",
    );
  }
  if (!token.startsWith(PREFIX)) {
    throw new PiiReverseError(
      `agentum.pii.reverseTokenize: missing '${PREFIX}' prefix`,
    );
  }
  const blob = Buffer.from(token.slice(PREFIX.length), "base64url");
  if (blob.length < NONCE_BYTES + TAG_BYTES) {
    throw new PiiReverseError(
      "agentum.pii.reverseTokenize: token too short (corrupted or truncated)",
    );
  }
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const ct = blob.subarray(NONCE_BYTES, blob.length - TAG_BYTES);

  const { createDecipheriv } = await import("node:crypto");
  const decipher = createDecipheriv("aes-256-gcm", secrets.tokenizeKey, nonce);
  decipher.setAuthTag(tag);
  try {
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString("utf8");
  } catch {
    // Node throws an opaque "Unsupported state or unable to authenticate
    // data" on GCM tag mismatch — wrap so callers can produce a clean
    // error.
    throw new PiiReverseError(
      "token did not authenticate; wrong key, wrong version, or corrupted token",
    );
  }
}
