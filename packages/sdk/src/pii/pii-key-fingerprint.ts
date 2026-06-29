/**
 * Y06 — active hash/tokenize key fingerprint helper.
 *
 * Stamped on every audit event whose Stage 1 trie applied `mode: hash` or
 * `mode: tokenize` at least once. The fingerprint lets operators
 * disambiguate ClickHouse rows hashed under different rotation epochs of
 * `LUPID_PII_HASH_SECRET` (the same row hashed against an old vs new
 * secret produces incomparable hashes; without `pii_key_id` there is no
 * post-hoc way to know which secret produced a given row).
 *
 * # Fingerprint algorithm
 *
 * `SHA-256(secret)[:16]` hex — 16 hex chars = 64 bits, sufficient to
 * disambiguate the handful of rotation epochs an operator will see in
 * practice without leaking enough bits to enable an offline preimage
 * search on the secret. The secret itself never leaves the customer
 * process; only the 64-bit fingerprint is transmitted.
 *
 * The hash secret is the canonical fingerprint source — it covers the
 * `mode: hash` path (deterministic, the rotation-forensics use case is
 * the primary driver). When the hash secret is unset but the tokenize
 * key is present (tokenize-only deployment), we fall back to the
 * tokenize key so the fingerprint still tracks the rotation epoch of
 * the only secret material in play. When neither is set, no PII
 * operation could have fired — `getActiveKeyFingerprint` returns
 * `undefined` and the pipeline leaves `pii_key_id` absent.
 *
 * # Edge safety
 *
 * No top-level `node:*` imports. The fingerprint computation uses
 * `node:crypto`'s sync `createHash` via the eval-acquired CJS `require`
 * (same pattern as `instrumentation/context.ts::tryAcquireRequire`).
 * Edge runtimes without a `require` symbol — and runtimes where the
 * `node:crypto` import fails — yield `undefined`; the pipeline simply
 * omits `pii_key_id` rather than crashing. The dispatch sites that
 * would actually fire `hash` / `tokenize` (which themselves dynamically
 * import `node:crypto`) are unreachable on those runtimes anyway, so
 * the absence is internally consistent.
 *
 * # Memoization
 *
 * The fingerprint is computed once per (resolved) secret and cached in
 * a module-local cell keyed by the secret `Buffer`'s identity. If
 * `setPiiSecretsForModule` is called again with a different secret
 * (test resets, in-process rotation), the cell is recomputed lazily on
 * the next read — `getPiiSecrets` returns the live holder, and the
 * memo's identity check detects the swap.
 */

import { getPiiSecrets } from "./secrets.js";

interface FingerprintCache {
  /** The exact `Buffer` identity that produced `value`. Identity-checked. */
  source: Buffer;
  value: string;
}

let CACHE: FingerprintCache | null = null;

/**
 * Returns the 16-hex-char fingerprint of the active hash or tokenize
 * secret, or `undefined` when neither secret is configured (no PII
 * operation could have fired). Sync, memoized, edge-safe.
 */
export function getActiveKeyFingerprint(): string | undefined {
  let secrets: ReturnType<typeof getPiiSecrets>;
  try {
    secrets = getPiiSecrets();
  } catch {
    // `getPiiSecrets` throws when `init()` has not run. In that
    // posture no hash/tokenize mode could have fired (the trie's
    // mode dispatchers also depend on the secrets holder), so the
    // pipeline will never ask for a fingerprint — but be defensive
    // anyway and return undefined rather than propagate.
    return undefined;
  }

  // Prefer the hash secret — it's the canonical rotation-forensics
  // source. Fall back to the tokenize key only when hash is unset
  // (tokenize-only deployment), so the fingerprint still tracks the
  // single secret in play.
  const source = secrets.hashSecret ?? secrets.tokenizeKey;
  if (source === null) return undefined;

  if (CACHE !== null && CACHE.source === source) {
    return CACHE.value;
  }

  const digest = sha256Hex(source);
  if (digest === undefined) return undefined;
  const value = digest.slice(0, 16);
  CACHE = { source, value };
  return value;
}

/** Test-only — clear the memo so a subsequent rotation/init starts clean. */
export function _resetActiveKeyFingerprintForTests(): void {
  CACHE = null;
}

/**
 * Compute SHA-256(input) hex synchronously via `node:crypto`. Returns
 * `undefined` when the runtime cannot resolve `node:crypto` (edge
 * bundlers, browsers).
 *
 * The eval-based require acquisition mirrors
 * `instrumentation/context.ts::tryAcquireRequire`: a top-level
 * `import { createRequire } from "node:module"` is unresolvable in
 * some edge bundlers, but `eval("typeof require ...")` evaluates in
 * the local CJS scope when tsup emits CJS and yields `undefined` on
 * runtimes that lack a CJS `require` symbol.
 */
function sha256Hex(input: Buffer): string | undefined {
  const req = tryAcquireRequire();
  if (!req) return undefined;
  try {
    const mod = req("node:crypto") as {
      createHash: (alg: string) => {
        update: (data: Buffer) => { digest: (enc: string) => string };
      };
    };
    return mod.createHash("sha256").update(input).digest("hex");
  } catch {
    return undefined;
  }
}

function tryAcquireRequire(): NodeJS.Require | undefined {
  try {
    // eslint-disable-next-line no-eval
    const r = eval("typeof require === 'function' ? require : undefined");
    return r as NodeJS.Require | undefined;
  } catch {
    return undefined;
  }
}
