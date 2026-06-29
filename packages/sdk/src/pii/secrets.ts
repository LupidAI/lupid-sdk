/**
 * PII secrets loader (Stage A primitive).
 *
 * Reads `LUPID_PII_HASH_SECRET` (32-byte HMAC key, base64) and
 * `LUPID_PII_TOKENIZE_KEY` (32-byte AES-256-GCM key, base64) from the env
 * at `init()` time. Validates length. Refuses to start when the active
 * manifest declares a mode whose secret is missing.
 *
 * All `node:crypto` access is intentionally absent from this file —
 * `Buffer.from(value, "base64")` is a Node global (not an import) so the
 * loader stays edge-bundle clean. The mode files (`./modes/{hash,tokenize}`)
 * lazy-import `node:crypto` inside their function bodies.
 *
 * Multi-version keys (`keyVersion > 1`) and rotation flow are out of scope
 * here. `keyVersion` is hardcoded to 1 so downstream consumers can rely on
 * the field existing without dispatching on it yet.
 */

import { getActiveSchema } from "../manifest/state.js";
import { getActivePiiBlock } from "./pii-state.js";

export interface PiiSecrets {
  hashSecret: Buffer | null;
  tokenizeKey: Buffer | null;
  /** Defaults to 1; multi-version support comes later. */
  keyVersion: number;
}

const HASH_ENV = "LUPID_PII_HASH_SECRET";
const TOKENIZE_ENV = "LUPID_PII_TOKENIZE_KEY";
const REQUIRED_BYTES = 32;

let secretsHolder: PiiSecrets | null = null;

/**
 * Decode one base64 env value to a 32-byte Buffer.
 *
 * Returns `null` when the env var is unset (silent — many callers do not
 * use masking) or when the decoded length is wrong (logged once via
 * `console.warn` since the operator clearly intended to set a secret and
 * silently dropping it would surface as a confusing "fail-CLOSED" later).
 *
 * `console.warn` is the SDK's only sanctioned use: `console.log` is
 * forbidden in `src/`, but boot-time warnings that would otherwise be
 * silent are explicitly permitted.
 */
function decodeSecret(envName: string, raw: string | undefined): Buffer | null {
  if (raw === undefined || raw === "") return null;
  const buf = Buffer.from(raw, "base64");
  if (buf.length !== REQUIRED_BYTES) {
    // eslint-disable-next-line no-console
    console.warn(
      `[agentum] ${envName} is set but decodes to ${buf.length} bytes ` +
        `(expected ${REQUIRED_BYTES}). Treating as unset; downstream PII ` +
        `dispatch will fail-CLOSED. Generate a fresh secret with ` +
        `\`openssl rand -base64 32\`.`,
    );
    return null;
  }
  return buf;
}

/**
 * Pure: takes the env map as argument, returns `PiiSecrets`. No side
 * effects, no `process.env` access. `init()` is the only production
 * caller; tests invoke directly with a synthetic env.
 */
export function loadPiiSecrets(env: Record<string, string | undefined>): PiiSecrets {
  return {
    hashSecret: decodeSecret(HASH_ENV, env[HASH_ENV]),
    tokenizeKey: decodeSecret(TOKENIZE_ENV, env[TOKENIZE_ENV]),
    keyVersion: 1,
  };
}

/**
 * Internal setter — flips the module-local holder. Only `init.ts` calls
 * this in production; tests reset via `_resetPiiSecretsForTests`.
 */
export function setPiiSecretsForModule(secrets: PiiSecrets): void {
  secretsHolder = secrets;
}

/**
 * Read the loaded secrets. Throws when called before `init()` has run.
 *
 * Used by the mode dispatchers (`./modes/{hash,tokenize}.ts`) to fail
 * fast and clearly when a consumer calls `applyPii` without having
 * booted the SDK.
 */
export function getPiiSecrets(): PiiSecrets {
  if (secretsHolder === null) {
    throw new Error(
      "agentum: PII secrets not loaded — call init() first",
    );
  }
  return secretsHolder;
}

/**
 * Called by `init()` AFTER the manifest is loaded.
 *
 * Scans the active schema's dimensions for any `pii: "hash"` (needs
 * `hashSecret`) or `pii: "tokenize"` (needs `tokenizeKey`). Y02 extends
 * the scan to the manifest `pii:` block (`field_rules[*].mode`) so a
 * field rule declaring `mode: "hash"` or `mode: "tokenize"` also requires
 * the matching secret env var to be present. Throws with an
 * operator-actionable message when a mode is declared but its env var
 * is missing or wrong-length.
 *
 * Field-rule `mode: "drop"` and `mode: "mask"` need no secret material
 * (drop replaces with `<redacted>`; mask is Y04-territory and uses
 * regex-based redaction). `text_scanners` are not scanned here — the
 * scanner output is fed back through `applyPii`'s `drop` / `hash` /
 * `tokenize` dispatchers, but the manifest doesn't bind a mode to the
 * scanner stanza itself, so there's nothing to check at init time.
 */
export function assertSecretsForActiveSchema(): void {
  // `getActiveSchema` throws InitError if no schema is set — propagate
  // that rather than catching, since the contract of this function
  // requires a live schema.
  const schema = getActiveSchema();
  const secrets = getPiiSecrets();

  for (const dim of schema.dimensions) {
    const mode = dim.pii;
    if (mode === "hash" && secrets.hashSecret === null) {
      throw new Error(
        "agentum.init: schema declares `pii: hash` on dimension '" +
          dim.name +
          "' but " +
          HASH_ENV +
          " is unset. " +
          "Set it to 32 bytes of base64-encoded random data " +
          "(e.g., `" +
          HASH_ENV +
          "=$(openssl rand -base64 32)`). " +
          "See .claude/plan/PII_MASKING_PIPELINE.md §Secret resolution.",
      );
    }
    if (mode === "tokenize" && secrets.tokenizeKey === null) {
      throw new Error(
        "agentum.init: schema declares `pii: tokenize` on dimension '" +
          dim.name +
          "' but " +
          TOKENIZE_ENV +
          " is unset. " +
          "Set it to 32 bytes of base64-encoded random data " +
          "(e.g., `" +
          TOKENIZE_ENV +
          "=$(openssl rand -base64 32)`). " +
          "See .claude/plan/PII_MASKING_PIPELINE.md §Secret resolution.",
      );
    }
  }

  // Y02 — also gate the manifest `pii.field_rules[*]` modes. Same
  // contract as dimension-level pii: declaring `mode: hash` without the
  // hash secret, or `mode: tokenize` without the tokenize key, is a
  // misconfiguration we refuse to boot under (fail-CLOSED at init).
  const piiBlock = getActivePiiBlock();
  if (piiBlock.field_rules) {
    for (let i = 0; i < piiBlock.field_rules.length; i += 1) {
      const rule = piiBlock.field_rules[i];
      if (rule === undefined) continue;
      if (rule.mode === "hash" && secrets.hashSecret === null) {
        throw new Error(
          "agentum.init: pii.field_rules[" +
            i +
            "] declares `mode: hash` for tool '" +
            rule.tool +
            "' (path " +
            rule.path +
            ") but " +
            HASH_ENV +
            " is unset. " +
            "Set it to 32 bytes of base64-encoded random data " +
            "(e.g., `" +
            HASH_ENV +
            "=$(openssl rand -base64 32)`). " +
            "See .claude/plan/PII_MASKING_PIPELINE.md §Secret resolution.",
        );
      }
      if (rule.mode === "tokenize" && secrets.tokenizeKey === null) {
        throw new Error(
          "agentum.init: pii.field_rules[" +
            i +
            "] declares `mode: tokenize` for tool '" +
            rule.tool +
            "' (path " +
            rule.path +
            ") but " +
            TOKENIZE_ENV +
            " is unset. " +
            "Set it to 32 bytes of base64-encoded random data " +
            "(e.g., `" +
            TOKENIZE_ENV +
            "=$(openssl rand -base64 32)`). " +
            "See .claude/plan/PII_MASKING_PIPELINE.md §Secret resolution.",
        );
      }
    }
  }
}

/**
 * Test-only: clear the module-local holder so a subsequent `init()` or
 * direct `setPiiSecretsForModule` call starts from a clean slate.
 */
export function _resetPiiSecretsForTests(): void {
  secretsHolder = null;
}
