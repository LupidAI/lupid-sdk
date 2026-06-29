/**
 * `applyPii(value, mode)` — the single dispatcher every consumer imports.
 *
 * Signature is fixed at `(value, mode)` to match exactly what
 * `resolveDimensions` calls.
 *
 * NOTE: callers must run `init()` before invoking `applyPii` with the
 * `hash` or `tokenize` modes — those paths read the module-local
 * secrets holder via `getPiiSecrets()`, which throws when unset. The
 * `none` and `drop` modes are init-free.
 */

import type { PiiMode } from "../manifest/types.js";
import { getPiiSecrets } from "./secrets.js";
import { hash } from "./modes/hash.js";
import { tokenize } from "./modes/tokenize.js";
import { drop } from "./modes/drop.js";

export async function applyPii(value: string, mode: PiiMode): Promise<string> {
  switch (mode) {
    case "none":
      return value;
    case "drop":
      return drop(value);
    case "hash":
      return hash(value, getPiiSecrets());
    case "tokenize":
      return tokenize(value, getPiiSecrets());
    default: {
      // Exhaustiveness — narrows to `never` if PiiMode is extended.
      const _exhaustive: never = mode;
      void _exhaustive;
      throw new Error(`agentum.pii: unknown mode '${String(mode)}'`);
    }
  }
}

export { REDACTED_LITERAL } from "./modes/drop.js";
export { reverseTokenize, PiiReverseError } from "./modes/tokenize.js";
