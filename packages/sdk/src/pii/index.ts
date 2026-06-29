/**
 * Public surface of the `pii/*` module, exposed via the
 * `@lupid/sdk/pii` subpath export.
 *
 * Deliberately NOT re-exported from `src/index.ts` — per
 * `.claude/rules/typescript.md` §1 anything reachable from `index.ts` is
 * subject to the `tests/edge-entry.test.ts` static-import audit. The
 * `pii/*` modules lazy-import `node:crypto` inside function bodies, so
 * the audit would still pass, but conservatively keep the top-level
 * export surface untouched until a clear consumer need surfaces.
 */

export { applyPii, REDACTED_LITERAL, reverseTokenize, PiiReverseError } from "./mask.js";
export {
  loadPiiSecrets,
  getPiiSecrets,
  assertSecretsForActiveSchema,
  setPiiSecretsForModule,
  _resetPiiSecretsForTests,
} from "./secrets.js";
export type { PiiSecrets } from "./secrets.js";
export {
  parsePiiManifestBlock,
  PiiManifestValidationError,
} from "./manifest-block.js";
export {
  getActivePiiBlock,
  _setActivePiiBlock,
  _resetActivePiiBlockForTests,
} from "./pii-state.js";
export {
  compileFieldRuleTrie,
  applyTrie,
  FieldRuleCompileError,
  MASK_LITERAL,
  type FieldRuleTrie,
  type ApplyTrieTracker,
} from "./field-rule-trie.js";
export {
  getActiveKeyFingerprint,
  _resetActiveKeyFingerprintForTests,
} from "./pii-key-fingerprint.js";
export {
  getActiveFieldRuleTrie,
  _setActiveFieldRuleTrie,
  _resetActiveFieldRuleTrieForTests,
} from "./trie-state.js";
export {
  compileScanner,
  scanAndMask,
  selfCheck,
  PiiSelfCheckFailedError,
  type Scanner,
  type CompiledPattern,
} from "./text-scanner.js";
export {
  getActiveTextScanner,
  _setActiveTextScanner,
  _resetActiveTextScannerForTests,
} from "./scanner-state.js";
export { runPiiPipeline, type PiiPipelineResult } from "./pipeline.js";
export type {
  PiiManifestBlock,
  PiiFieldRule,
  PiiTextScannerConfig,
} from "../types.js";
