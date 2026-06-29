/**
 * Barrel for the manifest pipeline.
 *
 * Exposed to consumers as a single import surface:
 *
 *   import { getActiveSchema } from '../manifest';
 *
 * The active-schema state is module-level (`state.ts`); see that file for
 * the lifecycle contract.
 */

export { discoverManifest, loadAndParse } from "./loader.js";
export { parseAndValidate, validate } from "./validator.js";
export { getLiveSchema } from "./client.js";
export { reconcileVersions } from "./reconcile.js";
export { getActiveSchema, _setActiveSchema } from "./state.js";
export {
  SchemaSubscriber,
  __resetSchemaSubscriberForTest,
  type SchemaSubscriberOptions,
  type SchemaSubscriberLogger,
} from "./sse-subscriber.js";
export {
  ManifestError,
  ManifestValidationError,
  InitError,
  type ValidationIssue,
  type ValidationIssueCode,
} from "./errors.js";
export type {
  TenantSchema,
  Dimension,
  Source,
  CedarBinding,
  CedarType,
  ClickhouseHint,
  EnrichmentDef,
  FailureMode,
  PiiMode,
  WhenMissing,
} from "./types.js";
