/**
 * Public exports for `@lupid/react`.
 *
 * Only the surface the host application needs is re-exported here. The
 * underlying fetch wrappers and tree builder live in `./api.js` and
 * `./tree.js` respectively; host apps may import them as deep paths if
 * they want to roll their own UI, but the package contract is defined
 * by what this file re-exports.
 */

export { CapabilityToggles } from "./CapabilityToggles.js";
export type { CapabilityTogglesProps } from "./CapabilityToggles.js";

export {
  LupidError,
} from "./types.js";
export type {
  CapabilityListResponse,
  CapabilityNode,
  CapabilityTogglesScope,
  LupidErrorCode,
  ScopeIdentity,
  SideEffects,
  ToggleResponse,
} from "./types.js";

export {
  deleteOverride,
  getDefaults,
  listCapabilities,
  toggleCapability,
} from "./api.js";

export { buildTree } from "./tree.js";
export type { TreeNode } from "./tree.js";
