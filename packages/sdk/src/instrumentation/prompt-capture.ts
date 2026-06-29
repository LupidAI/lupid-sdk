/**
 * R40 — observe-prompt data-locality: prompt-capture mode resolution +
 * PII masking of the observe-prompt content.
 *
 * The observe-prompt sidecar (`/sdk/observe-prompt`) carries the raw
 * `messages` + `tools_advertised` content to central so Sessions /
 * behavior analytics / alerts work. Actionable telemetry (decision, tool
 * names, dims, risk, event type) must keep flowing — so the default is to
 * still send the event, but with the S5 PII pipeline applied to the
 * sensitive content first ("masked"). Raw capture is an explicit opt-in;
 * "off" is the only no-send mode.
 *
 * Edge-safe: this module has no `node:*` imports. `runPiiPipeline` lazy-
 * imports `node:crypto` internally only when hash/tokenize modes fire, so
 * importing it here does not pull a static `node:*` into the universal
 * bundle.
 */

import type { PromptCaptureMode } from "../types.js";
import type { FeatureState } from "../evaluation/cedar-client.js";
import { runPiiPipeline, isPiiPipelineNoOp } from "../pii/pipeline.js";

/**
 * Resolve the effective {@link PromptCaptureMode} from the new
 * `promptCaptureMode` option and the legacy `capturePrompts` boolean.
 *
 * Contract (R40 §1): `capturePrompts === false` ⇒ `"off"`; otherwise the
 * explicit `promptCaptureMode` wins, defaulting to `"masked"`. `capturePrompts`
 * being `true`/`undefined` does NOT force `"masked"` — it only means "do not
 * force off", so a caller passing `promptCaptureMode: "raw"` (with no
 * `capturePrompts`) gets `"raw"`.
 */
/** R45b / INTEG-B1 — addon id that gates raw prompt capture. Raw content is
 *  honored only when this addon is explicitly `"enabled"`; `"disabled"` and
 *  `"unknown"` force masked. The interceptor install sites resolve its
 *  {@link FeatureState} per-request and pass it as `piiAdvanced`. */
export const PII_ADVANCED_ADDON = "addon.policy.pii-advanced";

export function resolvePromptCaptureMode(opts: {
  capturePrompts?: boolean;
  promptCaptureMode?: PromptCaptureMode;
  /**
   * INTEG-B1 — tri-state enablement of `addon.policy.pii-advanced`, as last
   * observed from a live PDP `/v1/authorize` response (via
   * `CedarToolCallClient.featureState("addon.policy.pii-advanced")`).
   *
   * SAFE-default semantics (raw content is only honored when the addon is
   * explicitly ON):
   *   - `"enabled"`  → honor an explicit `"raw"` request (the advanced-PII
   *     addon is on; raw content may leave the agent).
   *   - `"disabled"` → force `"raw"` → `"masked"` (the addon was turned off;
   *     fail-CLOSED to masked).
   *   - `"unknown"` / undefined → force `"raw"` → `"masked"` (no live
   *     snapshot yet; observe-only masking is the safe default and has no
   *     completion impact). This replaces the prior fail-OPEN behavior where
   *     an empty snapshot honored raw.
   */
  piiAdvanced?: FeatureState;
}): PromptCaptureMode {
  if (opts.capturePrompts === false) return "off";
  const mode = opts.promptCaptureMode ?? "masked";
  // INTEG-B1 (resolves TODO(R38)): raw is honored ONLY when the advanced-PII
  // addon is explicitly enabled. `"disabled"` and `"unknown"` (incl. the
  // cold-start / no-snapshot case) both force masked — the safe default for
  // an observe-only, no-completion-impact gate.
  if (mode === "raw" && opts.piiAdvanced !== "enabled") {
    return "masked";
  }
  return mode;
}

/** Content of the observe-prompt POST that carries raw/sensitive material. */
export interface ObserveContent {
  messages: unknown;
  tools_advertised: unknown;
}

/**
 * Apply the masking policy for the resolved `mode` to the observe-prompt
 * content. Only valid for `"masked"` and `"raw"` modes (the caller must
 * short-circuit `"off"` before reaching this — no POST is sent in that case).
 *
 * - `"raw"` → returned unchanged (explicit opt-in to send unmasked).
 * - `"masked"` → run the S5 PII pipeline over `{ messages, tools_advertised }`.
 *   When the pipeline is a no-op (no trie + no scanner configured) the content
 *   is returned verbatim — "masked" means "PII pipeline applied if configured",
 *   so a no-op deployment still sends content. On any pipeline error this
 *   THROWS; the caller MUST drop the observe POST (fail-CLOSED) so raw PII
 *   never leaks.
 */
export async function maskObserveContent(
  mode: Exclude<PromptCaptureMode, "off">,
  content: ObserveContent,
): Promise<ObserveContent> {
  if (mode === "raw") return content;
  // mode === "masked"
  if (isPiiPipelineNoOp()) return content;
  const { detail } = await runPiiPipeline(content, "*");
  // `runPiiPipeline` walks the object structurally; the shape is preserved.
  return detail as ObserveContent;
}
