/**
 * R45b / INTEG-B1 — `resolvePromptCaptureMode` advanced-PII addon gate.
 *
 * Raw prompt capture is honored ONLY when the `addon.policy.pii-advanced`
 * feature is explicitly `"enabled"` in the live PDP snapshot. The SAFE
 * default for `"unknown"` (no snapshot yet — cold start / central-only / PDP
 * not wired) and for `"disabled"` (the addon was turned off) is to force
 * `"raw"` → `"masked"`. This replaces the prior fail-OPEN behavior where an
 * empty/absent snapshot honored raw.
 */

import { resolvePromptCaptureMode } from "../src/instrumentation/prompt-capture";

describe("resolvePromptCaptureMode — pii-advanced gate (INTEG-B1)", () => {
  test("capturePrompts === false always wins → off", () => {
    expect(
      resolvePromptCaptureMode({
        capturePrompts: false,
        promptCaptureMode: "raw",
        piiAdvanced: "enabled",
      }),
    ).toBe("off");
  });

  test("unknown (no snapshot) forces raw → masked (SAFE default)", () => {
    expect(
      resolvePromptCaptureMode({ promptCaptureMode: "raw", piiAdvanced: "unknown" }),
    ).toBe("masked");
  });

  test("undefined piiAdvanced forces raw → masked (SAFE default)", () => {
    expect(resolvePromptCaptureMode({ promptCaptureMode: "raw" })).toBe("masked");
  });

  test("disabled forces raw → masked (fail-CLOSED)", () => {
    expect(
      resolvePromptCaptureMode({ promptCaptureMode: "raw", piiAdvanced: "disabled" }),
    ).toBe("masked");
  });

  test("enabled honors explicit raw", () => {
    expect(
      resolvePromptCaptureMode({ promptCaptureMode: "raw", piiAdvanced: "enabled" }),
    ).toBe("raw");
  });

  test("masked stays masked regardless of feature state", () => {
    for (const piiAdvanced of ["enabled", "disabled", "unknown"] as const) {
      expect(
        resolvePromptCaptureMode({ promptCaptureMode: "masked", piiAdvanced }),
      ).toBe("masked");
    }
  });

  test("default (no mode) is masked; gate is a no-op for non-raw", () => {
    expect(
      resolvePromptCaptureMode({ piiAdvanced: "disabled" }),
    ).toBe("masked");
  });
});
