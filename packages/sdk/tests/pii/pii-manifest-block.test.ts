/**
 * Y02 — unit tests for `parsePiiManifestBlock` + state plumbing.
 *
 * Covers the parser surface (positive shape, every negative branch, the
 * JSONPath syntactic gate) plus the init-time wiring contract:
 *   - empty / absent block → empty `PiiManifestBlock`, no throw
 *   - invalid block → throws `PiiManifestValidationError` synchronously
 */

import {
  parsePiiManifestBlock,
  PiiManifestValidationError,
  _setActivePiiBlock,
  getActivePiiBlock,
  _resetActivePiiBlockForTests,
} from "../../src/pii";
import type { PiiManifestBlock } from "../../src/types";

afterEach(() => {
  _resetActivePiiBlockForTests();
});

describe("parsePiiManifestBlock — positive shapes", () => {
  test("null / undefined input → empty block, no throw", () => {
    expect(parsePiiManifestBlock(null)).toEqual({});
    expect(parsePiiManifestBlock(undefined)).toEqual({});
  });

  test("empty object → empty block", () => {
    expect(parsePiiManifestBlock({})).toEqual({});
  });

  test("full valid block round-trips", () => {
    const raw = {
      field_rules: [
        { tool: "*", path: "$.args.email", mode: "hash" },
        { tool: "send_message", path: "$.body.text", mode: "mask" },
      ],
      text_scanners: [
        {
          enabled: true,
          patterns: ["pii.email", "pii.us_ssn"],
          custom: [
            { id: "internal_id", pattern: "INT-\\d+", severity: "low" },
            { id: "auth_token", pattern: "tok_[a-z]+" }, // no severity
          ],
        },
        { enabled: false },
      ],
    };
    const out = parsePiiManifestBlock(raw);
    expect(out.field_rules).toHaveLength(2);
    expect(out.field_rules?.[0]).toEqual({
      tool: "*",
      path: "$.args.email",
      mode: "hash",
    });
    expect(out.text_scanners).toHaveLength(2);
    expect(out.text_scanners?.[0]?.custom?.[0]?.severity).toBe("low");
    expect(out.text_scanners?.[0]?.custom?.[1]?.severity).toBeUndefined();
  });

  test("accepts all four field-rule modes", () => {
    for (const mode of ["drop", "hash", "tokenize", "mask"]) {
      expect(() =>
        parsePiiManifestBlock({
          field_rules: [{ tool: "t", path: "$.x", mode }],
        }),
      ).not.toThrow();
    }
  });

  test("accepts bracket-notation JSONPath with balanced brackets", () => {
    const out = parsePiiManifestBlock({
      field_rules: [
        { tool: "t", path: "$.args[0].email", mode: "drop" },
        { tool: "t", path: "$.deeply[0][1].nested", mode: "drop" },
      ],
    });
    expect(out.field_rules).toHaveLength(2);
  });
});

describe("parsePiiManifestBlock — negative shapes", () => {
  test("top-level non-object throws", () => {
    expect(() => parsePiiManifestBlock(42)).toThrow(PiiManifestValidationError);
    expect(() => parsePiiManifestBlock("oops")).toThrow(
      PiiManifestValidationError,
    );
    expect(() => parsePiiManifestBlock([1, 2])).toThrow(
      PiiManifestValidationError,
    );
  });

  test("field_rules is not an array → throws with path", () => {
    try {
      parsePiiManifestBlock({ field_rules: "nope" });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PiiManifestValidationError);
      const err = e as PiiManifestValidationError;
      expect(err.validationPath).toBe("pii.field_rules");
    }
  });

  test("field_rule missing tool → throws", () => {
    expect(() =>
      parsePiiManifestBlock({
        field_rules: [{ path: "$.email", mode: "drop" }],
      }),
    ).toThrow(/pii.field_rules\[0\].tool/);
  });

  test("field_rule missing path → throws", () => {
    expect(() =>
      parsePiiManifestBlock({
        field_rules: [{ tool: "t", mode: "drop" }],
      }),
    ).toThrow(/pii.field_rules\[0\].path/);
  });

  test("invalid JSONPath (no $. prefix) → throws with path locator", () => {
    try {
      parsePiiManifestBlock({
        field_rules: [
          { tool: "t", path: "$.ok", mode: "drop" },
          { tool: "t", path: "$.also_ok", mode: "drop" },
          { tool: "t", path: "args.email", mode: "drop" }, // <-- bad
        ],
      });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PiiManifestValidationError);
      const err = e as PiiManifestValidationError;
      expect(err.validationPath).toBe("pii.field_rules[2].path");
      expect(err.detail).toMatch(/JSONPath/);
    }
  });

  test("JSONPath with unbalanced brackets → throws", () => {
    expect(() =>
      parsePiiManifestBlock({
        field_rules: [{ tool: "t", path: "$.args[0", mode: "drop" }],
      }),
    ).toThrow(/unbalanced/);
    expect(() =>
      parsePiiManifestBlock({
        field_rules: [{ tool: "t", path: "$.args]", mode: "drop" }],
      }),
    ).toThrow(/unbalanced/);
  });

  test("unknown mode → throws", () => {
    try {
      parsePiiManifestBlock({
        field_rules: [{ tool: "t", path: "$.x", mode: "obliterate" }],
      });
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PiiManifestValidationError);
      const err = e as PiiManifestValidationError;
      expect(err.validationPath).toBe("pii.field_rules[0].mode");
    }
  });

  test("text_scanners not an array → throws", () => {
    expect(() =>
      parsePiiManifestBlock({ text_scanners: { enabled: true } }),
    ).toThrow(/pii.text_scanners/);
  });

  test("text_scanner.enabled missing or wrong type → throws", () => {
    expect(() =>
      parsePiiManifestBlock({ text_scanners: [{}] }),
    ).toThrow(/pii.text_scanners\[0\].enabled/);
    expect(() =>
      parsePiiManifestBlock({ text_scanners: [{ enabled: "yes" }] }),
    ).toThrow(/pii.text_scanners\[0\].enabled/);
  });

  test("text_scanner.patterns must be string array", () => {
    expect(() =>
      parsePiiManifestBlock({
        text_scanners: [{ enabled: true, patterns: [1, 2] }],
      }),
    ).toThrow(/patterns\[0\]/);
  });

  test("text_scanner.custom entry must have id + pattern", () => {
    expect(() =>
      parsePiiManifestBlock({
        text_scanners: [{ enabled: true, custom: [{ pattern: "x" }] }],
      }),
    ).toThrow(/custom\[0\].id/);
    expect(() =>
      parsePiiManifestBlock({
        text_scanners: [{ enabled: true, custom: [{ id: "a" }] }],
      }),
    ).toThrow(/custom\[0\].pattern/);
  });

  test("text_scanner.custom severity must be low|medium|high", () => {
    expect(() =>
      parsePiiManifestBlock({
        text_scanners: [
          {
            enabled: true,
            custom: [{ id: "a", pattern: "x", severity: "extreme" }],
          },
        ],
      }),
    ).toThrow(/severity/);
  });
});

describe("active pii block state", () => {
  test("default reader returns empty block before init", () => {
    expect(getActivePiiBlock()).toEqual({});
  });

  test("set + read round-trips and is frozen", () => {
    const block: PiiManifestBlock = {
      field_rules: [{ tool: "t", path: "$.x", mode: "drop" }],
    };
    _setActivePiiBlock(block);
    const out = getActivePiiBlock();
    expect(out).toEqual(block);
    expect(Object.isFrozen(out)).toBe(true);
    expect(Object.isFrozen(out.field_rules)).toBe(true);
    expect(Object.isFrozen(out.field_rules![0])).toBe(true);
  });

  test("reset returns to empty", () => {
    _setActivePiiBlock({
      field_rules: [{ tool: "t", path: "$.x", mode: "drop" }],
    });
    _resetActivePiiBlockForTests();
    expect(getActivePiiBlock()).toEqual({});
  });
});
