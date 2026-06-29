/**
 * S1-13 — derived-template evaluator unit tests.
 *
 * Covers the four pipe operators (`regex_extract`, `lowercase`, `uppercase`,
 * `default`), null propagation rules, mixed literal+interp templates, and
 * escape-quote handling. Cross-language parity with the Rust evaluator is
 * deferred to S1-13a.
 */

import {
  evaluateTemplate,
  TemplateParseError,
} from "../../src/instrumentation/derived-template";

describe("evaluateTemplate", () => {
  test("plain literal returns the literal", () => {
    expect(evaluateTemplate("hello", {})).toBe("hello");
  });

  test("empty template returns empty string", () => {
    expect(evaluateTemplate("", {})).toBe("");
  });

  test("bare interpolation reads from resolved", () => {
    expect(evaluateTemplate("${name}", { name: "alice" })).toBe("alice");
  });

  test("bare interpolation returns null when value is missing", () => {
    expect(evaluateTemplate("${name}", {})).toBeNull();
    expect(evaluateTemplate("${name}", { name: null })).toBeNull();
  });

  test("mixed literal + interpolation renders null as empty string", () => {
    expect(evaluateTemplate("prefix-${name}-suffix", { name: "x" })).toBe(
      "prefix-x-suffix",
    );
    expect(evaluateTemplate("prefix-${name}-suffix", {})).toBe("prefix--suffix");
  });

  test("lowercase op", () => {
    expect(evaluateTemplate("${name | lowercase}", { name: "ALICE" })).toBe(
      "alice",
    );
  });

  test("uppercase op", () => {
    expect(evaluateTemplate("${name | uppercase}", { name: "alice" })).toBe(
      "ALICE",
    );
  });

  test("regex_extract returns first capture group", () => {
    expect(
      evaluateTemplate('${name | regex_extract "_(sandbox|dev|prod)$"}', {
        name: "bot_sandbox",
      }),
    ).toBe("sandbox");
  });

  test("regex_extract returns null on no match", () => {
    expect(
      evaluateTemplate('${name | regex_extract "_(sandbox|dev|prod)$"}', {
        name: "bot",
      }),
    ).toBeNull();
  });

  test("regex_extract falls back to full match when no capture group", () => {
    expect(
      evaluateTemplate('${name | regex_extract "[a-z]+"}', { name: "ABC123def" }),
    ).toBe("def");
  });

  test("chained ops apply left-to-right", () => {
    expect(
      evaluateTemplate(
        '${name | regex_extract "_(sandbox|dev|prod)$" | uppercase}',
        { name: "bot_dev" },
      ),
    ).toBe("DEV");
  });

  test("default substitutes when value is null", () => {
    expect(
      evaluateTemplate('${name | regex_extract "_(sandbox|dev|prod)$" | default "prod"}', {
        name: "bot",
      }),
    ).toBe("prod");
  });

  test("default passes through when value is non-null", () => {
    expect(
      evaluateTemplate('${name | regex_extract "_(sandbox|dev|prod)$" | default "prod"}', {
        name: "bot_dev",
      }),
    ).toBe("dev");
  });

  test("default applies when input dimension is missing", () => {
    expect(evaluateTemplate('${missing | default "X"}', {})).toBe("X");
  });

  test("null propagates through lowercase but not default", () => {
    expect(evaluateTemplate("${missing | lowercase}", {})).toBeNull();
    expect(evaluateTemplate('${missing | lowercase | default "x"}', {})).toBe("x");
  });

  test("escaped quote in arg is preserved", () => {
    // The arg literal is `say "hi"` after unescaping the `\"` pairs.
    const out = evaluateTemplate('${name | default "say \\"hi\\""}', {});
    expect(out).toBe('say "hi"');
  });

  test("escaped backslash in arg is preserved", () => {
    const out = evaluateTemplate('${name | default "a\\\\b"}', {});
    expect(out).toBe("a\\b");
  });

  test("rejects unknown pipe operator", () => {
    expect(() => evaluateTemplate("${name | bogus}", { name: "x" })).toThrow(
      TemplateParseError,
    );
  });

  test("rejects lowercase with an argument", () => {
    expect(() => evaluateTemplate('${name | lowercase "x"}', { name: "y" })).toThrow(
      TemplateParseError,
    );
  });

  test("rejects regex_extract without an argument", () => {
    expect(() => evaluateTemplate("${name | regex_extract}", { name: "y" })).toThrow(
      TemplateParseError,
    );
  });

  test("rejects unterminated interpolation", () => {
    expect(() => evaluateTemplate("${name", { name: "y" })).toThrow(
      TemplateParseError,
    );
  });

  test("rejects invalid dimension name", () => {
    expect(() => evaluateTemplate("${9name}", {})).toThrow(TemplateParseError);
  });
});
