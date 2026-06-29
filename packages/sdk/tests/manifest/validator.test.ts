/**
 * S1-12 — validator parity tests.
 *
 * Asserts:
 *   (1) the Enterprise v3 fixture parses + validates cleanly (positive case)
 *   (2) every entry in `reject_cases.json` produces the expected SDK rule
 *       code (parity contract with Rust `SchemaError` variant names)
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as YAML from "yaml";

import {
  parseAndValidate,
  validate,
} from "../../src/manifest/validator";
import {
  ManifestValidationError,
  type ValidationIssueCode,
} from "../../src/manifest/errors";

interface RejectCase {
  name: string;
  yaml: string;
  expected_code: ValidationIssueCode;
}

const FIXTURE_DIR = path.join(__dirname, "fixtures");

describe("parseAndValidate — accept", () => {
  it("accepts the Enterprise v3 parity fixture", () => {
    const yamlText = fs.readFileSync(
      path.join(FIXTURE_DIR, "enterprise_v3.yaml"),
      "utf8",
    );
    const raw = YAML.parse(yamlText);
    const schema = parseAndValidate(raw);
    expect(schema.version).toBe(3);
    expect(schema.scoping_dimension).toBe("account_id");
    expect(schema.dimensions).toHaveLength(5);
    // Sanity: a sampling of the parsed shapes.
    expect(schema.dimensions[0]?.name).toBe("account_id");
    expect(schema.dimensions[0]?.source.kind).toBe("request_header");
    expect(schema.dimensions[3]?.pii).toBe("hash");
  });
});

describe("parseAndValidate — reject cases mirror Rust SchemaError codes", () => {
  const cases: RejectCase[] = JSON.parse(
    fs.readFileSync(path.join(FIXTURE_DIR, "reject_cases.json"), "utf8"),
  ) as RejectCase[];

  for (const tc of cases) {
    it(tc.name, () => {
      const raw = YAML.parse(tc.yaml);
      let caught: unknown;
      try {
        parseAndValidate(raw);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ManifestValidationError);
      const err = caught as ManifestValidationError;
      const codes = err.issues.map((i) => i.code);
      expect(codes).toContain(tc.expected_code);
    });
  }
});

describe("validate — granular", () => {
  it("returns no issues for a minimal valid schema", () => {
    const schema = {
      version: 1,
      dimensions: [
        { name: "bot_id", source: { kind: "context" as const, path: "bot_id" } },
      ],
    };
    expect(validate(schema)).toEqual([]);
  });
});
