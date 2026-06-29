/**
 * S1-13 — resolveDimensions() integration tests.
 *
 * Covers the four source kinds (context, request_header, derived, enrichment-stub),
 * required-dimension enforcement (`reject` vs `null`), real PII masking via the
 * S5-02 `applyPii` shim (`pii: hash` → `h:<64 hex>`), mixed-mode masking, and
 * nested `withAgentumContext` precedence (inner wins per-key).
 *
 * Schemas with `pii: "hash"` require `LUPID_PII_HASH_SECRET` to be loaded before
 * resolveDimensions runs; we set it via `setPiiSecretsForModule` in `beforeAll`.
 */

import {
  resolveDimensions,
  RequiredDimensionMissingError,
} from "../../src/instrumentation/resolve-dimensions";
import { withAgentumContext } from "../../src/instrumentation/context";
import { _setActiveSchema } from "../../src/manifest/index";
import type { TenantSchema, Dimension } from "../../src/manifest/types";
import {
  setPiiSecretsForModule,
  loadPiiSecrets,
  _resetPiiSecretsForTests,
} from "../../src/pii/secrets";
import { InitError } from "../../src/manifest/errors";

const HASH_B64 = Buffer.alloc(32, 0).toString("base64");

function schema(dimensions: Dimension[]): TenantSchema {
  return { version: 1, dimensions };
}

function dim(over: Partial<Dimension> & { name: string; source: Dimension["source"] }): Dimension {
  return { ...over };
}

beforeAll(() => {
  // S5-02 contract — hash mode reads from the module-local secrets holder.
  setPiiSecretsForModule(loadPiiSecrets({ LUPID_PII_HASH_SECRET: HASH_B64 }));
});

afterAll(() => {
  _resetPiiSecretsForTests();
});

afterEach(() => {
  _setActiveSchema(null);
});

describe("resolveDimensions", () => {
  test("throws InitError when init() has not run", async () => {
    _setActiveSchema(null);
    await expect(resolveDimensions()).rejects.toBeInstanceOf(InitError);
  });

  test("context-only: reads dimensions from ALS", async () => {
    _setActiveSchema(
      schema([
        dim({ name: "account_id", source: { kind: "context", path: "account_id" } }),
        dim({ name: "bot_id", source: { kind: "context", path: "bot_id" } }),
      ]),
    );
    const result = await withAgentumContext(
      { dimensions: { account_id: "acme", bot_id: "concierge" } },
      () => resolveDimensions(),
    );
    expect(result).toEqual({ account_id: "acme", bot_id: "concierge" });
  });

  test("header-only: reads via the request option", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "request_header", header: "x-acme-account-id" },
        }),
      ]),
    );
    const result = await resolveDimensions({
      request: { headers: { "x-acme-account-id": "acme" } },
    });
    expect(result).toEqual({ account_id: "acme" });
  });

  test("header is lowercased on lookup (mixed-case manifest)", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "request_header", header: "X-Acme-Account-Id" },
        }),
      ]),
    );
    const result = await resolveDimensions({
      request: { headers: { "x-acme-account-id": "acme" } },
    });
    expect(result).toEqual({ account_id: "acme" });
  });

  test("array-valued header takes the first element", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "request_header", header: "x-account" },
        }),
      ]),
    );
    const result = await resolveDimensions({
      request: { headers: { "x-account": ["first", "second"] } },
    });
    expect(result).toEqual({ account_id: "first" });
  });

  test("derived: references earlier-resolved dimensions", async () => {
    _setActiveSchema(
      schema([
        dim({ name: "bot_id", source: { kind: "context", path: "bot_id" } }),
        dim({
          name: "environment",
          source: {
            kind: "derived",
            template: '${bot_id | regex_extract "_(sandbox|dev|prod)$" | default "prod"}',
          },
        }),
      ]),
    );
    const got = await withAgentumContext({ dimensions: { bot_id: "concierge_dev" } }, () =>
      resolveDimensions(),
    );
    expect(got).toEqual({ bot_id: "concierge_dev", environment: "dev" });
  });

  test("derived with no match falls back to default literal", async () => {
    _setActiveSchema(
      schema([
        dim({ name: "bot_id", source: { kind: "context", path: "bot_id" } }),
        dim({
          name: "environment",
          source: {
            kind: "derived",
            template: '${bot_id | regex_extract "_(sandbox|dev|prod)$" | default "prod"}',
          },
        }),
      ]),
    );
    const got = await withAgentumContext({ dimensions: { bot_id: "plain" } }, () =>
      resolveDimensions(),
    );
    expect(got["environment"]).toBe("prod");
  });

  test("enrichment stub yields null (S1-14 lands the real client)", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "department",
          source: { kind: "enrichment", enrichment_ref: "hr_lookup" },
        }),
      ]),
    );
    const got = await resolveDimensions();
    expect(got).toEqual({ department: null });
  });

  test("missing required + when_missing reject throws", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "context", path: "account_id" },
          required: true,
          when_missing: "reject",
        }),
      ]),
    );
    await expect(resolveDimensions()).rejects.toBeInstanceOf(
      RequiredDimensionMissingError,
    );
  });

  test("missing required + when_missing reject is the default", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "context", path: "account_id" },
          required: true,
        }),
      ]),
    );
    await expect(resolveDimensions()).rejects.toBeInstanceOf(
      RequiredDimensionMissingError,
    );
  });

  test("missing required + when_missing null returns null", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "context", path: "account_id" },
          required: true,
          when_missing: "null",
        }),
      ]),
    );
    const got = await resolveDimensions();
    expect(got).toEqual({ account_id: null });
  });

  test("non-required missing dimension yields null", async () => {
    _setActiveSchema(
      schema([
        dim({ name: "account_id", source: { kind: "context", path: "account_id" } }),
      ]),
    );
    const got = await resolveDimensions();
    expect(got).toEqual({ account_id: null });
  });

  test("PII hash mode applies real HMAC-SHA256, yielding h:<64 hex>", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "end_user_id",
          source: { kind: "context", path: "end_user_id" },
          pii: "hash",
        }),
      ]),
    );
    const got = await withAgentumContext(
      { dimensions: { end_user_id: "alice@acme.com" } },
      () => resolveDimensions(),
    );
    const out = got["end_user_id"];
    expect(out).toMatch(/^h:[0-9a-f]{64}$/);
    expect(out).not.toBe("alice@acme.com");
  });

  test("mixed-mode masking: only pii: hash dims get h: prefix", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "account_id",
          source: { kind: "context", path: "account_id" },
          pii: "none",
        }),
        dim({
          name: "end_user_id",
          source: { kind: "context", path: "end_user_id" },
          pii: "hash",
        }),
      ]),
    );
    const got = await withAgentumContext(
      { dimensions: { account_id: "acme", end_user_id: "alice@acme.com" } },
      () => resolveDimensions(),
    );
    expect(got["account_id"]).toBe("acme");
    expect(got["end_user_id"]).toMatch(/^h:[0-9a-f]{64}$/);
  });

  test("PII masking skips null values (no h: on a missing dim)", async () => {
    _setActiveSchema(
      schema([
        dim({
          name: "end_user_id",
          source: { kind: "context", path: "end_user_id" },
          pii: "hash",
        }),
      ]),
    );
    const got = await resolveDimensions();
    expect(got).toEqual({ end_user_id: null });
  });

  test("nested withAgentumContext: inner dimension key shadows outer", async () => {
    _setActiveSchema(
      schema([
        dim({ name: "a", source: { kind: "context", path: "a" } }),
        dim({ name: "b", source: { kind: "context", path: "b" } }),
      ]),
    );
    const got = await withAgentumContext({ dimensions: { a: "outer", b: "outer-b" } }, () =>
      withAgentumContext({ dimensions: { a: "inner" } }, () => resolveDimensions()),
    );
    // Inner wins on `a`; outer `b` is preserved (per-key merge).
    expect(got).toEqual({ a: "inner", b: "outer-b" });
  });
});
