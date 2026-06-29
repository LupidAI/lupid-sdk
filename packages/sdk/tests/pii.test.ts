/**
 * Unit tests for the S5-02 PII primitives.
 *
 * Coverage:
 *   1. `loadPiiSecrets`         — base64 + length validation + warn-once.
 *   2. `assertSecretsForActiveSchema` — fail-CLOSED throws on missing env.
 *   3. `hash`                   — determinism + format + fail on unloaded.
 *   4. `tokenize` / `reverseTokenize` — round-trip + nonce-randomness + tamper.
 *   5. `drop`                   — literal `<redacted>`.
 *   6. `applyPii`               — mode dispatch + exhaustiveness.
 *
 * Test fixture secrets are checked-in constants (all-zero 32 bytes,
 * base64-encoded). They are non-production format documentation only.
 */

import {
  loadPiiSecrets,
  setPiiSecretsForModule,
  getPiiSecrets,
  assertSecretsForActiveSchema,
  _resetPiiSecretsForTests,
  type PiiSecrets,
} from "../src/pii/secrets";
import { hash } from "../src/pii/modes/hash";
import {
  tokenize,
  reverseTokenize,
  PiiReverseError,
} from "../src/pii/modes/tokenize";
import { drop, REDACTED_LITERAL } from "../src/pii/modes/drop";
import { applyPii } from "../src/pii/mask";
import { _setActiveSchema } from "../src/manifest/index";
import type { PiiMode } from "../src/manifest/types";
import type { TenantSchema, Dimension } from "../src/manifest/types";

// ── fixture secrets (non-production; documentation-only base64 strings) ────

/** 32 bytes of zeros, base64. Valid length, fixed content for determinism. */
const HASH_B64 = Buffer.alloc(32, 0).toString("base64");
/** 32 bytes of 0x01, base64. Distinct from HASH_B64 so cross-key tests
 *  catch a swapped argument. */
const TOKENIZE_B64 = Buffer.alloc(32, 1).toString("base64");
const ALT_HASH_B64 = Buffer.alloc(32, 2).toString("base64");

// ── helpers ────────────────────────────────────────────────────────────────

function makeDim(name: string, pii?: PiiMode): Dimension {
  const d: Dimension = {
    name,
    source: { kind: "context", path: `principal.${name}` },
  };
  if (pii) d.pii = pii;
  return d;
}

function makeSchema(dims: Dimension[]): TenantSchema {
  return { version: 1, dimensions: dims };
}

afterEach(() => {
  _resetPiiSecretsForTests();
  _setActiveSchema(null);
  jest.restoreAllMocks();
});

// ── 1. loadPiiSecrets ──────────────────────────────────────────────────────

describe("loadPiiSecrets", () => {
  test("missing env returns nulls silently (no warn)", () => {
    const spy = jest.spyOn(console, "warn").mockImplementation(() => undefined);
    const s = loadPiiSecrets({});
    expect(s.hashSecret).toBeNull();
    expect(s.tokenizeKey).toBeNull();
    expect(s.keyVersion).toBe(1);
    expect(spy).not.toHaveBeenCalled();
  });

  test("empty-string env returns nulls silently", () => {
    const spy = jest.spyOn(console, "warn").mockImplementation(() => undefined);
    const s = loadPiiSecrets({
      LUPID_PII_HASH_SECRET: "",
      LUPID_PII_TOKENIZE_KEY: "",
    });
    expect(s.hashSecret).toBeNull();
    expect(s.tokenizeKey).toBeNull();
    expect(spy).not.toHaveBeenCalled();
  });

  test("correct-length base64 yields 32-byte buffers", () => {
    const s = loadPiiSecrets({
      LUPID_PII_HASH_SECRET: HASH_B64,
      LUPID_PII_TOKENIZE_KEY: TOKENIZE_B64,
    });
    expect(s.hashSecret).not.toBeNull();
    expect(s.hashSecret!.length).toBe(32);
    expect(s.tokenizeKey).not.toBeNull();
    expect(s.tokenizeKey!.length).toBe(32);
  });

  test("wrong-length env returns null and warns once", () => {
    const spy = jest.spyOn(console, "warn").mockImplementation(() => undefined);
    const tooShort = Buffer.alloc(16, 0).toString("base64");
    const s = loadPiiSecrets({ LUPID_PII_HASH_SECRET: tooShort });
    expect(s.hashSecret).toBeNull();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toEqual(
      expect.stringContaining("LUPID_PII_HASH_SECRET"),
    );
    expect(spy.mock.calls[0]?.[0]).toEqual(expect.stringContaining("16 bytes"));
    expect(spy.mock.calls[0]?.[0]).toEqual(
      expect.stringContaining("openssl rand -base64 32"),
    );
  });
});

// ── 2. assertSecretsForActiveSchema ────────────────────────────────────────

describe("assertSecretsForActiveSchema", () => {
  test("throws when schema declares pii: hash but env is unset", () => {
    _setActiveSchema(makeSchema([makeDim("user", "hash")]));
    setPiiSecretsForModule(loadPiiSecrets({}));
    expect(() => assertSecretsForActiveSchema()).toThrow(
      /pii: hash.*dimension 'user'.*LUPID_PII_HASH_SECRET is unset/s,
    );
    // Spec mandates the openssl hint and forbids the lupid-CLI hint.
    try {
      assertSecretsForActiveSchema();
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).toEqual(expect.stringContaining("openssl rand -base64 32"));
      expect(msg).not.toEqual(expect.stringContaining("lupid pii generate-secrets"));
    }
  });

  test("throws when schema declares pii: hash but env is wrong-length", () => {
    jest.spyOn(console, "warn").mockImplementation(() => undefined);
    _setActiveSchema(makeSchema([makeDim("user", "hash")]));
    const tooShort = Buffer.alloc(16, 0).toString("base64");
    setPiiSecretsForModule(loadPiiSecrets({ LUPID_PII_HASH_SECRET: tooShort }));
    expect(() => assertSecretsForActiveSchema()).toThrow(
      /LUPID_PII_HASH_SECRET is unset/,
    );
  });

  test("throws when schema declares pii: tokenize but env is unset", () => {
    _setActiveSchema(makeSchema([makeDim("user", "tokenize")]));
    setPiiSecretsForModule(loadPiiSecrets({}));
    expect(() => assertSecretsForActiveSchema()).toThrow(
      /pii: tokenize.*dimension 'user'.*LUPID_PII_TOKENIZE_KEY is unset/s,
    );
  });

  test("succeeds when secrets match declared modes", () => {
    _setActiveSchema(
      makeSchema([makeDim("user", "hash"), makeDim("session", "tokenize")]),
    );
    setPiiSecretsForModule(
      loadPiiSecrets({
        LUPID_PII_HASH_SECRET: HASH_B64,
        LUPID_PII_TOKENIZE_KEY: TOKENIZE_B64,
      }),
    );
    expect(() => assertSecretsForActiveSchema()).not.toThrow();
  });

  test("succeeds silently when no dim declares hash/tokenize", () => {
    _setActiveSchema(
      makeSchema([makeDim("user"), makeDim("session", "none"), makeDim("kind", "drop")]),
    );
    setPiiSecretsForModule(loadPiiSecrets({}));
    expect(() => assertSecretsForActiveSchema()).not.toThrow();
  });
});

// ── getPiiSecrets unloaded ────────────────────────────────────────────────

describe("getPiiSecrets", () => {
  test("throws when secrets not loaded", () => {
    expect(() => getPiiSecrets()).toThrow(/PII secrets not loaded/);
  });
});

// ── 3. hash ────────────────────────────────────────────────────────────────

describe("hash", () => {
  function loadedSecrets(hashB64 = HASH_B64): PiiSecrets {
    return loadPiiSecrets({ LUPID_PII_HASH_SECRET: hashB64 });
  }

  test("deterministic: same input + same secret → same output", async () => {
    const s = loadedSecrets();
    const a = await hash("alice@acme.com", s);
    const b = await hash("alice@acme.com", s);
    expect(a).toBe(b);
  });

  test("different secret → different output", async () => {
    const a = await hash("alice@acme.com", loadedSecrets(HASH_B64));
    const b = await hash("alice@acme.com", loadedSecrets(ALT_HASH_B64));
    expect(a).not.toBe(b);
  });

  test("format is h: + 64 hex chars (full-width)", async () => {
    const out = await hash("alice@acme.com", loadedSecrets());
    expect(out).toMatch(/^h:[0-9a-f]{64}$/);
  });

  test("throws when hashSecret is null", async () => {
    const empty: PiiSecrets = { hashSecret: null, tokenizeKey: null, keyVersion: 1 };
    await expect(hash("x", empty)).rejects.toThrow(/hashSecret not loaded/);
  });
});

// ── 4. tokenize / reverseTokenize ─────────────────────────────────────────

describe("tokenize / reverseTokenize", () => {
  function loaded(): PiiSecrets {
    return loadPiiSecrets({ LUPID_PII_TOKENIZE_KEY: TOKENIZE_B64 });
  }

  test("round-trip identity", async () => {
    const s = loaded();
    const t = await tokenize("alice@acme.com", s);
    expect(t).toMatch(/^t:/);
    const back = await reverseTokenize(t, s);
    expect(back).toBe("alice@acme.com");
  });

  test("round-trip on empty string", async () => {
    const s = loaded();
    const t = await tokenize("", s);
    const back = await reverseTokenize(t, s);
    expect(back).toBe("");
  });

  test("round-trip on multi-byte utf8", async () => {
    const s = loaded();
    const t = await tokenize("héllo 🌍 üñîçødé", s);
    const back = await reverseTokenize(t, s);
    expect(back).toBe("héllo 🌍 üñîçødé");
  });

  test("nonce randomness: 1000 encryptions of same plaintext → 1000 distinct outputs", async () => {
    const s = loaded();
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      seen.add(await tokenize("same-plaintext", s));
    }
    expect(seen.size).toBe(1000);
  });

  test("tampered tag throws PiiReverseError", async () => {
    const s = loaded();
    const t = await tokenize("alice", s);
    // Flip a bit in the base64url body — recompose so length stays valid.
    const body = t.slice(2);
    const buf = Buffer.from(body, "base64url");
    buf[buf.length - 1] = buf[buf.length - 1]! ^ 0x01;
    const tampered = "t:" + buf.toString("base64url");
    await expect(reverseTokenize(tampered, s)).rejects.toThrow(PiiReverseError);
  });

  test("wrong prefix throws PiiReverseError", async () => {
    const s = loaded();
    await expect(reverseTokenize("h:deadbeef", s)).rejects.toThrow(
      /missing 't:' prefix/,
    );
  });

  test("too-short token throws PiiReverseError", async () => {
    const s = loaded();
    // 4 bytes of body — below the 28-byte (nonce + tag) minimum.
    const tiny = "t:" + Buffer.from([1, 2, 3, 4]).toString("base64url");
    await expect(reverseTokenize(tiny, s)).rejects.toThrow(/too short/);
  });

  test("throws when tokenizeKey is null", async () => {
    const empty: PiiSecrets = { hashSecret: null, tokenizeKey: null, keyVersion: 1 };
    await expect(tokenize("x", empty)).rejects.toThrow(/tokenizeKey not loaded/);
    await expect(reverseTokenize("t:abc", empty)).rejects.toThrow(PiiReverseError);
  });
});

// ── 5. drop ────────────────────────────────────────────────────────────────

describe("drop", () => {
  test("returns <redacted>", () => {
    expect(drop("anything")).toBe(REDACTED_LITERAL);
    expect(REDACTED_LITERAL).toBe("<redacted>");
  });

  test("idempotent", () => {
    expect(drop(drop("anything"))).toBe(REDACTED_LITERAL);
  });
});

// ── 6. applyPii dispatcher ─────────────────────────────────────────────────

describe("applyPii", () => {
  test("none returns input unchanged", async () => {
    expect(await applyPii("alice@acme.com", "none")).toBe("alice@acme.com");
  });

  test("drop returns the literal", async () => {
    expect(await applyPii("alice@acme.com", "drop")).toBe(REDACTED_LITERAL);
  });

  test("hash routes to HMAC and is deterministic", async () => {
    setPiiSecretsForModule(loadPiiSecrets({ LUPID_PII_HASH_SECRET: HASH_B64 }));
    const a = await applyPii("alice@acme.com", "hash");
    const b = await applyPii("alice@acme.com", "hash");
    expect(a).toBe(b);
    expect(a).toMatch(/^h:[0-9a-f]{64}$/);
  });

  test("tokenize routes to GCM and round-trips", async () => {
    setPiiSecretsForModule(
      loadPiiSecrets({ LUPID_PII_TOKENIZE_KEY: TOKENIZE_B64 }),
    );
    const out = await applyPii("alice@acme.com", "tokenize");
    expect(out).toMatch(/^t:/);
  });

  test("hash/tokenize throw when init hasn't loaded secrets", async () => {
    await expect(applyPii("x", "hash")).rejects.toThrow(/PII secrets not loaded/);
    await expect(applyPii("x", "tokenize")).rejects.toThrow(/PII secrets not loaded/);
  });

  test("unknown mode throws (exhaustiveness)", async () => {
    await expect(applyPii("x", "bogus" as PiiMode)).rejects.toThrow(
      /unknown mode 'bogus'/,
    );
  });
});
