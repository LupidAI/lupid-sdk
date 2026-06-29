/**
 * [HITL-7] args_hash cross-tree parity (SDK ↔ Rust) — ship-blocker for HITL-6.
 *
 * The HITL grant cache is keyed by `(agentId, toolName, args_hash)`. The SDK
 * computes `args_hash` via `hashArgsCanonical` (cedar-client.ts) and the PDP /
 * NestJS escalation computes it via `agentum-pdp/src/hitl.rs::hash_args`. If the
 * two canonicalisers disagree on JSON key order, unicode escaping, or number
 * formatting, an operator approval is recorded under one hash but the next tool
 * call hashes to a different one → the grant silently never matches and HITL
 * "approves" but re-denies forever.
 *
 * This suite pins the SDK output to the Rust authority. Rust is the grant-cache
 * authority; if these assertions fail, fix `hashArgsCanonical` to match Rust —
 * do NOT loosen the assertions.
 *
 *   - PINNED cross-tree digests: copied byte-for-byte from the Rust pinned
 *     vectors in `crates/agentum-pdp/src/hitl.rs`
 *     (`hash_args_matches_pinned_cross_tree_digests`): DIGEST_CMD_LS, DIGEST_NULL.
 *     These are the authoritative Rust-produced SHA-256 hex; the SDK MUST match.
 *   - CANONICAL-STRING parity: for the broader fixtures (nested objects, arrays,
 *     unicode, null/absent, control chars) we assert the exact canonical string
 *     the SDK feeds into SHA-256. That string is byte-identical to what Rust's
 *     `canonical_json(v).to_string()` (serde_json compact serializer) emits:
 *     recursive code-point-sorted keys, compact (no whitespace), raw UTF-8 (no
 *     `\u` escaping of non-ASCII), serde_json control-char escapes. Equal
 *     canonical string + same SHA-256 ⇒ equal hash on both planes.
 *   - KEY-REORDER IDENTITY: re-ordering object keys (at any depth) MUST yield an
 *     identical hash. This is the property whose absence causes the silent
 *     grant-miss bug.
 */
import {
  canonicalJsonStringify,
  hashArgsCanonical,
} from "../src/evaluation/cedar-client";

describe("[HITL-7] args_hash cross-tree parity (SDK ↔ Rust PDP)", () => {
  describe("pinned Rust digests (authoritative — copied from hitl.rs)", () => {
    // crates/agentum-pdp/src/hitl.rs::DIGEST_CMD_LS
    const DIGEST_CMD_LS =
      "a908494c958996ec8cebfa2e10728536e84904384b2497a4fbba9f48d99215ba";
    // crates/agentum-pdp/src/hitl.rs::DIGEST_NULL
    const DIGEST_NULL =
      "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b";

    test('hash_args(json!({"cmd":"ls"})) == DIGEST_CMD_LS', async () => {
      expect(canonicalJsonStringify({ cmd: "ls" })).toBe('{"cmd":"ls"}');
      await expect(hashArgsCanonical({ cmd: "ls" })).resolves.toBe(DIGEST_CMD_LS);
    });

    test("hash_args(Value::Null) == DIGEST_NULL (and absent/undefined agrees)", async () => {
      // Rust hash_args(&Value::Null); the SDK maps both `null` and absent
      // args (`undefined`) onto the same JSON `null` so grants recorded with
      // no args match calls made with no args.
      expect(canonicalJsonStringify(null)).toBe("null");
      expect(canonicalJsonStringify(undefined)).toBe("null");
      await expect(hashArgsCanonical(null)).resolves.toBe(DIGEST_NULL);
      await expect(hashArgsCanonical(undefined)).resolves.toBe(DIGEST_NULL);
    });

    test("null and empty-object hash differently (hitl.rs null_vs_empty_object_differ)", async () => {
      // serde_json: "null" vs "{}" — distinct canonical strings, distinct hash.
      const nullHash = await hashArgsCanonical(null);
      const emptyHash = await hashArgsCanonical({});
      expect(canonicalJsonStringify({})).toBe("{}");
      expect(nullHash).not.toBe(emptyHash);
    });
  });

  describe("canonical-string parity vs serde_json compact (key-sorted, raw UTF-8)", () => {
    test("nested objects: keys sorted recursively, arrays preserved", () => {
      // serde_json canonical_json + to_string: '{"a":1,"b":[2,3],"c":{"a":null,"z":true}}'
      expect(
        canonicalJsonStringify({ a: 1, b: [2, 3], c: { z: true, a: null } }),
      ).toBe('{"a":1,"b":[2,3],"c":{"a":null,"z":true}}');
    });

    test("top-level array: order preserved, nested object keys sorted", () => {
      expect(canonicalJsonStringify([3, 1, 2, { y: 1, x: 2 }])).toBe(
        '[3,1,2,{"x":2,"y":1}]',
      );
    });

    test("unicode: raw UTF-8 (no \\u escaping), code-point key sort", () => {
      // serde_json emits non-ASCII raw, not \uXXXX. Key 'emoji_🔑' sorts
      // before 'greeting' because 'e'(0x65) < 'g'(0x67) — code-point order
      // == Rust byte-wise String::cmp.
      expect(
        canonicalJsonStringify({
          greeting: "héllo 世界 🚀",
          "emoji_🔑": "v",
        }),
      ).toBe('{"emoji_🔑":"v","greeting":"héllo 世界 🚀"}');
    });

    test("control chars: serde_json escapes (\\n \\t \\u0001)", () => {
      // serde_json escapes C0 control chars as \uXXXX (lowercase hex), and
      // \n / \t with short forms — identical to JSON.stringify.
      expect(canonicalJsonStringify({ k: "line1\nline2\ttabctrl" })).toBe(
        '{"k":"line1\\nline2\\ttab\\u0001ctrl"}',
      );
    });

    test("integer-like keys sort byte-wise, not numerically", () => {
      // "10" < "2" byte-wise (0x31 vs 0x32). A naive JS Object.keys()
      // iteration / numeric sort would emit '{"2":2,"10":1}'.
      expect(canonicalJsonStringify({ "10": 1, "2": 2 })).toBe(
        '{"10":1,"2":2}',
      );
    });

    test("absent (undefined) values are dropped, like JSON.stringify / serde", () => {
      // The PDP never receives `undefined`; the SDK drops undefined-valued
      // keys so the canonical form matches the wire form sent to the PDP.
      expect(canonicalJsonStringify({ a: 1, b: undefined, c: 3 })).toBe(
        '{"a":1,"c":3}',
      );
    });
  });

  describe("key-reorder identity (the silent grant-miss tripwire)", () => {
    test("top-level key reorder → identical hash", async () => {
      const a = await hashArgsCanonical({ a: 1, b: [2, 3] });
      const b = await hashArgsCanonical({ b: [2, 3], a: 1 });
      expect(a).toBe(b);
    });

    test("nested key reorder (any depth) → identical hash", async () => {
      const forward = await hashArgsCanonical({
        a: 1,
        b: [2, 3],
        c: { z: true, a: null },
      });
      const reordered = await hashArgsCanonical({
        c: { a: null, z: true },
        b: [2, 3],
        a: 1,
      });
      expect(forward).toBe(reordered);
    });

    test("unicode key reorder → identical hash", async () => {
      const forward = await hashArgsCanonical({
        greeting: "héllo 世界 🚀",
        "emoji_🔑": "v",
      });
      const reordered = await hashArgsCanonical({
        "emoji_🔑": "v",
        greeting: "héllo 世界 🚀",
      });
      expect(forward).toBe(reordered);
    });

    test("array order is NOT canonicalised (arrays are ordered) → different hash", async () => {
      // Sanity: canonicalisation sorts object keys but MUST preserve array
      // order (matches Rust canonical_json: arrays map in place). [1,2] and
      // [2,1] are semantically different calls and must hash differently.
      const ab = await hashArgsCanonical({ items: [1, 2] });
      const ba = await hashArgsCanonical({ items: [2, 1] });
      expect(ab).not.toBe(ba);
    });
  });
});
