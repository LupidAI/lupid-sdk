/**
 * Y03 Sub-B — unit tests for `compileFieldRuleTrie` + `applyTrie`.
 *
 * Coverage matrix:
 *   - JSONPath subset: exact `$.foo.bar`, wildcard segment (`.*`),
 *     bracket key (`["foo"]`), recursive descent (`..`), array index
 *     (`[N]`), array wildcard (`[*]`).
 *   - Reject out-of-subset syntax at compile time: slices, filters,
 *     unions, negative indices, bare `$`.
 *   - Modes: drop (removes terminal key, replaces nested), hash, tokenize,
 *     mask.
 *   - Tool semantics: tool-specific rule only fires for matching tool;
 *     `tool: "*"` fires for every tool; both buckets unioned when both
 *     match.
 *   - Immutability: input value is never mutated; structural sharing
 *     where no subtree changed.
 *
 * `hash` / `tokenize` paths construct real secrets and exercise the
 * `node:crypto` lazy-import; no mocks. The output format is asserted
 * loosely (`h:<64 hex>` / `t:<base64url>`) so the test stays robust to
 * the underlying primitive's exact encoding.
 */

import {
  compileFieldRuleTrie,
  applyTrie,
  FieldRuleCompileError,
  MASK_LITERAL,
} from "../../src/pii/field-rule-trie";
import {
  setPiiSecretsForModule,
  _resetPiiSecretsForTests,
} from "../../src/pii/secrets";
import type { PiiFieldRule } from "../../src/types";

function makeRule(
  tool: string,
  path: string,
  mode: PiiFieldRule["mode"],
): PiiFieldRule {
  return { tool, path, mode };
}

beforeEach(() => {
  // Load real 32-byte secrets so the hash / tokenize modes can run end
  // to end. The secret material is constant across tests so hash output
  // for the same input is stable inside one run.
  setPiiSecretsForModule({
    hashSecret: Buffer.alloc(32, 0x11),
    tokenizeKey: Buffer.alloc(32, 0x22),
    keyVersion: 1,
  });
});

afterEach(() => {
  _resetPiiSecretsForTests();
});

describe("compileFieldRuleTrie — accepts subset", () => {
  test("empty input → empty trie, short-circuits", async () => {
    const trie = compileFieldRuleTrie([]);
    expect(trie.empty).toBe(true);
    const input = { a: 1 };
    const out = await applyTrie(input, trie, "search");
    expect(out).toBe(input);
  });

  test.each([
    ["$.args.email"],
    ["$.args.*"],
    ["$..email"],
    ['$.args["email"]'],
    ["$.args['email']"],
    ["$.tools[0].args.email"],
    ["$.tools[*].args.email"],
  ])("compiles supported syntax: %s", (path) => {
    expect(() =>
      compileFieldRuleTrie([makeRule("t", path, "mask")]),
    ).not.toThrow();
  });
});

describe("compileFieldRuleTrie — rejects out-of-subset syntax", () => {
  test.each([
    ["$.foo[1:5]", /slices/],
    ["$.foo[?(@.bar)]", /filter/],
    ['$.foo["a","b"]', /union/],
    ["$.foo[-1]", /unrecognised bracket/],
    ["$", /matches the entire value/],
    ["$.", /trailing "\."/],
    ["$..", /trailing ".."/],
    ["$.foo[", /unbalanced/],
  ])("rejects %s", (path, pattern) => {
    expect(() =>
      compileFieldRuleTrie([makeRule("t", path, "mask")]),
    ).toThrow(FieldRuleCompileError);
    expect(() =>
      compileFieldRuleTrie([makeRule("t", path, "mask")]),
    ).toThrow(pattern);
  });

  test("rejects when first character is not `$`", () => {
    expect(() =>
      compileFieldRuleTrie([makeRule("t", "args.email", "mask")]),
    ).toThrow(/must start with "\$"/);
  });
});

describe("applyTrie — JSONPath segment kinds", () => {
  test("exact path masks the matched leaf", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const out = await applyTrie(
      { args: { email: "alice@example.com", q: "find" } },
      trie,
      "search",
    );
    expect(out).toEqual({
      args: { email: MASK_LITERAL, q: "find" },
    });
  });

  test("wildcard segment masks every child", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.*", "mask"),
    ]);
    const out = await applyTrie(
      { args: { email: "a@b.c", phone: "+1", note: "x" } },
      trie,
      "search",
    );
    expect(out).toEqual({
      args: { email: MASK_LITERAL, phone: MASK_LITERAL, note: MASK_LITERAL },
    });
  });

  test("recursive descent finds matches at any depth", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$..email", "mask"),
    ]);
    const out = await applyTrie(
      {
        email: "top@e",
        args: {
          email: "mid@e",
          user: { email: "deep@e", phone: "+1" },
        },
        other: "x",
      },
      trie,
      "search",
    );
    expect(out).toEqual({
      email: MASK_LITERAL,
      args: {
        email: MASK_LITERAL,
        user: { email: MASK_LITERAL, phone: "+1" },
      },
      other: "x",
    });
  });

  test("array index targets a specific element", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.tools[1].name", "mask"),
    ]);
    const out = await applyTrie(
      { tools: [{ name: "a" }, { name: "b" }, { name: "c" }] },
      trie,
      "search",
    );
    expect(out).toEqual({
      tools: [{ name: "a" }, { name: MASK_LITERAL }, { name: "c" }],
    });
  });

  test("array wildcard targets every element", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.tools[*].name", "mask"),
    ]);
    const out = await applyTrie(
      { tools: [{ name: "a" }, { name: "b" }] },
      trie,
      "search",
    );
    expect(out).toEqual({
      tools: [{ name: MASK_LITERAL }, { name: MASK_LITERAL }],
    });
  });

  test("bracket-quoted key is equivalent to dot key", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", '$.args["email"]', "mask"),
    ]);
    const out = await applyTrie(
      { args: { email: "a@b.c" } },
      trie,
      "search",
    );
    expect(out).toEqual({ args: { email: MASK_LITERAL } });
  });

  test("missing key on input is a no-op", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const input = { args: { q: "find" } };
    const out = await applyTrie(input, trie, "search");
    expect(out).toBe(input);
  });

  test("array index past end is a no-op", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.tools[7].name", "mask"),
    ]);
    const input = { tools: [{ name: "a" }] };
    const out = await applyTrie(input, trie, "search");
    expect(out).toBe(input);
  });
});

describe("applyTrie — tool wildcard semantics", () => {
  test("tool-specific rule does not fire on other tools", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const input = { args: { email: "a@b.c" } };
    const out = await applyTrie(input, trie, "replace");
    expect(out).toBe(input);
  });

  test('tool: "*" applies to every tool', async () => {
    const trie = compileFieldRuleTrie([
      makeRule("*", "$.args.email", "mask"),
    ]);
    const out1 = await applyTrie(
      { args: { email: "a@b.c" } },
      trie,
      "search",
    );
    const out2 = await applyTrie(
      { args: { email: "a@b.c" } },
      trie,
      "replace",
    );
    expect(out1).toEqual({ args: { email: MASK_LITERAL } });
    expect(out2).toEqual({ args: { email: MASK_LITERAL } });
  });

  test("wildcard + tool-specific union both rules (wildcard first)", async () => {
    // Wildcard hashes; tool-specific drops afterwards. The terminal-key
    // drop removes the key entirely, so the final shape has no `email`
    // even though the wildcard ran first.
    const trie = compileFieldRuleTrie([
      makeRule("*", "$.args.email", "hash"),
      makeRule("search", "$.args.email", "drop"),
    ]);
    const out = (await applyTrie(
      { args: { email: "a@b.c", q: "find" } },
      trie,
      "search",
    )) as { args: Record<string, unknown> };
    expect(out.args.email).toBeUndefined();
    expect("email" in out.args).toBe(false);
    expect(out.args.q).toBe("find");
  });
});

describe("applyTrie — modes", () => {
  test('mode: "drop" removes terminal key entirely', async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "drop"),
    ]);
    const out = (await applyTrie(
      { args: { email: "a@b.c", q: "find" } },
      trie,
      "search",
    )) as { args: Record<string, unknown> };
    expect("email" in out.args).toBe(false);
    expect(out.args.q).toBe("find");
  });

  test('mode: "mask" replaces with the mask literal', async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const out = await applyTrie(
      { args: { email: "a@b.c" } },
      trie,
      "search",
    );
    expect(out).toEqual({ args: { email: MASK_LITERAL } });
  });

  test('mode: "hash" produces h:<64 hex>', async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "hash"),
    ]);
    const out = (await applyTrie(
      { args: { email: "alice@example.com" } },
      trie,
      "search",
    )) as { args: { email: string } };
    expect(out.args.email).toMatch(/^h:[0-9a-f]{64}$/);
  });

  test('mode: "tokenize" produces t:<base64url> that round-trips', async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "tokenize"),
    ]);
    const out = (await applyTrie(
      { args: { email: "alice@example.com" } },
      trie,
      "search",
    )) as { args: { email: string } };
    expect(out.args.email).toMatch(/^t:[A-Za-z0-9_-]+$/);

    // Round-trip through the corresponding reverse primitive — the
    // wider PII module re-exports `reverseTokenize` for the CLI.
    const { reverseTokenize } = await import("../../src/pii/modes/tokenize");
    const { getPiiSecrets } = await import("../../src/pii/secrets");
    const recovered = await reverseTokenize(out.args.email, getPiiSecrets());
    expect(recovered).toBe("alice@example.com");
  });

  test("recursive-descent + drop replaces matched values with sentinel", async () => {
    // `..email` over an object that has `email` at every depth. The
    // terminal-key drop logic removes the key when the match site is
    // reached via a key segment.
    const trie = compileFieldRuleTrie([
      makeRule("search", "$..email", "drop"),
    ]);
    const out = (await applyTrie(
      {
        email: "top@e",
        user: { email: "deep@e", phone: "+1" },
      },
      trie,
      "search",
    )) as Record<string, unknown>;
    expect("email" in out).toBe(false);
    expect("email" in (out["user"] as object)).toBe(false);
    expect((out["user"] as { phone: string }).phone).toBe("+1");
  });
});

describe("applyTrie — immutability + structural sharing", () => {
  test("does not mutate the input value", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const input = { args: { email: "a@b.c", q: "find" } };
    const snapshot = JSON.parse(JSON.stringify(input)) as typeof input;
    await applyTrie(input, trie, "search");
    expect(input).toEqual(snapshot);
  });

  test("returns the same reference when no rule applies", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const input = { args: { q: "find" } };
    expect(await applyTrie(input, trie, "search")).toBe(input);
    expect(await applyTrie(input, trie, "replace")).toBe(input);
  });

  test("unrelated branches share references with the input", async () => {
    const trie = compileFieldRuleTrie([
      makeRule("search", "$.args.email", "mask"),
    ]);
    const sibling = { large: "object", with: { nested: "data" } };
    const input = {
      args: { email: "a@b.c" },
      sibling,
    };
    const out = (await applyTrie(input, trie, "search")) as typeof input;
    expect(out.sibling).toBe(sibling);
  });
});
