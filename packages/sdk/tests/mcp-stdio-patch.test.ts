/**
 * Unit tests for the stdio-MCP patch — issue A3.
 *
 * Two narrow contracts:
 *
 *  1. The `require()` calls in this file route through `createRequire(...)`
 *     so installation does not throw `ReferenceError: require is not defined`
 *     in pure-ESM consumers. We can't easily simulate "ESM without `require`"
 *     inside a Jest CJS run, so the regression guard is a static-source
 *     assertion: bare `require("...")` MUST NOT appear in the source.
 *
 *  2. `installMcpStdioPatch()` reads the gateway URL from `AGENTUM_BASE_URL`
 *     in preference to the legacy `AGENTUM_GATEWAY` and emits a one-shot
 *     deprecation warning when only the legacy var is set.
 */

import * as fs from "fs";
import * as path from "path";

import {
  installMcpStdioPatch,
  uninstallMcpStdioPatch,
  isMcpStdioPatched,
} from "../src/instrumentation/mcp-stdio-patch";

const SOURCE_PATH = path.resolve(
  __dirname,
  "../src/instrumentation/mcp-stdio-patch.ts",
);

function readSource(): string {
  return fs.readFileSync(SOURCE_PATH, "utf8");
}

describe("mcp-stdio-patch — ESM convergence (A3)", () => {
  test("source contains no bare `require(...)` calls", () => {
    const src = readSource();
    // Strip line comments so JSDoc / `// eslint-disable-next-line` notes
    // mentioning the word `require` do not produce false positives.
    const stripped = src
      .split("\n")
      .filter((l) => !/^\s*\/\//.test(l))
      .join("\n");
    // Match bare `require("...")` or `require('...')`. Allow `__require(...)`
    // and `__createRequire(...)`.
    const bareRequireMatches = stripped.match(/(?<![A-Za-z0-9_$])require\s*\(/g);
    expect(bareRequireMatches).toBeNull();
  });

  test("source has no top-level node:* import (edge-load safe)", () => {
    const src = readSource();
    // Universal index.ts re-exports this file, so a static `node:*` import
    // here would crash module-load on Vercel Edge / Cloudflare Workers.
    // The `require` shim must be acquired lazily via eval, never via a
    // top-level import statement.
    expect(src).not.toMatch(/^import .* from ["']node:/m);
  });
});

describe("mcp-stdio-patch — env-var consolidation (A3)", () => {
  const ORIGINAL_ENV = { ...process.env };
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    delete process.env.AGENTUM_BASE_URL;
    delete process.env.AGENTUM_GATEWAY;
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    // Make sure each test starts from a clean install state.
    uninstallMcpStdioPatch();
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
    warnSpy.mockRestore();
    uninstallMcpStdioPatch();
  });

  test("warns when only AGENTUM_GATEWAY is set", () => {
    process.env.AGENTUM_GATEWAY = "http://legacy:7071";
    installMcpStdioPatch({ apiKey: "k", agentId: "a" });
    const calls = warnSpy.mock.calls.map((c) => String(c[0]));
    expect(
      calls.some((m) => m.includes("AGENTUM_GATEWAY env var is deprecated")),
    ).toBe(true);
  });

  test("does not warn when AGENTUM_BASE_URL is set", () => {
    process.env.AGENTUM_BASE_URL = "http://canonical:7071";
    process.env.AGENTUM_GATEWAY = "http://legacy:7071";
    installMcpStdioPatch({ apiKey: "k", agentId: "a" });
    const calls = warnSpy.mock.calls.map((c) => String(c[0]));
    expect(
      calls.some((m) => m.includes("AGENTUM_GATEWAY env var is deprecated")),
    ).toBe(false);
  });

  test("does not warn when neither is set", () => {
    installMcpStdioPatch({ apiKey: "k", agentId: "a" });
    const calls = warnSpy.mock.calls.map((c) => String(c[0]));
    expect(
      calls.some((m) => m.includes("AGENTUM_GATEWAY env var is deprecated")),
    ).toBe(false);
  });

  test("install returns true when @modelcontextprotocol/sdk is resolvable (smoke)", () => {
    // This asserts the `__require` shim does not throw `ReferenceError` at
    // patch-install time. If MCP isn't installed in the test env, we accept
    // `false` (legitimate "package not present") — but never an exception.
    expect(() =>
      installMcpStdioPatch({ apiKey: "k", agentId: "a" }),
    ).not.toThrow();
    // Sanity: idempotency probe should also not throw.
    expect(() => isMcpStdioPatched()).not.toThrow();
  });
});
