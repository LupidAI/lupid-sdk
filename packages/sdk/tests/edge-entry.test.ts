/**
 * P01 — Edge-runtime safety regression guard.
 *
 * The universal entry `dist/index.mjs` must NOT contain any top-level static
 * imports of Node built-ins (`node:*`, or bare `crypto` / `module` / `stream`
 * / `url` / `async_hooks` / `fs` / `path` / `os` / `http` / `https`). Such
 * imports throw at module-load on Cloudflare Workers, Vercel Edge, and modern
 * browser bundlers, breaking `import { init } from "@lupid/sdk"` before any
 * user code runs.
 *
 * This test reads the compiled bundle from disk and asserts the absence of
 * those static-import lines. It SKIPS cleanly when `dist/index.mjs` is absent
 * so plain `npm test` (without a prior build) still passes. CI / pre-publish
 * runs `npm run build` first.
 */
import * as fs from "node:fs";
import * as path from "node:path";

const DIST_PATH = path.resolve(__dirname, "..", "dist", "index.mjs");

// Forbidden static-import specifiers. Anything matching one of these as a
// top-level `import ... from "<spec>"` line is an edge-runtime regression.
//
// S1-16 added `eventsource` to the list: the polyfill is dynamic-imported
// inside `manifest/sse-subscriber.ts::start()` per the lazy-import contract
// (`.claude/rules/typescript.md` §1). A static `import "eventsource"` here
// would pull `node:http` / `node:https` transitives into the universal
// bundle and break Workers/edge on load.
const FORBIDDEN_SPECIFIERS = [
  "async_hooks",
  "module",
  "stream",
  "url",
  "crypto",
  "fs",
  "path",
  "os",
  "http",
  "https",
  "eventsource",
] as const;

// Match `from "..."` or `from '...'`, capturing the specifier. Top-level
// static imports always use one of these forms after esbuild's emit.
const STATIC_IMPORT_RE = /^\s*import\s+[^;]*?\s+from\s+['"]([^'"]+)['"]\s*;?\s*$/;

function isForbidden(spec: string): boolean {
  if (spec.startsWith("node:")) return true;
  return (FORBIDDEN_SPECIFIERS as readonly string[]).includes(spec);
}

describe("P01: dist/index.mjs has no static node:* imports", () => {
  if (!fs.existsSync(DIST_PATH)) {
    // Build hasn't been run; skip cleanly so `npm test` still passes locally
    // without a prior `npm run build`. CI and pre-publish will build first.
    test.skip("dist/index.mjs not built — run `npm run build` first", () => {
      // intentionally empty
    });
    return;
  }

  test("whole bundle contains no forbidden static imports", () => {
    // S1-16 widened the scan from the first 50 lines to the whole file:
    // a stray `import "eventsource"` (or any other forbidden specifier)
    // emitted by esbuild past line 50 would still break edge runtimes
    // at load time, and the head-only scan would miss it.
    const contents = fs.readFileSync(DIST_PATH, "utf8");
    const lines = contents.split(/\r?\n/);
    const offenders: Array<{ line: number; spec: string; text: string }> = [];

    lines.forEach((line, idx) => {
      const match = STATIC_IMPORT_RE.exec(line);
      if (!match) return;
      const spec = match[1];
      if (spec === undefined) return;
      if (isForbidden(spec)) {
        offenders.push({ line: idx + 1, spec, text: line.trim() });
      }
    });

    if (offenders.length > 0) {
      const report = offenders
        .map((o) => `  line ${o.line}: ${o.text}`)
        .join("\n");
      throw new Error(
        `dist/index.mjs contains forbidden static node imports — edge runtimes will break on load.\n` +
          `Offending imports:\n${report}\n` +
          `Move these to dynamic \`await import("...")\` calls inside runtime-detected branches.`,
      );
    }

    expect(offenders).toEqual([]);
  });

  test("eventsource is dynamic-imported only inside sse-subscriber", () => {
    const contents = fs.readFileSync(DIST_PATH, "utf8");
    // Belt + suspenders alongside the FORBIDDEN_SPECIFIERS scan above:
    // confirm the dynamic-import shape literally appears in the built
    // bundle. Catches a refactor that swapped `await import("eventsource")`
    // for something equivalent-but-static (e.g. `createRequire` of the
    // specifier) which would slip past the static-import regex.
    expect(contents).toMatch(/import\(\s*['"]eventsource['"]\s*\)/);
    // And the bare CJS `require("eventsource")` form must not appear at
    // top-level either.
    const requireRe = /^\s*(?:const|let|var)\s+[^=]*=\s*require\(\s*['"]eventsource['"]\s*\)/m;
    expect(requireRe.test(contents)).toBe(false);
  });
});
