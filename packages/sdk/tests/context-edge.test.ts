/**
 * Edge-runtime smoke tests for `instrumentation/context.ts` — A5.
 *
 * The universal `index.ts` re-exports `getAgentumContext`,
 * `setAgentumDefaults`, and `withAgentumContext`. Before A5, that import
 * graph reached `import { AsyncLocalStorage } from "node:async_hooks"` at
 * module top, crashing module-load on Vercel Edge / Cloudflare Workers.
 *
 * We assert two things:
 *
 *  1. **Static-source invariant.** No top-level `node:*` import remains in
 *     `context.ts`. Re-introducing one would re-break edge bundles, so the
 *     check is grep-level rather than runtime-level.
 *
 *  2. **Runtime semantics on Node.** `withAgentumContext` still installs
 *     ALS lazily and `getAgentumContext` reads it back. This guards the
 *     lazy-init path and replaces what `fetch-interceptor.test.ts:339`
 *     covered indirectly.
 */

import * as fs from "fs";
import * as path from "path";

import {
  getAgentumContext,
  withAgentumContext,
  setAgentumDefaults,
  clearAgentumDefaults,
} from "../src/instrumentation/context";

const SOURCE_PATH = path.resolve(
  __dirname,
  "../src/instrumentation/context.ts",
);

describe("context.ts — edge-load invariant (A5)", () => {
  test("source has no top-level `node:*` import", () => {
    const src = fs.readFileSync(SOURCE_PATH, "utf8");
    expect(src).not.toMatch(/^import .* from ["']node:/m);
  });

  test("module loads cleanly under Node (sanity)", () => {
    expect(typeof getAgentumContext).toBe("function");
    expect(typeof withAgentumContext).toBe("function");
  });
});

describe("context.ts — runtime behavior on Node", () => {
  afterEach(() => {
    clearAgentumDefaults();
  });

  test("withAgentumContext propagates session/user through ALS", () => {
    const captured = withAgentumContext(
      { sessionId: "sess-1", userId: "user-1" },
      () => getAgentumContext(),
    );
    expect(captured.sessionId).toBe("sess-1");
    expect(captured.userId).toBe("user-1");
  });

  test("setAgentumDefaults populates the fallback when ALS is unset", () => {
    setAgentumDefaults({ sessionId: "default-sess" });
    expect(getAgentumContext().sessionId).toBe("default-sess");
  });

  test("ALS overrides the per-process default within a context", () => {
    setAgentumDefaults({ sessionId: "default-sess" });
    const captured = withAgentumContext({ sessionId: "scoped" }, () =>
      getAgentumContext(),
    );
    expect(captured.sessionId).toBe("scoped");
  });
});

// OPEN-23 — no-ALS (edge) runtime: per-request context isolation is INACTIVE.
// We force the no-ALS branch by loading a FRESH module copy (so the lazy
// `_alsResolved` cache is unset) with `process.versions.node` stripped so
// `isNodeRuntime()` returns false and `getStore()` yields undefined.
describe("context.ts — no-ALS (edge) fallback + one-time warning (OPEN-23)", () => {
  /**
   * Load a fresh `context.ts` with the runtime made to look non-Node, run the
   * callback against that isolated module, then restore `process.versions`.
   */
  function withEdgeContextModule(
    cb: (mod: typeof import("../src/instrumentation/context")) => void,
  ): void {
    const realVersions = process.versions;
    // Replace `process.versions` with a copy lacking `node` so isNodeRuntime()
    // is false inside the freshly-loaded module.
    const edgeVersions = { ...realVersions } as Record<string, string>;
    delete edgeVersions["node"];
    Object.defineProperty(process, "versions", {
      value: edgeVersions,
      configurable: true,
    });
    // A prior Node test may have stashed a real ALS on the global store
    // symbol. The fresh module's cached-resolution path reads that global
    // once `_alsResolved` flips, so delete it to keep `getStore()` undefined
    // on every call (true no-ALS runtime behaviour).
    const storeSym = Symbol.for("agentum.context.store");
    const g = globalThis as Record<symbol, unknown>;
    const savedStore = g[storeSym];
    delete g[storeSym];
    try {
      jest.isolateModules(() => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const mod = require("../src/instrumentation/context") as typeof import("../src/instrumentation/context");
        cb(mod);
      });
    } finally {
      Object.defineProperty(process, "versions", {
        value: realVersions,
        configurable: true,
      });
      if (savedStore !== undefined) g[storeSym] = savedStore;
    }
  }

  test("withAgentumContext is a no-op (per-request session is NOT isolated)", () => {
    withEdgeContextModule((mod) => {
      mod.setAgentumDefaults({ sessionId: "global-default" });
      // The per-request sessionId is silently discarded; the global default
      // leaks through — this documents the cross-request bleed behaviour.
      const captured = mod.withAgentumContext({ sessionId: "per-req" }, () =>
        mod.getAgentumContext(),
      );
      expect(captured.sessionId).toBe("global-default");
      expect(captured.sessionId).not.toBe("per-req");
      mod.clearAgentumDefaults();
    });
  });

  test("dimensions from the context wrapper are dropped on edge", () => {
    withEdgeContextModule((mod) => {
      const captured = mod.withAgentumContext(
        { dimensions: { bot_id: "b-1" } },
        () => mod.getAgentumContext(),
      );
      expect(captured.dimensions).toBeUndefined();
    });
  });

  test("emits the no-ALS warning exactly once across multiple calls", () => {
    withEdgeContextModule((mod) => {
      const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
      try {
        mod._resetAlsUnavailableWarnedForTest();
        mod.withAgentumContext({ sessionId: "a" }, () => undefined);
        mod.withAgentumContext({ sessionId: "b" }, () => undefined);
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(String(warnSpy.mock.calls[0]![0])).toContain(
          "AsyncLocalStorage is not available",
        );
      } finally {
        warnSpy.mockRestore();
      }
    });
  });

  test("_resetAlsUnavailableWarnedForTest re-arms the one-time warning", () => {
    withEdgeContextModule((mod) => {
      const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
      try {
        mod._resetAlsUnavailableWarnedForTest();
        mod.withAgentumContext({ sessionId: "a" }, () => undefined);
        expect(warnSpy).toHaveBeenCalledTimes(1);
        mod._resetAlsUnavailableWarnedForTest();
        mod.withAgentumContext({ sessionId: "b" }, () => undefined);
        expect(warnSpy).toHaveBeenCalledTimes(2);
      } finally {
        warnSpy.mockRestore();
      }
    });
  });
});
