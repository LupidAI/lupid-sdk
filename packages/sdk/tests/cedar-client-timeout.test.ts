/**
 * TASK-5 regression: D.abort is not a function post-mortem.
 *
 * Pre-fix: manual `new AbortController()` + `setTimeout(() => ac.abort(), ms)`
 * could crash when consumer minification aliased the controller variable to
 * its signal, leaving `.abort()` undefined on the closed-over reference.
 *
 * Post-fix: `AbortSignal.timeout(ms)` removes the local controller variable
 * and closure entirely, so there is nothing to alias incorrectly.
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

describe("CedarToolCallClient.evaluateToolCall timeout (TASK-5)", () => {
  const OriginalAbortController = globalThis.AbortController;

  afterEach(() => {
    globalThis.AbortController = OriginalAbortController;
  });

  test("does not crash when the controller reference lacks abort()", async () => {
    // Simulate aggressive minification that shadows the controller variable
    // with the signal object (the exact scenario that produced
    // "D.abort is not a function" in production bundles).
    globalThis.AbortController = class BrokenAbortController {
      signal = {
        aborted: false,
        addEventListener: () => {},
        removeEventListener: () => {},
      };
      // Intentionally no abort() method — mimics the minified-signal alias.
    } as unknown as typeof AbortController;

    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      timeoutMs: 10,
      fetchImpl: (async (_url: string | URL, init?: RequestInit) => {
        const signal = init?.signal as AbortSignal | undefined;
        return new Promise((resolve, reject) => {
          // Resolve quickly so the non-timeout path doesn't race,
          // but register abort listener so the test works with the native
          // AbortSignal.timeout() used post-fix.
          const t = setTimeout(() => resolve(new Response('{"decision":"allow"}')), 50);
          signal?.addEventListener("abort", () => {
            clearTimeout(t);
            reject(new DOMException("Aborted", "AbortError"));
          });
        });
      }) as unknown as typeof fetch,
      logger: silentLogger(),
    });

    // Pre-fix: the 10ms timer would fire and call ac.abort() on the broken
    // controller, throwing an uncaught TypeError and causing the promise to
    // hang / the process to crash.
    // Post-fix: AbortSignal.timeout(10) aborts the native signal, the mock
    // fetch rejects, evaluateToolCall catches it and returns fail-closed.
    const result = await client.evaluateToolCall({ toolName: "test-tool" });
    expect(result.decision).toBe("deny");
  });
});
