/**
 * H2 regression — `requirePreInitImport` policy modes.
 *
 * `detectPreInitImports` walks the runtime's `require.cache` looking
 * for `node_modules/openai/index.js` or `node_modules/@anthropic-ai/sdk/index.js`.
 * Jest's runtime does not expose `globalThis.require`, so live cache
 * walking is unreliable inside the harness. The init option
 * `_requireCacheForTest` is an internal injection hook that lets the
 * test feed a synthetic cache and exercise each mode deterministically.
 */

import { init, _resetForTests, AgentumInitError } from "../src/index";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> & {
  warnCalls: string[];
} {
  const warnCalls: string[] = [];
  return {
    log: () => {},
    warn: (...args: unknown[]) => {
      warnCalls.push(args.map((a) => String(a)).join(" "));
    },
    error: () => {},
    warnCalls,
  };
}

const ENV_BASE = {
  AGENTUM_BASE_URL: "http://agentum:7071",
  AGENTUM_API_KEY: "ak_test",
  AGENTUM_AGENT_NAME: "h2-test-agent",
};

function mockFetchOk(): jest.Mock {
  return jest.fn().mockImplementation(async (url: string) => {
    // S1-12 (per-agent since PRE-S2-08) — `init()` calls
    // `GET /api/v1/agents/{agent_id}/schema` after `ensureAgent`. These
    // H2 tests don't exercise the schema path, so return a minimal valid
    // live schema envelope.
    if (typeof url === "string" && url.includes("/schema")) {
      const envelope = {
        tenant_id: "t-h2",
        version: 1,
        definition: { version: 1, dimensions: [] },
      };
      return {
        ok: true,
        status: 200,
        json: () => Promise.resolve(envelope),
        text: () => Promise.resolve(JSON.stringify(envelope)),
        headers: { get: () => "application/json" },
      };
    }
    return {
      ok: true,
      status: 200,
      json: () => Promise.resolve({ agent_id: "agent-h2", tenant_id: "t-h2" }),
      text: () => Promise.resolve('{"agent_id":"agent-h2","tenant_id":"t-h2"}'),
      headers: { get: () => "application/json" },
    };
  });
}

/** Synthetic require.cache with a fake openai import baked in. */
function cacheWithFakeOpenAI(): Record<string, unknown> {
  return {
    "/tmp/fake-h2/node_modules/openai/index.js": { id: "openai", exports: {} },
  };
}

/** Synthetic require.cache for both at-risk SDKs. */
function cacheWithBothSdks(): Record<string, unknown> {
  return {
    "/tmp/fake-h2/node_modules/openai/index.js": { id: "openai", exports: {} },
    "/tmp/fake-h2/node_modules/@anthropic-ai/sdk/index.js": {
      id: "anthropic",
      exports: {},
    },
  };
}

describe("init() — H2 requirePreInitImport policy", () => {
  beforeEach(async () => {
    await _resetForTests();
  });

  afterEach(async () => {
    await _resetForTests();
  });

  it("warn mode (default) logs and proceeds when openai is pre-imported", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    const runtime = await init({
      env: ENV_BASE,
      logger: log,
      fetchImpl,
      _requireCacheForTest: cacheWithFakeOpenAI(),
    });
    expect(runtime.agentId).toBe("agent-h2");
    const matched = log.warnCalls.find((m) =>
      m.includes("imported BEFORE agentum.init()"),
    );
    expect(matched).toBeDefined();
    expect(matched).toContain("node_modules/openai");
  });

  it("throw mode rejects init() with AgentumInitError + detected modules", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    let caught: unknown;
    try {
      await init({
        env: ENV_BASE,
        logger: log,
        fetchImpl,
        requirePreInitImport: "throw",
        _requireCacheForTest: cacheWithBothSdks(),
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AgentumInitError);
    const err = caught as AgentumInitError;
    expect(err.detectedModules.length).toBe(2);
    expect(err.detectedModules.some((p) => p.includes("openai"))).toBe(true);
    expect(err.detectedModules.some((p) => p.includes("@anthropic-ai/sdk"))).toBe(true);
    // No warning logged — the throw replaced it.
    // Filter to H2-specific warnings (the SDK also emits an unrelated
    // PDP-token warning during init that is orthogonal to H2).
    const h2Warns = log.warnCalls.filter((m) => m.includes("imported BEFORE"));
    expect(h2Warns.length).toBe(0);
  });

  it("throw mode passes cleanly when no pre-init imports", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    const runtime = await init({
      env: ENV_BASE,
      logger: log,
      fetchImpl,
      requirePreInitImport: "throw",
      _requireCacheForTest: {}, // empty cache → no flags
    });
    expect(runtime.agentId).toBe("agent-h2");
    // Filter to H2-specific warnings (the SDK also emits an unrelated
    // PDP-token warning during init that is orthogonal to H2).
    const h2Warns = log.warnCalls.filter((m) => m.includes("imported BEFORE"));
    expect(h2Warns.length).toBe(0);
  });

  it("ignore mode skips detection entirely (no warn, no throw)", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    const runtime = await init({
      env: ENV_BASE,
      logger: log,
      fetchImpl,
      requirePreInitImport: "ignore",
      _requireCacheForTest: cacheWithBothSdks(),
    });
    expect(runtime.agentId).toBe("agent-h2");
    // Filter to H2-specific warnings (the SDK also emits an unrelated
    // PDP-token warning during init that is orthogonal to H2).
    const h2Warns = log.warnCalls.filter((m) => m.includes("imported BEFORE"));
    expect(h2Warns.length).toBe(0);
  });

  it("throw does not pollute singleton — fixing the issue lets a second init succeed", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    // First call: pre-init imports present → throws.
    await expect(
      init({
        env: ENV_BASE,
        logger: log,
        fetchImpl,
        requirePreInitImport: "throw",
        _requireCacheForTest: cacheWithFakeOpenAI(),
      }),
    ).rejects.toBeInstanceOf(AgentumInitError);
    // Operator fixes their entrypoint — second call has a clean cache.
    const runtime = await init({
      env: ENV_BASE,
      logger: log,
      fetchImpl,
      requirePreInitImport: "throw",
      _requireCacheForTest: {},
    });
    expect(runtime.agentId).toBe("agent-h2");
  });

  it("warn mode is the default (no requirePreInitImport supplied)", async () => {
    const log = silentLogger();
    const fetchImpl = mockFetchOk() as unknown as typeof fetch;
    await init({
      env: ENV_BASE,
      logger: log,
      fetchImpl,
      _requireCacheForTest: cacheWithFakeOpenAI(),
    });
    const h2Warns = log.warnCalls.filter((m) => m.includes("imported BEFORE"));
    expect(h2Warns.length).toBeGreaterThan(0);
  });

  it("detected modules cap at 3 in the message but full list is on the error", async () => {
    const cache: Record<string, unknown> = {};
    for (let i = 0; i < 5; i++) {
      cache[`/tmp/p${i}/node_modules/openai/index.js`] = { id: "x" };
    }
    let caught: AgentumInitError | undefined;
    try {
      await init({
        env: ENV_BASE,
        logger: silentLogger(),
        fetchImpl: mockFetchOk() as unknown as typeof fetch,
        requirePreInitImport: "throw",
        _requireCacheForTest: cache,
      });
    } catch (e) {
      caught = e as AgentumInitError;
    }
    expect(caught).toBeDefined();
    expect(caught!.detectedModules.length).toBe(5);
    expect(caught!.message).toContain("(+2 more)");
  });
});
