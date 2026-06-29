/**
 * Unit tests for `resolveAnonymousClientId` (U01b SDK).
 *
 * Covers the resolution ladder:
 *   1. Explicit override always wins.
 *   2. Browser env returns a persisted localStorage value on the second call.
 *   3. Server env (no window, no TTY) returns undefined.
 *   4. Safari private-mode (`setItem` throws) falls back without throwing.
 *
 * The CLI tier is intentionally NOT exercised here — it writes to
 * `~/.config/agentum/anon_id` and the cost of safely sandboxing that path in
 * unit tests outweighs the value. The CLI heuristic is covered by manual
 * smoke-testing on developer machines and by the integration tests that boot
 * the SDK against a real filesystem.
 */

import { resolveAnonymousClientId } from "../src/anonymous-id";

// ── helpers ────────────────────────────────────────────────────────────────

interface FakeLocalStorage {
  getItem: jest.Mock<string | null, [string]>;
  setItem: jest.Mock<void, [string, string]>;
  removeItem: jest.Mock<void, [string]>;
  clear: jest.Mock<void, []>;
}

function makeLocalStorage(initial: Record<string, string> = {}): FakeLocalStorage {
  const store: Record<string, string> = { ...initial };
  return {
    getItem: jest.fn((k: string) => (k in store ? store[k]! : null)),
    setItem: jest.fn((k: string, v: string) => {
      store[k] = v;
    }),
    removeItem: jest.fn((k: string) => {
      delete store[k];
    }),
    clear: jest.fn(() => {
      for (const k of Object.keys(store)) delete store[k];
    }),
  };
}

/** Install a fake `window` global with `localStorage`. Returns a teardown. */
function installFakeBrowser(ls: FakeLocalStorage): () => void {
  const g = globalThis as unknown as { window?: { localStorage: FakeLocalStorage } };
  const prev = g.window;
  g.window = { localStorage: ls };
  return () => {
    if (prev === undefined) delete g.window;
    else g.window = prev;
  };
}

/** Force the CLI heuristic to fail so server-context tests work even on a
 *  developer machine that happens to be running Jest in a TTY. */
function forceServerContext(): () => void {
  const prevIsTTY = process.stdout.isTTY;
  const prevNodeEnv = process.env["NODE_ENV"];
  // Pretend we are a long-running server: no TTY, NODE_ENV=production.
  Object.defineProperty(process.stdout, "isTTY", {
    configurable: true,
    value: false,
  });
  process.env["NODE_ENV"] = "production";
  return () => {
    Object.defineProperty(process.stdout, "isTTY", {
      configurable: true,
      value: prevIsTTY,
    });
    if (prevNodeEnv === undefined) delete process.env["NODE_ENV"];
    else process.env["NODE_ENV"] = prevNodeEnv;
  };
}

// ── tests ──────────────────────────────────────────────────────────────────

describe("resolveAnonymousClientId — resolution ladder", () => {
  test("explicit override always wins, even in browser context", async () => {
    const ls = makeLocalStorage({ agentum_anon_id: "stored-value" });
    const restore = installFakeBrowser(ls);
    try {
      const got = await resolveAnonymousClientId("explicit-override");
      expect(got).toBe("explicit-override");
      // Override path must NOT touch localStorage.
      expect(ls.getItem).not.toHaveBeenCalled();
      expect(ls.setItem).not.toHaveBeenCalled();
    } finally {
      restore();
    }
  });

  test("browser env persists a generated UUID and reuses it on the second call", async () => {
    const ls = makeLocalStorage();
    const restore = installFakeBrowser(ls);
    try {
      const first = await resolveAnonymousClientId();
      expect(typeof first).toBe("string");
      // RFC 4122 v4 UUID shape: 8-4-4-4-12 hex.
      expect(first).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
      // Backend owns the `anon:` prefix; SDK must NOT prefix.
      expect(first?.startsWith("anon:")).toBe(false);
      expect(ls.setItem).toHaveBeenCalledTimes(1);
      expect(ls.setItem).toHaveBeenCalledWith("agentum_anon_id", first);

      const second = await resolveAnonymousClientId();
      expect(second).toBe(first);
      // Second call reads only — no new write.
      expect(ls.setItem).toHaveBeenCalledTimes(1);
    } finally {
      restore();
    }
  });

  test("server env (no window, no TTY) returns undefined", async () => {
    const restore = forceServerContext();
    try {
      const got = await resolveAnonymousClientId();
      expect(got).toBeUndefined();
    } finally {
      restore();
    }
  });

  test("Safari private mode (setItem throws) falls back without throwing", async () => {
    const ls = makeLocalStorage();
    // Override setItem to simulate Safari private mode QuotaExceededError.
    ls.setItem.mockImplementation(() => {
      throw new DOMException("QuotaExceededError", "QuotaExceededError");
    });
    const restore = installFakeBrowser(ls);
    try {
      const got = await resolveAnonymousClientId();
      // Falls back to a per-session in-memory UUID — must be a valid string
      // and must NOT throw.
      expect(typeof got).toBe("string");
      expect(got).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    } finally {
      restore();
    }
  });
});
