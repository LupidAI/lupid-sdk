/**
 * Unit tests for `anonymous_client_id` plumbing in `startSession` (U01b SDK).
 *
 * Covers three paths:
 *   1. Browser context (fake window + localStorage) → body carries a
 *      generated UUID in `anonymous_client_id`.
 *   2. Server context (no window, no TTY) → body omits `anonymous_client_id`.
 *   3. Explicit `anonymousClientId` override → body carries the exact value.
 */

import { AgentumClient } from "../src/index";
import { resolveAnonymousClientId } from "../src/anonymous-id";

const BASE = "http://localhost:7071";

function mockFetch(body: unknown, status = 200): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

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

function installFakeBrowser(ls: FakeLocalStorage): () => void {
  const g = globalThis as unknown as { window?: { localStorage: FakeLocalStorage } };
  const prev = g.window;
  g.window = { localStorage: ls };
  return () => {
    if (prev === undefined) delete g.window;
    else g.window = prev;
  };
}

function forceServerContext(): () => void {
  const prevIsTTY = process.stdout.isTTY;
  const prevNodeEnv = process.env["NODE_ENV"];
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

function installFakeCryptoUUID(): () => void {
  const g = globalThis as unknown as { crypto?: { randomUUID: () => string } };
  const prev = g.crypto;
  g.crypto = {
    randomUUID: () => "ffffffff-ffff-ffff-ffff-ffffffffffff",
  };
  return () => {
    if (prev === undefined) delete (g as { crypto?: unknown }).crypto;
    else g.crypto = prev;
  };
}

describe("startSession — anonymous_client_id plumbing", () => {
  test("browser env injects a generated UUID into the request body", async () => {
    const ls = makeLocalStorage();
    const restoreBrowser = installFakeBrowser(ls);
    const restoreCrypto = installFakeCryptoUUID();

    try {
      const sess = {
        session_id: "s-browser",
        agent_id: "a1",
        jwt: "jwt",
        started_at: "2024-01-01T00:00:00Z",
      };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });

      await c.startSession("a1");

      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.agent_id).toBe("a1");
      expect(body.anonymous_client_id).toBe("ffffffff-ffff-ffff-ffff-ffffffffffff");
      expect(body.user).toBeUndefined();
    } finally {
      restoreBrowser();
      restoreCrypto();
    }
  });

  test("server env omits anonymous_client_id from the request body", async () => {
    const restoreServer = forceServerContext();
    // Ensure no window global is present.
    const g = globalThis as unknown as { window?: unknown };
    const prevWindow = g.window;
    delete g.window;

    try {
      const sess = {
        session_id: "s-server",
        agent_id: "a1",
        jwt: "jwt",
        started_at: "2024-01-01T00:00:00Z",
      };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });

      await c.startSession("a1");

      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.agent_id).toBe("a1");
      expect(body).not.toHaveProperty("anonymous_client_id");
    } finally {
      restoreServer();
      if (prevWindow !== undefined) g.window = prevWindow;
    }
  });

  test("explicit anonymousClientId override is forwarded verbatim", async () => {
    // Override should win even in a server context.
    const restoreServer = forceServerContext();
    const g = globalThis as unknown as { window?: unknown };
    const prevWindow = g.window;
    delete g.window;

    try {
      const sess = {
        session_id: "s-override",
        agent_id: "a1",
        jwt: "jwt",
        started_at: "2024-01-01T00:00:00Z",
      };
      const f = mockFetch(sess);
      const c = new AgentumClient({ baseUrl: BASE, fetch: f as unknown as typeof fetch });

      await c.startSession("a1", undefined, { anonymousClientId: "my-custom-id" });

      const call = f.mock.calls[0] as [string, { body: string }];
      const body = JSON.parse(call[1].body);
      expect(body.agent_id).toBe("a1");
      expect(body.anonymous_client_id).toBe("my-custom-id");
    } finally {
      restoreServer();
      if (prevWindow !== undefined) g.window = prevWindow;
    }
  });
});
