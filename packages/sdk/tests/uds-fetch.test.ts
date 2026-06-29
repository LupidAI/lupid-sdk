/**
 * L08 — UDS fetch shim unit tests.
 *
 * The shim is the only file in the SDK that imports `node:http` for PDP
 * traffic. These tests cover:
 *   1. Happy path: shim hits a tmp `node:http.Server` listening on a UDS
 *      socket; body + headers round-trip; `headers.get()` works (proves we
 *      built a real Headers object, not the `as any` foot-gun).
 *   2. Fail-closed when invoked from a context without `process.versions.node`
 *      (simulated edge runtime).
 *   3. ECONNREFUSED is surfaced as a rejected Promise (no socket at the path).
 */

import * as http from "node:http";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { makeUdsFetch } from "../src/evaluation/uds-fetch";

function tmpSocketPath(): string {
  // mkdtemp keeps each test isolated even when the file runs in parallel.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "agentum-uds-test-"));
  return path.join(dir, "pdp.sock");
}

describe("makeUdsFetch", () => {
  test("round-trips body + headers against a tmp UDS http.Server", async () => {
    const socketPath = tmpSocketPath();
    const received: { method: string | undefined; url: string | undefined; body: string } = {
      method: undefined,
      url: undefined,
      body: "",
    };
    const server = http.createServer((req, res) => {
      received.method = req.method;
      received.url = req.url;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.body = Buffer.concat(chunks).toString("utf8");
        res.statusCode = 201;
        res.setHeader("content-type", "application/json");
        res.setHeader("x-custom", "from-server");
        res.end(JSON.stringify({ pong: true, echoed: received.body }));
      });
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));

    try {
      const udsFetch = await makeUdsFetch(socketPath);
      const resp = await udsFetch(
        `unix://${socketPath}/v1/authorize?x=1`,
        {
          method: "POST",
          headers: { "content-type": "application/json", authorization: "Bearer t" },
          body: JSON.stringify({ tool: "search" }),
        },
      );

      // Status + body.
      expect(resp.status).toBe(201);
      const parsed = (await resp.json()) as { pong: boolean; echoed: string };
      expect(parsed.pong).toBe(true);
      expect(parsed.echoed).toBe(JSON.stringify({ tool: "search" }));

      // The Headers object is a real one — `.get()` and `.has()` must work.
      expect(resp.headers.get("content-type")).toBe("application/json");
      expect(resp.headers.get("x-custom")).toBe("from-server");
      expect(resp.headers.has("x-custom")).toBe(true);

      // Server saw the method / path / body we sent.
      expect(received.method).toBe("POST");
      expect(received.url).toBe("/v1/authorize?x=1");
      expect(received.body).toBe(JSON.stringify({ tool: "search" }));
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
      // Best-effort cleanup of the tmp socket file + dir.
      try { fs.unlinkSync(socketPath); } catch { /* socket already gone */ }
      try { fs.rmdirSync(path.dirname(socketPath)); } catch { /* dir not empty */ }
    }
  });

  test("throws fail-closed in a simulated edge runtime (no process.versions.node)", async () => {
    // We can't actually unset `process.versions` without breaking the test
    // runner — instead we delete `versions.node` for the duration of the call.
    const originalNode = process.versions.node;
    // `process.versions` is read-only at the property level on some Node
    // builds; use defineProperty to make it writable for the test.
    Object.defineProperty(process, "versions", {
      value: { ...process.versions, node: undefined as unknown as string },
      configurable: true,
    });
    try {
      await expect(makeUdsFetch("/tmp/whatever.sock")).rejects.toThrow(
        /edge runtimes are not supported/i,
      );
    } finally {
      Object.defineProperty(process, "versions", {
        value: { ...process.versions, node: originalNode },
        configurable: true,
      });
    }
  });

  test("ECONNREFUSED surfaces as a rejected Promise when no socket exists", async () => {
    const socketPath = tmpSocketPath();
    // Intentionally do NOT create a server — the socket file is absent.
    const udsFetch = await makeUdsFetch(socketPath);
    await expect(
      udsFetch(`unix://${socketPath}/v1/health`, { method: "GET" }),
    ).rejects.toThrow();
    // Cleanup the empty tmp dir.
    try { fs.rmdirSync(path.dirname(socketPath)); } catch { /* ignore */ }
  });

  test("rejects URLs that do not start with the configured unix:// prefix", async () => {
    const socketPath = tmpSocketPath();
    const udsFetch = await makeUdsFetch(socketPath);
    await expect(
      udsFetch("https://example.com/v1/authorize", { method: "GET" }),
    ).rejects.toThrow(/unexpected URL/);
    try { fs.rmdirSync(path.dirname(socketPath)); } catch { /* ignore */ }
  });
});
