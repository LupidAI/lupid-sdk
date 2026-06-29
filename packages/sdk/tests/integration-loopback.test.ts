/**
 * Loopback integration tests for the Agentum TypeScript SDK.
 *
 * Each test boots a minimal `http.createServer()` bound to 127.0.0.1:0
 * (ephemeral port) so the real fetch path — including undici TLS,
 * retry, and abort wiring — is exercised end-to-end. No live Agentum
 * instance required.
 *
 * Covered behaviours:
 *
 *  (a) Per-request `X-Tenant-ID` override via `connectExisting({ tenantId })`
 *  (b) Network-error retry — the server closes the socket mid-request
 *      on attempt 1 and responds normally on attempt 2.
 *  (c) 503 retry + backoff honouring `Retry-After`.
 *  (d) Audit buffer 401 → refresh → 200 recovery flow.
 *  (e) `sourceIp` forwarded to `source_ip` in the StartSession body.
 *  (f) `onAuditError` receives a payload with secrets redacted.
 */

import * as http from "http";
import { AddressInfo } from "net";
import { AgentumClient } from "../src/client";
import { AgentumSession } from "../src/session";

// ── Test server helper ───────────────────────────────────────────────────────

interface CapturedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface LoopbackServer {
  url: string;
  requests: CapturedRequest[];
  close: () => Promise<void>;
}

type Handler = (
  req: CapturedRequest,
  raw: http.IncomingMessage,
  res: http.ServerResponse,
) => void | Promise<void>;

function startLoopbackServer(handler: Handler): Promise<LoopbackServer> {
  return new Promise((resolve) => {
    const requests: CapturedRequest[] = [];
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const captured: CapturedRequest = {
          method: req.method ?? "GET",
          url: req.url ?? "/",
          headers: req.headers,
          body: Buffer.concat(chunks).toString("utf-8"),
        };
        requests.push(captured);
        void Promise.resolve(handler(captured, req, res)).catch(() => {
          try {
            res.statusCode = 500;
            res.end();
          } catch {
            // socket already destroyed
          }
        });
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        requests,
        close: () =>
          new Promise<void>((r) => {
            server.closeAllConnections?.();
            server.close(() => r());
          }),
      });
    });
  });
}

/** Convenience: reply with JSON body + status. */
function sendJson(res: http.ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

/** Mint a JWT-shaped string with a future exp so decodeJwtExpiry treats it as valid. */
function makeJwt(exp: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ exp })).toString("base64url");
  return `${header}.${payload}.sig`;
}

const FUTURE_EXP = Math.floor(Date.now() / 1000) + 3600;

// ── (a) Per-request X-Tenant-ID override ─────────────────────────────────────

describe("integration — X-Tenant-ID per-request override", () => {
  it("connectExisting({ tenantId }) forwards X-Tenant-ID on every forked request", async () => {
    const server = await startLoopbackServer((req, _raw, res) => {
      if (req.url.endsWith("/sessions") && req.method === "POST") {
        return sendJson(res, 200, {
          session_id: "sess-tenant",
          agent_id: "ag-1",
          jwt: makeJwt(FUTURE_EXP),
          started_at: "2024-01-01T00:00:00Z",
        });
      }
      if (req.url.includes("/policies/simulate")) {
        return sendJson(res, 200, { outcome: "Allow", rule_id: "r1", reason: null });
      }
      if (/\/sessions\/[^/]+\/end$/.test(req.url)) {
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 404, { error: "nope" });
    });
    try {
      const client = new AgentumClient({ baseUrl: server.url, apiKey: "sk-mgmt", tenantId: "parent-tenant" });
      const session = await client.connectExisting("ag-1", { skipPolicyCheck: true, tenantId: "override-tenant" });
      await session.isAllowed("http.get", "/foo");

      // Management startSession should carry overrideTenant, not parentTenant.
      const start = server.requests.find((r) => r.url.endsWith("/sessions"))!;
      expect(start.headers["x-tenant-id"]).toBe("override-tenant");
      // Session-scoped isAllowed call should carry overrideTenant.
      const sim = server.requests.find((r) => r.url.includes("/policies/simulate"))!;
      expect(sim.headers["x-tenant-id"]).toBe("override-tenant");

      await session.close();
    } finally {
      await server.close();
    }
  });
});

// ── (b) Network-error retry ──────────────────────────────────────────────────

describe("integration — network-error retry", () => {
  it("retries on a mid-request socket close and eventually succeeds", async () => {
    let attempts = 0;
    const server = await startLoopbackServer((_req, raw, res) => {
      attempts += 1;
      if (attempts === 1) {
        // Destroy the socket without responding — emulates ECONNRESET.
        raw.socket.destroy();
        return;
      }
      return sendJson(res, 200, {
        agent_id: "ag-net",
        name: "bot",
        owner_email: "o@e.com",
        owner_team: null,
        purpose: "p",
        framework: "agentum-ts-sdk",
        declared_tools: [],
        data_classes: [],
        trust_level: "low",
        status: "active",
        version: 1,
        public_key_pem: "",
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
        last_active: null,
      });
    });
    try {
      const client = new AgentumClient({
        baseUrl: server.url,
        apiKey: "sk",
        retries: 3,
        retryDelayMs: 5,
      });
      const agent = await client.getAgent("ag-net");
      expect(agent.agent_id).toBe("ag-net");
      expect(attempts).toBeGreaterThanOrEqual(2);
    } finally {
      await server.close();
    }
  });
});

// ── (c) 503 retry + backoff ──────────────────────────────────────────────────

describe("integration — 503 retry + backoff", () => {
  it("honours Retry-After and succeeds on the second attempt", async () => {
    let attempts = 0;
    const server = await startLoopbackServer((_req, _raw, res) => {
      attempts += 1;
      if (attempts === 1) {
        res.setHeader("Retry-After", "0");
        return sendJson(res, 503, { error: "try later" });
      }
      return sendJson(res, 200, {
        agent_id: "ag-503",
        name: "bot",
        owner_email: "o@e.com",
        owner_team: null,
        purpose: "p",
        framework: "agentum-ts-sdk",
        declared_tools: [],
        data_classes: [],
        trust_level: "low",
        status: "active",
        version: 1,
        public_key_pem: "",
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
        last_active: null,
      });
    });
    try {
      const client = new AgentumClient({
        baseUrl: server.url,
        apiKey: "sk",
        retries: 2,
        retryDelayMs: 5,
      });
      const agent = await client.getAgent("ag-503");
      expect(agent.agent_id).toBe("ag-503");
      expect(attempts).toBe(2);
    } finally {
      await server.close();
    }
  });
});

// ── (d) Audit buffer 401 → refresh → 200 recovery ────────────────────────────

describe("integration — audit buffer 401 → refresh → 200", () => {
  it("refreshes the JWT on 401 and redelivers the batch via request-layer refresh", async () => {
    // L05: the audit flusher posts a single batch to /audit/ingest/batch.
    // On 401, the request layer's existing JWT-refresh path refreshes the
    // token and retries (provided `retries >= 1`). When refresh succeeds,
    // the second attempt within the same `request()` call returns 200 and
    // the batch is delivered. (When `retries: 0`, refresh is skipped and
    // the batch is dropped — that's covered by audit-buffer-batch.test.ts.)
    let ingestCalls = 0;
    const server = await startLoopbackServer((req, _raw, res) => {
      if (req.url.endsWith("/audit/ingest/batch")) {
        ingestCalls += 1;
        // First call: expired token → 401. Subsequent calls: 200.
        if (ingestCalls === 1) {
          return sendJson(res, 401, { error: "token expired" });
        }
        return sendJson(res, 200, { ingested: 1 });
      }
      return sendJson(res, 404, { error: "nope" });
    });
    try {
      let refreshCount = 0;
      const client = new AgentumClient({
        baseUrl: server.url,
        token: makeJwt(FUTURE_EXP),
        auditFlushIntervalMs: 50,
        retries: 1, // allow request-layer 401 refresh
        tokenRefreshFn: async () => {
          refreshCount += 1;
          return makeJwt(FUTURE_EXP);
        },
      });

      await client.ingestAuditEvent({
        agent_id: "ag-1",
        session_id: "sess-1",
        event_type: "tool_call",
      });

      // Wait for the flusher to run at least twice: initial → 401, retry-after-refresh → 200.
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && (refreshCount === 0 || ingestCalls < 2)) {
        await new Promise((r) => setTimeout(r, 30));
        await client.flushAuditBuffer();
      }

      expect(refreshCount).toBeGreaterThanOrEqual(1);
      expect(ingestCalls).toBeGreaterThanOrEqual(2);
      expect(client.auditBufferLength()).toBe(0);

      await client.close();
    } finally {
      await server.close();
    }
  });
});

// ── (e) sourceIp forwarded ──────────────────────────────────────────────────

describe("integration — sourceIp forwarded to StartSession", () => {
  it("connect({ sourceIp }) puts source_ip in the request body", async () => {
    const server = await startLoopbackServer((req, _raw, res) => {
      if (req.url.endsWith("/agents") && req.method === "POST") {
        return sendJson(res, 200, {
          agent_id: "ag-sip",
          name: "bot",
          status: "active",
          public_key_pem: "",
          session_jwt: makeJwt(FUTURE_EXP),
        });
      }
      if (req.url.endsWith("/sessions") && req.method === "POST") {
        return sendJson(res, 200, {
          session_id: "sess-sip",
          agent_id: "ag-sip",
          jwt: makeJwt(FUTURE_EXP),
          started_at: "2024-01-01T00:00:00Z",
        });
      }
      if (req.url.includes("/policies/simulate")) {
        return sendJson(res, 200, { outcome: "Allow", rule_id: "r", reason: null });
      }
      if (/\/sessions\/[^/]+\/end$/.test(req.url)) {
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 404, { error: "nope" });
    });
    try {
      const client = new AgentumClient({ baseUrl: server.url, apiKey: "sk" });
      const session = await client.connect({
        name: "bot",
        owner_email: "o@e.com",
        purpose: "p",
        skipPolicyCheck: true,
        sourceIp: "203.0.113.42",
      });
      expect(session).toBeInstanceOf(AgentumSession);

      const start = server.requests.find((r) => r.url.endsWith("/sessions") && r.method === "POST")!;
      const body = JSON.parse(start.body);
      expect(body.source_ip).toBe("203.0.113.42");

      await session.close();
    } finally {
      await server.close();
    }
  });
});

// ── (f) onAuditError receives redacted payload ──────────────────────────────

describe("integration — onAuditError redaction", () => {
  it("redacts Authorization / token / password fields on the error payload", async () => {
    const server = await startLoopbackServer((req, _raw, res) => {
      if (req.url.endsWith("/audit/ingest/batch")) {
        // Server replies with a payload that intentionally contains
        // secret-like keys; the SDK must redact these before passing
        // them to the user-supplied onAuditError.
        return sendJson(res, 500, {
          error: "boom",
          Authorization: "Bearer super-secret-jwt",
          api_key: "sk-oops",
          password: "hunter2",
          safe: "fine",
        });
      }
      return sendJson(res, 404, { error: "nope" });
    });
    try {
      const captured: unknown[] = [];
      const client = new AgentumClient({
        baseUrl: server.url,
        token: makeJwt(FUTURE_EXP),
        auditFlushIntervalMs: 40,
        retries: 0,
        onAuditError: (info) => {
          captured.push(info);
        },
      });

      await client.ingestAuditEvent({
        agent_id: "ag-1",
        session_id: "sess-1",
        event_type: "tool_call",
      });

      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && captured.length === 0) {
        await new Promise((r) => setTimeout(r, 30));
        await client.flushAuditBuffer();
      }

      expect(captured.length).toBeGreaterThan(0);
      const info = captured[0] as { error?: unknown };
      const err = info.error as { body?: Record<string, unknown> } | undefined;
      // The error surfaced to onAuditError is an AgentumError whose body has been redacted.
      expect(err?.body).toBeDefined();
      expect(err!.body!["Authorization"]).toBe("[REDACTED]");
      expect(err!.body!["api_key"]).toBe("[REDACTED]");
      expect(err!.body!["password"]).toBe("[REDACTED]");
      expect(err!.body!["safe"]).toBe("fine");

      await client.close();
    } finally {
      await server.close();
    }
  });
});
