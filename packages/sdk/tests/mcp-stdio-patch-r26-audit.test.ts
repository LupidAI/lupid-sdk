/**
 * R26 Problem 2 — MCP-stdio audit events reach the real ingest contract.
 *
 * Before R26 the emitter POSTed to `${gateway}/api/v1/audit/events`, which is
 * a GET-only SSE stream server-side; the 405/404 was treated as "permanent"
 * by the bounded-retry helper and swallowed, so every MCP tool-call audit was
 * silently dropped. The event-type string was also dotted (`"mcp.tool_call"`),
 * which lands as `Unknown` in `AuditEventType::from_str` and is invisible to
 * event-type filters.
 *
 * Coverage:
 *   1. Evaluator path (the common `init()` case): an MCP deny routes its audit
 *      through the shared `CedarToolCallClient` ring-buffer path, which POSTs
 *      to `POST /api/v1/audit/ingest` (NOT `/audit/events`) with the
 *      `AuditIngestRequest` shape — `agent_id`, snake_case `event_type`
 *      (`mcp_tool_deny` / `mcp_tool_call`), and replay-prevention freshness
 *      headers (`x-agentum-nonce` + `x-agentum-timestamp`).
 *   2. Raw-fetch fallback (standalone `installMcpStdioPatch` callers that never
 *      ran `init()` → no evaluator thunk): the emit still targets
 *      `/api/v1/audit/ingest` with `agent_id` + freshness headers, and a 4xx
 *      response is treated as permanent — the bounded retry does NOT loop.
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import {
  installMcpStdioPatch,
  uninstallMcpStdioPatch,
} from "../src/instrumentation/mcp-stdio-patch";
import {
  consumeMcpCallEvaluated,
  _resetMcpSuppression,
} from "../src/instrumentation/mcp-http";

// Direct CJS require — Jest runs under CJS so this is fine in tests.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const McpClientMod = require("@modelcontextprotocol/sdk/client/index.js") as {
  Client: { prototype: Record<string, unknown> };
};

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

function headerValue(init: RequestInit | undefined, name: string): string | undefined {
  const h = init?.headers as Record<string, string> | undefined;
  if (!h) return undefined;
  const key = Object.keys(h).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? h[key] : undefined;
}

function makeRoutedFetch(
  routes: Record<string, { status?: number; body?: string }>,
  capture: CapturedCall[],
): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    capture.push({ url: u, init });
    const matchKey = Object.keys(routes).find((k) => u.endsWith(k));
    const outcome = matchKey ? routes[matchKey]! : { status: 200, body: "{}" };
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

const HEALTH_OK = {
  status: 200,
  body: JSON.stringify({ status: "ok", agent_id: "agent-r26", policy_hash: "h1" }),
};
const PDP_DENY = {
  status: 200,
  body: JSON.stringify({
    decision: "deny",
    rule_id: "deny-search",
    reason: "denied by pdp",
    policy_hash: "h1",
  }),
};
const PDP_ALLOW = {
  status: 200,
  body: JSON.stringify({ decision: "allow", policy_hash: "h1" }),
};

interface CallToolResult {
  isError?: boolean;
  content?: Array<{ type: string; text: string }>;
}

function patchedCallTool(): (
  this: { _agentumServerName?: string },
  params: { name: string; arguments?: Record<string, unknown> },
) => Promise<CallToolResult> {
  return McpClientMod.Client.prototype["callTool"] as (
    this: { _agentumServerName?: string },
    params: { name: string; arguments?: Record<string, unknown> },
  ) => Promise<CallToolResult>;
}

describe("mcp-stdio-patch — R26 audit ingest endpoint", () => {
  beforeEach(() => uninstallMcpStdioPatch());
  afterEach(() => uninstallMcpStdioPatch());

  test("evaluator path: MCP deny audits to /api/v1/audit/ingest with agent_id, snake_case event_type, and freshness headers", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_DENY,
        "/api/v1/audit/ingest": { status: 200, body: "{}" },
      },
      captured,
    );
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-r26",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    expect(
      installMcpStdioPatch({
        gateway: "http://api.example",
        apiKey: "k",
        agentId: "agent-r26",
        getEvaluator: () => evaluator,
      }),
    ).toBe(true);

    const result = await patchedCallTool().call(
      { _agentumServerName: "filesystem" },
      { name: "read_file", arguments: { path: "/tmp/x" } },
    );
    expect(result.isError).toBe(true);

    // Drain the ring-buffer audit POSTs. The deny path emits two audit
    // events to /audit/ingest: the evaluator's own `local_pdp_decision`
    // (from `evaluateToolCall`) and the MCP patch's `mcp_tool_deny` (from
    // `emitMcpAudit`). We assert the MCP-specific one.
    await evaluator.flushPendingAudits();

    // NOT the GET-only SSE stream.
    expect(
      captured.find((c) => c.url.endsWith("/api/v1/audit/events")),
    ).toBeUndefined();

    const ingestCalls = captured.filter((c) =>
      c.url.endsWith("/api/v1/audit/ingest"),
    );
    expect(ingestCalls.length).toBeGreaterThan(0);
    const mcpIngest = ingestCalls.find((c) => {
      const b = JSON.parse(String(c.init?.body)) as Record<string, unknown>;
      return b["event_type"] === "mcp_tool_deny";
    });
    expect(mcpIngest).toBeDefined();

    const body = JSON.parse(String(mcpIngest!.init?.body)) as Record<string, unknown>;
    expect(body["agent_id"]).toBe("agent-r26");
    // snake_case variant that AuditEventType::from_str recognises.
    expect(body["event_type"]).toBe("mcp_tool_deny");
    expect(body["outcome"]).toBe("deny");
    expect(body["tool"]).toBe("read_file_mcp_filesystem");

    // Replay-prevention freshness headers present.
    expect(headerValue(mcpIngest!.init, "x-agentum-nonce")).toBeTruthy();
    expect(headerValue(mcpIngest!.init, "x-agentum-timestamp")).toBeTruthy();
  });

  test("evaluator path: MCP allow audits with event_type=mcp_tool_call", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_ALLOW,
        "/api/v1/audit/ingest": { status: 200, body: "{}" },
      },
      captured,
    );
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-r26",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    expect(
      installMcpStdioPatch({
        gateway: "http://api.example",
        apiKey: "k",
        agentId: "agent-r26",
        getEvaluator: () => evaluator,
      }),
    ).toBe(true);

    // `this` carries the original callTool override so the allow path's
    // `originalCallTool.call(...)` resolves without a live transport.
    await patchedCallTool().call(
      {
        _agentumServerName: "filesystem",
      } as unknown as { _agentumServerName?: string },
      { name: "list_dir", arguments: {} },
    ).catch(() => {
      /* allow path calls the original callTool which has no transport in this
         stub — the audit emit already fired before that, which is what we test */
    });

    await evaluator.flushPendingAudits();

    const ingestCalls = captured.filter((c) =>
      c.url.endsWith("/api/v1/audit/ingest"),
    );
    const mcpIngest = ingestCalls.find((c) => {
      const b = JSON.parse(String(c.init?.body)) as Record<string, unknown>;
      return b["event_type"] === "mcp_tool_call";
    });
    expect(mcpIngest).toBeDefined();
    const body = JSON.parse(String(mcpIngest!.init?.body)) as Record<string, unknown>;
    expect(body["event_type"]).toBe("mcp_tool_call");
    expect(body["outcome"]).toBe("allow");
  });

  test("raw-fetch fallback: targets /api/v1/audit/ingest with freshness headers and does NOT retry a 4xx", async () => {
    const captured: CapturedCall[] = [];
    const realFetch = globalThis.fetch;
    // Standalone install (no getEvaluator) → fallback path uses globalThis.fetch
    // for both the central decision and the raw-fetch audit emit.
    const stub = (async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      captured.push({ url: u, init });
      if (u.endsWith("/api/v1/sdk/evaluate-tool-call")) {
        return new Response(
          JSON.stringify({ decision: "deny", reason: "denied by central" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (u.endsWith("/api/v1/audit/ingest")) {
        // 400 = permanent; the bounded retry must treat this as terminal.
        return new Response("bad request", { status: 400 });
      }
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    globalThis.fetch = stub;

    try {
      expect(
        installMcpStdioPatch({
          gateway: "http://api.example",
          apiKey: "k",
          agentId: "agent-r26",
          // no getEvaluator → raw-fetch fallback emit path
        }),
      ).toBe(true);

      const result = await patchedCallTool().call(
        { _agentumServerName: "filesystem" },
        { name: "read_file", arguments: { path: "/tmp/x" } },
      );
      expect(result.isError).toBe(true);

      // Let the fire-and-forget emit + (non-)retry settle. The retry helper
      // backs off 100ms between attempts; 300ms is comfortably past a second
      // attempt had one been (incorrectly) scheduled.
      await new Promise<void>((r) => setTimeout(r, 300));

      const ingestCalls = captured.filter((c) =>
        c.url.endsWith("/api/v1/audit/ingest"),
      );
      // Exactly one — a 4xx is permanent, no retry loop.
      expect(ingestCalls.length).toBe(1);
      // Hit the ingest contract, not the GET-only SSE stream.
      expect(
        captured.find((c) => c.url.endsWith("/api/v1/audit/events")),
      ).toBeUndefined();

      const ingest = ingestCalls[0]!;
      const body = JSON.parse(String(ingest.init?.body)) as Record<string, unknown>;
      expect(body["agent_id"]).toBe("agent-r26");
      expect(body["event_type"]).toBe("mcp_tool_deny");
      expect(headerValue(ingest.init, "x-agentum-nonce")).toBeTruthy();
      expect(headerValue(ingest.init, "x-agentum-timestamp")).toBeTruthy();
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});

describe("mcp-stdio-patch — GR-19 suppression token + transport label", () => {
  beforeEach(() => {
    uninstallMcpStdioPatch();
    _resetMcpSuppression();
  });
  afterEach(() => {
    uninstallMcpStdioPatch();
    _resetMcpSuppression();
  });

  function installAllow(captured: CapturedCall[]): CedarToolCallClient {
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": {
          status: 200,
          body: JSON.stringify({ status: "ok", agent_id: "agent-gr19", policy_hash: "h1" }),
        },
        "/v1/authorize": PDP_ALLOW,
        "/api/v1/audit/ingest": { status: 200, body: "{}" },
      },
      captured,
    );
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-gr19",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });
    expect(
      installMcpStdioPatch({ gateway: "http://api.example", apiKey: "k", agentId: "agent-gr19", getEvaluator: () => evaluator }),
    ).toBe(true);
    return evaluator;
  }

  test("allow path marks the suppression token (wire plane would then skip)", async () => {
    const captured: CapturedCall[] = [];
    installAllow(captured);
    await patchedCallTool().call(
      { _agentumServerName: "filesystem" } as unknown as { _agentumServerName?: string },
      { name: "list_dir", arguments: { p: "/x" } },
    ).catch(() => {
      /* allow calls originalCallTool with no live transport — token is set first */
    });
    // The action is the namespaced form; the wire plane consumes the same key.
    expect(consumeMcpCallEvaluated("list_dir_mcp_filesystem", { p: "/x" })).toBe(true);
    // Consuming once deletes it.
    expect(consumeMcpCallEvaluated("list_dir_mcp_filesystem", { p: "/x" })).toBe(false);
  });

  test("an HTTP-transport client audits transport: \"http\"; stdio default unchanged", async () => {
    const captured: CapturedCall[] = [];
    const evaluator = installAllow(captured);

    // HTTP-transport instance (transport kind sniffed at connect-time).
    await patchedCallTool().call(
      { _agentumServerName: "filesystem", _agentumTransportKind: "http" } as unknown as { _agentumServerName?: string },
      { name: "read_file", arguments: {} },
    ).catch(() => {});
    // Default (no transport kind) → stdio.
    await patchedCallTool().call(
      { _agentumServerName: "filesystem" } as unknown as { _agentumServerName?: string },
      { name: "list_dir", arguments: {} },
    ).catch(() => {});

    await evaluator.flushPendingAudits();

    const mcpCalls = captured
      .filter((c) => c.url.endsWith("/api/v1/audit/ingest"))
      .map((c) => JSON.parse(String(c.init?.body)) as Record<string, unknown>)
      .filter((b) => b["event_type"] === "mcp_tool_call");

    const httpCall = mcpCalls.find((b) => b["tool"] === "read_file_mcp_filesystem");
    const stdioCall = mcpCalls.find((b) => b["tool"] === "list_dir_mcp_filesystem");
    expect((httpCall!["detail"] as Record<string, unknown>)["transport"]).toBe("http");
    expect((stdioCall!["detail"] as Record<string, unknown>)["transport"]).toBe("stdio");
  });
});
