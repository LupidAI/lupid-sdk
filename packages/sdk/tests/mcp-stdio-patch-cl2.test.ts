/**
 * CL-2 — MCP stdio enforcement routes through `CedarToolCallClient`
 * (PDP-first with central fallback), mirroring how LLM tool calls
 * already work.
 *
 * Two contracts:
 *  1. When the patch is installed with a `getEvaluator` thunk that
 *     returns a live `CedarToolCallClient`, an MCP tool call invokes
 *     the evaluator's PDP path (`/v1/health` + `/v1/authorize`) and
 *     NEVER touches central directly.
 *  2. When no evaluator thunk is provided (legacy `installMcpStdioPatch`
 *     callers that never ran `agentum.init()`), the patch falls back to
 *     the direct `POST /api/v1/sdk/evaluate-tool-call` central call —
 *     this preserves the post-A3 default for standalone consumers.
 *
 * We bypass the actual stdio transport by invoking the patched
 * `Client.prototype.callTool` with a stub `this`. The patched function
 * only reaches `originalCallTool` on `allow`; the deny path returns the
 * synthetic `{isError: true}` result without touching the original.
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import {
  installMcpStdioPatch,
  uninstallMcpStdioPatch,
} from "../src/instrumentation/mcp-stdio-patch";

// Direct CJS require — Jest runs under CJS so this is fine in tests.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const McpClientMod = require("@modelcontextprotocol/sdk/client/index.js") as {
  Client: { prototype: Record<string, unknown> };
};

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

function makeRoutedFetch(
  routes: Record<string, { status?: number; body?: string; throwErr?: Error }>,
  capture: CapturedCall[],
): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    capture.push({ url: u, init });
    const matchKey = Object.keys(routes).find((k) => u.endsWith(k));
    if (!matchKey) throw new Error(`unrouted URL in test fetch: ${u}`);
    const outcome = routes[matchKey]!;
    if (outcome.throwErr) throw outcome.throwErr;
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

const HEALTH_OK = {
  status: 200,
  body: JSON.stringify({
    status: "ok",
    agent_id: "agent-cl2",
    policy_hash: "h1",
    synced_at: new Date().toISOString(),
    uptime_secs: 1,
  }),
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

const CENTRAL_DENY = {
  status: 200,
  body: JSON.stringify({
    decision: "deny",
    rule_id: "deny-central",
    reason: "denied by central",
    ttl_ms: 0,
  }),
};

interface DenyResult {
  isError: boolean;
  content: Array<{ type: string; text: string }>;
}

describe("mcp-stdio-patch — CL-2 PDP-first routing", () => {
  beforeEach(() => {
    uninstallMcpStdioPatch();
  });

  afterEach(() => {
    uninstallMcpStdioPatch();
  });

  test("routes MCP tool-call enforcement through PDP when evaluator + PDP configured", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/v1/health": HEALTH_OK,
        "/v1/authorize": PDP_DENY,
      },
      captured,
    );
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-cl2",
      pdpUrl: "http://127.0.0.1:7080",
      pdpServiceToken: "s3cret",
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    const installed = installMcpStdioPatch({
      gateway: "http://api.example",
      apiKey: "k",
      agentId: "agent-cl2",
      getEvaluator: () => evaluator,
    });
    expect(installed).toBe(true);

    // Invoke the patched prototype method with a stub `this`. The deny
    // path never reaches `originalCallTool`, so we don't need a working
    // transport.
    const patchedCallTool = McpClientMod.Client.prototype["callTool"] as (
      this: { _agentumServerName?: string },
      params: { name: string; arguments?: Record<string, unknown> },
    ) => Promise<DenyResult>;

    const result = await patchedCallTool.call(
      { _agentumServerName: "filesystem" },
      { name: "read_file", arguments: { path: "/tmp/x" } },
    );

    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("denied by pdp");

    const urls = captured.map((c) => c.url);
    // PDP routes were hit.
    expect(urls).toContain("http://127.0.0.1:7080/v1/health");
    expect(urls).toContain("http://127.0.0.1:7080/v1/authorize");
    // Central /sdk/evaluate-tool-call was NOT hit — the whole point of CL-2.
    expect(
      urls.find((u) => u.includes("/api/v1/sdk/evaluate-tool-call")),
    ).toBeUndefined();

    // Drain any pending audit POSTs so they don't outlive the test.
    await evaluator.flushPendingAudits();
  });

  test("with evaluator and no PDP configured, deny routes through central (post-A3 default)", async () => {
    const captured: CapturedCall[] = [];
    const fetchImpl = makeRoutedFetch(
      {
        "/api/v1/sdk/evaluate-tool-call": CENTRAL_DENY,
      },
      captured,
    );
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-cl2",
      // No pdpUrl → CedarToolCallClient skips PDP and goes straight to central.
      fetchImpl,
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    const installed = installMcpStdioPatch({
      gateway: "http://api.example",
      apiKey: "k",
      agentId: "agent-cl2",
      getEvaluator: () => evaluator,
    });
    expect(installed).toBe(true);

    const patchedCallTool = McpClientMod.Client.prototype["callTool"] as (
      this: { _agentumServerName?: string },
      params: { name: string; arguments?: Record<string, unknown> },
    ) => Promise<DenyResult>;

    const result = await patchedCallTool.call(
      { _agentumServerName: "filesystem" },
      { name: "read_file" },
    );

    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toContain("denied by central");

    const urls = captured.map((c) => c.url);
    const centralCalls = urls.filter((u) =>
      u.includes("/api/v1/sdk/evaluate-tool-call"),
    ).length;
    expect(centralCalls).toBe(1);
    // No PDP traffic at all.
    expect(urls.find((u) => u.endsWith("/v1/health"))).toBeUndefined();
    expect(urls.find((u) => u.endsWith("/v1/authorize"))).toBeUndefined();

    await evaluator.flushPendingAudits();
  });

  test("idempotency guard preserved — Symbol.for-equivalent _agentumPatched is not re-wrapped", () => {
    const evaluator = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-cl2",
      logger: { log: () => {}, warn: () => {}, error: () => {} },
    });

    expect(
      installMcpStdioPatch({
        gateway: "http://api.example",
        apiKey: "k",
        agentId: "agent-cl2",
        getEvaluator: () => evaluator,
      }),
    ).toBe(true);

    const firstCallTool = McpClientMod.Client.prototype["callTool"];

    // Re-install: must not double-wrap.
    expect(
      installMcpStdioPatch({
        gateway: "http://api.example",
        apiKey: "k",
        agentId: "agent-cl2",
        getEvaluator: () => evaluator,
      }),
    ).toBe(true);

    const secondCallTool = McpClientMod.Client.prototype["callTool"];
    expect(secondCallTool).toBe(firstCallTool);
  });
});
