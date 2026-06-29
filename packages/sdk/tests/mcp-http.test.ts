/**
 * Unit tests for the shared MCP Streamable-HTTP primitives (GR-19).
 *
 * Covers detection (dual-Accept Tier 1, AGENTUM_MCP_ENDPOINTS Tier 2, kill
 * switch), body parsing (tools/call / initialize / notifications / batch /
 * non-jsonrpc), the deny envelope (exact stdio parity), the bounded session
 * map, and the suppression-token mark/consume + TTL.
 */

import {
  isMcpWireCandidate,
  isOldTransportEndpoint,
  parseMcpBody,
  buildMcpDenyResult,
  buildMcpDenyError,
  mcpEndpointKey,
  mcpActionFor,
  recordMcpServer,
  lookupMcpServer,
  extractServerInfo,
  scanInitializeSse,
  markMcpCallEvaluated,
  consumeMcpCallEvaluated,
  _resetMcpServerMap,
  _resetMcpSuppression,
} from "../src/instrumentation/mcp-http";

const ORIG_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIG_ENV };
  _resetMcpServerMap();
  _resetMcpSuppression();
});

const DUAL_ACCEPT = "application/json, text/event-stream";
const MCP_URL = "https://mcp.example.com/mcp";

describe("isMcpWireCandidate", () => {
  it("hits on a dual-Accept POST", () => {
    expect(isMcpWireCandidate("POST", DUAL_ACCEPT, MCP_URL)).toBe(true);
    expect(isMcpWireCandidate("post", "text/event-stream, application/json", MCP_URL)).toBe(true);
  });

  it("misses on single-Accept POST", () => {
    expect(isMcpWireCandidate("POST", "application/json", MCP_URL)).toBe(false);
    expect(isMcpWireCandidate("POST", "text/event-stream", MCP_URL)).toBe(false);
  });

  it("misses on GET (server→client stream)", () => {
    expect(isMcpWireCandidate("GET", "text/event-stream", MCP_URL)).toBe(false);
    expect(isMcpWireCandidate("GET", DUAL_ACCEPT, MCP_URL)).toBe(false);
  });

  it("Tier-2: hits a registered endpoint POST even without dual Accept", () => {
    process.env["AGENTUM_MCP_ENDPOINTS"] = "https://legacy.example.com/sse,https://other.example/mcp";
    expect(isMcpWireCandidate("POST", "application/json", "https://legacy.example.com/sse/messages")).toBe(true);
    expect(isOldTransportEndpoint("https://legacy.example.com/sse/messages")).toBe(true);
    // Non-POST against a registered endpoint still misses (no request body).
    expect(isMcpWireCandidate("GET", "text/event-stream", "https://legacy.example.com/sse")).toBe(false);
    // Unregistered URL without dual Accept misses.
    expect(isMcpWireCandidate("POST", "application/json", "https://unknown.example/x")).toBe(false);
  });

  it("kill switch: AGENTUM_MCP_HTTP=off disables both tiers", () => {
    process.env["AGENTUM_MCP_HTTP"] = "off";
    process.env["AGENTUM_MCP_ENDPOINTS"] = "https://legacy.example.com/sse";
    expect(isMcpWireCandidate("POST", DUAL_ACCEPT, MCP_URL)).toBe(false);
    expect(isMcpWireCandidate("POST", "application/json", "https://legacy.example.com/sse")).toBe(false);
    process.env["AGENTUM_MCP_HTTP"] = "0";
    expect(isMcpWireCandidate("POST", DUAL_ACCEPT, MCP_URL)).toBe(false);
    process.env["AGENTUM_MCP_HTTP"] = "false";
    expect(isMcpWireCandidate("POST", DUAL_ACCEPT, MCP_URL)).toBe(false);
  });
});

describe("parseMcpBody", () => {
  it("parses a tools/call", () => {
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "search", arguments: { q: "x" } },
    });
    const p = parseMcpBody(body);
    expect(p).toEqual({ kind: "tools/call", id: 7, toolName: "search", args: { q: "x" } });
  });

  it("parses initialize", () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    expect(parseMcpBody(body)).toEqual({ kind: "initialize", id: 1 });
  });

  it("treats a notification (and tools/list) as 'other'", () => {
    expect(parseMcpBody(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }))).toEqual({ kind: "other" });
    expect(parseMcpBody(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }))).toEqual({ kind: "other" });
  });

  it("returns null for non-jsonrpc bodies", () => {
    expect(parseMcpBody(JSON.stringify({ hello: "world" }))).toBeNull();
    expect(parseMcpBody("not json")).toBeNull();
    expect(parseMcpBody(JSON.stringify({ jsonrpc: "1.0", method: "tools/call" }))).toBeNull();
  });

  it("parses a 2025-03-26 batch array of tools/call + other", () => {
    const body = JSON.stringify([
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "a", arguments: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "b", arguments: { k: 1 } } },
      { jsonrpc: "2.0", id: 3, method: "tools/list" },
    ]);
    const p = parseMcpBody(body);
    expect(p?.kind).toBe("batch");
    if (p?.kind === "batch") {
      expect(p.calls).toHaveLength(2);
      expect(p.calls[0]).toEqual({ id: 1, toolName: "a", args: {} });
      expect(p.calls[1]).toEqual({ id: 2, toolName: "b", args: { k: 1 } });
      expect(p.otherIds).toEqual([3]);
    }
  });

  it("a batch with no tools/call collapses to 'other'", () => {
    const body = JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "tools/list" }]);
    expect(parseMcpBody(body)).toEqual({ kind: "other" });
  });
});

describe("buildMcpDenyResult / buildMcpDenyError", () => {
  it("deny result matches the stdio deny literal shape exactly", () => {
    // The stdio patch returns (mcp-stdio-patch.ts:262-270):
    //   { content: [{ type: "text", text: "[agentum] tool call denied by policy: <reason>" }], isError: true }
    // The HTTP deny wraps that same result in the JSON-RPC envelope.
    const out = buildMcpDenyResult(7, "no allow rule");
    expect(out).toEqual({
      jsonrpc: "2.0",
      id: 7,
      result: {
        content: [{ type: "text", text: "[agentum] tool call denied by policy: no allow rule" }],
        isError: true,
      },
    });
  });

  it("deny result falls back to the canonical reason when reason is undefined", () => {
    const out = buildMcpDenyResult(null, undefined);
    expect((out["result"] as { content: Array<{ text: string }> }).content[0]!.text).toBe(
      "[agentum] tool call denied by policy: no matching allow rule",
    );
  });

  it("deny error is a JSON-RPC -32000 protocol error", () => {
    expect(buildMcpDenyError("abc", "blocked")).toEqual({
      jsonrpc: "2.0",
      id: "abc",
      error: { code: -32000, message: "[agentum] tool call denied by policy: blocked" },
    });
  });
});

describe("session/server-name map", () => {
  it("records and looks up server name + session id by endpoint key", () => {
    const key = mcpEndpointKey("https://mcp.example.com/mcp?token=secret");
    expect(key).toBe("https://mcp.example.com/mcp"); // query stripped
    recordMcpServer(key, "filesystem", "sess-1");
    expect(lookupMcpServer(key)).toEqual({ serverName: "filesystem", sessionId: "sess-1" });
    expect(mcpActionFor(key, "read")).toBe("read_mcp_filesystem");
  });

  it("falls back to the bare tool name when the server is unknown", () => {
    expect(mcpActionFor("https://unseen/mcp", "read")).toBe("read");
  });

  it("is bounded with FIFO eviction past the cap", () => {
    // Cap is 128; insert 130 and assert the oldest two are gone.
    for (let i = 0; i < 130; i++) recordMcpServer(`k${i}`, `srv${i}`);
    expect(lookupMcpServer("k0")).toBeUndefined();
    expect(lookupMcpServer("k1")).toBeUndefined();
    expect(lookupMcpServer("k2")).toBeDefined();
    expect(lookupMcpServer("k129")).toBeDefined();
  });
});

describe("extractServerInfo / scanInitializeSse", () => {
  it("extracts result.serverInfo.name", () => {
    expect(extractServerInfo({ result: { serverInfo: { name: "fs" } } })).toBe("fs");
    expect(extractServerInfo({ result: {} })).toBeUndefined();
    expect(extractServerInfo({})).toBeUndefined();
  });

  it("scans an SSE initialize frame for the server name", () => {
    const frame = `event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { serverInfo: { name: "weather" } } })}\n\n`;
    expect(scanInitializeSse(frame)).toBe("weather");
  });

  it("returns undefined on an SSE frame without serverInfo", () => {
    expect(scanInitializeSse("data: {\"jsonrpc\":\"2.0\"}\n\n")).toBeUndefined();
    expect(scanInitializeSse(": comment only\n\n")).toBeUndefined();
  });
});

describe("suppression token", () => {
  it("mark then consume returns true once (consuming deletes)", () => {
    markMcpCallEvaluated("read_mcp_fs", { path: "/x" });
    expect(consumeMcpCallEvaluated("read_mcp_fs", { path: "/x" })).toBe(true);
    expect(consumeMcpCallEvaluated("read_mcp_fs", { path: "/x" })).toBe(false);
  });

  it("consume misses for a different action or args", () => {
    markMcpCallEvaluated("read_mcp_fs", { path: "/x" });
    expect(consumeMcpCallEvaluated("write_mcp_fs", { path: "/x" })).toBe(false);
    expect(consumeMcpCallEvaluated("read_mcp_fs", { path: "/y" })).toBe(false);
  });

  it("expires after the TTL", () => {
    jest.useFakeTimers();
    try {
      markMcpCallEvaluated("read_mcp_fs", undefined);
      jest.advanceTimersByTime(6_000); // > 5s TTL
      expect(consumeMcpCallEvaluated("read_mcp_fs", undefined)).toBe(false);
    } finally {
      jest.useRealTimers();
    }
  });
});
