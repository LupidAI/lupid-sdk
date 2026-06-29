/**
 * H4 regression: structured deny codes surface through CedarToolCallClient.
 *
 * The server's `/sdk/evaluate-tool-call` response carries a `deny_code`
 * field for every deny outcome (`deny_cedar_policy`, `deny_invalid_context`,
 * `deny_no_policy`, ...). The client must surface that as `denyCode` on the
 * returned `ToolCallEvaluation`. Fail-closed paths (timeout, transport
 * error) must synthesise `denyCode: "deny_fail_closed"`.
 *
 * Allow outcomes never carry a code.
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import type { DenyCode } from "../src/evaluation/cedar-client";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

function mockFetch(body: Record<string, unknown>, status = 200): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

function newClient(fetchImpl: typeof fetch) {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: "agent-1",
    timeoutMs: 100,
    fetchImpl,
    logger: silentLogger(),
  });
}

describe("CedarToolCallClient — H4 deny_code surfacing", () => {
  test("server deny with deny_cedar_policy is surfaced as denyCode", async () => {
    const client = newClient(
      mockFetch({
        decision: "deny",
        rule_id: "policy42",
        reason: "no matching allow rule",
        deny_code: "deny_cedar_policy",
        ttl_ms: 5000,
      }),
    );
    const r = await client.evaluateToolCall({ toolName: "send_email" });
    expect(r.decision).toBe("deny");
    expect(r.denyCode).toBe("deny_cedar_policy");
    expect(r.ruleId).toBe("policy42");
    expect(r.reason).toBe("no matching allow rule");
  });

  test("allow response never carries denyCode", async () => {
    const client = newClient(
      mockFetch({
        decision: "allow",
        rule_id: "permit_all",
        ttl_ms: 5000,
      }),
    );
    const r = await client.evaluateToolCall({ toolName: "read_file" });
    expect(r.decision).toBe("allow");
    expect(r.denyCode).toBeUndefined();
  });

  test("server deny_mcp_server_not_granted is surfaced as a typed denyCode", async () => {
    const client = newClient(
      mockFetch({
        decision: "deny",
        reason: "MCP server 'github' is not granted",
        deny_code: "deny_mcp_server_not_granted",
        ttl_ms: 0,
      }),
    );
    const r = await client.evaluateToolCall({ toolName: "github.search" });
    expect(r.decision).toBe("deny");
    // PDPC-C-ts: the union must include this member so it is not coerced
    // to an unknown/default value.
    const code: DenyCode | undefined = r.denyCode;
    expect(code).toBe("deny_mcp_server_not_granted");
  });

  test("server invalid_context deny is surfaced", async () => {
    const client = newClient(
      mockFetch({
        decision: "deny",
        reason: "invalid context: cannot parse field foo",
        deny_code: "deny_invalid_context",
        ttl_ms: 0,
      }),
    );
    const r = await client.evaluateToolCall({ toolName: "any" });
    expect(r.denyCode).toBe("deny_invalid_context");
  });

  test("missing deny_code field still produces a valid deny (back-compat)", async () => {
    const client = newClient(
      mockFetch({
        decision: "deny",
        reason: "legacy server",
        ttl_ms: 0,
      }),
    );
    const r = await client.evaluateToolCall({ toolName: "x" });
    expect(r.decision).toBe("deny");
    expect(r.denyCode).toBeUndefined();
    expect(r.reason).toBe("legacy server");
  });

  test("network failure synthesises deny_fail_closed", async () => {
    const failing: typeof fetch = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const client = newClient(failing);
    const r = await client.evaluateToolCall({ toolName: "x" });
    expect(r.decision).toBe("deny");
    expect(r.denyCode).toBe("deny_fail_closed");
    expect(r.reason).toContain("agentum-fail-closed");
  });

  test("HTTP 500 from server synthesises deny_fail_closed", async () => {
    const client = newClient(mockFetch({ error: "boom" }, 500));
    const r = await client.evaluateToolCall({ toolName: "x" });
    expect(r.decision).toBe("deny");
    expect(r.denyCode).toBe("deny_fail_closed");
  });
});
