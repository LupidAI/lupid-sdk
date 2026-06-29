/**
 * S1-15 Pre-3a — `CedarToolCallClient.evaluateToolCall` resolves tenant-
 * schema dimensions via the S1-13 resolver and ships them in the request
 * body to `/api/v1/sdk/evaluate-tool-call`. The cache key folds dims in so
 * two ALS contexts with different dim values never share a cache entry.
 *
 * Coverage:
 *   1. ALS context with dims → POST body carries `dimensions: { ... }`
 *   2. Two evaluations with different dim values → two HTTP calls
 *      (different cache keys).
 *   3. Two evaluations with identical (empty) dims → one HTTP call
 *      + one cache hit (stable hash).
 *   4. Resolver throw (no init / no active schema) degrades to empty dims
 *      rather than throwing out of evaluateToolCall.
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import { withAgentumContext } from "../src/instrumentation/context";
import { _setActiveSchema } from "../src/manifest/state";
import type { TenantSchema } from "../src/manifest/types";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

interface CapturedRequest {
  body: Record<string, unknown>;
}

function recordingFetch(
  recorded: CapturedRequest[],
  responseBody: Record<string, unknown>,
  status = 200,
): typeof fetch {
  return (async (
    url: unknown,
    init?: RequestInit,
  ): Promise<Response> => {
    const raw = init?.body;
    const parsed =
      typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : {};
    // L06 audit emissions also flow through fetchImpl as fire-and-forget;
    // filter them out so the test asserts only on /sdk/evaluate-tool-call.
    const urlStr = typeof url === "string" ? url : "";
    if (urlStr.includes("/sdk/evaluate-tool-call")) {
      recorded.push({ body: parsed });
    }
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function newClient(fetchImpl: typeof fetch): CedarToolCallClient {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: "agent-acme",
    // Disable PDP routing — keep the test focused on the central path.
    pdpUrl: "",
    timeoutMs: 200,
    fetchImpl,
    logger: silentLogger(),
  });
}

const SCHEMA: TenantSchema = {
  version: 3,
  dimensions: [
    { name: "account_id", source: { kind: "context", path: "account_id" } },
    { name: "bot_id", source: { kind: "context", path: "bot_id" } },
  ],
};

afterEach(() => {
  _setActiveSchema(null);
});

describe("CedarToolCallClient — S1-15 Pre-3a dimensions threading", () => {
  test("ALS-context dims surface in POST body and produce one HTTP call per dim-set", async () => {
    _setActiveSchema(SCHEMA);
    const recorded: CapturedRequest[] = [];
    const client = newClient(
      recordingFetch(recorded, {
        decision: "allow",
        ttl_ms: 5000,
      }),
    );

    await withAgentumContext(
      {
        dimensions: { account_id: "acme", bot_id: "acme_support_prod" },
      },
      async () => {
        await client.evaluateToolCall({ toolName: "search_web" });
      },
    );

    expect(recorded).toHaveLength(1);
    const first = recorded[0]!.body;
    expect(first["agent_id"]).toBe("agent-acme");
    expect(first["tool_name"]).toBe("search_web");
    expect(first["dimensions"]).toEqual({
      account_id: "acme",
      bot_id: "acme_support_prod",
    });
  });

  test("different ALS dim values yield distinct cache keys → two HTTP calls", async () => {
    _setActiveSchema(SCHEMA);
    const recorded: CapturedRequest[] = [];
    const client = newClient(
      recordingFetch(recorded, {
        decision: "allow",
        ttl_ms: 5000,
      }),
    );

    await withAgentumContext(
      { dimensions: { account_id: "acme", bot_id: "x" } },
      async () => {
        await client.evaluateToolCall({ toolName: "search_web" });
      },
    );
    await withAgentumContext(
      { dimensions: { account_id: "globex", bot_id: "x" } },
      async () => {
        await client.evaluateToolCall({ toolName: "search_web" });
      },
    );

    expect(recorded).toHaveLength(2);
    expect((recorded[0]!.body["dimensions"] as Record<string, string>)["account_id"]).toBe(
      "acme",
    );
    expect((recorded[1]!.body["dimensions"] as Record<string, string>)["account_id"]).toBe(
      "globex",
    );
  });

  test("identical empty-dims calls hit the cache (one HTTP call total)", async () => {
    // No active schema → resolver throws InitError → fallback to empty dims.
    // The wrapping shape `{ args, dims: {} }` is deterministic across calls.
    _setActiveSchema(null);
    const recorded: CapturedRequest[] = [];
    const client = newClient(
      recordingFetch(recorded, {
        decision: "allow",
        ttl_ms: 5000,
      }),
    );

    await client.evaluateToolCall({ toolName: "search_web", arguments: { q: "a" } });
    await client.evaluateToolCall({ toolName: "search_web", arguments: { q: "a" } });

    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.body["dimensions"]).toEqual({});
  });

  test("resolver throw (no active schema) degrades to empty dims, does not throw", async () => {
    _setActiveSchema(null);
    const recorded: CapturedRequest[] = [];
    const client = newClient(
      recordingFetch(recorded, {
        decision: "allow",
        ttl_ms: 5000,
      }),
    );

    // Should not throw — resolver's InitError is swallowed.
    const r = await client.evaluateToolCall({ toolName: "send_email" });
    expect(r.decision).toBe("allow");
    expect(recorded).toHaveLength(1);
    expect(recorded[0]!.body["dimensions"]).toEqual({});
  });
});
