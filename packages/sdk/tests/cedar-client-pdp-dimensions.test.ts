/**
 * R26 Problem 1 — `CedarToolCallClient.attemptPdp` resolves tenant-schema
 * dimensions exactly as the central path does and ships them as a top-level
 * `dimensions` field on the `/v1/authorize` POST body. Without this, the PDP
 * plane evaluates dimension-keyed Cedar policies (and S3-15b per-scope
 * capability sets) differently from central.
 *
 * Coverage:
 *   1. ALS-context dims surface as a top-level `dimensions` field on the
 *      `/v1/authorize` body (NOT nested under `context`).
 *   2. Resolver nulls are dropped (string→string only) so the PDP's
 *      `BTreeMap<String,String>` deserialise never sees a null.
 *   3. No-schema → empty `dimensions: {}` (serde default; PDP treats as none).
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";
import { withAgentumContext } from "../src/instrumentation/context";
import { _setActiveSchema } from "../src/manifest/state";
import type { TenantSchema } from "../src/manifest/types";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

interface CapturedRequest {
  url: string;
  body: Record<string, unknown>;
}

const AGENT_ID = "agent-acme";
const PDP_URL = "http://127.0.0.1:7080";

/**
 * Fetch double that answers the PDP `/v1/health` probe (so discovery marks
 * the PDP alive) and the `/v1/authorize` decision call, recording only the
 * authorize body. Audit-ingest POSTs are absorbed (200) but not recorded.
 */
function pdpRecordingFetch(recorded: CapturedRequest[]): typeof fetch {
  return (async (url: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : "";
    if (urlStr.endsWith("/v1/health")) {
      return new Response(JSON.stringify({ agent_id: AGENT_ID }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (urlStr.endsWith("/v1/authorize")) {
      const raw = init?.body;
      const parsed =
        typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : {};
      recorded.push({ url: urlStr, body: parsed });
      return new Response(
        JSON.stringify({ decision: "allow", policy_hash: "h1" }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    // Audit-ingest fire-and-forget — swallow.
    return new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function newPdpClient(fetchImpl: typeof fetch): CedarToolCallClient {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: AGENT_ID,
    pdpUrl: PDP_URL,
    pdpServiceToken: "svc-token",
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

describe("CedarToolCallClient — R26 PDP dimensions threading", () => {
  test("ALS-context dims surface as a top-level `dimensions` field on /v1/authorize", async () => {
    _setActiveSchema(SCHEMA);
    const recorded: CapturedRequest[] = [];
    const client = newPdpClient(pdpRecordingFetch(recorded));

    const result = await withAgentumContext(
      { dimensions: { account_id: "acme", bot_id: "acme_support_prod" } },
      async () => client.evaluateToolCall({ toolName: "search_web" }),
    );

    expect(result.decision).toBe("allow");
    expect(result.decisionSource).toBe("pdp");

    const authorize = recorded.find((r) => r.url.endsWith("/v1/authorize"));
    expect(authorize).toBeDefined();
    // Top-level dimensions, NOT nested in context.
    expect(authorize!.body["dimensions"]).toEqual({
      account_id: "acme",
      bot_id: "acme_support_prod",
    });
    // context sub-fields are unchanged.
    const ctx = authorize!.body["context"] as Record<string, unknown>;
    expect(ctx).toBeDefined();
    expect(ctx["arguments"]).toBeNull();
    expect(authorize!.body["principal"]).toBe(AGENT_ID);
    expect(authorize!.body["action"]).toBe("tool:search_web");
  });

  test("no active schema → empty `dimensions: {}` on /v1/authorize body", async () => {
    _setActiveSchema(null);
    const recorded: CapturedRequest[] = [];
    const client = newPdpClient(pdpRecordingFetch(recorded));

    await client.evaluateToolCall({ toolName: "send_email" });

    const authorize = recorded.find((r) => r.url.endsWith("/v1/authorize"));
    expect(authorize).toBeDefined();
    expect(authorize!.body["dimensions"]).toEqual({});
  });

  test("resolved dimension values are string→string (no nulls reach the PDP)", async () => {
    _setActiveSchema(SCHEMA);
    const recorded: CapturedRequest[] = [];
    const client = newPdpClient(pdpRecordingFetch(recorded));

    // Only account_id is supplied in context; bot_id is absent and the
    // resolver yields null for it — that null must be stripped before the
    // PDP sees the BTreeMap<String,String>.
    await withAgentumContext(
      { dimensions: { account_id: "acme" } },
      async () => client.evaluateToolCall({ toolName: "search_web" }),
    );

    const authorize = recorded.find((r) => r.url.endsWith("/v1/authorize"));
    expect(authorize).toBeDefined();
    const dims = authorize!.body["dimensions"] as Record<string, unknown>;
    for (const v of Object.values(dims)) {
      expect(typeof v).toBe("string");
    }
    expect(dims["account_id"]).toBe("acme");
  });
});
