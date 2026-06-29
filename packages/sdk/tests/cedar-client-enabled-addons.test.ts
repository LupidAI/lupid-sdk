/**
 * R45b / INTEG-B1 — SDK consumption of the live PDP `enabled_addons` /
 * `bundle_loaded` snapshot, exposed via `featureState(id)`.
 *
 * Asserts that `CedarToolCallClient`:
 *   - reports `featureState(...) === "unknown"` for every addon before any
 *     snapshot is received (cold start) — callers apply a per-feature SAFE
 *     default, NOT a blanket fail-OPEN
 *   - parses `enabled_addons` (+ `bundle_loaded`) from a PDP `/v1/authorize`
 *     200 into the snapshot, then reports exact tri-state membership
 *     (`"enabled"` for present, `"disabled"` for absent)
 *   - CORE PROOF: a populated-then-emptied snapshot (`enabled_addons:[]`,
 *     `bundle_loaded:true`) reports `"disabled"` (fail-CLOSED), and a
 *     never-populated snapshot reports `"unknown"`
 *   - resets back to `"unknown"` on policy / capability invalidation
 *   - does NOT pick up `enabled_addons` from the central evaluate-tool-call
 *     path (central never sends it)
 *
 * Reuses the `fetchImpl`-injection routed-fetch style of
 * `cedar-client-pdp.test.ts` (no nock — that suite doesn't use it either).
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

interface FetchOutcome {
  status?: number;
  body?: string;
}

function makeRoutedFetch(
  routes: Record<string, FetchOutcome>,
  capture: CapturedCall[] = [],
): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    capture.push({ url: u, init });
    const matchKey = Object.keys(routes).find((k) => u.endsWith(k));
    if (!matchKey) throw new Error(`unrouted URL in test fetch: ${u}`);
    const outcome = routes[matchKey]!;
    return new Response(outcome.body ?? "{}", {
      status: outcome.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

const HEALTH_OK: FetchOutcome = {
  status: 200,
  body: JSON.stringify({
    status: "ok",
    agent_id: "agent-1",
    policy_hash: "abc123",
    synced_at: new Date().toISOString(),
    uptime_secs: 1,
  }),
};

/**
 * Build a PDP permit. `enabledAddons === undefined` omits the field
 * (pre-INTEG-B1 PDP shape). `bundleLoaded` controls the `bundle_loaded`
 * field; default true mirrors the post-INTEG-B1 PDP (which always emits it
 * once a bundle is loaded).
 */
function pdpPermit(
  enabledAddons?: unknown,
  bundleLoaded: boolean = true,
): FetchOutcome {
  const body: Record<string, unknown> = {
    decision: "allow",
    rule_id: "permit-everything",
    policy_hash: "abc123",
    evaluated_locally: true,
    latency_us: 250,
    bundle_loaded: bundleLoaded,
  };
  if (enabledAddons !== undefined) body["enabled_addons"] = enabledAddons;
  return { status: 200, body: JSON.stringify(body) };
}

function makePdpClient(fetchImpl: typeof fetch): CedarToolCallClient {
  return new CedarToolCallClient({
    baseUrl: "http://api.example",
    apiKey: "k",
    agentId: "agent-1",
    pdpUrl: "http://127.0.0.1:7080",
    pdpServiceToken: "s3cret",
    fetchImpl,
    logger: silentLogger(),
  });
}

describe("CedarToolCallClient — featureState (INTEG-B1)", () => {
  test("cold start: every addon is 'unknown' before any snapshot", () => {
    const client = makePdpClient(makeRoutedFetch({}));
    expect(client.hasAddonSnapshot()).toBe(false);
    expect(client.featureState("addon.policy.hitl")).toBe("unknown");
    expect(client.featureState("addon.policy.pii-advanced")).toBe("unknown");
    expect(client.featureState("addon.anything")).toBe("unknown");
    expect(client.enabledAddonsSnapshot()).toEqual([]);
  });

  test("parses enabled_addons from PDP /v1/authorize → exact tri-state", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit([
          "addon.policy.hitl",
          "addon.policy.pii-advanced",
        ]),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.hasAddonSnapshot()).toBe(true);
    expect(client.enabledAddonsSnapshot()).toEqual([
      "addon.policy.hitl",
      "addon.policy.pii-advanced",
    ]);
    expect(client.featureState("addon.policy.hitl")).toBe("enabled");
    expect(client.featureState("addon.policy.pii-advanced")).toBe("enabled");
    // Snapshot received → absent addon is "disabled", not "unknown".
    expect(client.featureState("addon.policy.missing")).toBe("disabled");
  });

  test("CORE: populated-then-emptied snapshot → 'disabled' (fail-CLOSED)", async () => {
    // bundle_loaded:true with enabled_addons:[] is exactly the "feature was
    // turned off" shape — it MUST read as disabled, never unknown.
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit([]),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.hasAddonSnapshot()).toBe(true);
    expect(client.enabledAddonsSnapshot()).toEqual([]);
    expect(client.featureState("addon.policy.hitl")).toBe("disabled");
    expect(client.featureState("addon.policy.pii-advanced")).toBe("disabled");
  });

  test("CORE: bundle_loaded:false leaves snapshot 'unknown' (pre-sync)", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        // No enabled_addons array AND bundle_loaded:false → no snapshot signal.
        "/v1/authorize": pdpPermit(undefined, false),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.hasAddonSnapshot()).toBe(false);
    expect(client.featureState("addon.policy.hitl")).toBe("unknown");
  });

  test("bundle_loaded:true without an array field is a loaded-zero-addon bundle", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit(undefined, true),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.hasAddonSnapshot()).toBe(true);
    expect(client.featureState("addon.policy.hitl")).toBe("disabled");
  });

  test("non-string members are filtered out of the snapshot", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit([
          "addon.policy.hitl",
          42,
          null,
          { x: 1 },
        ]),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.enabledAddonsSnapshot()).toEqual(["addon.policy.hitl"]);
    expect(client.featureState("addon.policy.hitl")).toBe("enabled");
  });

  test("invalidatePolicyCache resets the snapshot to 'unknown'", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit(["addon.policy.hitl"]),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.featureState("addon.policy.missing")).toBe("disabled");
    client.invalidatePolicyCache();
    expect(client.hasAddonSnapshot()).toBe(false);
    expect(client.enabledAddonsSnapshot()).toEqual([]);
    expect(client.featureState("addon.policy.missing")).toBe("unknown");
  });

  test("invalidateCapabilityCache resets the snapshot to 'unknown'", async () => {
    const client = makePdpClient(
      makeRoutedFetch({
        "/v1/health": HEALTH_OK,
        "/v1/authorize": pdpPermit(["addon.policy.hitl"]),
      }),
    );
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.featureState("addon.policy.missing")).toBe("disabled");
    client.invalidateCapabilityCache();
    expect(client.hasAddonSnapshot()).toBe(false);
    expect(client.enabledAddonsSnapshot()).toEqual([]);
    expect(client.featureState("addon.policy.missing")).toBe("unknown");
  });

  test("central evaluate-tool-call path does NOT populate the snapshot", async () => {
    // No PDP configured → straight to central. Central response carries an
    // enabled_addons field that the SDK must ignore (the central plane does
    // not send it; even if present it must not be consumed).
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: makeRoutedFetch({
        "/api/v1/sdk/evaluate-tool-call": {
          status: 200,
          body: JSON.stringify({
            decision: "allow",
            ttl_ms: 5_000,
            policy_hash: "central-hash",
            enabled_addons: ["addon.policy.hitl"],
            bundle_loaded: true,
          }),
        },
      }),
      logger: silentLogger(),
    });
    await client.evaluateToolCall({ toolName: "fetch_url" });
    expect(client.hasAddonSnapshot()).toBe(false);
    expect(client.enabledAddonsSnapshot()).toEqual([]);
    expect(client.featureState("addon.policy.missing")).toBe("unknown");
  });

  afterEach(async () => {
    // No-op: clients are local to each test; nothing global to reset.
  });
});
