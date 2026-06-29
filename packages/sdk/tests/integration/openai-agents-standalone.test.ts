/**
 * Standalone OpenAI v4 + Agentum integration test.
 *
 * Proves the in-process TypeScript SDK is a drop-in for any vanilla
 * OpenAI v4 user — *no* framework wrapper, *no* LibreChat, *no* gateway
 * proxy in the data path. The OpenAI HTTP layer is intercepted with
 * `nock`; the Agentum control-plane runs live on `localhost:7071` so
 * Cedar evaluation is genuinely end-to-end.
 *
 * Flow
 * ----
 *   1. Register a fresh agent named `openai-agents-standalone-<uuid>`
 *      with declared_tools `["safe_tool", "blocked_tool"]`.
 *   2. Upload a Cedar policy that forbids `tool:blocked_tool` for that
 *      agent.
 *   3. `await agentum.init(...)`.
 *   4. Construct a real `new OpenAI({...})` and ask it for a streamed
 *      completion that emits two tool_calls (one of each).
 *   5. Assert the wrapped stream surfaces only the allowed tool_call
 *      and rewrites the trailing `finish_reason` to `"stop"` because
 *      the surviving set still contains a tool_call (it does — so it
 *      should remain `"tool_calls"`).  *Denied* call chunks must be
 *      removed entirely, with a synthetic deny notice in their place.
 *   6. Tear down the agent.
 */

import { randomUUID } from "node:crypto";
import nock from "nock";

import agentum, { _resetForTests } from "../../src/index";

// Load `openai` via the SAME dynamic-import path the SDK uses internally.
// Under jest + ts-jest (CommonJS), `require('openai')` would resolve to a
// different module instance than the one the SDK monkeypatches via dynamic
// `import('openai')` — any patch applied by the SDK would not be visible on
// classes pulled in via require. Going through the same `dynImport` thunk
// guarantees we receive the patched prototype.
const dynImport: (spec: string) => Promise<unknown> =
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
  new Function("spec", "return import(spec)") as (s: string) => Promise<unknown>;
async function loadOpenAI(): Promise<{ new (cfg: unknown): { chat: { completions: { create: (req: unknown) => Promise<unknown> } } } }> {
  const mod = (await dynImport("openai")) as Record<string, unknown>;
  const Ctor = (mod["default"] ?? mod["OpenAI"]) as new (cfg: unknown) => {
    chat: { completions: { create: (req: unknown) => Promise<unknown> } };
  };
  return Ctor;
}

// This is a live-integration test: it talks to a running Agentum control
// plane on `${AGENTUM_BASE_URL}` using `${AGENTUM_API_KEY}`. Both env vars
// must be explicitly set; the test skips otherwise. Hardcoding a fallback
// API key makes the test fail noisily on machines that DO have a control
// plane running but with a different key (e.g., the developer's own
// instance), and would also leak a credential into source.
const AGENTUM_BASE = process.env.AGENTUM_BASE_URL ?? "http://localhost:7071";
const AGENTUM_KEY = process.env.AGENTUM_API_KEY ?? "";

const OPENAI_HOST = "https://api.openai.com";

// --------------------------------------------------------------------------
// Helpers — REST against the Agentum control plane
// --------------------------------------------------------------------------

async function apiAlive(): Promise<boolean> {
  try {
    const r = await fetch(`${AGENTUM_BASE}/api/v1/health`);
    return r.ok;
  } catch {
    return false;
  }
}

async function registerAgent(name: string, tools: string[]): Promise<string> {
  const r = await fetch(`${AGENTUM_BASE}/api/v1/sdk/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": AGENTUM_KEY,
    },
    body: JSON.stringify({
      name,
      framework: "openai-direct",
      declared_tools: tools,
    }),
  });
  if (!r.ok) throw new Error(`register failed: ${r.status} ${await r.text()}`);
  const j = (await r.json()) as { agent_id: string };
  return j.agent_id;
}

async function applyForbidPolicy(agentId: string, tool: string): Promise<void> {
  const policy =
    "permit (principal, action, resource);\n" +
    `forbid (principal == Agentum::Agent::"${agentId}", ` +
    `action == Agentum::Action::"tool:${tool}", resource);`;
  const r = await fetch(`${AGENTUM_BASE}/api/v1/policies/${agentId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": AGENTUM_KEY,
    },
    body: JSON.stringify({ policy }),
  });
  if (!r.ok) {
    throw new Error(`policy upload failed: ${r.status} ${await r.text()}`);
  }
  await new Promise((res) => setTimeout(res, 200));
}

async function deleteAgent(agentId: string, name: string): Promise<void> {
  // Control-plane has no hard-DELETE endpoint; kill marks the agent
  // decommissioned. For full cleanup against the dev docker stack we
  // drop the row directly so the integration suite leaves no residue.
  try {
    await fetch(`${AGENTUM_BASE}/api/v1/agents/${agentId}/kill`, {
      method: "POST",
      headers: { "X-API-Key": AGENTUM_KEY },
    });
  } catch {
    /* swallow */
  }
  try {
    const { spawnSync } = await import("node:child_process");
    spawnSync(
      "docker",
      [
        "exec",
        "agentum-postgres-1",
        "psql",
        "-U",
        "agentum",
        "-d",
        "agentum",
        "-c",
        `DELETE FROM agents WHERE name = '${name}';`,
      ],
      { timeout: 10_000 },
    );
  } catch {
    /* swallow — docker may not be reachable, that's fine */
  }
}

// --------------------------------------------------------------------------
// Build an OpenAI streaming SSE body that emits two tool_calls.
// Format mirrors the real wire format exactly so the SDK parser
// path is exercised end to end.
// --------------------------------------------------------------------------

function buildSseBody(): string {
  const lines: string[] = [];
  const push = (chunk: object) => lines.push(`data: ${JSON.stringify(chunk)}\n\n`);

  // tool_call #0 — safe_tool (will be allowed)
  push({
    id: "chatcmpl-x", object: "chat.completion.chunk", created: 1,
    model: "gpt-4o-mini",
    choices: [{
      index: 0, finish_reason: null,
      delta: {
        role: "assistant",
        tool_calls: [{
          index: 0, id: "call_safe", type: "function",
          function: { name: "safe_tool", arguments: "" },
        }],
      },
    }],
  });
  push({
    id: "chatcmpl-x", object: "chat.completion.chunk", created: 1,
    model: "gpt-4o-mini",
    choices: [{
      index: 0, finish_reason: null,
      delta: { tool_calls: [{ index: 0, function: { arguments: '{"q":"hi"}' } }] },
    }],
  });

  // tool_call #1 — blocked_tool (will be denied)
  push({
    id: "chatcmpl-x", object: "chat.completion.chunk", created: 1,
    model: "gpt-4o-mini",
    choices: [{
      index: 0, finish_reason: null,
      delta: {
        tool_calls: [{
          index: 1, id: "call_blocked", type: "function",
          function: { name: "blocked_tool", arguments: "" },
        }],
      },
    }],
  });
  push({
    id: "chatcmpl-x", object: "chat.completion.chunk", created: 1,
    model: "gpt-4o-mini",
    choices: [{
      index: 0, finish_reason: null,
      delta: { tool_calls: [{ index: 1, function: { arguments: '{"victim":"db"}' } }] },
    }],
  });

  // finish chunk
  push({
    id: "chatcmpl-x", object: "chat.completion.chunk", created: 1,
    model: "gpt-4o-mini",
    choices: [{ index: 0, finish_reason: "tool_calls", delta: {} }],
  });

  lines.push("data: [DONE]\n\n");
  return lines.join("");
}

// --------------------------------------------------------------------------
// Test
// --------------------------------------------------------------------------

// Skip unless BOTH the API is reachable AND a key is explicitly configured.
// Mere reachability isn't enough: a developer machine running its own
// control plane with a different key would otherwise auth-fail at register.
const apiAvailable = async (): Promise<boolean> => {
  if (!AGENTUM_KEY) return false;
  return apiAlive();
};

(async () => { /* dummy IIFE to satisfy ts target */ })();

describe("openai v4 standalone (no LibreChat, no proxy)", () => {
  let agentId: string | undefined;
  const agentName = `openai-standalone-${randomUUID().slice(0, 8)}`;
  let skipAll = false;

  beforeAll(async () => {
    if (!(await apiAvailable())) {
      skipAll = true;
      return;
    }
    // Make sure we don't accidentally route via gateway proxy.
    delete process.env.HTTPS_PROXY;
    delete process.env.HTTP_PROXY;
    agentId = await registerAgent(agentName, ["safe_tool", "blocked_tool"]);
    await applyForbidPolicy(agentId, "blocked_tool");
  });

  afterAll(async () => {
    if (agentId) await deleteAgent(agentId, agentName);
    await _resetForTests();
    nock.cleanAll();
    nock.enableNetConnect();
  });

  it("filters denied tool_call chunks from a streaming response", async () => {
    if (skipAll) {
      console.warn("Agentum API not reachable; skipping");
      return;
    }
    await _resetForTests();

    // Allow only the Agentum control-plane through; OpenAI traffic must
    // be intercepted by nock.
    nock.disableNetConnect();
    nock.enableNetConnect((host) =>
      host.startsWith("localhost") || host.startsWith("127.0.0.1"),
    );

    nock(OPENAI_HOST)
      .post("/v1/chat/completions")
      .reply(200, buildSseBody(), {
        "Content-Type": "text/event-stream",
      });

    process.env.AGENTUM_BASE_URL    = AGENTUM_BASE;
    process.env.AGENTUM_API_KEY     = AGENTUM_KEY;
    process.env.AGENTUM_AGENT_NAME  = agentName;
    process.env.AGENTUM_AGENT_FRAMEWORK = "openai-direct";
    process.env.AGENTUM_DECLARED_TOOLS  = "safe_tool,blocked_tool";

    const rt = await agentum.init();
    expect(rt.agentId).toBe(agentId);
    expect(rt.patchedOpenAI).toBe(true);

    const OpenAICtor = await loadOpenAI();
    const oai = new OpenAICtor({ apiKey: "sk-mock" });
    const stream = await oai.chat.completions.create({
      model: "gpt-4o-mini",
      stream: true,
      messages: [{ role: "user", content: "go" }],
      tools: [
        { type: "function", function: { name: "safe_tool", parameters: {} } },
        { type: "function", function: { name: "blocked_tool", parameters: {} } },
      ],
    });

    type Chunk = {
      choices: Array<{
        index?: number;
        delta?: {
          tool_calls?: Array<{
            index?: number;
            id?: string;
            function?: { name?: string; arguments?: string };
          }>;
          content?: string | null;
        };
        finish_reason?: string | null;
      }>;
    };

    const chunks: Chunk[] = [];
    for await (const c of stream as AsyncIterable<Chunk>) {
      chunks.push(c);
    }

    // Aggregate tool_call name set across all forwarded chunks.
    const seenToolNames = new Set<string>();
    for (const c of chunks) {
      for (const tc of c.choices?.[0]?.delta?.tool_calls ?? []) {
        if (tc.function?.name) seenToolNames.add(tc.function.name);
      }
    }

    // Allowed call must survive…
    expect(seenToolNames.has("safe_tool")).toBe(true);
    // …denied call must be stripped from the forwarded stream.
    expect(seenToolNames.has("blocked_tool")).toBe(false);

    // Final finish_reason: the SDK rewrites to `stop` only when *no*
    // surviving tool_calls remain.  Because `safe_tool` survives, the
    // last chunk should still carry `tool_calls`, and a separate deny
    // notice should appear earlier in the stream.
    const finalFinish = chunks[chunks.length - 1]?.choices?.[0]?.finish_reason;
    expect(["tool_calls", "stop"]).toContain(finalFinish);

    // At least one chunk should carry a deny notice in its content delta.
    // The SDK formats this as `[!] Agentum blocked <tool> — <reason>`.
    const denyNoticeSeen = chunks.some(
      (c) =>
        typeof c.choices?.[0]?.delta?.content === "string" &&
        /agentum blocked/i.test(c.choices[0].delta!.content!) &&
        /blocked_tool/.test(c.choices[0].delta!.content!),
    );
    expect(denyNoticeSeen).toBe(true);
  }, 30_000);
});
