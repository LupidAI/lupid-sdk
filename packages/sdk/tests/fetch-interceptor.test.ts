/**
 * Unit tests for the Layer-1 fetch interceptor.
 *
 * The interceptor is exercised end-to-end with a mock upstream `fetch` and
 * a mock `CedarToolCallClient`. We never hit the real network. SSE streams
 * are constructed from `ReadableStream<Uint8Array>` so the byte-level
 * parser path runs.
 */

import {
  installFetchInterceptor,
  type FetchInterceptorOptions,
} from "../src/instrumentation/fetch-interceptor";
import { HostRegistry } from "../src/instrumentation/host-registry";
import { withAgentumContext } from "../src/instrumentation/context";
import {
  BedrockConverseStreamParser,
  BedrockInvokeStreamParser,
  encodeBedrockEventStreamMessage,
  encodeBedrockInvokeChunk,
  type WireEvent,
} from "../src/instrumentation/wire-parsers";
import {
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "../src/evaluation/cedar-client";
import {
  compileScanner,
  _setActiveTextScanner,
  _resetActiveTextScannerForTests,
} from "../src/pii";
import {
  markMcpCallEvaluated,
  _resetMcpServerMap,
  _resetMcpSuppression,
} from "../src/instrumentation/mcp-http";
import { _resetCacheForTests as _resetVaultCacheForTests } from "../src/vault/resolver";

// ── helpers ────────────────────────────────────────────────────────────────

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

function fakeEvaluator(
  decisions: Record<string, ToolCallEvaluation>,
  defaultDecision: ToolCallEvaluation = { decision: "allow", ttlMs: 0 },
): CedarToolCallClient {
  const evalFn = jest.fn(async ({ toolName }: { toolName: string }) => {
    return decisions[toolName] ?? defaultDecision;
  });
  // INTEG-B1 — default the advanced-PII addon to "enabled" so the legacy
  // "raw means raw" tests keep their intent. The dedicated tri-state test
  // below supplies its own mutable `featureState`.
  return {
    evaluateToolCall: evalFn,
    invalidateAll: jest.fn(),
    featureState: () => "enabled",
  } as unknown as CedarToolCallClient;
}

interface MockUpstream {
  fetchImpl: jest.Mock;
  calls: Array<{ url: string; init: RequestInit | undefined }>;
}

function mockUpstream(handler: (url: string, init?: RequestInit) => Response | Promise<Response>): MockUpstream {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const fetchImpl = jest.fn(async (input: string | Request | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, init });
    return handler(url, init);
  });
  return { fetchImpl: fetchImpl as unknown as jest.Mock, calls };
}

function jsonResponse(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...headers },
  });
}

function sseResponse(frames: string[]): Response {
  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      for (const f of frames) c.enqueue(enc.encode(f));
      c.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

/**
 * Build a `Response` carrying Bedrock's binary AWS event-stream framing
 * (`application/vnd.amazon.eventstream`). Frames are pre-encoded Uint8Arrays.
 */
function bedrockEventStreamResponse(frames: Uint8Array[]): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      for (const f of frames) c.enqueue(f);
      c.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "application/vnd.amazon.eventstream" },
  });
}

async function readSSE(resp: Response): Promise<string> {
  const reader = resp.body!.getReader();
  const dec = new TextDecoder();
  let out = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    out += dec.decode(value, { stream: true });
  }
  out += dec.decode();
  return out;
}

function baseOpts(
  evaluator: CedarToolCallClient,
  fetchImpl: typeof fetch,
  extra: Partial<FetchInterceptorOptions> = {},
): FetchInterceptorOptions {
  // P03: production default flipped to "deny" (fail-CLOSED). These tests
  // pin `"allow"` explicitly so happy-path / deny-rewrite cases remain
  // independent of the fail-mode decision. The named test
  // "failMode=allow on evaluator error passes through; failMode=deny
  // short-circuits" overrides per-case. The new default's behavior when
  // the option is omitted is covered by `tests/fail-closed-default.test.ts`.
  return {
    runtime: {
      baseUrl: "http://agentum.test:7071",
      apiKey: "ak_test",
      evaluator,
    },
    agentId: "a-1",
    hosts: new HostRegistry(),
    failMode: "allow",
    capturePrompts: false,
    fetchImpl,
    logger: silentLogger(),
    ...extra,
  };
}

afterEach(() => {
  delete (globalThis as { fetch?: unknown }).fetch;
});

// ── tests ──────────────────────────────────────────────────────────────────

describe("fetch-interceptor", () => {
  it("non-LLM URLs pass through with zero overhead", async () => {
    const ev = fakeEvaluator({});
    const up = mockUpstream(() => new Response("ok", { status: 200 }));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://example.com/non-llm");
    expect(r.status).toBe(200);
    expect(up.calls).toHaveLength(1);
    expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
    uninstall();
  });

  it("OpenAI non-streaming allow path passes the response through", async () => {
    const ev = fakeEvaluator({});
    const respBody = {
      id: "chatcmpl-1",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
    };
    const up = mockUpstream(() => jsonResponse(respBody));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    const json = await r.json() as { id: string };
    expect(json.id).toBe("chatcmpl-1");
    uninstall();
  });

  it("stamps the x-agentum-plane cross-plane marker on the forwarded request (undici-suppression contract)", async () => {
    // The undici dispatcher plane reads this marker, strips it, and skips its
    // own response-side enforcement so the same fetch() response is not
    // double-enforced. This asserts the PRODUCING side of that contract: the
    // marker reaches the outbound request the dispatcher will observe.
    const ev = fakeEvaluator({});
    const up = mockUpstream(() =>
      jsonResponse({ id: "x", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }),
    );
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer sk-app", "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    expect(up.calls).toHaveLength(1);
    const fwdHeaders = new Headers(up.calls[0]!.init?.headers);
    expect(fwdHeaders.get("x-agentum-plane")).toBe("fetch");
    // Provider auth header preserved through the marker merge.
    expect(fwdHeaders.get("authorization")).toBe("Bearer sk-app");
    uninstall();
  });

  it("preserves Request-input headers when stamping the marker (no auth loss)", async () => {
    // When `input` is a `Request`, the marker merge must UNION the Request's own
    // headers (provider key) with the marker — not replace them.
    const ev = fakeEvaluator({});
    const up = mockUpstream(() =>
      jsonResponse({ id: "y", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }),
    );
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const req = new Request("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "x-api-key": "sk-req", "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    await fetch(req);
    const fwdHeaders = new Headers(up.calls[0]!.init?.headers);
    expect(fwdHeaders.get("x-agentum-plane")).toBe("fetch");
    expect(fwdHeaders.get("x-api-key")).toBe("sk-req");
    uninstall();
  });

  it("OpenAI post-flight deny rewrites the response body", async () => {
    const ev = fakeEvaluator({ shell_exec: { decision: "deny", ttlMs: 0, reason: "blocked tool" } });
    const respBody = {
      id: "chatcmpl-2",
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          content: null,
          tool_calls: [{
            id: "call_1",
            type: "function",
            function: { name: "shell_exec", arguments: '{"cmd":"rm -rf /"}' },
          }],
        },
        finish_reason: "tool_calls",
      }],
    };
    const up = mockUpstream(() => jsonResponse(respBody));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    const json = await r.json() as { choices: Array<{ message: Record<string, unknown>; finish_reason: string }> };
    expect(json.choices[0]!.finish_reason).toBe("stop");
    expect(json.choices[0]!.message["tool_calls"]).toBeUndefined();
    expect(json.choices[0]!.message["content"]).toContain("Agentum blocked shell_exec");
    expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
    uninstall();
  });

  it("pre-flight deny short-circuits before fetch when request carries a tool_call", async () => {
    const ev = fakeEvaluator({ shell_exec: { decision: "deny", ttlMs: 0, reason: "no shell" } });
    const up = mockUpstream(() => jsonResponse({ should: "not be reached" }));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-4",
        messages: [{
          role: "assistant",
          tool_calls: [{
            id: "c1",
            type: "function",
            function: { name: "shell_exec", arguments: '{"cmd":"id"}' },
          }],
        }],
      }),
    });
    expect(up.calls).toHaveLength(0);
    expect(r.headers.get("x-agentum-policy")).toBe("sdk-denied");
    const json = await r.json() as { choices: Array<{ message: { content: string } }> };
    expect(json.choices[0]!.message.content).toContain("Agentum blocked shell_exec");
    uninstall();
  });

  it("streaming OpenAI happy path emits text deltas eagerly", async () => {
    const ev = fakeEvaluator({});
    const frames = [
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "Hel" } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "lo" } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] })}\n\n`,
      `data: [DONE]\n\n`,
    ];
    const up = mockUpstream(() => sseResponse(frames));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", stream: true, messages: [] }),
    });
    const text = await readSSE(r);
    expect(text).toContain('"content":"Hel"');
    expect(text).toContain('"content":"lo"');
    expect(text).toContain("[DONE]");
    uninstall();
  });

  it("streaming OpenAI deny splices a notice frame", async () => {
    const ev = fakeEvaluator({ rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" } });
    const frames = [
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "rm_rf", arguments: "" } }] } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"path":"/"}' } }] } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] })}\n\n`,
      `data: [DONE]\n\n`,
    ];
    const up = mockUpstream(() => sseResponse(frames));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", stream: true, messages: [] }),
    });
    const text = await readSSE(r);
    expect(text).toContain("Agentum blocked rm_rf");
    expect(text).not.toContain('"name":"rm_rf"');
    uninstall();
  });

  it("streaming OpenAI deny does not double-emit terminal frames", async () => {
    const ev = fakeEvaluator({ rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" } });
    const frames = [
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "rm_rf", arguments: "" } }] } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: '{"path":"/"}' } }] } }] })}\n\n`,
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] })}\n\n`,
      `data: [DONE]\n\n`,
    ];
    const up = mockUpstream(() => sseResponse(frames));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", stream: true, messages: [] }),
    });
    const text = await readSSE(r);
    // The upstream finish_reason="tool_calls" must be suppressed after the
    // synthetic stop frame is emitted.
    expect(text).not.toContain('"finish_reason":"tool_calls"');
    // Only one terminal [DONE] should appear (the synthetic one). The upstream
    // [DONE] is also a "finish" event; after inFlightTool is cleared the fix
    // would let it through. This assertion documents that edge-case gap.
    const doneMatches = text.match(/data: \[DONE\]/g);
    expect(doneMatches).toHaveLength(1);
    uninstall();
  });

  it("Anthropic non-streaming deny replaces tool_use with text block", async () => {
    const ev = fakeEvaluator({ web_search: { decision: "deny", ttlMs: 0, reason: "no net" } });
    const respBody = {
      id: "msg_1",
      type: "message",
      role: "assistant",
      content: [
        { type: "tool_use", id: "tu_1", name: "web_search", input: { q: "x" } },
      ],
      stop_reason: "tool_use",
    };
    const up = mockUpstream(() => jsonResponse(respBody));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-3", messages: [] }),
    });
    const json = await r.json() as { content: Array<Record<string, unknown>>; stop_reason: string };
    expect(json.content[0]!["type"]).toBe("text");
    expect(json.content[0]!["text"]).toContain("Agentum blocked web_search");
    expect(json.stop_reason).toBe("end_turn");
    uninstall();
  });

  it("Anthropic streaming happy path passes text deltas", async () => {
    const ev = fakeEvaluator({});
    const frames = [
      `event: content_block_start\ndata: ${JSON.stringify({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } })}\n\n`,
      `event: content_block_delta\ndata: ${JSON.stringify({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Hi" } })}\n\n`,
      `event: message_stop\ndata: ${JSON.stringify({ type: "message_stop" })}\n\n`,
    ];
    const up = mockUpstream(() => sseResponse(frames));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-3", stream: true, messages: [] }),
    });
    const text = await readSSE(r);
    expect(text).toContain('"text":"Hi"');
    expect(text).toContain("message_stop");
    uninstall();
  });

  it("Anthropic streaming deny: tool_use block replaced by text notice + stop_reason normalized", async () => {
    // Companion to the ALLOW path above. A streaming tool_use turn that the
    // evaluator denies must drop the whole tool block (start/delta/stop) and
    // splice the synthetic text triplet. The denied turn's terminal
    // stop_reason ("tool_use") rides on message_stop, which the deny path
    // suppresses — so it must never reach the consumer (normalization).
    const ev = fakeEvaluator({ rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" } });
    const frame = (name: string, payload: unknown): string =>
      `event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`;
    const frames = [
      frame("message_start", { type: "message_start", message: { role: "assistant" } }),
      frame("content_block_start", {
        type: "content_block_start",
        index: 0,
        content_block: { type: "tool_use", id: "tu_1", name: "rm_rf" },
      }),
      frame("content_block_delta", {
        type: "content_block_delta",
        index: 0,
        delta: { type: "input_json_delta", partial_json: `{"path":"/"}` },
      }),
      frame("content_block_stop", { type: "content_block_stop", index: 0 }),
      // Terminal stop_reason on message_stop (maps to a `finish` event that the
      // deny path suppresses). No standalone message_delta, so "tool_use"
      // never leaks through the passthrough path.
      frame("message_stop", { type: "message_stop", delta: { stop_reason: "tool_use" } }),
    ];
    const up = mockUpstream(() => sseResponse(frames));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      body: JSON.stringify({ model: "claude-3", stream: true, messages: [] }),
    });
    const text = await readSSE(r);
    // The tool_use block (name + type) is dropped on deny — no leak.
    expect(text).not.toContain(`"name":"rm_rf"`);
    expect(text).not.toContain(`"type":"tool_use"`);
    // The denied turn's terminal stop_reason was normalized away (suppressed).
    expect(text).not.toContain(`"stop_reason":"tool_use"`);
    // The synthetic text-notice triplet replaced the tool block.
    expect(text).toContain("event: content_block_start");
    expect(text).toContain('"type":"text_delta"');
    expect(text).toContain("Agentum blocked rm_rf");
    expect(text).toContain("event: content_block_stop");
    expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
    uninstall();
  });

  it("install is idempotent via Symbol tag", async () => {
    const ev = fakeEvaluator({});
    const up = mockUpstream(() => new Response("ok"));
    const u1 = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const firstFetch = globalThis.fetch;
    const u2 = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    expect(globalThis.fetch).toBe(firstFetch);
    u2();
    u1();
  });

  it("gateway-MITM coexistence: x-agentum-policy: enforced skips re-eval", async () => {
    const ev = fakeEvaluator({ shell_exec: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    const respBody = {
      id: "chatcmpl-3",
      choices: [{
        index: 0,
        message: {
          role: "assistant",
          tool_calls: [{ id: "c1", type: "function", function: { name: "shell_exec", arguments: "{}" } }],
        },
        finish_reason: "tool_calls",
      }],
    };
    const up = mockUpstream(() => jsonResponse(respBody, { "x-agentum-policy": "enforced" }));
    const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    const json = await r.json() as { choices: Array<{ message: Record<string, unknown> }> };
    expect(json.choices[0]!.message["tool_calls"]).toBeDefined();
    expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
    uninstall();
  });

  it("AsyncLocalStorage context propagates session_id to observe-prompt", async () => {
    const ev = fakeEvaluator({});
    const observed: Array<Record<string, unknown>> = [];
    const up = mockUpstream(async (url, init) => {
      if (url.includes("/sdk/observe-prompt")) {
        observed.push(JSON.parse(String(init?.body ?? "{}")));
        return jsonResponse({ ok: true, request_id: "x" });
      }
      return jsonResponse({ id: "x", choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }] });
    });
    const uninstall = installFetchInterceptor(
      baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { capturePrompts: true, syncObserve: true }),
    );
    await withAgentumContext({ sessionId: "sess-1", userId: "user-1" }, async () => {
      await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "hi" }] }),
      });
    });
    expect(observed).toHaveLength(1);
    expect(observed[0]!["session_id"]).toBe("sess-1");
    expect(observed[0]!["user_id"]).toBe("user-1");
    uninstall();
  });

  it("truncates oversized prompt content while preserving byte_count", async () => {
    const ev = fakeEvaluator({});
    const captured: Array<Record<string, unknown>> = [];
    const up = mockUpstream(async (url, init) => {
      if (url.includes("/sdk/observe-prompt")) {
        captured.push(JSON.parse(String(init?.body ?? "{}")));
        return jsonResponse({ ok: true, request_id: "x" });
      }
      return jsonResponse({ id: "x", choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }] });
    });
    const uninstall = installFetchInterceptor(
      baseOpts(ev, up.fetchImpl as unknown as typeof fetch, {
        capturePrompts: true,
        syncObserve: true,
        promptTruncationBytes: 32,
      }),
    );
    const big = "a".repeat(100_000);
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: big }] }),
    });
    const msg = (captured[0]!["messages"] as Array<Record<string, unknown>>)[0]!;
    expect(msg["truncated"]).toBe(true);
    expect(msg["byte_count"]).toBe(100_000);
    expect((msg["content"] as string).length).toBeLessThanOrEqual(32);
    uninstall();
  });

  it("failMode=allow on evaluator error passes through; failMode=deny short-circuits", async () => {
    const errEv = {
      evaluateToolCall: jest.fn(async () => { throw new Error("boom"); }),
      invalidateAll: jest.fn(),
    } as unknown as CedarToolCallClient;
    const respBody = {
      id: "x",
      choices: [{
        index: 0,
        message: { role: "assistant", tool_calls: [{ id: "c", type: "function", function: { name: "f", arguments: "{}" } }] },
        finish_reason: "tool_calls",
      }],
    };
    const up = mockUpstream(() => jsonResponse(respBody));

    const uAllow = installFetchInterceptor(baseOpts(errEv, up.fetchImpl as unknown as typeof fetch, { failMode: "allow" }));
    const r1 = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    const j1 = await r1.json() as { choices: Array<{ message: Record<string, unknown> }> };
    expect(j1.choices[0]!.message["tool_calls"]).toBeDefined();
    uAllow();

    const up2 = mockUpstream(() => jsonResponse(respBody));
    const uDeny = installFetchInterceptor(baseOpts(errEv, up2.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
    const r2 = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [] }),
    });
    const j2 = await r2.json() as { choices: Array<{ message: Record<string, unknown>; finish_reason: string }> };
    expect(j2.choices[0]!.message["tool_calls"]).toBeUndefined();
    expect(j2.choices[0]!.finish_reason).toBe("stop");
    uDeny();
  });

  it("uninstall + reinstall restores then re-replaces fetch", async () => {
    const ev = fakeEvaluator({});
    const up = mockUpstream(() => new Response("ok"));
    const orig = globalThis.fetch;
    const u1 = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    expect(globalThis.fetch).not.toBe(orig);
    u1();
    expect(globalThis.fetch).toBe(up.fetchImpl);
    const u2 = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
    expect(globalThis.fetch).not.toBe(up.fetchImpl);
    u2();
  });

  // ── A1: Cohere & Gemini coverage ──────────────────────────────────────────

  describe("Cohere", () => {
    it("classifies /v1/chat and passes allowed responses through", async () => {
      const ev = fakeEvaluator({});
      const respBody = {
        id: "cohere-1",
        text: "hi",
        finish_reason: "COMPLETE",
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://api.cohere.ai/v1/chat", {
        method: "POST",
        body: JSON.stringify({ model: "command-r", message: "hi" }),
      });
      const json = (await r.json()) as { id: string };
      expect(json.id).toBe("cohere-1");
      expect(up.calls.some((c) => c.url === "https://api.cohere.ai/v1/chat")).toBe(true);
      uninstall();
    });

    it("extracts top-level tool_calls for audit and rewrites on deny (v1 envelope)", async () => {
      const ev = fakeEvaluator({
        get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" },
      });
      const respBody = {
        id: "cohere-2",
        text: "thinking…",
        finish_reason: "TOOL_CALL",
        tool_calls: [
          { name: "get_weather", parameters: { city: "Paris" } },
        ],
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://api.cohere.ai/v1/chat", {
        method: "POST",
        body: JSON.stringify({ model: "command-r", message: "weather?" }),
      });
      const json = (await r.json()) as {
        tool_calls?: unknown;
        finish_reason: string;
        text: string;
      };
      expect(json.tool_calls).toBeUndefined();
      expect(json.finish_reason).toBe("COMPLETE");
      expect(json.text).toContain("Agentum blocked get_weather");
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(1);
      uninstall();
    });

    it("rewrites v2 chat envelope (message.content array)", async () => {
      const ev = fakeEvaluator({
        rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" },
      });
      const respBody = {
        id: "cohere-3",
        message: {
          role: "assistant",
          content: [{ type: "text", text: "thinking…" }],
        },
        finish_reason: "TOOL_CALL",
        tool_calls: [
          { name: "rm_rf", parameters: { path: "/" } },
        ],
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://api.cohere.ai/v2/chat", {
        method: "POST",
        body: JSON.stringify({ model: "command-r-plus", messages: [] }),
      });
      const json = (await r.json()) as {
        tool_calls?: unknown;
        message: { content: Array<Record<string, unknown>> };
        finish_reason: string;
      };
      expect(json.tool_calls).toBeUndefined();
      expect(json.finish_reason).toBe("COMPLETE");
      const last = json.message.content[json.message.content.length - 1]!;
      expect(last["type"]).toBe("text");
      expect(last["text"]).toContain("Agentum blocked rm_rf");
      uninstall();
    });

    it("opt-out via AGENTUM_STREAM_PASSTHROUGH=cohere passes through + emits audit", async () => {
      const previous = process.env["AGENTUM_STREAM_PASSTHROUGH"];
      process.env["AGENTUM_STREAM_PASSTHROUGH"] = "cohere";
      try {
        const ev = fakeEvaluator({});
        const frames = [
          `event: text-generation\ndata: ${JSON.stringify({ text: "hi" })}\n\n`,
          `event: stream-end\ndata: ${JSON.stringify({ finish_reason: "COMPLETE" })}\n\n`,
        ];
        const up = mockUpstream(() => sseResponse(frames));
        const auditCalls: Array<Record<string, unknown>> = [];
        const upWithAudit = mockUpstream(async (url, init) => {
          if (url.includes("/api/v1/audit/ingest")) {
            auditCalls.push(JSON.parse(String(init?.body ?? "{}")));
            return jsonResponse({ ok: true });
          }
          return up.fetchImpl(url, init) as Promise<Response>;
        });
        const uninstall = installFetchInterceptor(
          baseOpts(ev, upWithAudit.fetchImpl as unknown as typeof fetch),
        );
        const r = await fetch("https://api.cohere.ai/v1/chat", {
          method: "POST",
          body: JSON.stringify({ model: "command-r", message: "hi", stream: true }),
        });
        const text = await readSSE(r);
        for (const f of frames) expect(text).toContain(f);
        // Passthrough engaged → no SDK-enforced header, audit event emitted.
        expect(r.headers.get("x-agentum-policy")).toBeNull();
        await new Promise((r) => setTimeout(r, 20));
        const ev1 = auditCalls.find(
          (c) => c["event_type"] === "audit.streaming_unenforced",
        );
        expect(ev1).toBeDefined();
        const detail = ev1!["detail"] as Record<string, unknown>;
        expect(detail["provider"]).toBe("cohere");
        expect(detail["shape"]).toBe("cohere-chat");
        uninstall();
      } finally {
        if (previous === undefined) delete process.env["AGENTUM_STREAM_PASSTHROUGH"];
        else process.env["AGENTUM_STREAM_PASSTHROUGH"] = previous;
      }
    });

    it("v2 streaming: allowed tool call passes through with sdk-enforced header", async () => {
      const ev = fakeEvaluator({});
      const frames = [
        `event: tool-call-start\ndata: ${JSON.stringify({
          index: 0,
          delta: {
            message: {
              tool_calls: { id: "tc1", type: "function", function: { name: "ok_tool", arguments: "" } },
            },
          },
        })}\n\n`,
        `event: tool-call-delta\ndata: ${JSON.stringify({
          index: 0,
          delta: {
            message: { tool_calls: { function: { arguments: `{"q":"hi"}` } } },
          },
        })}\n\n`,
        `event: tool-call-end\ndata: ${JSON.stringify({ index: 0 })}\n\n`,
        `event: message-end\ndata: ${JSON.stringify({ delta: { finish_reason: "TOOL_CALL" } })}\n\n`,
      ];
      const up = mockUpstream(() => sseResponse(frames));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://api.cohere.ai/v2/chat", {
        method: "POST",
        body: JSON.stringify({ model: "command-r-plus", messages: [], stream: true }),
      });
      const text = await readSSE(r);
      // All four upstream frames forwarded verbatim.
      for (const f of frames) expect(text).toContain(f);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });

    it("v2 streaming: denied tool call rewrites to text + clean message-end", async () => {
      const ev = fakeEvaluator({
        send_email: { decision: "deny", ttlMs: 0, reason: "no smtp" },
      });
      const frames = [
        `event: tool-call-start\ndata: ${JSON.stringify({
          index: 0,
          delta: {
            message: {
              tool_calls: {
                id: "tc1", type: "function",
                function: { name: "send_email", arguments: "" },
              },
            },
          },
        })}\n\n`,
        `event: tool-call-delta\ndata: ${JSON.stringify({
          index: 0,
          delta: { message: { tool_calls: { function: { arguments: `{"to":"x@y.z"}` } } } },
        })}\n\n`,
        `event: tool-call-end\ndata: ${JSON.stringify({ index: 0 })}\n\n`,
        `event: message-end\ndata: ${JSON.stringify({ delta: { finish_reason: "TOOL_CALL" } })}\n\n`,
      ];
      const up = mockUpstream(() => sseResponse(frames));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://api.cohere.ai/v2/chat", {
        method: "POST",
        body: JSON.stringify({ model: "command-r-plus", messages: [], stream: true }),
      });
      const text = await readSSE(r);
      // Upstream tool-call SSE event headers must NOT leak — buffered+dropped.
      expect(text).not.toContain("event: tool-call-start");
      expect(text).not.toContain("event: tool-call-delta");
      expect(text).not.toContain("event: tool-call-end");
      // Upstream message-end carried `finish_reason: "TOOL_CALL"`; the
      // synthetic terminator must normalise that to "COMPLETE".
      expect(text).not.toContain(`"finish_reason":"TOOL_CALL"`);
      // Synthetic deny sequence present.
      expect(text).toContain("event: content-start");
      expect(text).toContain("event: content-delta");
      expect(text).toContain("Agentum blocked send_email");
      expect(text).toContain("event: content-end");
      expect(text).toContain(`"finish_reason":"COMPLETE"`);
      // No duplicate message-end (the upstream one is suppressed once a
      // synthetic terminator has been emitted).
      const messageEndCount = (text.match(/event: message-end/g) ?? []).length;
      expect(messageEndCount).toBe(1);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });
  });

  describe("Gemini", () => {
    it("classifies :generateContent and passes allowed responses through", async () => {
      const ev = fakeEvaluator({});
      const respBody = {
        candidates: [
          {
            content: {
              role: "model",
              parts: [{ text: "hello" }],
            },
            finishReason: "STOP",
          },
        ],
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        {
          method: "POST",
          body: JSON.stringify({ contents: [{ parts: [{ text: "hi" }] }] }),
        },
      );
      const json = (await r.json()) as {
        candidates: Array<{ content: { parts: Array<Record<string, unknown>> } }>;
      };
      expect(json.candidates[0]!.content.parts[0]!["text"]).toBe("hello");
      uninstall();
    });

    it("extracts functionCall parts and rewrites denied calls to text parts", async () => {
      const ev = fakeEvaluator({
        send_email: { decision: "deny", ttlMs: 0, reason: "no smtp" },
      });
      const respBody = {
        candidates: [
          {
            content: {
              role: "model",
              parts: [
                { text: "I'll email her." },
                {
                  functionCall: {
                    name: "send_email",
                    args: { to: "x@y.z", subject: "hi" },
                  },
                },
              ],
            },
            finishReason: "TOOL_USE",
          },
        ],
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        {
          method: "POST",
          body: JSON.stringify({ contents: [] }),
        },
      );
      const json = (await r.json()) as {
        candidates: Array<{
          content: { parts: Array<Record<string, unknown>> };
          finishReason: string;
        }>;
      };
      const parts = json.candidates[0]!.content.parts;
      expect(parts[0]!["text"]).toBe("I'll email her.");
      expect(parts[1]!["functionCall"]).toBeUndefined();
      expect(parts[1]!["text"]).toContain("Agentum blocked send_email");
      // No remaining functionCall → finishReason normalised to STOP.
      expect(json.candidates[0]!.finishReason).toBe("STOP");
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });

    it("opt-out via AGENTUM_STREAM_PASSTHROUGH=gemini passes through + emits audit", async () => {
      const previous = process.env["AGENTUM_STREAM_PASSTHROUGH"];
      process.env["AGENTUM_STREAM_PASSTHROUGH"] = "gemini";
      try {
        const ev = fakeEvaluator({});
        const frames = [
          `data: ${JSON.stringify({
            candidates: [
              { content: { parts: [{ text: "hi" }], role: "model" } },
            ],
          })}\n\n`,
        ];
        const auditCalls: Array<Record<string, unknown>> = [];
        const up = mockUpstream(async (url, init) => {
          if (url.includes("/api/v1/audit/ingest")) {
            auditCalls.push(JSON.parse(String(init?.body ?? "{}")));
            return jsonResponse({ ok: true });
          }
          return sseResponse(frames);
        });
        const uninstall = installFetchInterceptor(
          baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
        );
        const r = await fetch(
          "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
          {
            method: "POST",
            body: JSON.stringify({ contents: [], stream: true }),
          },
        );
        const text = await readSSE(r);
        for (const f of frames) expect(text).toContain(f);
        expect(r.headers.get("x-agentum-policy")).toBeNull();
        await new Promise((r) => setTimeout(r, 20));
        const ev1 = auditCalls.find(
          (c) => c["event_type"] === "audit.streaming_unenforced",
        );
        expect(ev1).toBeDefined();
        const detail = ev1!["detail"] as Record<string, unknown>;
        expect(detail["provider"]).toBe("gemini");
        expect(detail["shape"]).toBe("gemini-generate");
        uninstall();
      } finally {
        if (previous === undefined) delete process.env["AGENTUM_STREAM_PASSTHROUGH"];
        else process.env["AGENTUM_STREAM_PASSTHROUGH"] = previous;
      }
    });

    it("streaming text-only chunks forward verbatim with sdk-enforced header", async () => {
      const ev = fakeEvaluator({});
      const frames = [
        `data: ${JSON.stringify({
          candidates: [
            { content: { parts: [{ text: "hi" }], role: "model" } },
          ],
        })}\n\n`,
        `data: ${JSON.stringify({
          candidates: [
            { content: { parts: [{ text: " world" }], role: "model" }, finishReason: "STOP" },
          ],
        })}\n\n`,
      ];
      const up = mockUpstream(() => sseResponse(frames));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        {
          method: "POST",
          body: JSON.stringify({ contents: [], stream: true }),
        },
      );
      const text = await readSSE(r);
      for (const f of frames) expect(text).toContain(f);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });

    it("streaming denied functionCall is rewritten to a text part", async () => {
      const ev = fakeEvaluator({
        send_email: { decision: "deny", ttlMs: 0, reason: "no smtp" },
      });
      const frames = [
        `data: ${JSON.stringify({
          candidates: [
            { content: { parts: [{ text: "I'll email her." }], role: "model" } },
          ],
        })}\n\n`,
        `data: ${JSON.stringify({
          candidates: [
            {
              content: {
                parts: [
                  { functionCall: { name: "send_email", args: { to: "x@y.z" } } },
                ],
                role: "model",
              },
              finishReason: "STOP",
            },
          ],
        })}\n\n`,
      ];
      const up = mockUpstream(() => sseResponse(frames));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        {
          method: "POST",
          body: JSON.stringify({ contents: [], stream: true }),
        },
      );
      const text = await readSSE(r);
      // First (text-only) chunk must reach the consumer verbatim.
      expect(text).toContain("I'll email her.");
      // The chunk that carried the functionCall must be DROPPED — no leak.
      expect(text).not.toContain(`"functionCall"`);
      expect(text).not.toContain(`"send_email"`);
      // Synthetic deny: a text part with the notice + finishReason: STOP.
      expect(text).toContain("Agentum blocked send_email");
      expect(text).toContain(`"finishReason":"STOP"`);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });

    it(":streamGenerateContent classifies and enforces denies (A13)", async () => {
      // Before A13 the streaming variant was deliberately unclassified
      // and slipped past the SDK plane entirely. Same wire shape and
      // deny rewriter as :generateContent.
      const ev = fakeEvaluator({
        send_email: { decision: "deny", ttlMs: 0, reason: "no smtp" },
      });
      const frames = [
        `data: ${JSON.stringify({
          candidates: [
            { content: { parts: [{ text: "I'll email her." }], role: "model" } },
          ],
        })}\n\n`,
        `data: ${JSON.stringify({
          candidates: [
            {
              content: {
                parts: [
                  { functionCall: { name: "send_email", args: { to: "x@y.z" } } },
                ],
                role: "model",
              },
              finishReason: "STOP",
            },
          ],
        })}\n\n`,
      ];
      const up = mockUpstream(() => sseResponse(frames));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse",
        {
          method: "POST",
          body: JSON.stringify({ contents: [] }),
        },
      );
      const text = await readSSE(r);
      // First (text-only) chunk reaches the consumer verbatim.
      expect(text).toContain("I'll email her.");
      // The functionCall chunk MUST be dropped — no leak.
      expect(text).not.toContain(`"functionCall"`);
      expect(text).not.toContain(`"send_email"`);
      // Synthetic deny: text part with notice + finishReason normalised.
      expect(text).toContain("Agentum blocked send_email");
      expect(text).toContain(`"finishReason":"STOP"`);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });
  });

  // ── Bedrock (GR-18) ───────────────────────────────────────────────────────
  describe("Bedrock", () => {
    const CONVERSE_URL =
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet/converse";
    const CONVERSE_STREAM_URL =
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet/converse-stream";
    const INVOKE_URL =
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet/invoke";
    const INVOKE_STREAM_URL =
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet/invoke-with-response-stream";

    it("Converse deny rewrite: toolUse dropped, notice + end_turn, sdk-enforced", async () => {
      const ev = fakeEvaluator({
        get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" },
      });
      const respBody = {
        output: {
          message: {
            role: "assistant",
            content: [
              { text: "let me check" },
              { toolUse: { toolUseId: "tu_1", name: "get_weather", input: { city: "Paris" } } },
            ],
          },
        },
        stopReason: "tool_use",
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(CONVERSE_URL, {
        method: "POST",
        body: JSON.stringify({ messages: [], toolConfig: {} }),
      });
      const json = (await r.json()) as {
        output: { message: { content: Array<Record<string, unknown>> } };
        stopReason: string;
      };
      const blocks = json.output.message.content;
      expect(blocks.some((b) => b["toolUse"] !== undefined)).toBe(false);
      expect(JSON.stringify(blocks)).toContain("Agentum blocked get_weather");
      expect(json.stopReason).toBe("end_turn");
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      uninstall();
    });

    it("Converse allow → byte-identical pass-through", async () => {
      const ev = fakeEvaluator({});
      const respBody = {
        output: {
          message: {
            role: "assistant",
            content: [{ toolUse: { toolUseId: "tu_1", name: "ok_tool", input: {} } }],
          },
        },
        stopReason: "tool_use",
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(CONVERSE_URL, {
        method: "POST",
        body: JSON.stringify({ messages: [] }),
      });
      const json = (await r.json()) as typeof respBody;
      expect(json).toEqual(respBody);
      uninstall();
    });

    it("Converse pre-flight deny short-circuits with the Converse deny envelope", async () => {
      const ev = fakeEvaluator({ rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" } });
      const up = mockUpstream(() => jsonResponse({ should: "not reach" }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(CONVERSE_URL, {
        method: "POST",
        body: JSON.stringify({
          messages: [
            {
              role: "assistant",
              content: [{ toolUse: { toolUseId: "tu_1", name: "rm_rf", input: { path: "/" } } }],
            },
          ],
        }),
      });
      expect(up.calls).toHaveLength(0);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-denied");
      const json = (await r.json()) as {
        output: { message: { content: Array<Record<string, unknown>> } };
        stopReason: string;
      };
      expect(json.stopReason).toBe("end_turn");
      expect(JSON.stringify(json.output.message.content)).toContain("Agentum blocked rm_rf");
      uninstall();
    });

    it("Converse-stream deny: denied toolUse frames dropped, synthetic notice/messageStop decode", async () => {
      const ev = fakeEvaluator({ get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" } });
      const frames = bedrockEventStreamResponse([
        encodeBedrockEventStreamMessage("messageStart", { role: "assistant" }),
        encodeBedrockEventStreamMessage("contentBlockStart", {
          contentBlockIndex: 0,
          start: { toolUse: { toolUseId: "tu_1", name: "get_weather" } },
        }),
        encodeBedrockEventStreamMessage("contentBlockDelta", {
          contentBlockIndex: 0,
          delta: { toolUse: { input: `{"city":"Paris"}` } },
        }),
        encodeBedrockEventStreamMessage("contentBlockStop", { contentBlockIndex: 0 }),
        encodeBedrockEventStreamMessage("messageStop", { stopReason: "tool_use" }),
      ]);
      const up = mockUpstream(() => frames);
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(CONVERSE_STREAM_URL, {
        method: "POST",
        body: JSON.stringify({ messages: [], stream: true }),
      });
      // Decode the rewritten binary stream back through the parser and assert
      // no tool-call survived + the synthetic notice text is present.
      const parser = new BedrockConverseStreamParser();
      const reader = r.body!.getReader();
      const events: WireEvent[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        events.push(...parser.feed(value));
      }
      events.push(...parser.flush());
      expect(events.some((e) => e.kind === "tool-call-start")).toBe(false);
      const text = events
        .filter((e) => e.kind === "text-delta")
        .map((e) => (e as Extract<WireEvent, { kind: "text-delta" }>).text)
        .join("");
      expect(text).toContain("Agentum blocked get_weather");
      const finish = events.find((e) => e.kind === "finish");
      expect((finish as Extract<WireEvent, { kind: "finish" }>).finishReason).toBe("end_turn");
      uninstall();
    });

    it("Invoke (anthropic-on-bedrock) non-streaming deny → anthropic-style rewrite", async () => {
      const ev = fakeEvaluator({ lookup: { decision: "deny", ttlMs: 0, reason: "nope" } });
      const respBody = {
        id: "msg_1",
        type: "message",
        role: "assistant",
        content: [{ type: "tool_use", id: "toolu_1", name: "lookup", input: { id: 1 } }],
        stop_reason: "tool_use",
      };
      const up = mockUpstream(() => jsonResponse(respBody));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(INVOKE_URL, {
        method: "POST",
        body: JSON.stringify({ anthropic_version: "bedrock-2023-05-31", messages: [] }),
      });
      const json = (await r.json()) as {
        content: Array<Record<string, unknown>>;
        stop_reason: string;
      };
      expect(json.content.some((b) => b["type"] === "tool_use")).toBe(false);
      expect(json.content[0]!["type"]).toBe("text");
      expect(json.stop_reason).toBe("end_turn");
      uninstall();
    });

    it("Invoke-with-response-stream deny: denied tool_use frames dropped, anthropic notice triplet decodes", async () => {
      // Strongest parity gap: the anthropic-on-bedrock InvokeModel stream
      // (base64 chunk frames wrapping Anthropic stream events) was only ever
      // parser-proven — never driven through a real transport on ANY plane.
      // Feed `encodeBedrockInvokeChunk` frames in, then decode the rewritten
      // binary stream back through `BedrockInvokeStreamParser` and assert the
      // tool turn was replaced by the synthetic text-notice triplet.
      const ev = fakeEvaluator({ lookup: { decision: "deny", ttlMs: 0, reason: "nope" } });
      const frames = bedrockEventStreamResponse([
        encodeBedrockInvokeChunk({ type: "message_start", message: { role: "assistant" } }),
        encodeBedrockInvokeChunk({
          type: "content_block_start",
          index: 0,
          content_block: { type: "tool_use", id: "toolu_1", name: "lookup" },
        }),
        encodeBedrockInvokeChunk({
          type: "content_block_delta",
          index: 0,
          delta: { type: "input_json_delta", partial_json: `{"id":1}` },
        }),
        encodeBedrockInvokeChunk({ type: "content_block_stop", index: 0 }),
        // stop_reason rides on the terminal message_stop; on deny the whole
        // tool turn is suppressed so "tool_use" never reaches the consumer.
        encodeBedrockInvokeChunk({ type: "message_stop", delta: { stop_reason: "tool_use" } }),
      ]);
      const up = mockUpstream(() => frames);
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch(INVOKE_STREAM_URL, {
        method: "POST",
        body: JSON.stringify({ anthropic_version: "bedrock-2023-05-31", messages: [], stream: true }),
      });
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-enforced");
      // Decode the rewritten binary stream back through the invoke parser.
      const parser = new BedrockInvokeStreamParser();
      const reader = r.body!.getReader();
      const events: WireEvent[] = [];
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        events.push(...parser.feed(value));
      }
      events.push(...parser.flush());
      // No tool-call survived the rewrite.
      expect(events.some((e) => e.kind === "tool-call-start")).toBe(false);
      // The denied tool's terminal stop_reason ("tool_use") was suppressed —
      // no `finish` event leaks the tool turn.
      expect(events.some((e) => e.kind === "finish")).toBe(false);
      // The synthetic notice arrived as a text delta.
      const text = events
        .filter((e) => e.kind === "text-delta")
        .map((e) => (e as Extract<WireEvent, { kind: "text-delta" }>).text)
        .join("");
      expect(text).toContain("Agentum blocked lookup");
      uninstall();
    });

    it("fail-CLOSED: evaluator throws on Converse pre-flight deny denies the request", async () => {
      const throwing = {
        evaluateToolCall: jest.fn(async () => {
          throw new Error("evaluator down");
        }),
        invalidateAll: jest.fn(),
      } as unknown as CedarToolCallClient;
      const up = mockUpstream(() => jsonResponse({ should: "not reach" }));
      const uninstall = installFetchInterceptor(
        baseOpts(throwing, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }),
      );
      const r = await fetch(CONVERSE_URL, {
        method: "POST",
        body: JSON.stringify({
          messages: [
            {
              role: "assistant",
              content: [{ toolUse: { toolUseId: "tu_1", name: "get_weather", input: {} } }],
            },
          ],
        }),
      });
      expect(up.calls).toHaveLength(0);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-denied");
      uninstall();
    });
  });
});

// ── R40: observe-prompt PII masking + promptCaptureMode ─────────────────────

describe("fetch-interceptor — R40 observe-prompt PII masking", () => {
  // Reset the active PII scanner between tests so masking config does not
  // leak across cases (per .claude/rules/tests.md). The patched-fetch
  // Symbol is cleared by the top-level afterEach (deletes globalThis.fetch).
  afterEach(() => {
    _resetActiveTextScannerForTests();
  });

  function observeUpstream(): {
    up: MockUpstream;
    observed: Array<Record<string, unknown>>;
  } {
    const observed: Array<Record<string, unknown>> = [];
    const up = mockUpstream(async (url, init) => {
      if (url.includes("/sdk/observe-prompt")) {
        observed.push(JSON.parse(String(init?.body ?? "{}")));
        return jsonResponse({ ok: true, request_id: "x" });
      }
      return jsonResponse({
        id: "x",
        choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }],
      });
    });
    return { up, observed };
  }

  // Build options WITHOUT the legacy `capturePrompts` key so the resolver
  // honors `promptCaptureMode`. `baseOpts` hardcodes `capturePrompts: false`
  // (which would force "off"), so the R40 mode cases construct opts directly.
  function modeOpts(
    ev: CedarToolCallClient,
    fetchImpl: typeof fetch,
    mode: "masked" | "raw" | "off",
  ): FetchInterceptorOptions {
    return {
      runtime: { baseUrl: "http://agentum.test:7071", apiKey: "ak_test", evaluator: ev },
      agentId: "a-1",
      hosts: new HostRegistry(),
      failMode: "allow",
      promptCaptureMode: mode,
      syncObserve: true,
      fetchImpl,
      logger: silentLogger(),
    };
  }

  // Fail-CLOSED first: a scanner whose mask itself re-matches forces a
  // PiiSelfCheckFailedError out of the pipeline → the observe POST MUST be
  // dropped (no raw content leaves the agent).
  it("masked mode: pipeline self-check failure drops the observe POST (fail-closed)", async () => {
    // Mask output `***pii***` itself contains `pii`, so Stage D's re-scan
    // keeps matching → PiiSelfCheckFailedError (same trick as the pipeline
    // unit tests).
    _setActiveTextScanner(
      compileScanner({
        enabled: true,
        patterns: [],
        custom: [{ id: "pii", pattern: "pii", severity: "high" }],
      }),
    );
    const ev = fakeEvaluator({});
    const { up, observed } = observeUpstream();
    const uninstall = installFetchInterceptor(
      modeOpts(ev, up.fetchImpl as unknown as typeof fetch, "masked"),
    );
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "this has pii here" }] }),
    });
    // No observe-prompt POST happened; only the upstream LLM call.
    expect(observed).toHaveLength(0);
    expect(up.calls.some((c) => c.url.includes("/sdk/observe-prompt"))).toBe(false);
    uninstall();
  });

  it("masked mode (default) runs the pipeline; observe body carries masked content", async () => {
    _setActiveTextScanner(compileScanner({ enabled: true, patterns: ["email"] }));
    const ev = fakeEvaluator({});
    const { up, observed } = observeUpstream();
    // Default mode is masked — pass neither capturePrompts nor mode.
    const uninstall = installFetchInterceptor({
      runtime: { baseUrl: "http://agentum.test:7071", apiKey: "ak_test", evaluator: ev },
      agentId: "a-1",
      hosts: new HostRegistry(),
      failMode: "allow",
      syncObserve: true,
      fetchImpl: up.fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
    });
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-4",
        messages: [{ role: "user", content: "ping alice@example.com" }],
      }),
    });
    expect(observed).toHaveLength(1);
    const msgs = observed[0]!["messages"] as Array<Record<string, unknown>>;
    const content = String(msgs[0]!["content"]);
    expect(content).toContain("***email***");
    expect(content).not.toContain("alice@example.com");
    uninstall();
  });

  it("off mode sends NO observe POST (still forwards the LLM call)", async () => {
    _setActiveTextScanner(compileScanner({ enabled: true, patterns: ["email"] }));
    const ev = fakeEvaluator({});
    const { up, observed } = observeUpstream();
    const uninstall = installFetchInterceptor(
      modeOpts(ev, up.fetchImpl as unknown as typeof fetch, "off"),
    );
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "ping alice@example.com" }] }),
    });
    expect(r.status).toBe(200);
    expect(observed).toHaveLength(0);
    // The upstream LLM call still went out.
    expect(up.calls.some((c) => c.url.includes("/v1/chat/completions"))).toBe(true);
    uninstall();
  });

  it("raw mode sends UNMASKED content even with a scanner configured", async () => {
    _setActiveTextScanner(compileScanner({ enabled: true, patterns: ["email"] }));
    const ev = fakeEvaluator({});
    const { up, observed } = observeUpstream();
    const uninstall = installFetchInterceptor(
      modeOpts(ev, up.fetchImpl as unknown as typeof fetch, "raw"),
    );
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "ping alice@example.com" }] }),
    });
    expect(observed).toHaveLength(1);
    const msgs = observed[0]!["messages"] as Array<Record<string, unknown>>;
    expect(String(msgs[0]!["content"])).toContain("alice@example.com");
    uninstall();
  });

  // OPEN-22 / INTEG-B1 — the addon feature-state must be re-read PER REQUEST,
  // and the PII gate fails CLOSED to the SAFE (masked) default. With the old
  // install-time bake, a "raw" pin stayed "raw" forever. Under the new
  // tri-state semantics:
  //   - "unknown" (no PDP snapshot yet)  → raw upgraded to MASKED (safe)
  //   - "enabled" (pii-advanced on)      → raw honored
  //   - "disabled" (pii-advanced absent) → raw upgraded to MASKED
  it("re-reads pii-advanced feature state per-request — unknown→masked, enabled→raw, disabled→masked", async () => {
    _setActiveTextScanner(compileScanner({ enabled: true, patterns: ["email"] }));
    // Mutable tri-state the test flips between requests.
    let state: "enabled" | "disabled" | "unknown" = "unknown";
    const ev = {
      evaluateToolCall: jest.fn(async () => ({ decision: "allow", ttlMs: 0 })),
      invalidateAll: jest.fn(),
      featureState: (id: string) =>
        id === "addon.policy.pii-advanced" ? state : "unknown",
    } as unknown as CedarToolCallClient;
    const { up, observed } = observeUpstream();
    const uninstall = installFetchInterceptor(
      modeOpts(ev, up.fetchImpl as unknown as typeof fetch, "raw"),
    );

    const post = () =>
      fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({
          model: "gpt-4",
          messages: [{ role: "user", content: "ping alice@example.com" }],
        }),
      });
    const contentOf = (i: number): string =>
      String((observed[i]!["messages"] as Array<Record<string, unknown>>)[0]!["content"]);

    // Request 1: "unknown" (no snapshot) → SAFE default → masked.
    await post();
    expect(observed).toHaveLength(1);
    expect(contentOf(0)).toContain("***email***");
    expect(contentOf(0)).not.toContain("alice@example.com");

    // PDP populates a bundle WITH pii-advanced → raw honored.
    state = "enabled";
    await post();
    expect(observed).toHaveLength(2);
    expect(contentOf(1)).toContain("alice@example.com");

    // pii-advanced turned OFF (populated-then-emptied) → masked again.
    state = "disabled";
    await post();
    expect(observed).toHaveLength(3);
    expect(contentOf(2)).toContain("***email***");
    expect(contentOf(2)).not.toContain("alice@example.com");
    uninstall();
  });

  it("legacy capturePrompts=false maps to off (no observe POST)", async () => {
    const ev = fakeEvaluator({});
    const { up, observed } = observeUpstream();
    const uninstall = installFetchInterceptor(
      baseOpts(ev, up.fetchImpl as unknown as typeof fetch, {
        capturePrompts: false,
        syncObserve: true,
      }),
    );
    await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ model: "gpt-4", messages: [{ role: "user", content: "x" }] }),
    });
    expect(observed).toHaveLength(0);
    uninstall();
  });

  // ── R50: vault placeholder in a request BODY → fail-CLOSED ────────────────
  describe("vault body placeholder fail-closed (R50)", () => {
    const PH = "agentum://SECRET/lease_abc123";

    it("string body with a placeholder throws and never forwards upstream", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => jsonResponse({ id: "x" }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      await expect(
        fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          body: JSON.stringify({ model: "gpt-4", token: PH, messages: [] }),
        }),
      ).rejects.toThrow(/body contains an agentum:\/\/SECRET/);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });

    it("non-LLM URL with a placeholder body also fails closed", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      await expect(
        fetch("https://example.com/webhook", {
          method: "POST",
          body: `{"secret":"${PH}"}`,
        }),
      ).rejects.toThrow(/body resolution is not supported/);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });

    it("Uint8Array body with a placeholder fails closed", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const bytes = new TextEncoder().encode(`{"secret":"${PH}"}`);
      await expect(
        fetch("https://example.com/webhook", { method: "POST", body: bytes }),
      ).rejects.toThrow(/body contains an agentum:\/\/SECRET/);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });

    it("Request input whose body carries a placeholder fails closed", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const req = new Request("https://example.com/webhook", {
        method: "POST",
        body: `{"secret":"${PH}"}`,
      });
      await expect(fetch(req)).rejects.toThrow(/body contains an agentum:\/\/SECRET/);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });

    it("placeholder only in a HEADER still resolves and forwards (header path unchanged)", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      // Resolver hits POST /api/v1/vault/resolve on the runtime baseUrl; the
      // interceptor passes the ORIGINAL fetch as the resolver's fetchImpl, so
      // the mock upstream sees the resolve call too. Return the secret value
      // for that endpoint, "ok" for everything else.
      const upWithResolve = mockUpstream((url) => {
        if (url.includes("/api/v1/vault/resolve")) {
          return jsonResponse({ value: "real-secret-token" });
        }
        return new Response("ok", { status: 200 });
      });
      const uninstall = installFetchInterceptor(
        baseOpts(ev, upWithResolve.fetchImpl as unknown as typeof fetch),
      );
      const r = await fetch("https://example.com/webhook", {
        method: "POST",
        headers: { Authorization: `Bearer ${PH}` },
        body: JSON.stringify({ benign: "payload" }),
      });
      expect(r.status).toBe(200);
      const upstreamCall = upWithResolve.calls.find((c) => c.url === "https://example.com/webhook");
      expect(upstreamCall).toBeDefined();
      const hdrs = upstreamCall!.init!.headers as [string, string][];
      const auth = hdrs.find((h) => h[0] === "Authorization");
      expect(auth![1]).toBe("Bearer real-secret-token");
      // Quiet the unused-evaluator lint by referencing it.
      expect(ev.evaluateToolCall).toBeDefined();
      uninstall();
    });

    it("non-scannable body type (URLSearchParams) passes through (documented limitation)", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch),
      );
      const params = new URLSearchParams({ secret: PH });
      const r = await fetch("https://example.com/webhook", { method: "POST", body: params });
      expect(r.status).toBe(200);
      expect(up.calls).toHaveLength(1);
      uninstall();
    });
  });

  // ── PDPC-A4: skip in-process vault resolve for R22 destinations ───────────
  describe("vault resolve skipped for R22 destinations (PDPC-A4)", () => {
    const PDP_PROXY = "http://127.0.0.1:7081";

    beforeEach(() => {
      _resetVaultCacheForTests();
    });

    it("R22-bound header placeholder is forwarded verbatim; /vault/resolve is NOT called", async () => {
      const PH = "agentum://SECRET/lease_r22_fwd";
      const ev = fakeEvaluator({});
      // R22 destination shares the configured proxy origin. The placeholder
      // must reach R22 untouched; the SDK must not call /api/v1/vault/resolve.
      const up = mockUpstream((url) => {
        if (url.includes("/api/v1/vault/resolve")) {
          throw new Error("in-process resolve must NOT run for R22 destinations");
        }
        return new Response("ok", { status: 200 });
      });
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { pdpProxyUrl: PDP_PROXY }),
      );
      const r = await fetch(`${PDP_PROXY}/v1/chat/completions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${PH}` },
        body: JSON.stringify({ benign: "payload" }),
      });
      expect(r.status).toBe(200);
      // No resolve call happened.
      expect(up.calls.some((c) => c.url.includes("/api/v1/vault/resolve"))).toBe(false);
      // The placeholder was forwarded to R22 verbatim.
      const proxied = up.calls.find((c) => c.url === `${PDP_PROXY}/v1/chat/completions`);
      expect(proxied).toBeDefined();
      const hdrs = proxied!.init!.headers as Record<string, string> | [string, string][];
      const authValue = Array.isArray(hdrs)
        ? hdrs.find((h) => h[0] === "Authorization")?.[1]
        : (hdrs as Record<string, string>)["Authorization"];
      expect(authValue).toBe(`Bearer ${PH}`);
      uninstall();
    });

    it("non-R22 destination still resolves the header placeholder in-process", async () => {
      const PH = "agentum://SECRET/lease_non_r22";
      const ev = fakeEvaluator({});
      const up = mockUpstream((url) => {
        if (url.includes("/api/v1/vault/resolve")) {
          return jsonResponse({ value: "real-secret-token" });
        }
        return new Response("ok", { status: 200 });
      });
      // pdpProxyUrl is configured, but the destination origin differs.
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { pdpProxyUrl: PDP_PROXY }),
      );
      const r = await fetch("https://example.com/webhook", {
        method: "POST",
        headers: { Authorization: `Bearer ${PH}` },
        body: JSON.stringify({ benign: "payload" }),
      });
      expect(r.status).toBe(200);
      // The in-process resolve ran.
      expect(up.calls.some((c) => c.url.includes("/api/v1/vault/resolve"))).toBe(true);
      const upstreamCall = up.calls.find((c) => c.url === "https://example.com/webhook");
      const hdrs = upstreamCall!.init!.headers as [string, string][];
      const auth = hdrs.find((h) => h[0] === "Authorization");
      expect(auth![1]).toBe("Bearer real-secret-token");
      uninstall();
    });

    it("R50 body-placeholder guard still throws even for R22 destinations", async () => {
      const PH = "agentum://SECRET/lease_r22_body";
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(
        baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { pdpProxyUrl: PDP_PROXY }),
      );
      await expect(
        fetch(`${PDP_PROXY}/v1/chat/completions`, {
          method: "POST",
          body: JSON.stringify({ model: "gpt-4", token: PH, messages: [] }),
        }),
      ).rejects.toThrow(/body contains an agentum:\/\/SECRET/);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });
  });

  // ── GR-19: MCP Streamable-HTTP ────────────────────────────────────────────
  describe("MCP Streamable-HTTP (GR-19)", () => {
    const MCP_URL = "https://mcp.example.test/mcp";
    const DUAL = "application/json, text/event-stream";

    function toolsCallBody(name: string, args: Record<string, unknown> = {}): string {
      return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } });
    }

    /** Wrap a fake evaluator with a spyable `emitMcpAudit`. */
    function withAudit(ev: CedarToolCallClient): CedarToolCallClient & { emitMcpAudit: jest.Mock } {
      const emitMcpAudit = jest.fn();
      (ev as unknown as { emitMcpAudit: jest.Mock }).emitMcpAudit = emitMcpAudit;
      return ev as CedarToolCallClient & { emitMcpAudit: jest.Mock };
    }

    afterEach(() => {
      _resetMcpServerMap();
      _resetMcpSuppression();
    });

    it("denies a tools/call on an unregistered host with a spec-legal isError result; upstream never called", async () => {
      const ev = withAudit(fakeEvaluator({ search: { decision: "deny", ttlMs: 0, reason: "no allow rule" } }));
      const up = mockUpstream(() => new Response("UPSTREAM", { status: 200 }));
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
      const r = await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("search", { q: "x" }) });
      expect(r.status).toBe(200);
      expect(r.headers.get("x-agentum-policy")).toBe("sdk-denied");
      const json = (await r.json()) as { jsonrpc: string; id: number; result: { isError: boolean; content: Array<{ text: string }> } };
      expect(json.jsonrpc).toBe("2.0");
      expect(json.id).toBe(1);
      expect(json.result.isError).toBe(true);
      expect(json.result.content[0]!.text).toContain("denied by policy");
      // Upstream MCP server was never contacted.
      expect(up.calls).toHaveLength(0);
      // Audit emitted as a transport: "http" deny.
      const auditArg = ev.emitMcpAudit.mock.calls[0]![0] as { eventType: string; detail: { transport: string } };
      expect(auditArg.eventType).toBe("mcp_tool_deny");
      expect(auditArg.detail.transport).toBe("http");
      uninstall();
    });

    it("allows a tools/call and forwards to upstream once", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream(() => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [], isError: false } }), { status: 200, headers: { "content-type": "application/json" } }));
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
      const r = await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("search") });
      expect(r.status).toBe(200);
      expect(up.calls).toHaveLength(1);
      expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(1);
      uninstall();
    });

    it("captures server name from an application/json initialize, then namespaces the tools/call action", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream((_url, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        if (body.includes("initialize")) {
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { serverInfo: { name: "filesystem" } } }), {
            status: 200,
            headers: { "content-type": "application/json", "mcp-session-id": "sess-9" },
          });
        }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 2, result: { content: [], isError: false } }), { status: 200, headers: { "content-type": "application/json" } });
      });
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
      await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
      await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("read") });
      const evalArg = (ev.evaluateToolCall as jest.Mock).mock.calls[0]![0] as { toolName: string };
      expect(evalArg.toolName).toBe("read_mcp_filesystem");
      uninstall();
    });

    it("captures server name from an SSE initialize response", async () => {
      const ev = fakeEvaluator({});
      const up = mockUpstream((_url, init) => {
        const body = typeof init?.body === "string" ? init.body : "";
        if (body.includes("initialize")) {
          const frame = `event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: 1, result: { serverInfo: { name: "weather" } } })}\n\n`;
          return sseResponse([frame]);
        }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 2, result: { content: [], isError: false } }), { status: 200, headers: { "content-type": "application/json" } });
      });
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch));
      const initResp = await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) });
      // Drain the teed pass branch so the scan branch completes.
      await initResp.text();
      // Give the detached scan microtask a tick to record.
      await new Promise((r) => setTimeout(r, 5));
      await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("forecast") });
      const evalArg = (ev.evaluateToolCall as jest.Mock).mock.calls[0]![0] as { toolName: string };
      expect(evalArg.toolName).toBe("forecast_mcp_weather");
      uninstall();
    });

    it("skips SDK-own origin (central baseUrl)", async () => {
      const ev = fakeEvaluator({ search: { decision: "deny", ttlMs: 0 } });
      const up = mockUpstream(() => new Response("ok", { status: 200 }));
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
      // baseUrl is http://agentum.test:7071
      const r = await fetch("http://agentum.test:7071/mcp", { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("search") });
      expect(r.status).toBe(200);
      expect(up.calls).toHaveLength(1);
      expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
      uninstall();
    });

    it("fail-CLOSED: evaluator transport error denies (failMode default deny)", async () => {
      const evalFn = jest.fn(async () => { throw new Error("transport down"); });
      const ev = { evaluateToolCall: evalFn, invalidateAll: jest.fn() } as unknown as CedarToolCallClient;
      const up = mockUpstream(() => new Response("UPSTREAM", { status: 200 }));
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
      const r = await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("search") });
      const json = (await r.json()) as { result: { isError: boolean } };
      expect(json.result.isError).toBe(true);
      expect(up.calls).toHaveLength(0);
      uninstall();
    });

    it("suppression token: a marked call forwards without re-evaluation", async () => {
      const ev = fakeEvaluator({ search: { decision: "deny", ttlMs: 0 } });
      const up = mockUpstream(() => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), { status: 200, headers: { "content-type": "application/json" } }));
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
      // The stdio patch would have marked this exact (action, args) on allow.
      markMcpCallEvaluated("search", { q: "z" });
      const r = await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: toolsCallBody("search", { q: "z" }) });
      expect(r.status).toBe(200);
      expect(up.calls).toHaveLength(1);
      // Suppressed → evaluator never consulted despite a deny rule.
      expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
      uninstall();
    });

    it("non-jsonrpc dual-Accept POST forwards byte-identically", async () => {
      const ev = fakeEvaluator({});
      let seenBody = "";
      const up = mockUpstream((_url, init) => {
        seenBody = typeof init?.body === "string" ? init.body : "";
        return new Response("ok", { status: 200 });
      });
      const uninstall = installFetchInterceptor(baseOpts(ev, up.fetchImpl as unknown as typeof fetch, { failMode: "deny" }));
      const raw = JSON.stringify({ hello: "world", nested: [1, 2, 3] });
      await fetch(MCP_URL, { method: "POST", headers: { accept: DUAL }, body: raw });
      expect(up.calls).toHaveLength(1);
      expect(seenBody).toBe(raw);
      expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
      uninstall();
    });
  });
});
