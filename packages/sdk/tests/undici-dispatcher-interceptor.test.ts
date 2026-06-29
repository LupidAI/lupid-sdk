/**
 * Unit tests for the undici global-dispatcher interception plane (R24).
 *
 * The interceptor is exercised with a fake dispatcher (injected via
 * `opts.dispatcher`) and a fake `CedarToolCallClient`. No real network, no
 * real undici. We assert on the dispatch opts the fake dispatcher receives
 * (origin/path/headers) and on the synthetic handler callbacks for the deny
 * path.
 */

import {
  installUndiciDispatcherInterceptor,
  type UndiciDispatcher,
  type UndiciDispatcherInterceptorOptions,
} from "../src/instrumentation/undici-dispatcher-interceptor";
import { HostRegistry } from "../src/instrumentation/host-registry";
import { withAgentumContext } from "../src/instrumentation/context";
import {
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "../src/evaluation/cedar-client";
import {
  markMcpCallEvaluated,
  _resetMcpSuppression,
} from "../src/instrumentation/mcp-http";
import {
  encodeBedrockEventStreamMessage,
  BedrockConverseStreamParser,
  type WireEvent,
} from "../src/instrumentation/wire-parsers";

const PATCHED_TAG = Symbol.for("agentum.undici_dispatcher.patched");
const PLANE_HEADER = "x-agentum-plane";

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
  return {
    evaluateToolCall: evalFn,
    invalidateAll: jest.fn(),
  } as unknown as CedarToolCallClient;
}

interface DispatchedCall {
  opts: Record<string, unknown>;
  handler: Record<string, unknown>;
}

/**
 * Fake undici dispatcher. Records every `dispatch` it receives. The `forward`
 * flag controls whether the original (pre-wrap) dispatch synthesizes a benign
 * upstream completion through the handler callbacks (so the allow path can
 * assert the call went through).
 */
function fakeDispatcher(): {
  dispatcher: UndiciDispatcher;
  calls: DispatchedCall[];
} {
  const calls: DispatchedCall[] = [];
  const dispatcher: UndiciDispatcher = {
    dispatch(opts, handler): boolean {
      calls.push({
        opts: opts as unknown as Record<string, unknown>,
        handler: handler as unknown as Record<string, unknown>,
      });
      return true;
    },
  };
  return { dispatcher, calls };
}

function baseOpts(
  dispatcher: UndiciDispatcher,
  evaluator: CedarToolCallClient,
  extra: Partial<UndiciDispatcherInterceptorOptions> = {},
): UndiciDispatcherInterceptorOptions {
  return {
    runtime: {
      baseUrl: "http://localhost:7071",
      apiKey: "test-key",
      evaluator,
    },
    agentId: "agent-1",
    hosts: new HostRegistry(),
    failMode: "deny",
    logger: silentLogger(),
    dispatcher,
    ...extra,
  };
}

const REAL_NODE = process.versions.node;

afterEach(() => {
  // Restore the (possibly deleted) node version marker after edge-runtime test.
  if (!process.versions.node) {
    Object.defineProperty(process.versions, "node", {
      value: REAL_NODE,
      configurable: true,
      writable: true,
    });
  }
});

// ── install idempotency ──────────────────────────────────────────────────────

describe("install idempotency", () => {
  test("re-install on an already-patched dispatcher is a no-op (Symbol marker)", () => {
    const { dispatcher } = fakeDispatcher();
    const ev = fakeEvaluator({});

    const uninstall1 = installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    expect((dispatcher as unknown as Record<symbol, unknown>)[PATCHED_TAG]).toBe(true);
    const wrappedDispatch = dispatcher.dispatch;

    // Second install must NOT re-wrap.
    const uninstall2 = installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    expect(dispatcher.dispatch).toBe(wrappedDispatch);

    // Teardown from the first install restores the original dispatch and
    // clears the marker.
    uninstall1();
    expect((dispatcher as unknown as Record<symbol, unknown>)[PATCHED_TAG]).toBeUndefined();
    // Second teardown is harmless.
    uninstall2();
  });
});

// ── non-LLM passthrough ──────────────────────────────────────────────────────

describe("non-LLM passthrough", () => {
  test("non-LLM host is dispatched untouched", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    dispatcher.dispatch(
      { origin: "https://example.com", path: "/api/data", method: "GET" },
      {},
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("https://example.com");
    expect(calls[0]!.opts["path"]).toBe("/api/data");
    expect(ev.evaluateToolCall).not.toHaveBeenCalled();
  });

  test("LLM host but non-classifiable path passes through (no proxy mode)", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    // api.openai.com but a path classifyUrl returns shape:null for.
    dispatcher.dispatch(
      { origin: "https://api.openai.com", path: "/v1/models", method: "GET" },
      {},
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("https://api.openai.com");
    expect(calls[0]!.opts["path"]).toBe("/v1/models");
  });
});

// ── PDP-proxy routing mode (a) ───────────────────────────────────────────────

describe("PDP-proxy routing", () => {
  test("OpenAI chat call is rewritten to the proxy URL with provider segment", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: { authorization: "Bearer sk-app", "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      {},
    );

    expect(calls).toHaveLength(1);
    const opts = calls[0]!.opts;
    expect(opts["origin"]).toBe("http://127.0.0.1:7081");
    expect(opts["path"]).toBe("/proxy/openai/v1/chat/completions");
    // The app's provider key is preserved (passed through to the proxy).
    const headers = opts["headers"] as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer sk-app");
    // In-process evaluation is SKIPPED in proxy mode.
    expect(ev.evaluateToolCall).not.toHaveBeenCalled();
  });

  test("identity headers are injected from the active context", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    withAgentumContext(
      {
        sessionId: "sess-9",
        userId: "user-7",
        dimensions: { account_id: "acct-1", bot_id: "bot-2" },
      },
      () => {
        dispatcher.dispatch(
          {
            origin: "https://api.anthropic.com",
            path: "/v1/messages",
            method: "POST",
            headers: { "x-api-key": "ant-key" },
            body: JSON.stringify({ model: "claude", messages: [] }),
          },
          {},
        );
      },
    );

    const opts = calls[0]!.opts;
    expect(opts["origin"]).toBe("http://127.0.0.1:7081");
    expect(opts["path"]).toBe("/proxy/anthropic/v1/messages");
    const headers = opts["headers"] as Record<string, string>;
    expect(headers["X-Agentum-Session-Id"]).toBe("sess-9");
    expect(headers["X-Agentum-User-Id"]).toBe("user-7");
    expect(JSON.parse(headers["X-Agentum-Dimensions"]!)).toEqual({
      account_id: "acct-1",
      bot_id: "bot-2",
    });
    // Provider key still present.
    expect(headers["x-api-key"]).toBe("ant-key");
  });

  test("deepseek (openai-compatible, in the PDP builtin map) rewrites to the proxy", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    dispatcher.dispatch(
      {
        origin: "https://api.deepseek.com",
        path: "/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "deepseek-chat", messages: [] }),
      },
      {},
    );
    await new Promise((r) => setImmediate(r));

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("http://127.0.0.1:7081");
    expect(calls[0]!.opts["path"]).toBe("/proxy/deepseek/chat/completions");
  });

  test("unroutable openai-compatible provider in proxy mode falls back to in-process pre-flight", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    // together.xyz classifies as openai-compatible but is NOT in the PDP's
    // builtin upstream map → not rewritten, handled by mode (b) pre-flight
    // (no tool_calls here, so it forwards untouched).
    dispatcher.dispatch(
      {
        origin: "https://api.together.xyz",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "llama-3", messages: [] }),
      },
      {},
    );
    await new Promise((r) => setImmediate(r));

    expect(calls).toHaveLength(1);
    // Not rewritten to the proxy.
    expect(calls[0]!.opts["origin"]).toBe("https://api.together.xyz");
  });

  test("app-native proxy destination gets identity headers injected, no rewrite", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    // The app itself routes to the PDP proxy (e.g. DEEPSEEK_PROXY_URL).
    withAgentumContext(
      {
        sessionId: "native-sess",
        userId: "native-user",
        dimensions: { customer_id: "cust-42" },
      },
      () => {
        dispatcher.dispatch(
          {
            origin: "http://127.0.0.1:7081",
            path: "/proxy/deepseek/v1/chat/completions",
            method: "POST",
            headers: { authorization: "Bearer sk-x" },
            body: JSON.stringify({ model: "deepseek-chat", messages: [] }),
          },
          {},
        );
      },
    );

    expect(calls).toHaveLength(1);
    const opts = calls[0]!.opts;
    // Destination untouched.
    expect(opts["origin"]).toBe("http://127.0.0.1:7081");
    expect(opts["path"]).toBe("/proxy/deepseek/v1/chat/completions");
    const headers = opts["headers"] as Record<string, string>;
    expect(headers["X-Agentum-Session-Id"]).toBe("native-sess");
    expect(headers["X-Agentum-User-Id"]).toBe("native-user");
    expect(JSON.parse(headers["X-Agentum-Dimensions"]!)).toEqual({
      customer_id: "cust-42",
    });
    expect(headers["authorization"]).toBe("Bearer sk-x");
  });
});

// ── SDK-own-endpoint exemption ───────────────────────────────────────────────

describe("SDK-own-endpoint exemption", () => {
  test("central API base URL is never intercepted/rewritten", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    // Even with proxy mode on, the SDK's own base URL must pass through.
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    dispatcher.dispatch(
      {
        origin: "http://localhost:7071",
        path: "/api/v1/audit/ingest",
        method: "POST",
        body: JSON.stringify({ event_type: "x" }),
      },
      {},
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("http://localhost:7071");
    expect(calls[0]!.opts["path"]).toBe("/api/v1/audit/ingest");
  });

  test("PDP proxy URL itself is never re-routed (no recursion)", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(
      baseOpts(dispatcher, ev, { pdpProxyUrl: "http://127.0.0.1:7081" }),
    );

    dispatcher.dispatch(
      { origin: "http://127.0.0.1:7081", path: "/proxy/openai/v1/chat/completions" },
      {},
    );

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("http://127.0.0.1:7081");
    expect(calls[0]!.opts["path"]).toBe("/proxy/openai/v1/chat/completions");
  });
});

// ── edge-runtime no-op ───────────────────────────────────────────────────────

describe("edge runtime", () => {
  test("no process.versions.node → clean no-op, returns a teardown", () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    Object.defineProperty(process.versions, "node", {
      value: undefined,
      configurable: true,
      writable: true,
    });

    const teardown = installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    // Dispatcher must NOT be patched on edge.
    expect((dispatcher as unknown as Record<symbol, unknown>)[PATCHED_TAG]).toBeUndefined();
    expect(typeof teardown).toBe("function");
    teardown();
    expect(calls).toHaveLength(0);
  });
});

// ── mode (b) in-process pre-flight (fail-CLOSED first) ───────────────────────

describe("in-process pre-flight (mode b)", () => {
  test("FAIL-CLOSED: evaluator transport error denies the request", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const throwingEval = {
      evaluateToolCall: jest.fn(async () => {
        throw new Error("transport timeout");
      }),
      invalidateAll: jest.fn(),
    } as unknown as CedarToolCallClient;
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, throwingEval));

    const onHeaders = jest.fn();
    const onData = jest.fn();
    const onComplete = jest.fn();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [
            {
              role: "assistant",
              tool_calls: [
                { function: { name: "wire_money", arguments: "{}" } },
              ],
            },
          ],
        }),
      },
      {
        onConnect: () => {},
        onHeaders,
        onData,
        onComplete,
      },
    );
    await new Promise((r) => setImmediate(r));

    // Upstream was NOT dispatched.
    expect(calls).toHaveLength(0);
    // A synthetic deny response was emitted.
    expect(onHeaders).toHaveBeenCalledWith(
      200,
      expect.arrayContaining(["x-agentum-policy", "sdk-denied"]),
      expect.any(Function),
      "OK",
    );
    expect(onData).toHaveBeenCalledTimes(1);
    expect(onComplete).toHaveBeenCalledWith(null);
  });

  test("deny verdict synthesizes a provider-shaped response, no upstream", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({
      wire_money: { decision: "deny", ttlMs: 0, reason: "blocked by policy" },
    });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    let body = "";
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [
            {
              role: "assistant",
              tool_calls: [
                { function: { name: "wire_money", arguments: '{"amt":100}' } },
              ],
            },
          ],
        }),
      },
      {
        onConnect: () => {},
        onHeaders: () => true,
        onData: (chunk: Uint8Array) => {
          body += new TextDecoder().decode(chunk);
          return true;
        },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));

    expect(calls).toHaveLength(0);
    const json = JSON.parse(body) as { object?: string; choices?: unknown[] };
    expect(json.object).toBe("chat.completion");
    expect(Array.isArray(json.choices)).toBe(true);
  });

  test("allow verdict forwards to upstream untouched", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ search: { decision: "allow", ttlMs: 0 } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({
          model: "gpt-4o",
          messages: [
            {
              role: "assistant",
              tool_calls: [{ function: { name: "search", arguments: "{}" } }],
            },
          ],
        }),
      },
      {},
    );
    await new Promise((r) => setImmediate(r));

    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["origin"]).toBe("https://api.openai.com");
    expect(calls[0]!.opts["path"]).toBe("/v1/chat/completions");
    expect(ev.evaluateToolCall).toHaveBeenCalledWith({
      toolName: "search",
      arguments: {},
    });
  });

  // ── GR-18: Cohere / Gemini / Bedrock request-side parity ──────────────────

  test("Cohere deny synthesizes a NATIVE Cohere v2 envelope, no upstream", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ rm_rf: { decision: "deny", ttlMs: 0, reason: "destructive" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    let body = "";
    dispatcher.dispatch(
      {
        origin: "https://api.cohere.ai",
        path: "/v1/chat",
        method: "POST",
        body: JSON.stringify({
          model: "command-r",
          tool_calls: [{ name: "rm_rf", parameters: { path: "/" } }],
        }),
      },
      {
        onConnect: () => {},
        onHeaders: () => true,
        onData: (c: Uint8Array) => {
          body += new TextDecoder().decode(c);
          return true;
        },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(0);
    // NATIVE Cohere v2 chat envelope — NOT the OpenAI `{choices}` shape.
    const json = JSON.parse(body) as {
      choices?: unknown;
      finish_reason?: string;
      message?: { role: string; content: Array<{ type: string; text: string }> };
    };
    expect(json.choices).toBeUndefined();
    expect(json.finish_reason).toBe("COMPLETE");
    expect(json.message?.role).toBe("assistant");
    expect(json.message?.content?.[0]?.type).toBe("text");
    expect(json.message?.content?.[0]?.text).toContain("Agentum blocked rm_rf");
    expect(ev.evaluateToolCall).toHaveBeenCalledWith({ toolName: "rm_rf", arguments: { path: "/" } });
  });

  test("Gemini deny synthesizes a NATIVE Gemini envelope, no upstream", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ wipe: { decision: "deny", ttlMs: 0, reason: "no" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    let body = "";
    dispatcher.dispatch(
      {
        origin: "https://generativelanguage.googleapis.com",
        path: "/v1beta/models/gemini-pro:generateContent",
        method: "POST",
        body: JSON.stringify({
          contents: [{ role: "model", parts: [{ functionCall: { name: "wipe", args: { x: 1 } } }] }],
        }),
      },
      {
        onConnect: () => {},
        onHeaders: () => true,
        onData: (c: Uint8Array) => {
          body += new TextDecoder().decode(c);
          return true;
        },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(0);
    // NATIVE Gemini envelope — `{candidates:[...]}`, NOT OpenAI `{choices}`.
    const json = JSON.parse(body) as {
      choices?: unknown;
      candidates?: Array<{
        content: { role: string; parts: Array<{ text: string }> };
        finishReason: string;
      }>;
    };
    expect(json.choices).toBeUndefined();
    expect(Array.isArray(json.candidates)).toBe(true);
    expect(json.candidates?.[0]?.finishReason).toBe("STOP");
    expect(json.candidates?.[0]?.content.role).toBe("model");
    expect(json.candidates?.[0]?.content.parts?.[0]?.text).toContain("Agentum blocked wipe");
    expect(ev.evaluateToolCall).toHaveBeenCalledWith({ toolName: "wipe", arguments: { x: 1 } });
  });

  test("Bedrock-converse deny synthesizes the Converse envelope, no upstream", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    let body = "";
    dispatcher.dispatch(
      {
        origin: "https://bedrock-runtime.us-east-1.amazonaws.com",
        path: "/model/anthropic.claude-3-sonnet/converse",
        method: "POST",
        body: JSON.stringify({
          messages: [
            {
              role: "assistant",
              content: [{ toolUse: { toolUseId: "tu_1", name: "get_weather", input: { city: "Paris" } } }],
            },
          ],
        }),
      },
      {
        onConnect: () => {},
        onHeaders: () => true,
        onData: (c: Uint8Array) => {
          body += new TextDecoder().decode(c);
          return true;
        },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(0);
    const json = JSON.parse(body) as { stopReason?: string; output?: { message: { content: unknown } } };
    expect(json.stopReason).toBe("end_turn");
    expect(JSON.stringify(json.output?.message.content)).toContain("Agentum blocked get_weather");
  });

  test("Anthropic deny synthesizes a NATIVE Anthropic message envelope, no upstream", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ delete_db: { decision: "deny", ttlMs: 0, reason: "destructive" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    let body = "";
    dispatcher.dispatch(
      {
        origin: "https://api.anthropic.com",
        path: "/v1/messages",
        method: "POST",
        body: JSON.stringify({
          model: "claude-3-sonnet",
          messages: [
            {
              role: "assistant",
              content: [
                { type: "tool_use", id: "toolu_1", name: "delete_db", input: { name: "prod" } },
              ],
            },
          ],
        }),
      },
      {
        onConnect: () => {},
        onHeaders: () => true,
        onData: (c: Uint8Array) => {
          body += new TextDecoder().decode(c);
          return true;
        },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));
    // No upstream dispatch — synthesized request-side.
    expect(calls).toHaveLength(0);
    // NATIVE Anthropic message envelope — NOT OpenAI `{choices}`.
    const json = JSON.parse(body) as {
      choices?: unknown;
      type?: string;
      role?: string;
      stop_reason?: string;
      content?: Array<{ type: string; text: string }>;
    };
    expect(json.choices).toBeUndefined();
    expect(json.type).toBe("message");
    expect(json.role).toBe("assistant");
    expect(json.stop_reason).toBe("end_turn");
    expect(json.content?.[0]?.type).toBe("text");
    expect(json.content?.[0]?.text).toContain("Agentum blocked delete_db");
    expect(ev.evaluateToolCall).toHaveBeenCalledWith({
      toolName: "delete_db",
      arguments: { name: "prod" },
    });
  });

  test("Bedrock-converse allow forwards to upstream untouched", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ ok_tool: { decision: "allow", ttlMs: 0 } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    dispatcher.dispatch(
      {
        origin: "https://bedrock-runtime.us-east-1.amazonaws.com",
        path: "/model/anthropic.claude-3-sonnet/converse",
        method: "POST",
        body: JSON.stringify({
          messages: [
            { role: "assistant", content: [{ toolUse: { toolUseId: "tu_1", name: "ok_tool", input: {} } }] },
          ],
        }),
      },
      {},
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["path"]).toBe("/model/anthropic.claude-3-sonnet/converse");
  });
});

// ── GR-19: MCP Streamable-HTTP over the dispatcher ──────────────────────────

describe("MCP Streamable-HTTP (GR-19)", () => {
  const DUAL = "application/json, text/event-stream";

  afterEach(() => {
    _resetMcpSuppression();
  });

  function toolsCall(name: string, args: Record<string, unknown> = {}): string {
    return JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name, arguments: args } });
  }

  test("dual-Accept POST to an unregistered host → deny synthesizes a JSON-RPC isError result with the request id", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ search: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    let body = "";
    let status = 0;
    dispatcher.dispatch(
      {
        origin: "https://mcp.example.test",
        path: "/mcp",
        method: "POST",
        headers: { accept: DUAL },
        body: toolsCall("search", { q: "x" }),
      },
      {
        onConnect: () => {},
        onHeaders: (s: number) => { status = s; return true; },
        onData: (chunk: Uint8Array) => { body += new TextDecoder().decode(chunk); return true; },
        onComplete: () => {},
      },
    );
    await new Promise((r) => setImmediate(r));

    expect(calls).toHaveLength(0); // upstream MCP server never contacted
    expect(status).toBe(200);
    const json = JSON.parse(body) as { jsonrpc: string; id: number; result: { isError: boolean } };
    expect(json.jsonrpc).toBe("2.0");
    expect(json.id).toBe(5);
    expect(json.result.isError).toBe(true);
  });

  test("allow forwards the original MCP POST untouched", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    dispatcher.dispatch(
      { origin: "https://mcp.example.test", path: "/mcp", method: "POST", headers: { accept: DUAL }, body: toolsCall("search") },
      {},
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts["path"]).toBe("/mcp");
    expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(1);
  });

  test("suppression token set ⇒ forwarded with zero evaluator calls", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({ search: { decision: "deny", ttlMs: 0 } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    markMcpCallEvaluated("search", { q: "z" });
    dispatcher.dispatch(
      { origin: "https://mcp.example.test", path: "/mcp", method: "POST", headers: { accept: DUAL }, body: toolsCall("search", { q: "z" }) },
      {},
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
  });

  test("single-Accept POST is not treated as MCP (forwards untouched, no eval)", async () => {
    const { dispatcher, calls } = fakeDispatcher();
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));
    dispatcher.dispatch(
      { origin: "https://mcp.example.test", path: "/mcp", method: "POST", headers: { accept: "application/json" }, body: toolsCall("search") },
      {},
    );
    await new Promise((r) => setImmediate(r));
    expect(calls).toHaveLength(1);
    expect((ev.evaluateToolCall as jest.Mock).mock.calls).toHaveLength(0);
  });
});

// ── response-side (model-emitted) enforcement (parity with fetch/node:http) ──
//
// On the ALLOW preflight path the interceptor forwards through a WRAPPED
// handler that enforces the upstream RESPONSE. We simulate the upstream by
// driving the wrapped handler's callbacks from a custom dispatcher.

const TE = new TextEncoder();
const TD = new TextDecoder();

/** Captures what the ORIGINAL (consumer) handler observes. */
interface Captured {
  status: number;
  headers: string[];
  body: string;
  completed: boolean;
}

function captureHandler(): { handler: Record<string, unknown>; captured: Captured } {
  const captured: Captured = { status: 0, headers: [], body: "", completed: false };
  const handler: Record<string, unknown> = {
    onConnect: () => {},
    onHeaders: (status: number, headers: string[] | null) => {
      captured.status = status;
      captured.headers = (headers ?? []).map((h) => (typeof h === "string" ? h : String(h)));
      return true;
    },
    onData: (chunk: Uint8Array) => {
      captured.body += TD.decode(chunk);
      return true;
    },
    onComplete: () => {
      captured.completed = true;
    },
    onError: () => {},
  };
  return { handler, captured };
}

/**
 * A dispatcher that, on dispatch, simulates an upstream HTTP response by
 * driving the (wrapped) handler's callbacks with `responder`. Also records the
 * dispatchOpts so request-side assertions (marker strip) are possible.
 */
function respondingDispatcher(
  responder: (h: WrappedHandler) => void,
): { dispatcher: UndiciDispatcher; seen: Array<Record<string, unknown>> } {
  const seen: Array<Record<string, unknown>> = [];
  const dispatcher: UndiciDispatcher = {
    dispatch(opts, handler): boolean {
      seen.push(opts as unknown as Record<string, unknown>);
      // The handler here is the WRAPPED handler the interceptor installed.
      responder(handler as unknown as WrappedHandler);
      return true;
    },
  };
  return { dispatcher, seen };
}

type WrappedHandler = {
  onConnect?: (abort: () => void) => void;
  onHeaders?: (s: number, h: string[] | null, resume: () => void, st?: string) => boolean;
  onData?: (c: Uint8Array) => boolean;
  onComplete?: (t: string[] | null) => void;
  onError?: (e: Error) => void;
};

describe("response-side enforcement (mode b, allow path)", () => {
  test("STREAMING (Cohere v2) deny: tool frames dropped + notice spliced", async () => {
    const cohereFrames = [
      `event: tool-call-start\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { id: "tc1", type: "function", function: { name: "send_email", arguments: "" } } } },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { function: { arguments: `{"to":"a@b.c"}` } } } },
      })}\n\n`,
      `event: tool-call-end\ndata: ${JSON.stringify({ index: 0 })}\n\n`,
    ];
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "text/event-stream"], () => {});
      for (const f of cohereFrames) h.onData?.(TE.encode(f));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ send_email: { decision: "deny", ttlMs: 0, reason: "no smtp" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.cohere.ai",
        path: "/v2/chat",
        method: "POST",
        body: JSON.stringify({ model: "command-r", messages: [], stream: true }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // Headers passed through immediately; streaming has no content-length.
    expect(captured.status).toBe(200);
    // Tool-call frames must NOT leak; the notice must appear.
    expect(captured.body).not.toContain("event: tool-call-start");
    expect(captured.body).not.toContain("event: tool-call-delta");
    expect(captured.body).toContain("Agentum blocked send_email");
    expect(captured.completed).toBe(true);
    expect(ev.evaluateToolCall).toHaveBeenCalledWith({
      toolName: "send_email",
      arguments: { to: "a@b.c" },
    });
  });

  test("STREAMING (Bedrock-converse binary) deny: tool frames dropped + notice spliced", async () => {
    const frames: Uint8Array[] = [
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
    ];
    const out: Uint8Array[] = [];
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/vnd.amazon.eventstream"], () => {});
      for (const f of frames) h.onData?.(f);
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const handler: WrappedHandler = {
      onConnect: () => {},
      onHeaders: () => true,
      onData: (c: Uint8Array) => {
        out.push(c.slice());
        return true;
      },
      onComplete: () => {},
      onError: () => {},
    };
    dispatcher.dispatch(
      {
        origin: "https://bedrock-runtime.us-east-1.amazonaws.com",
        path: "/model/anthropic.claude-3-sonnet/converse-stream",
        method: "POST",
        body: JSON.stringify({ messages: [], stream: true }),
      },
      handler as unknown as Record<string, unknown>,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // Re-parse the emitted binary frames: NO tool-call-start should survive,
    // and the notice text must be present.
    let total = 0;
    for (const c of out) total += c.byteLength;
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of out) { merged.set(c, off); off += c.byteLength; }
    const parser = new BedrockConverseStreamParser();
    const events: WireEvent[] = [...parser.feed(merged), ...parser.flush()];
    expect(events.some((e) => e.kind === "tool-call-start")).toBe(false);
    const text = events
      .filter((e) => e.kind === "text-delta")
      .map((e) => (e as Extract<WireEvent, { kind: "text-delta" }>).text)
      .join("");
    expect(text).toContain("Agentum blocked get_weather");
  });

  test("STREAMING (Cohere v2) allow: tool frames forwarded verbatim", async () => {
    const cohereFrames = [
      `event: tool-call-start\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { id: "tc1", type: "function", function: { name: "send_email", arguments: "" } } } },
      })}\n\n`,
      `event: tool-call-delta\ndata: ${JSON.stringify({
        index: 0,
        delta: { message: { tool_calls: { function: { arguments: `{"to":"a@b.c"}` } } } },
      })}\n\n`,
      `event: tool-call-end\ndata: ${JSON.stringify({ index: 0 })}\n\n`,
    ];
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "text/event-stream"], () => {});
      for (const f of cohereFrames) h.onData?.(TE.encode(f));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ send_email: { decision: "allow", ttlMs: 0 } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.cohere.ai",
        path: "/v2/chat",
        method: "POST",
        body: JSON.stringify({ model: "command-r", messages: [], stream: true }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // Allowed: the tool-call frames are forwarded verbatim — not dropped, no notice.
    expect(captured.body).toContain("event: tool-call-start");
    expect(captured.body).toContain("event: tool-call-delta");
    expect(captured.body).not.toContain("Agentum blocked");
    expect(captured.completed).toBe(true);
  });

  test("STREAMING enforce strips a stale upstream content-length (Bedrock binary)", async () => {
    const frames: Uint8Array[] = [
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
    ];
    let totalLen = 0;
    for (const f of frames) totalLen += f.byteLength;
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      // Upstream unusually carries a content-length on the binary event-stream;
      // the deny-rewrite changes the byte count, so it MUST be stripped.
      h.onHeaders?.(
        200,
        ["content-type", "application/vnd.amazon.eventstream", "content-length", String(totalLen)],
        () => {},
      );
      for (const f of frames) h.onData?.(f);
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ get_weather: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://bedrock-runtime.us-east-1.amazonaws.com",
        path: "/model/anthropic.claude-3-sonnet/converse-stream",
        method: "POST",
        body: JSON.stringify({ messages: [], stream: true }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    expect(captured.headers.some((h) => h.toLowerCase() === "content-length")).toBe(false);
  });

  test("NON-STREAMING (OpenAI JSON) deny: body rewritten + content-length corrected", async () => {
    const upstreamBody = JSON.stringify({
      id: "chatcmpl-1",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "t1", type: "function", function: { name: "wire_money", arguments: '{"amt":99}' } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json", "content-length", String(upstreamBody.length)], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ wire_money: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    expect(captured.status).toBe(200);
    expect(captured.completed).toBe(true);
    const json = JSON.parse(captured.body) as {
      choices: Array<{ message: { content: unknown; tool_calls?: unknown }; finish_reason: string }>;
    };
    // Denied tool_call dropped; finish_reason normalized to "stop".
    expect(json.choices[0]!.message.tool_calls).toBeUndefined();
    expect(json.choices[0]!.finish_reason).toBe("stop");
    expect(String(json.choices[0]!.message.content)).toContain("Agentum blocked wire_money");
    // content-length header corrected to the rewritten byte length + enforced marker.
    const idx = captured.headers.findIndex((h) => h.toLowerCase() === "content-length");
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(Number(captured.headers[idx + 1])).toBe(TE.encode(captured.body).byteLength);
    expect(captured.headers.map((h) => h.toLowerCase())).toContain("x-agentum-policy");
  });

  test("NON-STREAMING (Gemini JSON) deny: native candidates envelope rewritten", async () => {
    const upstreamBody = JSON.stringify({
      candidates: [
        {
          content: { role: "model", parts: [{ functionCall: { name: "wipe", args: { x: 1 } } }] },
          finishReason: "STOP",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ wipe: { decision: "deny", ttlMs: 0, reason: "no" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://generativelanguage.googleapis.com",
        path: "/v1beta/models/gemini-pro:generateContent",
        method: "POST",
        body: JSON.stringify({ contents: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const json = JSON.parse(captured.body) as {
      candidates: Array<{ content: { parts: Array<{ text?: string; functionCall?: unknown }> } }>;
    };
    const parts = json.candidates[0]!.content.parts;
    expect(parts.some((p) => p.functionCall !== undefined)).toBe(false);
    expect(parts.map((p) => p.text ?? "").join("")).toContain("Agentum blocked wipe");
  });

  test("ALLOW passthrough: non-streaming JSON bytes are untouched", async () => {
    const upstreamBody = JSON.stringify({
      id: "chatcmpl-2",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "t1", type: "function", function: { name: "search", arguments: "{}" } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ search: { decision: "allow", ttlMs: 0 } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // Allow → body byte-identical to upstream.
    expect(captured.body).toBe(upstreamBody);
  });

  test("non-2xx response passes through untouched (no enforce)", async () => {
    const errBody = JSON.stringify({ error: { message: "rate limited" } });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(429, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(errBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    expect(captured.status).toBe(429);
    expect(captured.body).toBe(errBody);
  });

  test("FAIL-CLOSED: response-side evaluator throw denies the model-emitted tool call", async () => {
    const upstreamBody = JSON.stringify({
      id: "chatcmpl-3",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "t1", type: "function", function: { name: "danger", arguments: "{}" } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const throwingEval = {
      evaluateToolCall: jest.fn(async () => {
        throw new Error("transport timeout");
      }),
      invalidateAll: jest.fn(),
    } as unknown as CedarToolCallClient;
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, throwingEval));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    const json = JSON.parse(captured.body) as {
      choices: Array<{ message: { content: unknown; tool_calls?: unknown } }>;
    };
    // Fail-CLOSED: the un-evaluable tool call is dropped + notice spliced.
    expect(json.choices[0]!.message.tool_calls).toBeUndefined();
    expect(String(json.choices[0]!.message.content)).toContain("Agentum blocked danger");
  });
});

// ── double-enforcement suppression (cross-plane marker) ──────────────────────

describe("double-enforcement suppression (x-agentum-plane marker)", () => {
  test("fetch-marked request: undici does NOT re-enforce the response AND strips the marker", async () => {
    // Upstream emits a denied OpenAI tool call. Because the fetch plane owns
    // this request (marker present), undici must forward the body VERBATIM.
    const upstreamBody = JSON.stringify({
      id: "chatcmpl-9",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "t1", type: "function", function: { name: "wire_money", arguments: "{}" } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher, seen } = respondingDispatcher(responder);
    // Deny verdict would normally rewrite — but suppression must prevent it.
    const ev = fakeEvaluator({ wire_money: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: {
          authorization: "Bearer sk-app",
          "content-type": "application/json",
          [PLANE_HEADER]: "fetch",
        },
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // The response was forwarded VERBATIM (no rewrite — fetch owns it).
    expect(captured.body).toBe(upstreamBody);
    // The marker was STRIPPED from what the upstream dispatcher received.
    expect(seen).toHaveLength(1);
    const fwdHeaders = seen[0]!["headers"] as Record<string, string>;
    const keysLower = Object.keys(fwdHeaders).map((k) => k.toLowerCase());
    expect(keysLower).not.toContain(PLANE_HEADER);
    // Provider auth header preserved.
    expect(fwdHeaders["authorization"]).toBe("Bearer sk-app");
  });

  test("marker present (array headers form) is stripped before forwarding", async () => {
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(JSON.stringify({ ok: true })));
      h.onComplete?.(null);
    };
    const { dispatcher, seen } = respondingDispatcher(responder);
    const ev = fakeEvaluator({});
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: ["authorization", "Bearer sk-arr", PLANE_HEADER, "fetch"],
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));

    const fwdHeaders = seen[0]!["headers"] as string[];
    // Marker key removed from the flat array; auth kept.
    expect(fwdHeaders.map((h) => h.toLowerCase())).not.toContain(PLANE_HEADER);
    expect(fwdHeaders).toContain("Bearer sk-arr");
  });

  test("raw undici.request (no marker): undici DOES enforce the response", async () => {
    const upstreamBody = JSON.stringify({
      id: "chatcmpl-10",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: null,
            tool_calls: [{ id: "t1", type: "function", function: { name: "wire_money", arguments: "{}" } }],
          },
          finish_reason: "tool_calls",
        },
      ],
    });
    const responder = (h: WrappedHandler): void => {
      h.onConnect?.(() => {});
      h.onHeaders?.(200, ["content-type", "application/json"], () => {});
      h.onData?.(TE.encode(upstreamBody));
      h.onComplete?.(null);
    };
    const { dispatcher } = respondingDispatcher(responder);
    const ev = fakeEvaluator({ wire_money: { decision: "deny", ttlMs: 0, reason: "blocked" } });
    installUndiciDispatcherInterceptor(baseOpts(dispatcher, ev));

    const { handler, captured } = captureHandler();
    dispatcher.dispatch(
      {
        origin: "https://api.openai.com",
        path: "/v1/chat/completions",
        method: "POST",
        headers: { authorization: "Bearer sk-raw", "content-type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o", messages: [] }),
      },
      handler,
    );
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));

    // No marker → undici enforces: the denied tool_call is dropped.
    const json = JSON.parse(captured.body) as {
      choices: Array<{ message: { tool_calls?: unknown } }>;
    };
    expect(json.choices[0]!.message.tool_calls).toBeUndefined();
  });
});
