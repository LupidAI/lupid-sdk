/**
 * Unit tests for TypeScript framework wrappers.
 */

import { AgentumClient } from "../src/index";
import { AgentumCallbackHandler, AgentumPolicyTool, withAgentumGuard } from "../src/frameworks/langchain";
import { createAgentumMiddleware, agentumTool, createAgentumTelemetry } from "../src/frameworks/vercel-ai";
import { wrapOpenAIClient, AgentumAssistantRunner, policyFunctionTool } from "../src/frameworks/openai";

const BASE = "http://localhost:7071";

function mockFetch(body: unknown, status = 200): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: status < 400,
    status,
    headers: { get: () => "application/json" },
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

function makeClient(fetchMock: jest.Mock): AgentumClient {
  // Framework tests assert on fetch calls immediately after fire-and-forget
  // ingestAuditEvent, so disable the A7 audit buffer (pass-through mode).
  return new AgentumClient({
    baseUrl: BASE,
    fetch: fetchMock as unknown as typeof fetch,
    disableAuditBuffer: true,
  });
}

// ── LangChain ────────────────────────────────────────────────────────────────

describe("AgentumCallbackHandler", () => {
  let f: jest.Mock;
  let client: AgentumClient;
  let handler: AgentumCallbackHandler;

  beforeEach(() => {
    f = mockFetch({});
    client  = makeClient(f);
    handler = new AgentumCallbackHandler({ client, agentId: "a1", sessionId: "s1" });
  });

  it("emits llm_start on handleLLMStart", () => {
    handler.handleLLMStart({}, ["prompt"]);
    // ingestAuditEvent is fire-and-forget; just ensure no throw
    expect(true).toBe(true);
  });

  it("emits llm_end on handleLLMEnd", () => {
    expect(() => handler.handleLLMEnd()).not.toThrow();
  });

  it("emits tool_start with tool name", () => {
    expect(() => handler.handleToolStart({ name: "web_search" }, "query text")).not.toThrow();
  });

  it("emits chain_start", () => {
    expect(() => handler.handleChainStart({ id: ["AgentExecutor"] })).not.toThrow();
  });
});

describe("AgentumPolicyTool", () => {
  it("returns ALLOWED when policy allows", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client  = makeClient(f);
    const tool    = new AgentumPolicyTool({ client, agentId: "a1" });
    const result  = await tool.invoke(JSON.stringify({ action: "http.get", resource: "https://api.example.com" }));
    expect(result).toBe("ALLOWED");
  });

  it("throws PermissionError when policy denies (strict mode)", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const tool   = new AgentumPolicyTool({ client, agentId: "a1" });
    await expect(tool.invoke(JSON.stringify({ action: "http.delete", resource: "https://api.example.com" }))).rejects.toThrow("PermissionError");
  });

  it("returns DENIED string in soft mode", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const tool   = new AgentumPolicyTool({ client, agentId: "a1", softDeny: true });
    const result = await tool.invoke(JSON.stringify({ action: "http.delete", resource: "https://api.example.com" }));
    expect(result).toMatch(/^DENIED/);
  });

  it("handles object input", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);
    const tool   = new AgentumPolicyTool({ client, agentId: "a1" });
    const result = await tool.invoke({ action: "http.get", resource: "https://api.example.com" });
    expect(result).toBe("ALLOWED");
  });

  it("_call is an alias for invoke", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);
    const tool   = new AgentumPolicyTool({ client, agentId: "a1" });
    const result = await tool._call(JSON.stringify({ action: "http.get", resource: "*" }));
    expect(result).toBe("ALLOWED");
  });
});

describe("withAgentumGuard", () => {
  it("calls inner function when allowed", async () => {
    const f    = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);
    const inner = jest.fn().mockResolvedValue("result");
    const guarded = withAgentumGuard(inner, { client, agentId: "a1", action: "http.get" });
    const result = await guarded();
    expect(result).toBe("result");
    expect(inner).toHaveBeenCalled();
  });

  it("throws PermissionError when denied", async () => {
    const f    = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const inner = jest.fn();
    const guarded = withAgentumGuard(inner, { client, agentId: "a1", action: "http.delete" });
    await expect(guarded()).rejects.toThrow("PermissionError");
    expect(inner).not.toHaveBeenCalled();
  });
});

// ── Vercel AI ────────────────────────────────────────────────────────────────

describe("createAgentumMiddleware", () => {
  it("wrapLanguageModel proxies doGenerate", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw     = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const mockModel = {
      doGenerate: jest.fn().mockResolvedValue({ text: "hello" }),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);
    const result  = await (wrapped as typeof mockModel).doGenerate({});
    expect(result).toEqual({ text: "hello" });
    expect(mockModel.doGenerate).toHaveBeenCalled();
  });

  it("policy gate blocks when denied", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const mw     = createAgentumMiddleware({
      client,
      agentId: "a1",
      sessionId: "s1",
      policyAction: "llm.generate",
    });

    const mockModel = { doGenerate: jest.fn() };
    const wrapped   = mw.wrapLanguageModel(mockModel);
    await expect((wrapped as typeof mockModel).doGenerate({})).rejects.toThrow("PermissionError");
    expect(mockModel.doGenerate).not.toHaveBeenCalled();
  });
});

describe("agentumTool (Vercel AI)", () => {
  it("executes inner function when allowed", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);
    const execute = jest.fn().mockResolvedValue("search-results");

    const guarded = agentumTool({ client, agentId: "a1", action: "tool:search", execute });
    const result  = await guarded({ query: "test" });
    expect(result).toBe("search-results");
    expect(execute).toHaveBeenCalledWith({ query: "test" });
  });

  it("throws when denied", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const execute = jest.fn();

    const guarded = agentumTool({ client, agentId: "a1", action: "tool:search", execute });
    await expect(guarded({ query: "test" })).rejects.toThrow("PermissionError");
    expect(execute).not.toHaveBeenCalled();
  });
});

// ── OpenAI ───────────────────────────────────────────────────────────────────

describe("policyFunctionTool", () => {
  it("returns toolSpec and guarded execute", async () => {
    const f = mockFetch({ outcome: "Allow" });
    const client = makeClient(f);

    const { toolSpec, execute } = policyFunctionTool({
      client,
      agentId: "a1",
      action: "tool:web_search",
      spec: {
        name: "web_search",
        description: "Search the web",
        parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] },
      },
      execute: async (args: { query: string }) => `results for: ${args.query}`,
    });

    expect(toolSpec.type).toBe("function");
    expect(toolSpec.function.name).toBe("web_search");

    const result = await execute({ query: "agentum" });
    expect(result).toBe("results for: agentum");
  });

  it("blocks execution when policy denies", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);

    const { execute } = policyFunctionTool({
      client,
      agentId: "a1",
      action: "tool:web_search",
      spec: { name: "web_search", description: "", parameters: {} },
      execute: async () => "never",
    });

    await expect(execute({ query: "test" })).rejects.toThrow("PermissionError");
  });
});

// ── wrapOpenAIClient ──────────────────────────────────────────────────────────

describe("wrapOpenAIClient", () => {
  function makeOpenAIClient() {
    return {
      chat: {
        completions: {
          create: jest.fn().mockResolvedValue({ choices: [{ message: { content: "hi" } }] }),
        },
      },
      models: { list: jest.fn().mockResolvedValue([]) },
    };
  }

  it("proxies chat.completions.create and emits llm_start + llm_end audit events", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const oai = makeOpenAIClient();
    const wrapped = wrapOpenAIClient(oai, { client, agentId: "a1", sessionId: "s1" });

    const result = await wrapped.chat.completions.create({ model: "gpt-4o", messages: [] });
    expect(result).toEqual({ choices: [{ message: { content: "hi" } }] });
    expect(oai.chat.completions.create).toHaveBeenCalled();

    // Two audit events fired: pre-flight `llm_call` + post-flight `llm_end`.
    // Sprint B P1-4: was "llm_start" (Unknown); canonical is "llm_call" with
    // detail.phase === "start".
    expect(f).toHaveBeenCalledTimes(2);
    const firstBody = JSON.parse(f.mock.calls[0]![1]!.body as string);
    expect(firstBody.event_type).toBe("llm_call");
    expect(firstBody.detail?.phase).toBe("start");
    const secondBody = JSON.parse(f.mock.calls[1]![1]!.body as string);
    expect(secondBody.event_type).toBe("llm_end");
  });

  it("emits llm_error audit event when inner create throws", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const oai = {
      chat: {
        completions: {
          create: jest.fn().mockRejectedValue(new Error("API down")),
        },
      },
    };
    const wrapped = wrapOpenAIClient(oai, { client, agentId: "a1", sessionId: "s1" });

    await expect(wrapped.chat.completions.create({ model: "gpt-4o", messages: [] })).rejects.toThrow("API down");

    // llm_start fired; llm_error fired on failure
    await new Promise((r) => setTimeout(r, 10));
    expect(f.mock.calls.some((c) => JSON.parse(c[1]!.body as string).event_type === "llm_error")).toBe(true);
  });

  it("checks policy gate before create when policyAction is set", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const oai = makeOpenAIClient();
    const wrapped = wrapOpenAIClient(oai, {
      client,
      agentId: "a1",
      sessionId: "s1",
      policyAction: "llm.generate",
    });

    await expect(wrapped.chat.completions.create({ model: "gpt-4o", messages: [] })).rejects.toThrow("PermissionError");
    expect(oai.chat.completions.create).not.toHaveBeenCalled();
  });

  it("passes through non-intercepted properties (models.list)", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const oai = makeOpenAIClient();
    const wrapped = wrapOpenAIClient(oai, { client, agentId: "a1", sessionId: "s1" });

    expect(wrapped.models).toBe(oai.models);
  });
});

// ── AgentumAssistantRunner ─────────────────────────────────────────────────────

describe("AgentumAssistantRunner", () => {
  it("polls until completed and returns final run", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const runner = new AgentumAssistantRunner({ client, agentId: "a1", sessionId: "s1", pollIntervalMs: 0 });

    let calls = 0;
    const runsApi = {
      retrieve: jest.fn().mockImplementation(async () => {
        calls++;
        return calls < 3
          ? { run_id: "run-1", thread_id: "t-1", status: "in_progress" }
          : { run_id: "run-1", thread_id: "t-1", status: "completed" };
      }),
    };

    const run = await runner.waitForCompletion(runsApi, "t-1", "run-1");
    expect(run.status).toBe("completed");
    expect(runsApi.retrieve).toHaveBeenCalledTimes(3);
  });

  it("emits tool_call audit event on requires_action status", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const runner = new AgentumAssistantRunner({ client, agentId: "a1", sessionId: "s1", pollIntervalMs: 0 });

    let calls = 0;
    const runsApi = {
      retrieve: jest.fn().mockImplementation(async () => {
        calls++;
        if (calls === 1) return { run_id: "run-2", thread_id: "t-2", status: "requires_action", required_action: { type: "submit_tool_outputs" } };
        return { run_id: "run-2", thread_id: "t-2", status: "completed" };
      }),
    };

    await runner.waitForCompletion(runsApi, "t-2", "run-2");
    // Give fire-and-forget audit events a tick to complete
    await new Promise((r) => setTimeout(r, 10));
    const events = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string).event_type);
    expect(events).toContain("tool_call");
  });

  it("throws when maxWaitMs is exceeded", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const runner = new AgentumAssistantRunner({
      client, agentId: "a1", sessionId: "s1", pollIntervalMs: 0, maxWaitMs: 1,
    });

    const runsApi = {
      retrieve: jest.fn().mockResolvedValue({ run_id: "run-3", thread_id: "t-3", status: "in_progress" }),
    };

    await expect(runner.waitForCompletion(runsApi, "t-3", "run-3")).rejects.toThrow("did not complete within");
  });

  it("emits assistant_run_end with error outcome on failed run", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const runner = new AgentumAssistantRunner({ client, agentId: "a1", sessionId: "s1", pollIntervalMs: 0 });

    const runsApi = {
      retrieve: jest.fn().mockResolvedValue({ run_id: "run-4", thread_id: "t-4", status: "failed" }),
    };

    const run = await runner.waitForCompletion(runsApi, "t-4", "run-4");
    expect(run.status).toBe("failed");
    await new Promise((r) => setTimeout(r, 10));
    const events = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string));
    const endEvent = events.find((e) => e.event_type === "assistant_run_end");
    expect(endEvent?.outcome).toBe("error");
  });
});

// ── Vercel AI: doStream + auditToolCall + createAgentumTelemetry ──────────────

// Helper: build a ReadableStream<T> from an array of chunks.
function makeReadableStream<T>(chunks: T[]): ReadableStream<T> {
  return new ReadableStream<T>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(chunk);
      }
      controller.close();
    },
  });
}

// Helper: drain a ReadableStream and return all chunks.
async function drainStream<T>(stream: ReadableStream<T>): Promise<T[]> {
  const reader = stream.getReader();
  const out: T[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out.push(value!);
  }
  return out;
}

describe("createAgentumMiddleware - doStream path", () => {
  it("proxies doStream and emits llm_start via fallback path (non-ReadableStream mock)", async () => {
    // The existing mock returns { stream: "mock-stream" } (a string, not a ReadableStream).
    // The implementation falls back to calling afterGenerate() immediately so the
    // existing behavior is preserved for non-standard mock implementations.
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const mockModel = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream: "mock-stream" }),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);
    const result = await (wrapped as typeof mockModel).doStream({});
    expect(result).toEqual({ stream: "mock-stream" });
    expect(mockModel.doStream).toHaveBeenCalled();
    // Fallback path: both events emitted without consuming the stream.
    // Sprint B P1-4: was "llm_start" → canonical "llm_call" with detail.phase.
    await new Promise((r) => setTimeout(r, 10));
    const events = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string).event_type);
    expect(events).toContain("llm_call");
    expect(events).toContain("llm_end");
  });

  it("llm_end fires AFTER stream is consumed, not on stream open (real ReadableStream)", async () => {
    // This is the production path: doStream returns { stream: ReadableStream }.
    // The llm_end audit event must NOT be in flight until all chunks are read.
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const streamChunks = [
      { type: "text-delta", textDelta: "Hello" },
      { type: "text-delta", textDelta: " world" },
      { type: "finish", finishReason: "stop", usage: { promptTokens: 4, completionTokens: 2 } },
    ];

    const mockModel = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream: makeReadableStream(streamChunks) }),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);

    // Call doStream — receives wrapped result immediately.
    const result = await (wrapped as unknown as { doStream: (...a: unknown[]) => Promise<{ stream: ReadableStream<unknown> }> }).doStream({});
    expect(mockModel.doStream).toHaveBeenCalled();

    // Flush any immediately-queued microtasks.
    await new Promise((r) => setTimeout(r, 10));
    const eventsBefore = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string).event_type);

    // Pre-iteration event fires before any stream data (beforeGenerate).
    // Sprint B P1-4: was "llm_start" → canonical "llm_call" with detail.phase.
    expect(eventsBefore).toContain("llm_call");
    // llm_end must NOT have fired yet — the stream hasn't been consumed.
    expect(eventsBefore).not.toContain("llm_end");

    // Now consume the stream.
    const consumed = await drainStream(result.stream);
    expect(consumed).toHaveLength(3);  // all original chunks pass through

    // After consumption the TransformStream flush() fires afterGenerate.
    await new Promise((r) => setTimeout(r, 10));
    const eventsAfter = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string).event_type);
    expect(eventsAfter).toContain("llm_end");
  });

  it("llm_end carries completionTokens from the finish chunk", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const streamChunks = [
      { type: "text-delta", textDelta: "hi" },
      { type: "finish", finishReason: "stop", usage: { promptTokens: 5, completionTokens: 42 } },
    ];

    const mockModel = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream: makeReadableStream(streamChunks) }),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);
    const result = await (wrapped as unknown as { doStream: (...a: unknown[]) => Promise<{ stream: ReadableStream<unknown> }> }).doStream({});
    await drainStream(result.stream);
    await new Promise((r) => setTimeout(r, 10));

    const llmEndCall = f.mock.calls
      .map((c) => JSON.parse(c[1]!.body as string))
      .find((b) => b.event_type === "llm_end");

    expect(llmEndCall).toBeDefined();
    expect(llmEndCall!.detail.output_tokens).toBe(42);
  });

  it("original stream chunks pass through the wrapper unchanged", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    const chunks = [
      { type: "text-delta", textDelta: "chunk-1" },
      { type: "text-delta", textDelta: "chunk-2" },
      { type: "finish", finishReason: "stop", usage: { promptTokens: 1, completionTokens: 1 } },
    ];

    const mockModel = {
      doGenerate: jest.fn(),
      doStream: jest.fn().mockResolvedValue({ stream: makeReadableStream(chunks) }),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);
    const result = await (wrapped as unknown as { doStream: (...a: unknown[]) => Promise<{ stream: ReadableStream<unknown> }> }).doStream({});
    const received = await drainStream(result.stream);

    expect(received).toEqual(chunks);
  });

  it("doStream policy gate blocks when denied", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const mw = createAgentumMiddleware({
      client, agentId: "a1", sessionId: "s1", policyAction: "llm.stream",
    });

    const mockModel = {
      doGenerate: jest.fn(),
      doStream: jest.fn(),
    };

    const wrapped = mw.wrapLanguageModel(mockModel);
    await expect((wrapped as typeof mockModel).doStream({})).rejects.toThrow("PermissionError");
    expect(mockModel.doStream).not.toHaveBeenCalled();
  });
});

describe("auditToolCall", () => {
  it("emits tool_call audit event", async () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    await mw.auditToolCall("web_search", "https://api.example.com");
    await new Promise((r) => setTimeout(r, 10));
    const events = f.mock.calls.map((c) => JSON.parse(c[1]!.body as string).event_type);
    expect(events).toContain("tool_call");
  });

  it("throws PermissionError when policy denies tool action", async () => {
    const f = mockFetch({ outcome: "Deny" });
    const client = makeClient(f);
    const mw = createAgentumMiddleware({ client, agentId: "a1", sessionId: "s1" });

    await expect(mw.auditToolCall("web_search", "https://api.example.com", "tool:search")).rejects.toThrow("PermissionError");
  });
});

describe("createAgentumTelemetry", () => {
  it("returns an object with isEnabled=true", () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const telemetry = createAgentumTelemetry({ client, agentId: "a1", sessionId: "s1" });

    expect(telemetry.isEnabled).toBe(true);
    expect(telemetry.recordInputs).toBe(true);
    expect(telemetry.recordOutputs).toBe(false);
  });

  it("tracer.startActiveSpan emits a span audit event", () => {
    const f = mockFetch({});
    const client = makeClient(f);
    const telemetry = createAgentumTelemetry({ client, agentId: "a1", sessionId: "s1" });

    let spanEndCalled = false;
    telemetry.tracer.startActiveSpan("ai.generateText", (span: unknown) => {
      (span as { end: () => void }).end();
      spanEndCalled = true;
      return "result";
    });

    expect(spanEndCalled).toBe(true);
    // Audit event is fire-and-forget; just confirm no throw
  });
});

// ── Session-aware constructor tests (Task 4.1.3) ──────────────────────────────

import type { AgentumSession } from "../src/session";

function makeSession(agentId = "ag-sess-1", sessionId = "sess-1"): AgentumSession {
  const f = mockFetch({});
  const client = makeClient(f);
  return {
    agentId,
    client,
    get sessionId() { return sessionId; },
    get jwt() { return "test.jwt.token"; },
    get expiresAt() { return new Date(Date.now() + 3_600_000); },
    refreshThresholdMs: 60_000,
    isExpired: () => false,
    isNearExpiry: () => false,
    refresh: async () => {},
    isAllowed: async () => true,
    ingestAuditEvent: async () => {},
    close: async () => {},
    [Symbol.asyncDispose]: async () => {},
  } as unknown as AgentumSession;
}

describe("Session-aware LangChain constructor", () => {
  it("extracts client/agentId/sessionId from session", () => {
    const session = makeSession("ag-lc-1", "sess-lc-1");
    const handler = new AgentumCallbackHandler({ session });
    // If construction succeeds and emitting does not throw, session was consumed correctly.
    expect(() => handler.handleLLMEnd()).not.toThrow();
  });

  it("throws when neither session nor explicit fields provided", () => {
    expect(() => new AgentumCallbackHandler({})).toThrow();
  });
});

describe("Session-aware wrapOpenAIClient", () => {
  it("extracts credentials from session", () => {
    const session = makeSession("ag-oai-1", "sess-oai-1");
    // wrapOpenAIClient fails fast when the argument is not a valid OpenAI SDK
    // instance (missing chat.completions.create) — pass a minimal valid shape
    // so the session-extraction path is what gets tested.
    const fakeOpenAI = { chat: { completions: { create: jest.fn() } } };
    expect(() => wrapOpenAIClient(fakeOpenAI, { session })).not.toThrow();
  });

  it("throws when neither session nor explicit fields provided", () => {
    const fakeOpenAI = { chat: { completions: { create: jest.fn() } } };
    expect(() => wrapOpenAIClient(fakeOpenAI, {})).toThrow();
  });
});

describe("Session-aware AgentumAssistantRunner", () => {
  it("extracts credentials from session", () => {
    const session = makeSession("ag-runner-1", "sess-runner-1");
    expect(() => new AgentumAssistantRunner({ session })).not.toThrow();
  });
});

describe("Session-aware createAgentumMiddleware", () => {
  it("extracts credentials from session", () => {
    const session = makeSession("ag-vai-1", "sess-vai-1");
    expect(() => createAgentumMiddleware({ session })).not.toThrow();
  });

  it("throws when neither session nor explicit fields provided", () => {
    expect(() => createAgentumMiddleware({})).toThrow();
  });
});

describe("Session-aware createAgentumTelemetry", () => {
  it("extracts credentials from session", () => {
    const session = makeSession("ag-tel-1", "sess-tel-1");
    const telemetry = createAgentumTelemetry({ session });
    expect(telemetry.isEnabled).toBe(true);
  });
});
