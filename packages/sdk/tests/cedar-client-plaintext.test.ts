/**
 * Unit tests for `CedarToolCallClient.recordPlaintextCompletion` — A4.
 *
 * Closes the gap where plain-text non-streaming OpenAI completions left no
 * post-flight audit row. The method is called from
 * `instrumentation/openai-patch.ts::enforceNonStreamingOpenAI` whenever a
 * response carries no `tool_calls` block.
 *
 * Contract under test:
 *   1. POST to `/api/v1/sdk/observe-prompt` with a v4 UUID `request_id`
 *      and `params.kind === "plaintext_completion"`.
 *   2. Detached / fire-and-forget: the call returns synchronously (no
 *      awaitable promise leaks back to the caller of the method).
 *   3. Fail-OPEN: a transport / non-2xx response does not throw.
 *   4. Retry with exponential backoff on 5xx / transport errors (same
 *      knob as tool-call path: `observePromptMaxRetries`, default 1).
 *   5. No retry on 4xx (permanent client error).
 */

import { CedarToolCallClient } from "../src/evaluation/cedar-client";

interface CapturedCall {
  url: string;
  init: RequestInit | undefined;
}

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

function makeFetch(
  status = 200,
  capture: CapturedCall[] = [],
  throwErr?: Error,
): typeof fetch {
  return (async (url: string | URL, init?: RequestInit) => {
    capture.push({ url: String(url), init });
    if (throwErr) throw throwErr;
    return new Response("{}", {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

function flushMicrotasks(): Promise<void> {
  // Two queue flushes are enough for the .then().catch() chain inside
  // recordPlaintextCompletion to settle.
  return new Promise((resolve) => setImmediate(resolve));
}

describe("CedarToolCallClient.recordPlaintextCompletion (A4)", () => {
  test("POSTs observe-prompt with kind=plaintext_completion and a UUID request_id", async () => {
    const captured: CapturedCall[] = [];
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example/",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: makeFetch(200, captured),
      logger: silentLogger(),
    });

    client.recordPlaintextCompletion({
      provider: "openai",
      model: "gpt-4o",
      finishReason: "stop",
      role: "assistant",
      completionId: "chatcmpl-xyz",
      contentByteCount: 17,
    });

    await flushMicrotasks();

    expect(captured).toHaveLength(1);
    const call = captured[0]!;
    expect(call.url).toBe("http://api.example/api/v1/sdk/observe-prompt");
    expect(call.init?.method).toBe("POST");
    const headers = call.init?.headers as Record<string, string>;
    expect(headers["X-Api-Key"]).toBe("k");
    expect(headers["Content-Type"]).toBe("application/json");
    const body = JSON.parse(String(call.init?.body));
    expect(body.agent_id).toBe("agent-1");
    expect(body.provider).toBe("openai");
    expect(body.model).toBe("gpt-4o");
    expect(body.params.kind).toBe("plaintext_completion");
    expect(body.params.finish_reason).toBe("stop");
    expect(body.params.completion_id).toBe("chatcmpl-xyz");
    expect(body.params.content_byte_count).toBe(17);
    expect(Array.isArray(body.messages)).toBe(true);
    expect(body.messages).toHaveLength(0);
    // UUID v4 — accept any RFC 4122 UUID.
    expect(typeof body.request_id).toBe("string");
    expect(body.request_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
  });

  test("returns synchronously — does not await the POST", async () => {
    const captured: CapturedCall[] = [];
    let pendingResolve: (() => void) | undefined;
    const slowFetch = (async (url: string | URL, init?: RequestInit) => {
      captured.push({ url: String(url), init });
      await new Promise<void>((r) => {
        pendingResolve = r;
      });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;

    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: slowFetch,
      logger: silentLogger(),
    });

    const start = Date.now();
    const ret = client.recordPlaintextCompletion({
      provider: "openai",
      model: "gpt-4o",
    });
    const elapsed = Date.now() - start;
    expect(ret).toBeUndefined();
    expect(elapsed).toBeLessThan(20);
    // Drain so jest doesn't complain about a hanging request.
    pendingResolve?.();
    await flushMicrotasks();
  });

  test("does not throw when the upstream returns 5xx", async () => {
    const warn = jest.fn();
    const captured: CapturedCall[] = [];
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: makeFetch(503, captured),
      logger: { log: () => {}, warn, error: () => {} },
    });

    expect(() =>
      client.recordPlaintextCompletion({ provider: "openai", model: "gpt-4o" }),
    ).not.toThrow();
    await new Promise((r) => setTimeout(r, 100));
    // Default maxRetries = 1 → 2 attempts.
    expect(captured).toHaveLength(2);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("plaintext-audit dropped"),
    );
  });

  test("does not throw when the fetch impl rejects", async () => {
    const warn = jest.fn();
    const captured: CapturedCall[] = [];
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: makeFetch(200, captured, new Error("ECONNRESET")),
      logger: { log: () => {}, warn, error: () => {} },
    });

    expect(() =>
      client.recordPlaintextCompletion({ provider: "openai", model: "gpt-4o" }),
    ).not.toThrow();
    await new Promise((r) => setTimeout(r, 100));
    // Default maxRetries = 1 → 2 attempts.
    expect(captured).toHaveLength(2);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("plaintext-audit dropped"),
    );
  });

  test("does not retry on 4xx", async () => {
    const warn = jest.fn();
    const captured: CapturedCall[] = [];
    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl: makeFetch(400, captured),
      logger: { log: () => {}, warn, error: () => {} },
    });

    client.recordPlaintextCompletion({ provider: "openai", model: "gpt-4o" });
    await new Promise((r) => setTimeout(r, 50));
    expect(captured).toHaveLength(1);
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("plaintext-audit observe-prompt HTTP 400 (no retry)"),
    );
  });

  test("retries on 5xx and succeeds on second attempt", async () => {
    const warn = jest.fn();
    const captured: CapturedCall[] = [];
    let callCount = 0;
    const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
      captured.push({ url: String(url), init });
      callCount++;
      if (callCount === 1) {
        return new Response("{}", {
          status: 503,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const client = new CedarToolCallClient({
      baseUrl: "http://api.example",
      apiKey: "k",
      agentId: "agent-1",
      fetchImpl,
      logger: { log: () => {}, warn, error: () => {} },
    });

    client.recordPlaintextCompletion({ provider: "openai", model: "gpt-4o" });
    await new Promise((r) => setTimeout(r, 100));
    expect(captured).toHaveLength(2);
    expect(warn).not.toHaveBeenCalled();
  });
});
