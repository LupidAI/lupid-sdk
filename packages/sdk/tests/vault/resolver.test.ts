import {
  VAULT_PLACEHOLDER_PREFIX,
  resolveHeaderPlaceholders,
  resolvePlaceholder,
  _resetCacheForTests,
} from "../../src/vault/resolver";

describe("vault placeholder resolver", () => {
  beforeEach(() => _resetCacheForTests());

  test("VAULT_PLACEHOLDER_PREFIX is the expected wire constant", () => {
    expect(VAULT_PLACEHOLDER_PREFIX).toBe("agentum://SECRET/");
  });

  test("resolvePlaceholder calls POST /vault/resolve and returns value", async () => {
    const fetchImpl = jest.fn(async () =>
      new Response(JSON.stringify({ value: "sk-real-secret" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const value = await resolvePlaceholder(
      "agentum://SECRET/abc-123",
      {
        apiBaseUrl: "https://api.example.com",
        apiKey: "test-key",
        fetchImpl,
      },
    );
    expect(value).toBe("sk-real-secret");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = (fetchImpl as jest.Mock).mock.calls[0];
    expect(url).toBe("https://api.example.com/api/v1/vault/resolve");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.placeholder).toBe("agentum://SECRET/abc-123");
    expect((init.headers as Record<string, string>)["X-Api-Key"]).toBe("test-key");
  });

  test("resolvePlaceholder caches by lease_id", async () => {
    const fetchImpl = jest.fn(async () =>
      new Response(JSON.stringify({ value: "cached-secret" }), { status: 200 }),
    ) as unknown as typeof fetch;
    const opts = { apiBaseUrl: "https://api", apiKey: "k", fetchImpl };
    await resolvePlaceholder("agentum://SECRET/lease-x", opts);
    await resolvePlaceholder("agentum://SECRET/lease-x", opts);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test("resolvePlaceholder fails-CLOSED on non-2xx", async () => {
    const fetchImpl = jest.fn(async () =>
      new Response("forbidden", { status: 403, statusText: "Forbidden" }),
    ) as unknown as typeof fetch;
    await expect(
      resolvePlaceholder("agentum://SECRET/x", {
        apiBaseUrl: "https://api",
        apiKey: "k",
        fetchImpl,
      }),
    ).rejects.toThrow(/403/);
  });

  test("resolvePlaceholder rejects malformed placeholders", async () => {
    await expect(
      resolvePlaceholder("not-an-agentum-uri", {
        apiBaseUrl: "https://api",
        apiKey: "k",
      }),
    ).rejects.toThrow(/not an agentum/);
  });

  test("resolveHeaderPlaceholders passes through when no placeholder present", async () => {
    const fetchImpl = jest.fn() as unknown as typeof fetch;
    const init: RequestInit = {
      method: "GET",
      headers: { Authorization: "Bearer real-static-token" },
    };
    const out = await resolveHeaderPlaceholders(init, {
      apiBaseUrl: "https://api",
      apiKey: "k",
      fetchImpl,
    });
    expect(out).toBe(init);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test("resolveHeaderPlaceholders swaps a placeholder in Authorization header", async () => {
    const fetchImpl = jest.fn(async () =>
      new Response(JSON.stringify({ value: "sk-resolved-456" }), { status: 200 }),
    ) as unknown as typeof fetch;
    const init: RequestInit = {
      method: "POST",
      headers: { Authorization: "Bearer agentum://SECRET/lease-99" },
      body: '{"prompt":"x"}',
    };
    const out = await resolveHeaderPlaceholders(init, {
      apiBaseUrl: "https://api",
      apiKey: "k",
      fetchImpl,
    });
    expect(out).not.toBe(init);
    const headers = out!.headers as [string, string][];
    expect(headers).toContainEqual(["Authorization", "Bearer sk-resolved-456"]);
  });

  test("resolveHeaderPlaceholders preserves non-placeholder headers", async () => {
    const fetchImpl = jest.fn(async () =>
      new Response(JSON.stringify({ value: "S" }), { status: 200 }),
    ) as unknown as typeof fetch;
    const init: RequestInit = {
      headers: {
        Authorization: "Bearer agentum://SECRET/x",
        "X-Trace": "abc",
        "Content-Type": "application/json",
      },
    };
    const out = await resolveHeaderPlaceholders(init, {
      apiBaseUrl: "https://api",
      apiKey: "k",
      fetchImpl,
    });
    const headers = out!.headers as [string, string][];
    expect(headers).toContainEqual(["Authorization", "Bearer S"]);
    expect(headers).toContainEqual(["X-Trace", "abc"]);
    expect(headers).toContainEqual(["Content-Type", "application/json"]);
  });
});
