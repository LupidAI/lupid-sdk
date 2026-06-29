import {
  deleteOverride,
  getDefaults,
  listCapabilities,
  toggleCapability,
} from "../src/api.js";
import { LupidError } from "../src/types.js";

type MockFetch = jest.MockedFunction<typeof fetch>;

const originalFetch = global.fetch;

function installMockFetch(): MockFetch {
  const mock = jest.fn() as unknown as MockFetch;
  global.fetch = mock as unknown as typeof fetch;
  return mock;
}

/**
 * jsdom does not expose the WHATWG `Response` constructor; rather than
 * pulling a polyfill, we hand-roll a duck-typed object with just the
 * surface our `api.ts` calls — `.ok`, `.status`, `.text()`, `.json()`.
 */
function jsonResponse(body: unknown, status = 200): Response {
  const text = JSON.stringify(body);
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    headers: new Headers({ "Content-Type": "application/json" }),
    text: () => Promise.resolve(text),
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

afterEach(() => {
  global.fetch = originalFetch;
  jest.resetAllMocks();
});

describe("listCapabilities", () => {
  it("builds the correct URL and forwards auth headers", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ tenant_id: "t", agent_name: "a", capabilities: [] }),
    );

    await listCapabilities(
      "https://bff.example.com/lupid-proxy",
      "t",
      "a",
      { dimension: "account_id", value: "acme" },
      { "X-Session": "s" },
    );

    const [calledUrl, calledInit] = mock.mock.calls[0]!;
    expect(calledUrl).toBe(
      "https://bff.example.com/lupid-proxy/api/v1/tenants/t/agents/a/scopes/account_id/acme/capabilities/",
    );
    const headers = (calledInit as RequestInit).headers as Record<string, string>;
    expect(headers["X-Session"]).toBe("s");
    expect(headers.Accept).toBe("application/json");
    expect((calledInit as RequestInit).method).toBe("GET");
  });

  it("strips a trailing slash from the apiBase", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ tenant_id: "t", agent_name: "a", capabilities: [] }),
    );
    await listCapabilities(
      "https://bff.example.com/lupid-proxy/",
      "t",
      "a",
      { dimension: "account_id", value: "acme" },
    );
    const [url] = mock.mock.calls[0]!;
    expect(url).toBe(
      "https://bff.example.com/lupid-proxy/api/v1/tenants/t/agents/a/scopes/account_id/acme/capabilities/",
    );
  });

  it("URL-encodes path segments", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ tenant_id: "t", agent_name: "a", capabilities: [] }),
    );
    await listCapabilities("https://bff.example.com", "tenant/with/slash", "agent name", {
      dimension: "account_id",
      value: "acme inc",
    });
    const [url] = mock.mock.calls[0]!;
    expect(url).toBe(
      "https://bff.example.com/api/v1/tenants/tenant%2Fwith%2Fslash/agents/agent%20name/scopes/account_id/acme%20inc/capabilities/",
    );
  });

  it("returns the parsed body on success", async () => {
    const mock = installMockFetch();
    const body = {
      tenant_id: "t",
      agent_name: "a",
      scope: { dimension: "account_id", value: "acme" },
      capabilities: [
        {
          id: "cap.x",
          parent_id: null,
          display: "X",
          description: null,
          risk: "low",
          customer_visible: true,
          default: "enabled",
          effective: true,
          override_value: null,
        },
      ],
    };
    mock.mockResolvedValue(jsonResponse(body));
    const result = await listCapabilities("https://bff.example.com", "t", "a", {
      dimension: "account_id",
      value: "acme",
    });
    expect(result).toEqual(body);
  });
});

describe("getDefaults", () => {
  it("hits the /capabilities/defaults endpoint", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ tenant_id: "t", agent_name: "a", capabilities: [] }),
    );
    await getDefaults("https://bff.example.com", "t", "a");
    const [url] = mock.mock.calls[0]!;
    expect(url).toBe("https://bff.example.com/api/v1/tenants/t/agents/a/capabilities/defaults");
  });
});

describe("toggleCapability", () => {
  it("sends PUT with the enabled flag", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({
        new_effective_set: ["cap.x"],
        side_effects: {
          descendants_now_effective_off: [],
          dependents_now_effective_off: [],
        },
        from_state: "default_off",
        to_state: "override_on",
      }),
    );
    await toggleCapability(
      "https://bff.example.com",
      "t",
      "a",
      { dimension: "account_id", value: "acme" },
      "cap.x",
      true,
      undefined,
      "operator audit note",
    );
    const [url, init] = mock.mock.calls[0]!;
    expect(url).toBe(
      "https://bff.example.com/api/v1/tenants/t/agents/a/scopes/account_id/acme/capabilities/cap.x",
    );
    expect((init as RequestInit).method).toBe("PUT");
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      enabled: true,
      reason: "operator audit note",
    });
  });

  it("omits the reason field when not provided", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({
        new_effective_set: [],
        side_effects: {
          descendants_now_effective_off: [],
          dependents_now_effective_off: [],
        },
        from_state: "default_on",
        to_state: "override_off",
      }),
    );
    await toggleCapability(
      "https://bff.example.com",
      "t",
      "a",
      { dimension: "account_id", value: "acme" },
      "cap.x",
      false,
    );
    const init = mock.mock.calls[0]![1]!;
    expect(JSON.parse(init.body as string)).toEqual({ enabled: false });
  });
});

describe("deleteOverride", () => {
  it("sends DELETE to the /override sub-resource", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({
        new_effective_set: [],
        side_effects: {
          descendants_now_effective_off: [],
          dependents_now_effective_off: [],
        },
        from_state: "override_on",
        to_state: "default_on",
      }),
    );
    await deleteOverride(
      "https://bff.example.com",
      "t",
      "a",
      { dimension: "account_id", value: "acme" },
      "cap.x",
    );
    const [url, init] = mock.mock.calls[0]!;
    expect(url).toBe(
      "https://bff.example.com/api/v1/tenants/t/agents/a/scopes/account_id/acme/capabilities/cap.x/override",
    );
    expect((init as RequestInit).method).toBe("DELETE");
  });
});

describe("error mapping", () => {
  it("maps the structured envelope with `code` field", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse(
        { error: "boom", code: "not_customer_visible" },
        422,
      ),
    );
    await expect(
      toggleCapability(
        "https://bff.example.com",
        "t",
        "a",
        { dimension: "account_id", value: "acme" },
        "cap.x",
        true,
      ),
    ).rejects.toMatchObject({
      code: "not_customer_visible",
      status: 422,
    } satisfies Partial<LupidError>);
  });

  it("recognizes the legacy generic envelope (code-as-error-message)", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ error: "scope_dimension_mismatch" }, 400),
    );
    await expect(
      listCapabilities("https://bff.example.com", "t", "a", {
        dimension: "account_id",
        value: "acme",
      }),
    ).rejects.toMatchObject({
      code: "scope_dimension_mismatch",
      status: 400,
    });
  });

  it("falls back to unknown_error for unrecognized codes", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ error: "something_we_have_never_seen" }, 418),
    );
    await expect(
      listCapabilities("https://bff.example.com", "t", "a", {
        dimension: "account_id",
        value: "acme",
      }),
    ).rejects.toMatchObject({
      code: "unknown_error",
      status: 418,
    });
  });

  it("maps a network-level rejection to LupidError(unknown_error, status=0)", async () => {
    const mock = installMockFetch();
    mock.mockRejectedValue(new TypeError("Failed to fetch"));
    await expect(
      listCapabilities("https://bff.example.com", "t", "a", {
        dimension: "account_id",
        value: "acme",
      }),
    ).rejects.toMatchObject({
      code: "unknown_error",
      status: 0,
    });
  });

  it("recognises every documented error code via the structured envelope", async () => {
    const codes = [
      "scope_dimension_mismatch",
      "dimension_not_materialized",
      "too_many_dimension_filters",
      "bulk_too_large",
      "not_customer_visible",
      "no_scoping_dimension_declared",
    ] as const;
    for (const code of codes) {
      const mock = installMockFetch();
      mock.mockResolvedValue(jsonResponse({ error: "msg", code }, 400));
      await expect(
        getDefaults("https://bff.example.com", "t", "a"),
      ).rejects.toMatchObject({ code });
    }
  });
});
