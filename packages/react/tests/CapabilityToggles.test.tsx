/**
 * Component tests for `<CapabilityToggles>`. We mock `global.fetch` and
 * exercise the three planes the spec calls out:
 *
 *   1. Initial fetch + tree render
 *   2. Optimistic toggle (success path)
 *   3. Optimistic toggle revert on error
 *   4. Defaults mode hides toggle controls
 *   5. Friendly error copy per known LupidErrorCode
 */

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CapabilityToggles } from "../src/CapabilityToggles.js";
import type { CapabilityListResponse, ToggleResponse } from "../src/types.js";

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

function listResponse(): CapabilityListResponse {
  return {
    tenant_id: "t",
    agent_name: "a",
    scope: { dimension: "account_id", value: "acme" },
    capabilities: [
      {
        id: "cap.root",
        parent_id: null,
        display: "Root",
        description: null,
        risk: "low",
        customer_visible: true,
        default: "enabled",
        effective: true,
        override_value: null,
      },
      {
        id: "cap.child",
        parent_id: "cap.root",
        display: "Child",
        description: "An example child capability.",
        risk: "high",
        customer_visible: true,
        default: "disabled",
        effective: false,
        override_value: null,
      },
    ],
  };
}

function toggleSuccess(): ToggleResponse {
  return {
    new_effective_set: ["cap.root", "cap.child"],
    side_effects: {
      descendants_now_effective_off: [],
      dependents_now_effective_off: [],
    },
    from_state: "default_off",
    to_state: "override_on",
  };
}

afterEach(() => {
  global.fetch = originalFetch;
  jest.resetAllMocks();
});

describe("<CapabilityToggles> initial render", () => {
  it("shows a loading state and then the tree", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(jsonResponse(listResponse()));

    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope={{ dimension: "account_id", value: "acme" }}
      />,
    );

    expect(screen.getByTestId("capability-toggles-loading")).toBeInTheDocument();

    await waitFor(() =>
      expect(screen.getByTestId("capability-toggles")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("capability-node-cap.root")).toBeInTheDocument();
    expect(screen.getByTestId("capability-node-cap.child")).toBeInTheDocument();
  });

  it("renders the tree from the flat list with parent_id pointers", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(jsonResponse(listResponse()));

    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope={{ dimension: "account_id", value: "acme" }}
      />,
    );

    await waitFor(() => screen.getByTestId("capability-toggles"));
    // Child is nested INSIDE root (depth=1).
    const rootDiv = screen.getByTestId("capability-node-cap.root");
    const childDiv = screen.getByTestId("capability-node-cap.child");
    expect(rootDiv.contains(childDiv)).toBe(true);
    expect(childDiv.getAttribute("data-depth")).toBe("1");
  });
});

describe("<CapabilityToggles> toggle interaction", () => {
  it("issues a PUT and calls onToggle on success", async () => {
    const mock = installMockFetch();
    // First call: initial list. Second call: PUT. Subsequent: polls.
    mock.mockResolvedValueOnce(jsonResponse(listResponse()));
    mock.mockResolvedValueOnce(jsonResponse(toggleSuccess()));
    mock.mockResolvedValue(jsonResponse(listResponse()));

    const onToggle = jest.fn();
    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope={{ dimension: "account_id", value: "acme" }}
        onToggle={onToggle}
      />,
    );

    await waitFor(() => screen.getByTestId("capability-toggle-cap.child"));
    const childToggle = screen.getByTestId("capability-toggle-cap.child") as HTMLInputElement;
    expect(childToggle.checked).toBe(false);

    await act(async () => {
      fireEvent.click(childToggle);
    });

    await waitFor(() => expect(onToggle).toHaveBeenCalledTimes(1));
    expect(onToggle).toHaveBeenCalledWith(
      "cap.child",
      true,
      expect.objectContaining({ from_state: "default_off", to_state: "override_on" }),
    );

    // Confirm the PUT was issued.
    const putCall = mock.mock.calls.find((c) => (c[1] as RequestInit)?.method === "PUT");
    expect(putCall).toBeDefined();
    expect(putCall?.[0]).toBe(
      "https://bff.example.com/api/v1/tenants/t/agents/a/scopes/account_id/acme/capabilities/cap.child",
    );
  });

  it("reverts the optimistic update when the PUT fails", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValueOnce(jsonResponse(listResponse()));
    mock.mockResolvedValueOnce(
      jsonResponse({ error: "msg", code: "not_customer_visible" }, 422),
    );
    mock.mockResolvedValue(jsonResponse(listResponse()));

    const onError = jest.fn();
    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope={{ dimension: "account_id", value: "acme" }}
        onError={onError}
      />,
    );

    await waitFor(() => screen.getByTestId("capability-toggle-cap.child"));
    const childToggle = screen.getByTestId("capability-toggle-cap.child") as HTMLInputElement;
    expect(childToggle.checked).toBe(false);

    await act(async () => {
      fireEvent.click(childToggle);
    });

    await waitFor(() => expect(onError).toHaveBeenCalledTimes(1));
    expect(onError.mock.calls[0]?.[0]).toMatchObject({ code: "not_customer_visible" });

    // Optimistic state reverted: child checkbox still unchecked.
    const childAgain = screen.getByTestId("capability-toggle-cap.child") as HTMLInputElement;
    expect(childAgain.checked).toBe(false);
  });
});

describe("<CapabilityToggles> defaults mode", () => {
  it("renders the defaults banner and disables toggle controls", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(jsonResponse(listResponse()));

    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope="defaults"
      />,
    );

    await waitFor(() => screen.getByTestId("capability-toggles"));
    expect(
      screen.getByTestId("capability-toggles-defaults-banner"),
    ).toBeInTheDocument();
    const childToggle = screen.getByTestId("capability-toggle-cap.child") as HTMLInputElement;
    expect(childToggle.disabled).toBe(true);
  });

  it("hits the /capabilities/defaults endpoint", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(jsonResponse(listResponse()));

    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope="defaults"
      />,
    );
    await waitFor(() => screen.getByTestId("capability-toggles"));
    const initialUrl = mock.mock.calls[0]?.[0];
    expect(initialUrl).toBe(
      "https://bff.example.com/api/v1/tenants/t/agents/a/capabilities/defaults",
    );
  });
});

describe("<CapabilityToggles> error banner", () => {
  it("renders a friendly message for scope_dimension_mismatch", async () => {
    const mock = installMockFetch();
    mock.mockResolvedValue(
      jsonResponse({ error: "msg", code: "scope_dimension_mismatch" }, 400),
    );

    render(
      <CapabilityToggles
        apiBase="https://bff.example.com"
        tenant="t"
        agent="a"
        scope={{ dimension: "wrong", value: "x" }}
      />,
    );

    await waitFor(() => screen.getByTestId("capability-toggles-error"));
    const banner = screen.getByTestId("capability-toggles-error");
    expect(banner.getAttribute("data-lupid-error-code")).toBe("scope_dimension_mismatch");
    expect(banner.textContent).toMatch(/scoping dimension/i);
  });

  it("renders a friendly message for every known LupidErrorCode", async () => {
    const codes = [
      "scope_dimension_mismatch",
      "dimension_not_materialized",
      "too_many_dimension_filters",
      "bulk_too_large",
      "not_customer_visible",
      "no_scoping_dimension_declared",
      "unknown_error",
    ];
    for (const code of codes) {
      const mock = installMockFetch();
      mock.mockResolvedValue(jsonResponse({ error: "msg", code }, 400));
      const { unmount } = render(
        <CapabilityToggles
          apiBase="https://bff.example.com"
          tenant="t"
          agent="a"
          scope={{ dimension: "account_id", value: "acme" }}
        />,
      );
      await waitFor(() => screen.getByTestId("capability-toggles-error"));
      const banner = screen.getByTestId("capability-toggles-error");
      expect(banner.getAttribute("data-lupid-error-code")).toBe(code);
      // Each message is non-empty.
      expect((banner.textContent ?? "").length).toBeGreaterThan(20);
      unmount();
      global.fetch = originalFetch;
      jest.resetAllMocks();
    }
  });
});
