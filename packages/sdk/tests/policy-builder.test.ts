/**
 * Unit tests for the declarative `PolicyBuilder` (Sprint 1.4.3).
 *
 * Exercises rule accumulation, camelCase→snake_case translation, and the
 * externally-tagged `whenUser` input shapes. `apply()` covered via
 * `admin.test.ts`; this file focuses on the build pipeline.
 */

import { AgentumAdminClient, PolicyBuilder } from "../src/index";

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

describe("PolicyBuilder", () => {
  it("is returned from admin.policies.builder()", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies.builder("agent-1");
    expect(b).toBeInstanceOf(PolicyBuilder);
  });

  it("rejects empty agentId", () => {
    const admin = new AgentumAdminClient(BASE);
    expect(() => admin.policies.builder("")).toThrow(/non-empty agentId/);
  });

  it("permitHttp / forbidHttp produce wire-shape rules in insertion order", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com", pathLike: "/orders/*" })
      .forbidHttp({ method: "DELETE", host: "api.example.com" })
      .build();

    expect(spec).toEqual({
      agent_id: "agent-1",
      rules: [
        {
          kind: "http",
          permit: true,
          method: "GET",
          host: "api.example.com",
          path_like: "/orders/*",
        },
        {
          kind: "http",
          permit: false,
          method: "DELETE",
          host: "api.example.com",
        },
      ],
    });
  });

  it("permitMcp / forbidMcp emit mcp_tool rules", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitMcp({ server: "jira", tool: "create_issue" })
      .forbidMcp({ server: "github", tool: "create_issue" })
      .build();

    expect(spec.rules).toEqual([
      { kind: "mcp_tool", permit: true, server: "jira", tool: "create_issue" },
      { kind: "mcp_tool", permit: false, server: "github", tool: "create_issue" },
    ]);
  });

  it("normalises externally-tagged whenUser to wire shape", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({
        method: "GET",
        host: "api.example.com",
        whenUser: { emailLike: "*@example.com" },
      })
      .permitHttp({
        method: "POST",
        host: "api.example.com",
        whenUser: { attributeEquals: { key: "role", value: "admin" } },
      })
      .permitMcp({
        server: "gmail",
        tool: "send",
        whenUser: { trustEquals: "service" },
      })
      .build();

    const [r0, r1, r2] = spec.rules;
    expect(r0!.when_user).toEqual({ kind: "email_like", pattern: "*@example.com" });
    expect(r1!.when_user).toEqual({
      kind: "attribute_equals",
      key: "role",
      value: "admin",
    });
    expect(r2!.when_user).toEqual({ kind: "trust_equals", trust: "service" });
  });

  it("accepts wire-shape whenUser pass-through unchanged", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({
        method: "GET",
        host: "api.example.com",
        whenUser: { kind: "email_like", pattern: "*@example.com" },
      })
      .build();
    expect(spec.rules[0]!.when_user).toEqual({
      kind: "email_like",
      pattern: "*@example.com",
    });
  });

  it("omits server when not provided — compiles to 'any server' on the backend (Task 1.4.4)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .forbidMcp({ tool: "nuke_production" })
      .build();
    const r0 = spec.rules[0]!;
    expect(r0).toEqual({
      kind: "mcp_tool",
      permit: false,
      tool: "nuke_production",
    });
    expect("server" in r0).toBe(false);
  });

  it("treats server: '' as absent (sends no server field)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitMcp({ server: "", tool: "send" })
      .build();
    const r0 = spec.rules[0]!;
    expect("server" in r0).toBe(false);
  });

  it("omits pathLike / whenUser when not provided", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com" })
      .build();
    const r0 = spec.rules[0]!;
    expect(r0).toEqual({
      kind: "http",
      permit: true,
      method: "GET",
      host: "api.example.com",
    });
    expect("path_like" in r0).toBe(false);
    expect("when_user" in r0).toBe(false);
  });

  it("ruleCount reflects staged rules; reset() clears them", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "a" })
      .permitHttp({ method: "POST", host: "a" });
    expect(b.ruleCount).toBe(2);
    b.reset();
    expect(b.ruleCount).toBe(0);
    expect(b.build().rules).toEqual([]);
  });

  it("build() returns a defensive copy — mutating the return does not affect future apply()", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com" });
    const spec1 = b.build();
    spec1.rules.push({ kind: "http", permit: true, method: "POST", host: "hacked" });
    const spec2 = b.build();
    expect(spec2.rules).toHaveLength(1);
  });

  it("apply() sends the accumulated spec and decodes the response", async () => {
    const f = mockFetch({
      compiled_cedar: "permit(principal, action, resource);",
      applied_at: "2026-04-18T12:00:00Z",
      policy_id: "agent-1",
    });
    const admin = new AgentumAdminClient({
      baseUrl: BASE,
      apiKey: "ak",
      fetch: f as unknown as typeof fetch,
      retries: 0,
    });
    const result = await admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com", pathLike: "/x" })
      .forbidHttp({ method: "DELETE", host: "api.example.com" })
      .apply();

    expect(result.compiledCedar).toMatch(/permit/);
    expect(result.appliedAt).toBe("2026-04-18T12:00:00Z");
    expect(result.policyId).toBe("agent-1");

    const sent = JSON.parse(
      ((f.mock.calls[0] as unknown[])[1] as { body: string }).body,
    ) as { agent_id: string; rules: unknown[] };
    expect(sent.agent_id).toBe("agent-1");
    expect(sent.rules).toHaveLength(2);
  });

  // ── Task 1.4.6 — action wildcards + RBAC role shortcuts ─────────────────

  it("method '*' wildcard serialises as-is for server-side expansion (G30)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "*", host: "api.example.com" })
      .build();
    expect(spec.rules).toEqual([
      { kind: "http", permit: true, method: "*", host: "api.example.com" },
    ]);
  });

  it("permitAny / forbidAny emit all_actions rules (G30)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitAny({ whenUser: { attributeEquals: { key: "role", value: "admin" } } })
      .forbidAny({ whenUser: { trustEquals: "trusted" } })
      .build();
    expect(spec.rules).toEqual([
      {
        kind: "all_actions",
        permit: true,
        when_user: { kind: "attribute_equals", key: "role", value: "admin" },
      },
      {
        kind: "all_actions",
        permit: false,
        when_user: { kind: "trust_equals", trust: "trusted" },
      },
    ]);
  });

  it("permitAny with no arguments stages an unconditional god-mode permit", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies.builder("agent-1").permitAny().build();
    expect(spec.rules).toEqual([{ kind: "all_actions", permit: true }]);
  });

  it("role() accumulates into spec.roles (G31)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .role("admin", { allow: "*" })
      .role("developer", {
        allow: ["http.get:*/*", "http.post:api.codeforge.io/api/repos/*/files"],
        deny: ["http.post:api.codeforge.io/api/repos/*/prs/*/merge"],
      })
      .role("viewer", { allow: ["http.get:*/*"] })
      .build();

    expect(spec.roles).toEqual({
      admin: { allow: "*" },
      developer: {
        allow: ["http.get:*/*", "http.post:api.codeforge.io/api/repos/*/files"],
        deny: ["http.post:api.codeforge.io/api/repos/*/prs/*/merge"],
      },
      viewer: { allow: ["http.get:*/*"] },
    });
    expect(spec.rules).toEqual([]);
  });

  it("role() with same name replaces previous definition", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .role("admin", { allow: ["http.get:a.example.com"] })
      .role("admin", { allow: "*" })
      .build();
    expect(spec.roles).toEqual({ admin: { allow: "*" } });
  });

  it("role() rejects empty name", () => {
    const admin = new AgentumAdminClient(BASE);
    expect(() => admin.policies.builder("a").role("", { allow: "*" })).toThrow(
      /non-empty/,
    );
    expect(() => admin.policies.builder("a").role("   ", { allow: "*" })).toThrow(
      /non-empty/,
    );
  });

  it("userRoleField() sets the spec field", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .role("ops", { allow: "*" })
      .userRoleField("group")
      .build();
    expect(spec.user_role_field).toBe("group");
  });

  it("userRoleField() rejects empty value", () => {
    const admin = new AgentumAdminClient(BASE);
    expect(() => admin.policies.builder("a").userRoleField("")).toThrow(/non-empty/);
  });

  it("reset() clears rules AND roles AND userRoleField", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com" })
      .role("admin", { allow: "*" })
      .userRoleField("group");
    expect(b.ruleCount).toBe(1);
    expect(b.roleCount).toBe(1);
    b.reset();
    expect(b.ruleCount).toBe(0);
    expect(b.roleCount).toBe(0);
    const spec = b.build();
    expect(spec.rules).toEqual([]);
    expect(spec.roles).toBeUndefined();
    expect(spec.user_role_field).toBeUndefined();
  });

  it("build() omits roles and user_role_field when unused (wire shape matches Rust's skip_serializing_if)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com" })
      .build();
    expect(spec).not.toHaveProperty("roles");
    expect(spec).not.toHaveProperty("user_role_field");
  });

  it("build() deep-clones roles so later mutations don't leak", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies
      .builder("agent-1")
      .role("admin", { allow: "*" });
    const spec1 = b.build();
    b.role("admin", { allow: ["http.get:x.example.com"] });
    const spec2 = b.build();
    expect(spec1.roles).toEqual({ admin: { allow: "*" } });
    expect(spec2.roles).toEqual({
      admin: { allow: ["http.get:x.example.com"] },
    });
  });

  it("CodeForge 3-role DoD scenario round-trips through build()", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-codeforge")
      .role("admin", { allow: "*" })
      .role("developer", {
        allow: ["http.get:*/*", "http.post:api.codeforge.io/api/repos/*/files"],
        deny: ["http.post:api.codeforge.io/api/repos/*/prs/*/merge"],
      })
      .role("viewer", { allow: ["http.get:*/*"] })
      .userRoleField("role")
      .build();

    // Every field maps 1:1 to the Rust wire shape verified by
    // crates/agentum-policy-dsl/tests/round_trip.rs::codeforge_dsl_matches_reference.
    expect(spec.agent_id).toBe("agent-codeforge");
    expect(spec.rules).toEqual([]);
    expect(Object.keys(spec.roles ?? {})).toEqual([
      "admin",
      "developer",
      "viewer",
    ]);
    expect(spec.user_role_field).toBe("role");
  });

  // ── Task 1.4.8 — G38: whenContext (request body fields) ─────────────────

  it("whenContext fieldGreaterThan normalises to wire shape and attaches to rule", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({
        method: "POST",
        host: "claims.example.com",
        whenUser: { trustEquals: "verified" },
        whenContext: { fieldGreaterThan: { field: "amount", value: 10000 } },
      })
      .build();
    const [rule] = spec.rules;
    if (!rule || rule.kind !== "http") throw new Error("unreachable");
    expect(rule.when_context).toEqual({
      kind: "field_greater_than",
      field: "amount",
      value: 10000,
    });
    expect(rule.when_user).toEqual({ kind: "trust_equals", trust: "verified" });
  });

  it("whenContext accepts all four variant shapes", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({
        method: "GET",
        host: "a.example.com",
        whenContext: { fieldEquals: { field: "claim_type", value: "life" } },
      })
      .permitHttp({
        method: "GET",
        host: "b.example.com",
        whenContext: { fieldNotEquals: { field: "region", value: "sanctioned" } },
      })
      .permitHttp({
        method: "GET",
        host: "c.example.com",
        whenContext: { fieldGreaterThan: { field: "amount", value: 100 } },
      })
      .permitHttp({
        method: "GET",
        host: "d.example.com",
        whenContext: { fieldLessThan: { field: "delta", value: -500 } },
      })
      .build();
    const conds = spec.rules.map((r) => {
      if (r.kind !== "http") throw new Error("unreachable");
      return r.when_context;
    });
    expect(conds).toEqual([
      { kind: "field_equals", field: "claim_type", value: "life" },
      { kind: "field_not_equals", field: "region", value: "sanctioned" },
      { kind: "field_greater_than", field: "amount", value: 100 },
      { kind: "field_less_than", field: "delta", value: -500 },
    ]);
  });

  it("whenContext pass-through wire shape is accepted unchanged", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitMcp({
        tool: "transfer_funds",
        whenContext: { kind: "field_greater_than", field: "amount_usd", value: 100000 },
      })
      .build();
    const [rule] = spec.rules;
    if (!rule || rule.kind !== "mcp_tool") throw new Error("unreachable");
    expect(rule.when_context).toEqual({
      kind: "field_greater_than",
      field: "amount_usd",
      value: 100000,
    });
  });

  it("whenContext on permitAny threads through the AllActions shape", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitAny({
        whenUser: { attributeEquals: { key: "role", value: "junior" } },
        whenContext: { fieldLessThan: { field: "amount", value: 1000 } },
      })
      .build();
    const [rule] = spec.rules;
    if (!rule || rule.kind !== "all_actions") throw new Error("unreachable");
    expect(rule.when_context).toEqual({
      kind: "field_less_than",
      field: "amount",
      value: 1000,
    });
    expect(rule.when_user).toEqual({
      kind: "attribute_equals",
      key: "role",
      value: "junior",
    });
  });

  it("whenContext rejects fractional values for integer-only operators", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies.builder("agent-1");
    expect(() =>
      b.permitHttp({
        method: "POST",
        host: "api.example.com",
        // 10.5 is not an integer — Cedar's Long type rejects fractions.
        whenContext: { fieldGreaterThan: { field: "amount", value: 10.5 } },
      }),
    ).toThrow(/must be an integer/);
    expect(() =>
      b.permitHttp({
        method: "POST",
        host: "api.example.com",
        whenContext: { fieldLessThan: { field: "amount", value: 0.25 } },
      }),
    ).toThrow(/must be an integer/);
  });

  it("whenContext omitted → no when_context key on the wire (skip_serializing_if parity)", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .permitHttp({ method: "GET", host: "api.example.com" })
      .build();
    expect(Object.hasOwn(spec.rules[0]!, "when_context")).toBe(false);
  });

  // ── Task 1.5.9 — requireApproval / approvalConfig ────────────────────────

  it("forbidHttp with requireApproval emits wire-shape require_approval", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .forbidHttp({
        method: "POST",
        host: "lab-api",
        pathLike: "/orders*",
        requireApproval: true,
      })
      .build();
    expect(spec.rules[0]).toEqual({
      kind: "http",
      permit: false,
      method: "POST",
      host: "lab-api",
      path_like: "/orders*",
      require_approval: true,
    });
  });

  it("forbidHttp with approvalConfig emits snake_case params", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .forbidHttp({
        method: "POST",
        host: "lab-api",
        requireApproval: true,
        approvalConfig: { requiredApprovals: 2, timeoutSeconds: 600 },
      })
      .build();
    expect(spec.rules[0]).toMatchObject({
      require_approval: true,
      approval_config: { required_approvals: 2, timeout_seconds: 600 },
    });
  });

  it("permitHttp with requireApproval throws at build time", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies.builder("agent-1");
    expect(() =>
      b.permitHttp({
        method: "POST",
        host: "lab-api",
        requireApproval: true,
      }),
    ).toThrow(/only valid on forbid/);
  });

  it("forbidHttp with approvalConfig but no requireApproval throws", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies.builder("agent-1");
    expect(() =>
      b.forbidHttp({
        method: "POST",
        host: "lab-api",
        approvalConfig: { requiredApprovals: 1 },
      }),
    ).toThrow(/approvalConfig is set but requireApproval is false/);
  });

  it("forbidHttp with non-integer approvalConfig fields throws", () => {
    const admin = new AgentumAdminClient(BASE);
    const b = admin.policies.builder("agent-1");
    expect(() =>
      b.forbidHttp({
        method: "POST",
        host: "lab-api",
        requireApproval: true,
        approvalConfig: { requiredApprovals: 1.5 },
      }),
    ).toThrow(/positive integer/);
    expect(() =>
      b.forbidHttp({
        method: "POST",
        host: "lab-api",
        requireApproval: true,
        approvalConfig: { timeoutSeconds: -5 },
      }),
    ).toThrow(/positive integer/);
  });

  it("forbidMcp + forbidAny also support requireApproval", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .forbidMcp({ server: "stripe", tool: "charges.create", requireApproval: true })
      .forbidAny({
        requireApproval: true,
        approvalConfig: { requiredApprovals: 1, timeoutSeconds: 300 },
      })
      .build();
    expect(spec.rules).toEqual([
      {
        kind: "mcp_tool",
        permit: false,
        server: "stripe",
        tool: "charges.create",
        require_approval: true,
      },
      {
        kind: "all_actions",
        permit: false,
        require_approval: true,
        approval_config: { required_approvals: 1, timeout_seconds: 300 },
      },
    ]);
  });

  it("forbidHttp without requireApproval omits the field entirely", () => {
    const admin = new AgentumAdminClient(BASE);
    const spec = admin.policies
      .builder("agent-1")
      .forbidHttp({ method: "DELETE", host: "api.example.com" })
      .build();
    expect(Object.hasOwn(spec.rules[0]!, "require_approval")).toBe(false);
    expect(Object.hasOwn(spec.rules[0]!, "approval_config")).toBe(false);
  });
});
