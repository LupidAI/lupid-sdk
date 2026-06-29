/**
 * Type-safety regression test (Sprint 1.3.7).
 *
 * Enforces the runtime/admin client separation at compile time: the
 * admin sub-APIs (`agents` / `policies` / `mcp` / `apiKeys`) must live
 * ONLY on `AgentumAdminClient`. If anyone accidentally adds one of
 * these sub-API fields to `AgentumClient`, the `@ts-expect-error`
 * directives below become "unused" (TS2578) and
 * `tsc -p tsconfig.tests.json` fails.
 *
 * Two layers of protection:
 *  1. `npm run typecheck:tests` — dedicated `tsc --noEmit` pass.
 *  2. `npm test` — ts-jest compiles this file with `diagnostics: true`,
 *     so unused directives also surface as Jest failures.
 *
 * The type-level assertions below are expressed via **type queries**
 * (`AgentumClient["policies"]`, etc.) rather than runtime property
 * access so they never execute — only the type checker sees them.
 */

import { AgentumAdminClient, AgentumClient } from "../src/index";

// ── Negative assertions: each type query MUST be a type error. ──
// If any line ceases to be an error (i.e. someone added the field to
// AgentumClient), the `@ts-expect-error` becomes "unused" and tsc
// fails the build with TS2578.

// @ts-expect-error — `policies` is an admin sub-API; belongs on AgentumAdminClient only.
type _RuntimePolicies = AgentumClient["policies"];
// @ts-expect-error — `mcp` is an admin sub-API; belongs on AgentumAdminClient only.
type _RuntimeMcp = AgentumClient["mcp"];
// @ts-expect-error — `apiKeys` is an admin sub-API; belongs on AgentumAdminClient only.
type _RuntimeApiKeys = AgentumClient["apiKeys"];
// @ts-expect-error — `agents` sub-API (not the `registerAgent` method) belongs on AgentumAdminClient only.
type _RuntimeAgents = AgentumClient["agents"];

// Also assert that attempting to invoke any admin sub-API on an
// AgentumClient instance is a type error. This catches the specific
// regression the plan describes (`client.policies.put(...)`) rather
// than only catching the property existence.
function _compileTimeOnly(runtime: AgentumClient): void {
  // @ts-expect-error — `runtime.policies.put(...)` must be a type error.
  runtime.policies.put("agent-uuid", "permit(principal, action, resource);");
  // @ts-expect-error — `runtime.mcp.registerServer(...)` must be a type error.
  runtime.mcp.registerServer({ name: "x", url: "y" });
  // @ts-expect-error — `runtime.apiKeys.mint(...)` must be a type error.
  runtime.apiKeys.mint({ email: "x@y.z", role: "admin", tenantId: "t" });
  // @ts-expect-error — `runtime.agents.register(...)` must be a type error.
  runtime.agents.register({
    name: "x",
    owner_email: "x@y.z",
    purpose: "test",
  });
}

// Reference the function so TS doesn't prune it before diagnostics run.
void _compileTimeOnly;
// Reference the unused type aliases so TS doesn't prune them.
type _Aliases = _RuntimePolicies | _RuntimeMcp | _RuntimeApiKeys | _RuntimeAgents;
type _UnusedAliases = _Aliases; // silences "unused" lints without suppressing diagnostics.
void (null as _UnusedAliases | null);

describe("type-safety: admin surface must not leak onto AgentumClient", () => {
  it("compile-time assertions above guarantee the runtime/admin split", () => {
    // The real assertions live at module scope above (type queries and a
    // never-called function with `@ts-expect-error` directives). This
    // test body exists so Jest has a runnable unit and surfaces the file
    // in the report. If the file fails to type-check, ts-jest reports
    // the TS error instead of running this body.
    expect(true).toBe(true);
  });

  it("AgentumAdminClient must expose all four admin sub-APIs (positive control)", () => {
    const admin = new AgentumAdminClient({
      baseUrl: "http://localhost:7071",
      apiKey: "test-key",
    });

    // These must be valid — no `@ts-expect-error` — so if someone
    // removed an admin sub-API, this file would fail to compile.
    const agents: AgentumAdminClient["agents"] = admin.agents;
    const policies: AgentumAdminClient["policies"] = admin.policies;
    const mcp: AgentumAdminClient["mcp"] = admin.mcp;
    const apiKeys: AgentumAdminClient["apiKeys"] = admin.apiKeys;

    expect(agents).toBeDefined();
    expect(policies).toBeDefined();
    expect(mcp).toBeDefined();
    expect(apiKeys).toBeDefined();
  });
});
