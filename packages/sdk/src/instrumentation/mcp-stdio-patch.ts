/**
 * Stdio-MCP interception shim (TypeScript).
 *
 * Mirror of `sdk/python/agentum_sdk/instrumentation/mcp_stdio_patch.py`.
 *
 * Why this exists — stdio MCP servers run as child processes and the MCP
 * client communicates with them via OS pipes. None of that traffic ever
 * traverses `HTTPS_PROXY`, so the gateway proxy is structurally unable
 * to see or block tool calls. This shim closes the hole by monkey-patching
 * `Client.prototype.callTool` from `@modelcontextprotocol/sdk/client/index.js`:
 * every call is run past `POST /api/v1/sdk/evaluate-tool-call` *before*
 * the JSON-RPC request leaves the client. On deny we synthesise an
 * MCP-spec-compliant `CallToolResult` with `isError: true` and never
 * write to the pipe.
 *
 * Tool-name namespacing rule — see the Python shim docstring and
 * `sdk/docs/mcp-stdio-interception.md`. Both languages produce
 * `{tool_name}_mcp_{server_name}` so a single Cedar policy file covers
 * both planes.
 *
 * Fail-closed — if the Agentum API is unreachable or returns a non-2xx,
 * we deny the call. Silent pass-through on connection error would be
 * a security hole.
 *
 * Bundler / prototype caveat: this patch mutates the prototype
 * of `Client` from the dynamically-imported `@modelcontextprotocol/sdk`.
 * If a downstream bundler aggressively inlines / tree-shakes that module
 * into a dedicated copy (e.g. multiple webpack contexts ending up with
 * distinct `Client` constructors), the patch installed against the
 * top-level import will not be visible to other copies. In practice this
 * affects only end-applications that bundle the SDK twice — most
 * deployments use a single resolution, and the Node http/https
 * interceptor (`node-http-interceptor.ts`) catches MCP-over-HTTP traffic
 * regardless. The stdio plane is genuinely off-network and prototype
 * patching is the only intercept point — there is no Node built-in
 * equivalent to fall back on, so single-resolution is a hard requirement
 * for stdio-MCP coverage.
 */

import type { CedarToolCallClient, ToolCallEvaluation } from "../evaluation/cedar-client.js";
import { freshnessHeaders } from "../audit/freshness.js";
import { markMcpCallEvaluated } from "./mcp-http.js";
import { warnHitlUnsupportedOnce } from "./hitl-unsupported.js";

// Bare `require()` throws `ReferenceError: require is not defined` in
// pure-ESM consumers (Vercel Edge, modern Next.js without
// --experimental-require-module, SvelteKit). Route every `require(...)`
// in this file through a lazy CJS-bridge so the stdio-MCP loader is
// resolved on demand and never throws at module-load time.
//
// We deliberately avoid a top-level `import { createRequire } from
// "node:module"`: this file is exported from the universal `index.ts`
// and any static `node:*` import here would crash module-load on edge
// runtimes that pre-scan the import graph (Vercel Edge, Cloudflare
// Workers). `Function("return require")()` is invisible to the
// edge bundler's static analysis. In CJS bundles and CJS Node it
// returns the local `require`; in pure-ESM Node and edge runtimes it
// returns `undefined` and the install short-circuits cleanly to
// "MCP-stdio not available" — better than a thrown ReferenceError.
let __requireResolved = false;
let __require: NodeJS.Require | undefined;
function getRequire(): NodeJS.Require | undefined {
  if (__requireResolved) return __require;
  __requireResolved = true;
  try {
    // Direct `eval` runs in the caller's local scope, so it sees the
    // CJS module's own `require` symbol when present. `new Function(...)`
    // would resolve against global scope, which doesn't carry the local
    // CJS require. Returns undefined (and we short-circuit) under
    // ESM Node and edge runtimes.
    // eslint-disable-next-line no-eval
    __require = eval(
      "typeof require === 'function' ? require : undefined",
    ) as NodeJS.Require | undefined;
  } catch {
    __require = undefined;
  }
  return __require;
}

export interface McpStdioPatchOptions {
  gateway?: string;
  apiKey?: string;
  agentId?: string;
  /**
   * Thunk that returns the shared `CedarToolCallClient` constructed by
   * `init.ts`. When supplied (and the thunk returns a live evaluator at
   * call time), MCP tool-call enforcement is routed through the same
   * PDP-first-with-central-fallback evaluator that LLM tool calls use
   * (CL-2). When unsupplied, or when the thunk returns `undefined`,
   * enforcement falls back to the legacy direct `POST /api/v1/sdk/
   * evaluate-tool-call` central call so standalone `installMcpStdioPatch`
   * callers (no `init()`) keep working.
   *
   * Mirrors the `getEvaluator` parameter on `installOpenAIPatch` /
   * `installAnthropicPatch`.
   */
  getEvaluator?: () => CedarToolCallClient | undefined;
}

interface EvaluateResponse {
  decision: string;
  reason?: string;
  rule_id?: string;
  advice?: string[];
  ttl_ms?: number;
}

const DENY_TIMEOUT_MS = 5_000;

let _config: { gateway: string; apiKey: string; agentId: string } | null = null;
// CL-2 — getter for the shared `CedarToolCallClient`. Held as a thunk so
// `init.ts` can publish the evaluator after the patch installs (mirrors
// the OpenAI / Anthropic patch installer shape). A re-install refreshes
// the thunk so a re-init under a new key picks up the new evaluator.
let _getEvaluator: (() => CedarToolCallClient | undefined) | null = null;

/**
 * Build the canonical Cedar action subject for an MCP tool call.
 * Returns `{tool}_mcp_{server}` when the server name is known, falling
 * back to the bare tool name otherwise.
 */
export function namespacedToolName(toolName: string, serverName?: string | null): string {
  if (serverName) return `${toolName}_mcp_${serverName}`;
  return toolName;
}

export function isMcpStdioPatched(): boolean {
  try {
    const req = getRequire();
    if (!req) return false;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod: any = req("@modelcontextprotocol/sdk/client/index.js");
    return mod?.Client?._agentumPatched === true;
  } catch {
    return false;
  }
}

/**
 * Install the stdio-MCP shim. Returns `true` if the patch is in place
 * (either freshly installed or already present), `false` if the
 * `@modelcontextprotocol/sdk` package is not installed or required
 * config is missing.
 *
 * Idempotent: re-installing on an already-patched class is a no-op.
 */
export function installMcpStdioPatch(opts: McpStdioPatchOptions = {}): boolean {
  // `AGENTUM_BASE_URL` is the canonical name (matches `init.ts`); the legacy
  // `AGENTUM_GATEWAY` is honored for back-compat with v0.x deployments and
  // emits a one-shot deprecation warning at install time. The new var wins
  // when both are set so customers staging the rename don't get spammed.
  const gateway =
    opts.gateway ??
    process.env.AGENTUM_BASE_URL ??
    process.env.AGENTUM_GATEWAY ??
    "http://localhost:7071";
  if (process.env.AGENTUM_GATEWAY && !process.env.AGENTUM_BASE_URL) {
    // eslint-disable-next-line no-console
    console.warn(
      "[agentum] AGENTUM_GATEWAY env var is deprecated; use AGENTUM_BASE_URL instead. " +
        "Support will be removed in a future release.",
    );
  }
  const apiKey = opts.apiKey ?? process.env.AGENTUM_API_KEY;
  const agentId = opts.agentId ?? process.env.AGENTUM_AGENT_ID;

  if (!apiKey || !agentId) {
    // eslint-disable-next-line no-console
    console.warn(
      `[agentum] mcp_stdio_patch: api_key and agent_id required (got apiKey=${!!apiKey}, agentId=${!!agentId}) — patch NOT installed`,
    );
    return false;
  }

  let mod: any;
  try {
    const req = getRequire();
    if (!req) return false;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    mod = req("@modelcontextprotocol/sdk/client/index.js");
  } catch {
    return false;
  }

  const ClientClass: any = mod.Client;
  if (!ClientClass || typeof ClientClass !== "function") return false;
  // Re-cast through `unknown` to a record we can attach our patch markers
  // to. The original `any` declaration narrows to `never` after the
  // typeof-function guard under TS's strict mode (`as never` no-ops),
  // breaking property access. Going through `unknown` defeats the
  // narrowing without losing call-site type info.
  const PatchableClass = ClientClass as unknown as {
    prototype: Record<string, unknown>;
    _agentumPatched?: boolean;
    _agentumOriginalCallTool?: unknown;
    _agentumOriginalConnect?: unknown;
  };

  _config = { gateway, apiKey, agentId };
  // Refresh the evaluator thunk on every install (including the
  // already-patched short-circuit below) so a re-init under a new
  // CedarToolCallClient still routes through the live evaluator. Same
  // contract as `EVALUATOR_REF` on openai-patch.ts.
  _getEvaluator = opts.getEvaluator ?? null;

  if (PatchableClass._agentumPatched) return true;

  const proto = PatchableClass.prototype;
  const originalCallTool = proto.callTool as (
    this: { getServerVersion?: () => { name?: string } | undefined; _agentumServerName?: string },
    params: { name: string; arguments?: Record<string, unknown> },
    ...rest: unknown[]
  ) => Promise<unknown>;
  const originalConnect = proto.connect as (
    this: unknown,
    ...rest: unknown[]
  ) => Promise<unknown>;

  PatchableClass._agentumOriginalCallTool = originalCallTool;
  PatchableClass._agentumOriginalConnect = originalConnect;

  // Wrap connect so that as soon as initialize() resolves we cache the
  // server's self-reported `serverInfo.name` on the instance — same
  // mechanism as the Python shim.
  proto.connect = async function patchedConnect(this: { _agentumServerName?: string; _agentumTransportKind?: "http" | "stdio"; getServerVersion?: () => { name?: string } | undefined }, ...args: unknown[]) {
    // GR-19: best-effort sniff of the transport instance (args[0]) so audit
    // events can attribute the right plane. An official-SDK client on
    // StreamableHTTP/SSE was previously mislabelled `transport: "stdio"`.
    try {
      if (!this._agentumTransportKind) {
        this._agentumTransportKind = detectTransportKind(args[0]);
      }
    } catch {
      /* best-effort — default to "stdio" at emit time */
    }
    const result = await originalConnect.call(this, ...args);
    try {
      if (!this._agentumServerName && typeof this.getServerVersion === "function") {
        const info = this.getServerVersion();
        if (info?.name) this._agentumServerName = info.name;
      }
    } catch {
      /* best-effort */
    }
    return result;
  } as unknown;

  proto.callTool = async function patchedCallTool(
    this: { _agentumServerName?: string; _agentumTransportKind?: "http" | "stdio"; getServerVersion?: () => { name?: string } | undefined },
    params: { name: string; arguments?: Record<string, unknown> },
    ...rest: unknown[]
  ) {
    let serverName = this._agentumServerName;
    if (!serverName && typeof this.getServerVersion === "function") {
      try {
        serverName = this.getServerVersion()?.name;
        if (serverName) this._agentumServerName = serverName;
      } catch {
        /* best-effort */
      }
    }
    const transportKind = this._agentumTransportKind ?? "stdio";
    const action = namespacedToolName(params.name, serverName ?? null);
    // MCP-REDESIGN Phase 2b — pass the captured `serverInfo.name`
    // (`_agentumServerName`) so central can resolve the canonical `server_id`.
    // The namespaced `action` is unchanged (dual-accept).
    const decision = await evaluateToolCall(action, params.arguments, serverName);

    if (decision.decision !== "allow") {
      // HITL-8: the stdio MCP plane has no session to suspend — warn once on
      // a require_hitl deny, then stand by the fail-CLOSED deny (no retry).
      warnHitlUnsupportedOnce("mcp-stdio", {
        decision: "deny",
        advice: decision.advice,
      });
      emitAuditBestEffort(action, "deny", decision.reason, params.arguments, transportKind);
      // eslint-disable-next-line no-console
      console.info(
        `[agentum] mcp_stdio_patch: DENY tool=${action} reason=${decision.reason ?? "no allow rule"}`,
      );
      // MCP-spec CallToolResult: see types.ts CallToolResultSchema.
      // isError=true + textual content block, no exception thrown.
      return {
        content: [
          {
            type: "text",
            text: `[agentum] tool call denied by policy: ${decision.reason ?? "no matching allow rule"}`,
          },
        ],
        isError: true,
      };
    }

    emitAuditBestEffort(action, "allow", decision.reason, params.arguments, transportKind);
    // GR-19: mark the call as already-evaluated so the wire plane (which sees
    // the transport-level POST the official SDK is about to make over
    // Streamable HTTP) skips re-evaluating + re-auditing it.
    markMcpCallEvaluated(action, params.arguments);
    return originalCallTool.call(this, params, ...rest);
  } as unknown;

  PatchableClass._agentumPatched = true;

  // Bundler-duplication detection. If a downstream bundler (webpack
  // contexts, federated modules, monorepo with two resolutions of
  // `@modelcontextprotocol/sdk`) ships a *second* copy of the package
  // into the same process, the patch we just installed is invisible to
  // consumers of that other copy — they bypass governance silently. We
  // can't fix the dup (the second copy lives behind a different module
  // record), but we can detect and warn loudly. Walk Node's CJS
  // require.cache for any matching path that DOESN'T resolve to the
  // module we patched and surface it so operators can collapse the
  // duplicate via package-manager dedup or `resolutions` overrides.
  detectMcpBundlerDuplicates(mod);

  // eslint-disable-next-line no-console
  console.info(
    `[agentum] mcp_stdio_patch: installed (gateway=${gateway}, agentId=${agentId})`,
  );
  return true;
}

function detectMcpBundlerDuplicates(patchedMod: unknown): void {
  try {
    const req = getRequire();
    if (!req) return;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const cache = (req as unknown as { cache?: Record<string, unknown> }).cache;
    if (!cache) return;
    const otherCopies: string[] = [];
    for (const [path, entry] of Object.entries(cache)) {
      // Match any resolution of @modelcontextprotocol/sdk client/index
      if (!/[\\/]@modelcontextprotocol[\\/]sdk[\\/]/.test(path)) continue;
      const exp = (entry as { exports?: unknown } | undefined)?.exports;
      if (exp && exp !== patchedMod) {
        // Different module record at this path → second copy.
        otherCopies.push(path);
      }
    }
    if (otherCopies.length > 0) {
      // eslint-disable-next-line no-console
      console.warn(
        "[agentum] mcp_stdio_patch: detected duplicate copies of " +
        "@modelcontextprotocol/sdk in require.cache. Calls routed through " +
        "the duplicate copy will BYPASS governance. Resolve via package " +
        "deduplication (`npm dedupe` / pnpm `dedupe` / yarn `resolutions`). " +
        `Other copies: ${otherCopies.slice(0, 3).join(", ")}` +
        (otherCopies.length > 3 ? ` (+${otherCopies.length - 3} more)` : ""),
      );
    }
  } catch {
    /* require.cache walking is best-effort */
  }
}

export function uninstallMcpStdioPatch(): boolean {
  let mod: any;
  try {
    const req = getRequire();
    if (!req) return false;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    mod = req("@modelcontextprotocol/sdk/client/index.js");
  } catch {
    return false;
  }
  const ClientClass: any = mod.Client;
  if (!ClientClass?._agentumPatched) return false;
  const proto = ClientClass.prototype as Record<string, unknown>;
  if (ClientClass._agentumOriginalCallTool) {
    proto.callTool = ClientClass._agentumOriginalCallTool as unknown;
  }
  if (ClientClass._agentumOriginalConnect) {
    proto.connect = ClientClass._agentumOriginalConnect as unknown;
  }
  delete ClientClass._agentumPatched;
  delete ClientClass._agentumOriginalCallTool;
  delete ClientClass._agentumOriginalConnect;
  return true;
}

// ── internal helpers ────────────────────────────────────────────────────────

async function evaluateToolCall(
  toolName: string,
  args: Record<string, unknown> | undefined,
  // MCP-REDESIGN Phase 2b — the MCP server's self-reported `serverInfo.name`
  // (the cached `_agentumServerName`). Central resolves this alias to the
  // canonical `server_id`. Additive; the namespaced `toolName` is unchanged.
  mcpServerName?: string,
): Promise<EvaluateResponse> {
  if (!_config) {
    return { decision: "deny", reason: "agentum SDK not configured" };
  }

  // CL-2 — prefer the shared `CedarToolCallClient` (PDP-first with
  // central fallback) when `init.ts` has wired one through. Fail-CLOSED
  // semantics are preserved by the evaluator itself: a transport /
  // timeout error to PDP and central resolves to a deny ToolCallEvaluation
  // with `denyCode: "deny_fail_closed"`. We adapt the result back to the
  // legacy `EvaluateResponse` shape so the rest of this file is unchanged.
  const evaluator = _getEvaluator?.();
  if (evaluator) {
    try {
      const result: ToolCallEvaluation = await evaluator.evaluateToolCall({
        toolName,
        arguments: args,
        ...(mcpServerName !== undefined && mcpServerName.length > 0
          ? { mcpServerName }
          : {}),
      });
      const out: EvaluateResponse = { decision: result.decision };
      if (result.reason) out.reason = result.reason;
      if (result.ruleId) out.rule_id = result.ruleId;
      if (result.advice) out.advice = result.advice;
      if (typeof result.ttlMs === "number") out.ttl_ms = result.ttlMs;
      return out;
    } catch (err) {
      // CedarToolCallClient.evaluateToolCall never throws in normal use
      // (failModes are internal). A defensive deny on the rare runtime-
      // error case preserves the fail-CLOSED posture.
      return {
        decision: "deny",
        reason: `agentum evaluator failure: ${(err as Error).message}`,
      };
    }
  }

  // Fallback: legacy direct-to-central path. Reached when:
  //   - the patch was installed without `getEvaluator` (standalone
  //     `installMcpStdioPatch` callers that never ran `agentum.init()`),
  //   - or init() ran but had not yet published the evaluator (race
  //     window during boot).
  //
  // This path is fail-CLOSED (a non-200 / transport error below denies the
  // tool call) but was previously silent, so an operator could not tell that
  // a boot-race had pushed a call onto the legacy central path instead of the
  // local PDP evaluator. The `console.debug` below makes the fallback
  // observable when `AGENTUM_DEBUG=true`, without spamming production.
  const body: Record<string, unknown> = { agent_id: _config.agentId, tool_name: toolName };
  if (args && Object.keys(args).length > 0) body.arguments = args;
  // MCP-REDESIGN Phase 2b — additive server identifier for central
  // `server_id` resolution (serde-default on the Rust side).
  if (mcpServerName && mcpServerName.length > 0) body.mcp_server_name = mcpServerName;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DENY_TIMEOUT_MS);
  if (process.env.AGENTUM_DEBUG === "true") {
    console.debug(
      "[agentum] mcp-stdio: evaluator not ready at call time, using legacy central path",
    );
  }
  try {
    const resp = await fetch(`${_config.gateway}/api/v1/sdk/evaluate-tool-call`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Api-Key": _config.apiKey,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (resp.status !== 200) {
      const text = await resp.text().catch(() => "");
      return {
        decision: "deny",
        reason: `agentum evaluate-tool-call HTTP ${resp.status}: ${text.slice(0, 200)}`,
      };
    }
    return (await resp.json()) as EvaluateResponse;
  } catch (err) {
    return {
      decision: "deny",
      reason: `agentum gateway unreachable: ${(err as Error).message}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Best-effort sniff of the MCP transport instance passed to `Client.connect`.
 * The official SDK transport classes are named `StreamableHTTPClientTransport`
 * / `SSEClientTransport` (HTTP) and `StdioClientTransport` (stdio). We also
 * treat the presence of a URL-ish field (`_url` / `url`) as an HTTP signal.
 * Returns "stdio" when nothing indicates HTTP — the historical default.
 */
function detectTransportKind(transport: unknown): "http" | "stdio" {
  if (!transport || typeof transport !== "object") return "stdio";
  const ctorName = (transport as { constructor?: { name?: string } }).constructor?.name ?? "";
  if (/StreamableHTTP/i.test(ctorName) || /SSE/i.test(ctorName)) return "http";
  const t = transport as Record<string, unknown>;
  const urlish = t["_url"] ?? t["url"];
  if (typeof urlish === "string" && /^https?:/i.test(urlish)) return "http";
  if (urlish && typeof urlish === "object" && typeof (urlish as { href?: unknown }).href === "string") {
    return "http";
  }
  return "stdio";
}

function emitAuditBestEffort(
  toolName: string,
  outcome: string,
  reason: string | undefined,
  args: Record<string, unknown> | undefined,
  transportKind: "http" | "stdio" = "stdio",
): void {
  if (!_config) return;

  // Event-type string MUST parse via the Rust `AuditEventType::from_str`
  // (`crates/agentum-core/src/models/audit.rs`). The old `"mcp.tool_call"`
  // (dotted) landed as `Unknown` and was invisible to event-type filters
  // (R26). `mcp_tool_deny` / `mcp_tool_call` are the real snake_case
  // variants — deny vs. allow keeps the same split the gateway uses.
  const eventType = outcome === "deny" ? "mcp_tool_deny" : "mcp_tool_call";
  const detail: Record<string, unknown> = {
    tool: toolName,
    reason: reason ?? null,
    // GR-19: an official-SDK client on Streamable HTTP previously audited as
    // "stdio" (a mislabel that now matters for plane attribution). The kind is
    // sniffed at connect-time from the transport instance.
    transport: transportKind,
    source: "@lupid/sdk/instrumentation/mcp-stdio-patch",
    // Keys only — never the values; argument bodies can carry sensitive
    // payloads and the MCP audit path is best-effort, not PII-scrubbed at
    // this layer (the evaluator path that follows runs the PII pipeline).
    argument_keys: args ? Object.keys(args).sort() : [],
  };

  // Prefer the shared evaluator's ring-buffer-backed audit path when the
  // runtime singleton is reachable (the common `init()` case): it resolves
  // tenant-schema dimensions, runs the PII pipeline, and POSTs to the real
  // `/api/v1/audit/ingest` ingest contract with replay-prevention freshness
  // headers. Fall back to a raw fetch only for standalone
  // `installMcpStdioPatch` callers that never ran `init()` (no evaluator).
  const evaluator = _getEvaluator?.();
  if (evaluator) {
    evaluator.emitMcpAudit({ eventType, toolName, outcome, detail });
    return;
  }

  // Raw-fetch fallback. Targets the real ingest endpoint
  // (`POST /api/v1/audit/ingest`) with the `AuditIngestRequest` shape —
  // NOT the GET-only SSE stream at `/api/v1/audit/events`, which is why
  // every MCP audit event used to be silently dropped (R26). `agent_id` is
  // required on the X-Api-Key path; `session_id` is best-effort empty here
  // (standalone callers have no ALS context).
  const payload = JSON.stringify({
    agent_id: _config.agentId,
    session_id: "",
    event_type: eventType,
    outcome,
    tool: toolName,
    detail,
  });
  // Bounded retry replaces the previous .catch(()=>{}) — single network
  // blip used to silently drop the audit event. Still detached from the
  // calling tool-call (no await), so the agent isn't slowed; only the
  // audit emission has bounded resilience.
  void shipWithRetry(
    `${_config.gateway}/api/v1/audit/ingest`,
    payload,
    _config.apiKey,
  );
}

async function shipWithRetry(url: string, payload: string, apiKey: string): Promise<void> {
  const attempts = 2; // initial + 1 retry
  for (let i = 0; i < attempts; i++) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": apiKey,
          // Q4: replay-prevention freshness headers — central default
          // `audit_ingest_require_freshness` is TRUE, so a POST without
          // these is rejected on net-new tenants. Reuse the SDK helper
          // rather than reimplementing the nonce/timestamp shape.
          ...freshnessHeaders(),
        },
        body: payload,
      });
      if (resp.ok) return;
      // 4xx is permanent (bad request / auth) — do NOT retry. This also
      // stops the previous behaviour where a 405/404 against the wrong
      // endpoint was retried then swallowed with zero signal.
      if (resp.status >= 400 && resp.status < 500) return; // permanent
    } catch {
      /* network — fall through to retry */
    }
    if (i < attempts - 1) {
      await new Promise<void>((r) => setTimeout(r, 100));
    }
  }
}
