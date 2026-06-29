/**
 * Shared MCP Streamable-HTTP governance primitives (GR-19).
 *
 * Why this module exists
 * ----------------------
 * The stdio MCP plane (`mcp-stdio-patch.ts`) patches `Client.prototype.callTool`,
 * which is transport-agnostic — official-SDK clients on
 * `StreamableHTTPClientTransport` are already enforced. But three gaps remain:
 *   (a) raw-`fetch`/axios/undici JSON-RPC clients that speak Streamable HTTP
 *       without the official `@modelcontextprotocol/sdk`,
 *   (b) duplicate bundle copies of the official SDK that escape the prototype
 *       patch (the scenario `mcp-stdio-patch.ts` already warns about),
 *   (c) any framework with its own MCP client implementation.
 * GR-19 closes those with a wire-level branch in all three HTTP interceptors —
 * defense-in-depth for (b), sole coverage for (a)/(c).
 *
 * Edge-safe contract: this module is reachable from `index.ts` via the fetch
 * interceptor and ships in the universal bundle (`dist/index.mjs`). It MUST
 * contain NO `node:*` imports, NO `Buffer`, NO top-level Node access. Every
 * `process` read is gated behind `typeof process !== "undefined"`.
 * `tests/edge-entry.test.ts` greps the built bundle for leaked built-ins.
 *
 * Policy contract (kept transport-agnostic): a `tools/call` is checked through
 * the SAME `evaluator.evaluateToolCall({ toolName: namespaced, arguments })`
 * call the LLM interceptors use, where `namespaced = namespacedToolName(tool,
 * server)` → `{tool}_mcp_{server}`. Identical action string ⇒ a single Cedar
 * policy governs stdio and HTTP MCP. A deny is rendered as a spec-legal
 * `CallToolResult { isError: true }`, byte-identical to the stdio deny literal
 * (`mcp-stdio-patch.ts:262-270`).
 */

import { namespacedToolName } from "./mcp-stdio-patch.js";
import type { CedarToolCallClient } from "../evaluation/cedar-client.js"; // type-only — allowed

// ── kill switch + Tier-2 endpoint registration (edge-safe env reads) ─────────

function readEnv(name: string): string | undefined {
  if (typeof process === "undefined" || !process || !process.env) return undefined;
  return process.env[name];
}

let _httpEnabledCache: { source: string | undefined; enabled: boolean } | null = null;

/**
 * `AGENTUM_MCP_HTTP=off|0|false` disables both detection tiers. Default
 * enabled. Cached against the raw env value so a test that mutates
 * `process.env` between cases re-reads.
 */
function mcpHttpEnabled(): boolean {
  const raw = readEnv("AGENTUM_MCP_HTTP");
  if (_httpEnabledCache && _httpEnabledCache.source === raw) {
    return _httpEnabledCache.enabled;
  }
  const v = (raw ?? "").trim().toLowerCase();
  const enabled = !(v === "off" || v === "0" || v === "false");
  _httpEnabledCache = { source: raw, enabled };
  return enabled;
}

let _endpointsCache: { source: string | undefined; prefixes: string[] } | null = null;

/**
 * `AGENTUM_MCP_ENDPOINTS` — comma-separated URL prefixes. Tier-2 detection
 * matches a request URL by `startsWith` against any of these. Covers the
 * deprecated 2024-11-05 HTTP+SSE transport (whose POSTs don't reliably carry
 * the dual-Accept header) and non-spec-compliant clients that drop it.
 */
function mcpEndpointPrefixes(): string[] {
  const raw = readEnv("AGENTUM_MCP_ENDPOINTS");
  if (_endpointsCache && _endpointsCache.source === raw) {
    return _endpointsCache.prefixes;
  }
  const prefixes = (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  _endpointsCache = { source: raw, prefixes };
  return prefixes;
}

// ── detection ────────────────────────────────────────────────────────────────

/**
 * Is this request a Streamable-HTTP MCP client message?
 *
 * Tier 1 (default): a POST whose `Accept` header lists BOTH
 *   `application/json` AND `text/event-stream` — the spec-MUST wire signature
 *   of every Streamable HTTP client message (MCP `2025-06-18`/`2025-03-26`).
 * Tier 2: the URL starts with one of the `AGENTUM_MCP_ENDPOINTS` prefixes
 *   (covers old-transport POSTs / clients that drop the dual Accept).
 *
 * MCP servers live on arbitrary URLs, so hostname classification is
 * structurally impossible — the wire signature is the only general key.
 */
export function isMcpWireCandidate(
  method: string | undefined,
  accept: string | undefined,
  url: string,
): boolean {
  if (!mcpHttpEnabled()) return false;
  // Tier 2: explicit endpoint prefix match (any method — old transport POSTs).
  const prefixes = mcpEndpointPrefixes();
  if (prefixes.length > 0) {
    for (const p of prefixes) {
      if (url.startsWith(p)) {
        // Tier-2 still only governs POST bodies (the request-carrying method).
        if ((method ?? "").toUpperCase() === "POST") return true;
      }
    }
  }
  // Tier 1: dual-Accept POST.
  if ((method ?? "").toUpperCase() !== "POST") return false;
  const a = (accept ?? "").toLowerCase();
  return a.includes("application/json") && a.includes("text/event-stream");
}

/**
 * Did the request URL match a Tier-2 registered endpoint prefix? Used by the
 * deny-shape decision: old-transport endpoints can't receive a synthesized
 * `application/json` deny on the POST (responses flow on the GET stream we
 * don't own), so they get an HTTP 403 + JSON-RPC error instead.
 */
export function isOldTransportEndpoint(url: string): boolean {
  const prefixes = mcpEndpointPrefixes();
  return prefixes.some((p) => url.startsWith(p));
}

// ── body parsing ──────────────────────────────────────────────────────────────

export interface McpToolCall {
  id: string | number | null;
  toolName: string;
  args: Record<string, unknown> | undefined;
}

export type McpParsed =
  | { kind: "tools/call"; id: string | number | null; toolName: string; args: Record<string, unknown> | undefined }
  | { kind: "initialize"; id: string | number | null }
  | { kind: "batch"; calls: McpToolCall[]; otherIds: Array<string | number | null> }
  | { kind: "other" }
  | null;

function asId(v: unknown): string | number | null {
  if (typeof v === "string" || typeof v === "number") return v;
  return null;
}

function parseOneMessage(
  obj: Record<string, unknown>,
): { kind: "tools/call"; call: McpToolCall } | { kind: "initialize"; id: string | number | null } | { kind: "other"; id: string | number | null } | null {
  if (obj["jsonrpc"] !== "2.0") return null;
  const method = obj["method"];
  const id = asId(obj["id"]);
  if (method === "tools/call") {
    const params = obj["params"];
    if (params && typeof params === "object" && !Array.isArray(params)) {
      const p = params as Record<string, unknown>;
      const name = typeof p["name"] === "string" ? (p["name"] as string) : "";
      const rawArgs = p["arguments"];
      const args =
        rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
          ? (rawArgs as Record<string, unknown>)
          : undefined;
      return { kind: "tools/call", call: { id, toolName: name, args } };
    }
    return { kind: "tools/call", call: { id, toolName: "", args: undefined } };
  }
  if (method === "initialize") return { kind: "initialize", id };
  return { kind: "other", id };
}

/**
 * Parse a raw HTTP request body as one or more JSON-RPC 2.0 messages.
 *
 * Returns `null` when the body is not JSON-RPC 2.0 — the interceptor then
 * forwards it byte-identically (coverage-level fail-open, mirroring the
 * bedrock-invoke non-Anthropic precedent: a non-MCP body is not our concern).
 * Only spec-shaped `tools/call` is ever acted on.
 */
export function parseMcpBody(rawBody: string): McpParsed {
  let json: unknown;
  try {
    json = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (Array.isArray(json)) {
    // 2025-03-26 batch array.
    const calls: McpToolCall[] = [];
    const otherIds: Array<string | number | null> = [];
    let sawJsonRpc = false;
    for (const entry of json) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      const parsed = parseOneMessage(entry as Record<string, unknown>);
      if (!parsed) continue;
      sawJsonRpc = true;
      if (parsed.kind === "tools/call") {
        calls.push(parsed.call);
      } else {
        otherIds.push(parsed.id);
      }
    }
    if (!sawJsonRpc) return null;
    if (calls.length === 0) return { kind: "other" };
    return { kind: "batch", calls, otherIds };
  }
  if (json && typeof json === "object") {
    const parsed = parseOneMessage(json as Record<string, unknown>);
    if (!parsed) return null;
    if (parsed.kind === "tools/call") {
      return {
        kind: "tools/call",
        id: parsed.call.id,
        toolName: parsed.call.toolName,
        args: parsed.call.args,
      };
    }
    if (parsed.kind === "initialize") {
      return { kind: "initialize", id: parsed.id };
    }
    return { kind: "other" };
  }
  return null;
}

// ── deny envelope (exact stdio parity, mcp-stdio-patch.ts:262-270) ───────────

/**
 * Build the spec-legal deny `CallToolResult` — a tool RESULT error visible to
 * the model, not a JSON-RPC protocol error. Byte-identical text to the stdio
 * deny literal so a single Cedar policy produces the same model-facing output
 * across both transports.
 */
export function buildMcpDenyResult(
  id: string | number | null,
  reason: string | undefined,
): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: `[agentum] tool call denied by policy: ${reason ?? "no matching allow rule"}`,
        },
      ],
      isError: true,
    },
  };
}

/**
 * Build a JSON-RPC protocol error for old-transport (Tier-2) endpoints whose
 * response channel (the GET stream) is not ours to write a 200 result on. The
 * interceptor serializes this as an HTTP 403 body so the client's `send()`
 * rejects — blocked is blocked (documented deviation from the isError-result
 * shape).
 */
export function buildMcpDenyError(
  id: string | number | null,
  reason: string | undefined,
): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32000,
      message: `[agentum] tool call denied by policy: ${reason ?? "no matching allow rule"}`,
    },
  };
}

// ── session / server-name correlation (bounded FIFO map) ─────────────────────

interface McpEndpointRecord {
  serverName?: string;
  sessionId?: string;
}

const MAX_ENDPOINTS = 128;
const _endpointMap = new Map<string, McpEndpointRecord>();

/**
 * Derive the correlation key for an endpoint: origin + pathname (NO query
 * string — it may carry tokens). Returns the raw URL if it can't be parsed.
 */
export function mcpEndpointKey(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return url;
  }
}

/**
 * Record an MCP server's self-reported name and/or session id for an endpoint
 * key, populated from the `initialize` response. Bounded FIFO — evicts the
 * oldest entry past `MAX_ENDPOINTS`.
 */
export function recordMcpServer(endpointKey: string, serverName?: string, sessionId?: string): void {
  if (!serverName && !sessionId) return;
  const existing = _endpointMap.get(endpointKey);
  const next: McpEndpointRecord = { ...existing };
  if (serverName) next.serverName = serverName;
  if (sessionId) next.sessionId = sessionId;
  // Re-insert at the tail (delete first so Map ordering reflects recency).
  _endpointMap.delete(endpointKey);
  _endpointMap.set(endpointKey, next);
  while (_endpointMap.size > MAX_ENDPOINTS) {
    const oldest = _endpointMap.keys().next().value;
    if (oldest === undefined) break;
    _endpointMap.delete(oldest);
  }
}

export function lookupMcpServer(endpointKey: string): McpEndpointRecord | undefined {
  return _endpointMap.get(endpointKey);
}

/** Test hook — clear the correlation map between cases. */
export function _resetMcpServerMap(): void {
  _endpointMap.clear();
}

/**
 * Resolve the Cedar action subject for a tool call against an endpoint. Uses
 * the recorded server name when known; falls back to the bare tool name (the
 * same fallback stdio uses at `mcp-stdio-patch.ts:121-124`).
 */
export function mcpActionFor(endpointKey: string, toolName: string): string {
  const rec = _endpointMap.get(endpointKey);
  return namespacedToolName(toolName, rec?.serverName ?? null);
}

/**
 * MCP-REDESIGN Phase 2b — the additive server-identifier inputs central uses
 * to resolve the canonical `server_id`. `url` is the endpoint key (origin +
 * pathname, query stripped); `name` is the recorded `serverInfo.name` when
 * `initialize` has been observed. Both are best-effort and may be undefined;
 * the namespaced action (`mcpActionFor`) is the unchanged dual-accept subject.
 */
export function mcpServerInfoFor(
  endpointKey: string,
): { url?: string; name?: string } {
  const rec = _endpointMap.get(endpointKey);
  const out: { url?: string; name?: string } = {};
  if (endpointKey.length > 0) out.url = endpointKey;
  if (rec?.serverName) out.name = rec.serverName;
  return out;
}

// ── initialize-response parsing ───────────────────────────────────────────────

/** Extract `result.serverInfo.name` from a parsed initialize response. */
export function extractServerInfo(json: Record<string, unknown>): string | undefined {
  const result = json["result"];
  if (!result || typeof result !== "object" || Array.isArray(result)) return undefined;
  const serverInfo = (result as Record<string, unknown>)["serverInfo"];
  if (!serverInfo || typeof serverInfo !== "object" || Array.isArray(serverInfo)) return undefined;
  const name = (serverInfo as Record<string, unknown>)["name"];
  return typeof name === "string" ? name : undefined;
}

const SSE_SCAN_CAP_BYTES = 64 * 1024;

/**
 * Incremental scanner for an SSE-framed `initialize` response. Accumulates
 * `data:` lines and tries to parse `result.serverInfo.name` from each complete
 * JSON payload. Returns the server name on first hit, else `undefined`. The
 * caller is responsible for the 64 KiB hard cap and detaching at first hit.
 */
export function scanInitializeSse(chunk: string): string | undefined {
  // SSE data payloads are `data: <json>` lines; a single event may span
  // multiple `data:` lines concatenated with `\n`. We scan line-by-line and
  // attempt a parse per accumulated data block.
  const lines = chunk.split(/\r?\n/);
  let dataBuf = "";
  for (const line of lines) {
    if (line.startsWith("data:")) {
      dataBuf += line.slice(5).trimStart();
    } else if (line.length === 0 && dataBuf.length > 0) {
      const name = tryServerNameFromJson(dataBuf);
      if (name) return name;
      dataBuf = "";
    }
  }
  if (dataBuf.length > 0) {
    const name = tryServerNameFromJson(dataBuf);
    if (name) return name;
  }
  return undefined;
}

export { SSE_SCAN_CAP_BYTES };

function tryServerNameFromJson(s: string): string | undefined {
  try {
    const json = JSON.parse(s);
    if (json && typeof json === "object" && !Array.isArray(json)) {
      return extractServerInfo(json as Record<string, unknown>);
    }
  } catch {
    /* incomplete / non-JSON data line */
  }
  return undefined;
}

// ── cross-plane double-enforcement suppression ───────────────────────────────
//
// When the official SDK runs over Streamable HTTP, both the Client-level
// `callTool` patch AND this wire plane observe the same call. The stdio patch
// marks the call as already-evaluated before forwarding; the wire plane
// consumes the token and skips re-evaluation + re-audit. Same philosophy as
// the `IN_FLIGHT` coalescing in init.ts.

interface SuppressionEntry {
  expiresAt: number;
}

const SUPPRESSION_TTL_MS = 5_000;
const SUPPRESSION_MAX = 64;
const _suppressionMap = new Map<string, SuppressionEntry>();

function suppressionKey(action: string, args: unknown): string {
  let argsStr: string;
  try {
    argsStr = args === undefined ? "null" : JSON.stringify(args);
  } catch {
    argsStr = String(args);
  }
  return `${action}::${argsStr}`.slice(0, 512);
}

function pruneSuppression(now: number): void {
  for (const [k, v] of _suppressionMap) {
    if (v.expiresAt <= now) _suppressionMap.delete(k);
  }
  while (_suppressionMap.size > SUPPRESSION_MAX) {
    const oldest = _suppressionMap.keys().next().value;
    if (oldest === undefined) break;
    _suppressionMap.delete(oldest);
  }
}

/** Stdio patch calls this on an allow, before forwarding to the official SDK. */
export function markMcpCallEvaluated(action: string, args: unknown): void {
  const now = Date.now();
  pruneSuppression(now);
  _suppressionMap.set(suppressionKey(action, args), { expiresAt: now + SUPPRESSION_TTL_MS });
}

/**
 * Wire plane calls this. Returns `true` (and deletes the token) when the call
 * was already evaluated by the stdio patch within the TTL — the wire plane
 * then forwards untouched, skipping eval + audit.
 */
export function consumeMcpCallEvaluated(action: string, args: unknown): boolean {
  const now = Date.now();
  const key = suppressionKey(action, args);
  const entry = _suppressionMap.get(key);
  if (!entry) return false;
  _suppressionMap.delete(key);
  if (entry.expiresAt <= now) return false;
  return true;
}

/** Test hook — clear the suppression map between cases. */
export function _resetMcpSuppression(): void {
  _suppressionMap.clear();
}

// ── audit (parity with stdio, transport flipped to "http") ───────────────────

/**
 * Emit an MCP HTTP audit event through the shared evaluator's ring-buffer
 * audit path. `eventType` is the same snake_case string stdio uses
 * (`mcp_tool_call` / `mcp_tool_deny`) so it parses via the Rust
 * `AuditEventType::from_str`. `decision_source` parity is automatic — the
 * `evaluateToolCall` path emits `local_pdp_decision` itself.
 */
export function emitMcpHttpAudit(
  evaluator: Pick<CedarToolCallClient, "emitMcpAudit">,
  args: {
    outcome: "allow" | "deny";
    action: string;
    callArgs: Record<string, unknown> | undefined;
    endpointKey: string;
    reason?: string | undefined;
    sessionId?: string | undefined;
  },
): void {
  const eventType = args.outcome === "deny" ? "mcp_tool_deny" : "mcp_tool_call";
  const detail: Record<string, unknown> = {
    tool: args.action,
    reason: args.reason ?? null,
    transport: "http",
    source: "@lupid/sdk/instrumentation/mcp-http",
    // Keys only — never values (argument bodies can carry sensitive payloads).
    argument_keys: args.callArgs ? Object.keys(args.callArgs).sort() : [],
    endpoint: args.endpointKey,
    mcp_session_id: args.sessionId ?? null,
  };
  // Audit is fire-and-forget and MUST never break a live tool call. Defensive
  // against an evaluator that predates the `emitMcpAudit` accessor.
  if (typeof evaluator.emitMcpAudit === "function") {
    try {
      evaluator.emitMcpAudit({ eventType, toolName: args.action, outcome: args.outcome, detail });
    } catch {
      /* swallow — audit best-effort */
    }
  }
}
