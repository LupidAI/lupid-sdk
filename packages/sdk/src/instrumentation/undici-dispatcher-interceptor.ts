/**
 * undici global-dispatcher interception plane (R24, fixes G18a).
 *
 * Why this plane exists at all
 * ----------------------------
 * `installFetchInterceptor` patches `globalThis.fetch`. In a Next.js app the
 * patch installs in the `instrumentation.ts` boot context, but route handlers
 * execute with a *different* `fetch` binding (Next.js per-request context /
 * its own bundled undici wrapper). The patched fetch is never seen there, so
 * every outbound provider call from a route handler bypasses governance.
 * Probe evidence (2026-06-09): `fetch.patched=true` at boot but
 * `globalFetch.patched=false` inside a route handler.
 *
 * Node's `fetch` (and Next.js's bundled copy in most paths) routes through
 * undici's **global dispatcher**, which is process-wide state stored on
 * `globalThis[Symbol.for('undici.globalDispatcher.1')]`. That symbol is shared
 * even when `fetch` function identities differ across bundles, so wrapping the
 * dispatcher's `dispatch` reaches traffic the fetch wrapper misses.
 *
 * This is a defense-in-depth plane: the fetch + node:http interceptors stay
 * installed. The dispatcher plane tolerates a request that already traversed
 * the patched fetch — the SDK's own sidecar calls go out through the
 * un-patched fetch (see `fetch-interceptor.ts::fetchOriginal`) and are
 * exempted here by destination match before any classification.
 *
 * Two enforcement modes (priority order)
 * --------------------------------------
 *   (a) PDP-proxy routing — when `AGENTUM_PDP_PROXY_URL` (or `opts.pdpProxyUrl`)
 *       is set and the destination is a known LLM host: rewrite the dispatch
 *       `origin`/`path` to `${proxyUrl}/proxy/<provider>/<original-path>`,
 *       inject `X-Agentum-*` identity headers, and skip in-process evaluation
 *       entirely (the PDP reverse proxy is the enforcement point — R22).
 *   (b) In-process enforcement — no proxy URL set: extract request-body
 *       tool_calls, evaluate fail-CLOSED, and on deny synthesize a
 *       provider-shaped response through the undici handler callbacks without
 *       contacting the upstream (request-side pre-flight). On allow, the
 *       upstream call is forwarded through a WRAPPED handler that ALSO enforces
 *       the RESPONSE (model-emitted) tool calls — streaming (SSE +
 *       Bedrock binary event-stream) and non-streaming (buffered JSON) — at
 *       parity with the `fetch` + `node:http` planes. This covers the
 *       undici-only case: a Next.js route handler whose `globalThis.fetch` is
 *       UNPATCHED but whose traffic still rides the shared undici global
 *       dispatcher. The response-enforce logic lives in the transport-neutral
 *       `_response-enforce.ts` core (modelled on `node:http`'s push-based
 *       `wrapStreaming`/`wrapJsonResponse`).
 *
 * Double-enforcement suppression: a `globalThis.fetch()` call rides THIS global
 * dispatcher, and the fetch interceptor already enforces its response. To avoid
 * re-enforcing it here, the fetch plane stamps `x-agentum-plane: fetch` on the
 * outbound request it is about to enforce; the dispatcher reads that marker,
 * STRIPS it (upstream must never see it), and SKIPS response-side enforcement
 * (request-side pre-flight may still run). Raw `undici.request` traffic (no
 * fetch wrapper) carries no marker → the dispatcher is the sole enforcer.
 *
 * Edge-runtime contract: no `process.versions.node` → no-op, returns `false`.
 * No static `node:*` import; `undici` is reached only via the global-dispatcher
 * symbol (or a runtime-gated `createRequire` fallback).
 */

import { classifyUrl, type HostRegistry, type HostMatch, type Provider } from "./host-registry.js";
import { getAgentumContext, contextToProxyHeaders } from "./context.js";
import { makeBlockNoticeText } from "./_parsers.js";
import { extractRequestToolCalls } from "./provider-extractors.js";
import {
  createStreamingEnforcer,
  enforceNonStreamingBody,
  streamProviderForShape,
  type ResponseEnforceConfig,
} from "./_response-enforce.js";
import {
  isMcpWireCandidate,
  isOldTransportEndpoint,
  parseMcpBody,
  buildMcpDenyResult,
  buildMcpDenyError,
  mcpEndpointKey,
  mcpActionFor,
  lookupMcpServer,
  consumeMcpCallEvaluated,
  emitMcpHttpAudit,
  type McpParsed,
} from "./mcp-http.js";
import type { CedarToolCallClient, ToolCallEvaluation } from "../evaluation/cedar-client.js";

const PATCHED_TAG = Symbol.for("agentum.undici_dispatcher.patched");
const ORIGINAL_DISPATCH_TAG = Symbol.for("agentum.undici_dispatcher.original");
const GLOBAL_DISPATCHER_SYM = Symbol.for("undici.globalDispatcher.1");

/**
 * Cross-plane request marker (shared with `fetch-interceptor.ts`). When the
 * fetch interceptor forwards a request it is about to enforce, it stamps this
 * header. A `globalThis.fetch()` call rides the undici global dispatcher, so
 * the dispatcher would otherwise re-enforce the same response. On seeing the
 * marker the dispatcher STRIPS it (upstream must never see it) and SKIPS
 * response-side enforcement. Exported so the fetch plane imports the single
 * canonical constant rather than re-typing the literal. */
export const AGENTUM_PLANE_HEADER = "x-agentum-plane";

/** Minimal contract the dispatcher interceptor needs from the SDK runtime. */
export interface UndiciInterceptorRuntime {
  baseUrl: string;
  apiKey: string;
  evaluator: CedarToolCallClient;
}

export interface UndiciDispatcherInterceptorOptions {
  runtime: UndiciInterceptorRuntime;
  agentId: string;
  hosts: HostRegistry;
  /** When set, route known-LLM-host traffic through the PDP reverse proxy
   *  instead of evaluating in-process. e.g. `http://127.0.0.1:7081`. */
  pdpProxyUrl?: string;
  /** Fail-CLOSED ("deny") is the default for mode (b) pre-flight. */
  failMode?: "allow" | "deny";
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Test injection: a dispatcher to wrap instead of the live global one. */
  dispatcher?: UndiciDispatcher;
}

// ── undici dispatcher shape (structural, no `undici` type dependency) ───────

interface UndiciDispatchOptions {
  origin?: string | URL;
  path?: string;
  method?: string;
  headers?: Record<string, string | string[] | undefined> | string[] | null;
  body?: unknown;
}

interface UndiciDispatchHandler {
  onConnect?: (abort: (err?: Error) => void) => void;
  onHeaders?: (
    statusCode: number,
    headers: string[] | Buffer[] | null,
    resume: () => void,
    statusText?: string,
  ) => boolean;
  onData?: (chunk: Uint8Array) => boolean;
  onComplete?: (trailers: string[] | null) => void;
  onError?: (err: Error) => void;
  [key: string]: unknown;
}

export interface UndiciDispatcher {
  dispatch(opts: UndiciDispatchOptions, handler: UndiciDispatchHandler): boolean;
  [PATCHED_TAG]?: boolean;
  [ORIGINAL_DISPATCH_TAG]?: UndiciDispatcher["dispatch"];
}

type GlobalWithDispatcher = typeof globalThis & {
  [GLOBAL_DISPATCHER_SYM]?: UndiciDispatcher;
};

function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof (process as { versions?: { node?: string } }).versions?.node === "string"
  );
}

/**
 * Read the live global dispatcher. Prefers the `globalThis` symbol (shared
 * across bundled undici copies); falls back to `require('undici')
 * .getGlobalDispatcher()` via a runtime-gated `createRequire` when the symbol
 * is absent. Never top-level-imports `undici`. Returns `null` if neither path
 * resolves a dispatcher.
 */
function resolveGlobalDispatcher(
  logger: Pick<Console, "log" | "warn" | "error">,
): { dispatcher: UndiciDispatcher; set: (d: UndiciDispatcher) => void } | null {
  const g = globalThis as GlobalWithDispatcher;
  const fromSym = g[GLOBAL_DISPATCHER_SYM];
  if (fromSym && typeof fromSym.dispatch === "function") {
    return {
      dispatcher: fromSym,
      set: (d) => {
        g[GLOBAL_DISPATCHER_SYM] = d;
      },
    };
  }
  // Fallback: require('undici') via createRequire. `node:module` is a Node-only
  // specifier; we only reach this branch on Node (guarded by the caller's
  // isNodeRuntime check), and we resolve `require` defensively.
  try {
    // eslint-disable-next-line no-eval
    const req = eval("typeof require === 'function' ? require : undefined") as
      | NodeJS.Require
      | undefined;
    if (!req) return null;
    const undici = req("undici") as {
      getGlobalDispatcher?: () => UndiciDispatcher;
      setGlobalDispatcher?: (d: UndiciDispatcher) => void;
    };
    const cur = undici.getGlobalDispatcher?.();
    if (!cur || typeof cur.dispatch !== "function" || !undici.setGlobalDispatcher) {
      return null;
    }
    const setFn = undici.setGlobalDispatcher;
    return { dispatcher: cur, set: (d) => setFn(d) };
  } catch (err) {
    logger.warn(
      `[agentum] undici dispatcher resolve failed: ${(err as Error).message ?? String(err)}`,
    );
    return null;
  }
}

/**
 * Map a host-registry provider classification to the PDP proxy's `<provider>`
 * path segment (R22 upstream map). Only providers the PDP knows how to route
 * are returned; everything else yields `null` and the request passes through
 * untouched (the PDP would 502 an unknown provider, so we never rewrite to it).
 */
function pdpProxyProvider(provider: Provider, host: string): string | null {
  switch (provider) {
    case "openai":
      return "openai";
    case "anthropic":
      return "anthropic";
    case "cohere":
      // PASS2-PDP-01 added a native `cohere` upstream to the R22 proxy
      // (`agentum-pdp/src/proxy.rs:61` → https://api.cohere.ai), so the
      // dispatcher plane can now route Cohere through the PDP proxy instead of
      // falling through to in-process mode.
      return "cohere";
    case "gemini":
      // PASS2-PDP-01 added a native `gemini` upstream to the R22 proxy
      // (`agentum-pdp/src/proxy.rs:62` → https://generativelanguage.googleapis.com).
      return "gemini";
    case "openai-compatible":
      // The PDP built-in map (R22 `resolve_upstream`) covers deepseek
      // explicitly; other openai-compatible hosts are not in the static map,
      // so we cannot safely rewrite them (the PDP would 502). Leave those to
      // in-process / fetch-interceptor coverage.
      if (host === "api.deepseek.com") return "deepseek";
      return null;
    case "bedrock":
      // Bedrock uses SigV4 request signing bound to the original host; routing
      // it through the PDP proxy would invalidate the signature. The PDP has no
      // bedrock upstream for the same reason. Documented limitation — Bedrock
      // stays on in-process / fetch-interceptor coverage. (See the init log
      // line + InitOptions.pdpProxyUrl JSDoc.)
      return null;
    default:
      return null;
  }
}

/**
 * Reconstruct the absolute request URL from undici dispatch opts. `origin` may
 * be a string or URL; `path` already includes the query string.
 */
function reconstructUrl(opts: UndiciDispatchOptions): string | null {
  if (!opts.origin) return null;
  const origin = typeof opts.origin === "string" ? opts.origin : opts.origin.toString();
  const path = opts.path ?? "/";
  try {
    return new URL(path, origin).toString();
  } catch {
    return null;
  }
}

function originAndPathOf(url: string): { origin: string; path: string } | null {
  try {
    const u = new URL(url);
    return { origin: u.origin, path: `${u.pathname}${u.search}` };
  } catch {
    return null;
  }
}

export function installUndiciDispatcherInterceptor(
  opts: UndiciDispatcherInterceptorOptions,
): () => void {
  const logger = opts.logger ?? console;
  const failMode = opts.failMode ?? "deny";

  if (!isNodeRuntime()) {
    // Edge runtime: no undici global dispatcher; clean no-op.
    return () => {};
  }

  let dispatcher: UndiciDispatcher;
  let setDispatcher: ((d: UndiciDispatcher) => void) | undefined;
  if (opts.dispatcher) {
    dispatcher = opts.dispatcher;
  } else {
    const resolved = resolveGlobalDispatcher(logger);
    if (!resolved) {
      logger.warn("[agentum] undici global dispatcher not found; dispatcher plane skipped");
      return () => {};
    }
    dispatcher = resolved.dispatcher;
    setDispatcher = resolved.set;
  }

  // Idempotency: never double-wrap. A re-run of init() finds the marker and
  // returns the existing teardown (no-op).
  if (dispatcher[PATCHED_TAG]) {
    return () => {};
  }

  const originalDispatch = dispatcher.dispatch.bind(dispatcher);

  const wrapped: UndiciDispatcher["dispatch"] = function patchedDispatch(
    dispatchOpts: UndiciDispatchOptions,
    handler: UndiciDispatchHandler,
  ): boolean {
    try {
      const url = reconstructUrl(dispatchOpts);
      if (!url) return originalDispatch(dispatchOpts, handler);

      // Cross-plane suppression: a `globalThis.fetch()` call the fetch plane is
      // already enforcing carries `x-agentum-plane: fetch`. Read-and-strip it
      // here (upstream must never see it). When present, response-side
      // enforcement is skipped below (the fetch plane owns the response);
      // request-side pre-flight may still run as a cheap second check. Raw
      // `undici.request` traffic carries no marker → the dispatcher enforces.
      const skipResponseEnforce = consumePlaneMarker(dispatchOpts);

      let host: string;
      try {
        host = new URL(url).hostname.toLowerCase();
      } catch {
        return originalDispatch(dispatchOpts, handler);
      }

      // App-native proxy routing: the agent app itself points a provider
      // base-URL at the PDP proxy (e.g. LobeChat `DEEPSEEK_PROXY_URL=
      // http://127.0.0.1:7081/proxy/deepseek/v1`). The destination is already
      // the proxy, so we never evaluate or rewrite — but we DO inject the
      // X-Agentum-* identity headers so session/user/dimensions flow into the
      // proxy's Cedar context and audit events.
      if (opts.pdpProxyUrl && originMatches(url, opts.pdpProxyUrl)) {
        try {
          const path = new URL(url).pathname;
          if (path.startsWith("/proxy/")) {
            dispatchOpts.headers = mergeHeaders(
              dispatchOpts.headers,
              contextToProxyHeaders(getAgentumContext()),
            );
          }
        } catch {
          // Never break the hot path on header injection failure.
        }
        return originalDispatch(dispatchOpts, handler);
      }

      // The SDK's OWN calls (central API, PDP, audit ingest) must never be
      // intercepted/rewritten. Guard by destination before classification.
      // (Keep this ahead of the MCP gate — per GR-19.)
      if (isSdkOwnEndpoint(url, opts)) {
        return originalDispatch(dispatchOpts, handler);
      }

      // GR-19: MCP Streamable-HTTP gate. MCP servers live on arbitrary hosts,
      // so the wire-level detection runs independent of the host registry —
      // both when the host is unregistered AND when a registered host yields
      // no LLM shape.
      const mcpGateHit = isMcpWireCandidate(
        dispatchOpts.method,
        readDispatchAccept(dispatchOpts.headers),
        url,
      );

      if (!opts.hosts.matches(host)) {
        if (mcpGateHit) {
          // The dead `mcp-http`/`mcp-jsonrpc` types go live here. MCP has its
          // own request-side deny envelope; no response rewrite → skip flag
          // is irrelevant (always true).
          void runPreflight(
            dispatchOpts,
            handler,
            { provider: "mcp-http", shape: "mcp-jsonrpc" },
            { runtime: opts.runtime, agentId: opts.agentId, failMode, logger, originalDispatch, skipResponseEnforce: true },
          );
          return true;
        }
        return originalDispatch(dispatchOpts, handler);
      }

      const match = classifyUrl(url);

      // Mode (a): PDP-proxy routing. Highest priority — when engaged we skip
      // in-process evaluation entirely (proxy is the enforcement point).
      if (opts.pdpProxyUrl) {
        const provider = pdpProxyProvider(match.provider, host);
        if (provider) {
          rewriteToPdpProxy(dispatchOpts, opts.pdpProxyUrl, provider, url, logger);
          return originalDispatch(dispatchOpts, handler);
        }
        // Known LLM host the PDP can't route → fall through to mode (b).
      }

      // Mode (b): in-process enforcement. Only classifiable shapes carry
      // tool_calls worth evaluating; everything else passes through.
      if (!match.shape) {
        if (mcpGateHit) {
          void runPreflight(
            dispatchOpts,
            handler,
            { provider: "mcp-http", shape: "mcp-jsonrpc" },
            { runtime: opts.runtime, agentId: opts.agentId, failMode, logger, originalDispatch, skipResponseEnforce: true },
          );
          return true;
        }
        return originalDispatch(dispatchOpts, handler);
      }

      void runPreflight(dispatchOpts, handler, match, {
        runtime: opts.runtime,
        agentId: opts.agentId,
        failMode,
        logger,
        originalDispatch,
        skipResponseEnforce,
      });
      // We always return true: either runPreflight forwards via
      // originalDispatch (its return value is irrelevant to the caller here,
      // which only awaits the handler callbacks) or it synthesizes a deny.
      return true;
    } catch (err) {
      logger.warn(
        `[agentum] undici dispatcher internal error: ${(err as Error).message ?? String(err)}`,
      );
      // On any internal error, forward untouched rather than dropping traffic —
      // the fetch/node:http planes still enforce. This mirrors the
      // fetch-interceptor's "never break the app" posture for unexpected
      // failures while keeping per-tool-call decisions fail-CLOSED.
      return originalDispatch(dispatchOpts, handler);
    }
  };

  dispatcher.dispatch = wrapped;
  dispatcher[PATCHED_TAG] = true;
  dispatcher[ORIGINAL_DISPATCH_TAG] = originalDispatch;
  // Re-publish on the symbol so any consumer reading the dispatcher sees the
  // wrapped one. (When `set` is undefined — test-injected dispatcher — the
  // caller already holds the reference.)
  setDispatcher?.(dispatcher);

  return () => {
    if (dispatcher[PATCHED_TAG] && dispatcher[ORIGINAL_DISPATCH_TAG]) {
      dispatcher.dispatch = dispatcher[ORIGINAL_DISPATCH_TAG];
      delete dispatcher[PATCHED_TAG];
      delete dispatcher[ORIGINAL_DISPATCH_TAG];
      setDispatcher?.(dispatcher);
    }
  };
}

/**
 * Is this URL one of the SDK's own control-plane endpoints (central API base
 * URL, PDP, audit ingest)? Such traffic must never be intercepted/rewritten.
 * The SDK's sidecar POSTs already go out through the un-patched fetch, but a
 * Next.js bundle may route them through the global dispatcher regardless — so
 * we guard by base-URL match here too.
 */
function isSdkOwnEndpoint(url: string, opts: UndiciDispatcherInterceptorOptions): boolean {
  const base = opts.runtime.baseUrl;
  if (base && originMatches(url, base)) return true;
  if (opts.pdpProxyUrl && originMatches(url, opts.pdpProxyUrl)) return true;
  return false;
}

function originMatches(url: string, base: string): boolean {
  try {
    return new URL(url).origin === new URL(base).origin;
  } catch {
    return false;
  }
}

/**
 * Rewrite the dispatch opts in place to target the PDP reverse proxy:
 *   origin → proxyUrl origin
 *   path   → /proxy/<provider><original-path>
 * and inject the `X-Agentum-*` identity headers from the active context.
 */
function rewriteToPdpProxy(
  dispatchOpts: UndiciDispatchOptions,
  pdpProxyUrl: string,
  provider: string,
  originalUrl: string,
  logger: Pick<Console, "log" | "warn" | "error">,
): void {
  const op = originAndPathOf(originalUrl);
  if (!op) return;
  const proxyParts = originAndPathOf(pdpProxyUrl) ?? { origin: pdpProxyUrl, path: "" };
  // `/proxy/<provider>` + original path (which begins with `/`).
  const newPath = `/proxy/${provider}${op.path.startsWith("/") ? op.path : `/${op.path}`}`;
  dispatchOpts.origin = proxyParts.origin;
  dispatchOpts.path = newPath;

  // Inject identity headers. Never throw on the hot path.
  let injected: Record<string, string>;
  try {
    injected = contextToProxyHeaders(getAgentumContext());
  } catch (err) {
    logger.warn(
      `[agentum] undici proxy header injection failed: ${(err as Error).message ?? String(err)}`,
    );
    injected = {};
  }
  dispatchOpts.headers = mergeHeaders(dispatchOpts.headers, injected);
}

/**
 * Merge injected headers into undici's header representation. undici accepts
 * either a record, a flat `[k, v, k, v, ...]` array, or null/undefined.
 * Injected headers win on collision (the SDK's identity context is canonical).
 */
function mergeHeaders(
  existing: UndiciDispatchOptions["headers"],
  injected: Record<string, string>,
): Record<string, string | string[] | undefined> | string[] {
  const injectedKeysLower = new Set(Object.keys(injected).map((k) => k.toLowerCase()));
  if (existing == null) {
    return { ...injected };
  }
  if (Array.isArray(existing)) {
    const out: string[] = [];
    for (let i = 0; i + 1 < existing.length; i += 2) {
      const k = existing[i];
      if (typeof k === "string" && injectedKeysLower.has(k.toLowerCase())) continue;
      out.push(existing[i]!, existing[i + 1]!);
    }
    for (const [k, v] of Object.entries(injected)) out.push(k, v);
    return out;
  }
  // Record form.
  const out: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(existing)) {
    if (injectedKeysLower.has(k.toLowerCase())) continue;
    out[k] = v;
  }
  for (const [k, v] of Object.entries(injected)) out[k] = v;
  return out;
}

// ── mode (b): in-process pre-flight ─────────────────────────────────────────

interface PreflightCtx {
  runtime: UndiciInterceptorRuntime;
  agentId: string;
  failMode: "allow" | "deny";
  logger: Pick<Console, "log" | "warn" | "error">;
  originalDispatch: UndiciDispatcher["dispatch"];
  /**
   * When `true`, the fetch plane is already enforcing this request's response
   * (it stamped `x-agentum-plane: fetch`, since stripped). The dispatcher must
   * forward the upstream response untouched to avoid double-enforcement.
   * Request-side pre-flight still runs.
   */
  skipResponseEnforce: boolean;
}

async function runPreflight(
  dispatchOpts: UndiciDispatchOptions,
  handler: UndiciDispatchHandler,
  match: HostMatch,
  ctx: PreflightCtx,
): Promise<void> {
  // GR-19: the MCP JSON-RPC shape has its own pre-flight + deny envelope.
  // For MCP, undici stays request-side pre-flight only: no initialize-response
  // sniffing here. In Node, `fetch` rides the global dispatcher, so the fetch
  // plane populates the shared server-name map first and the suppression token
  // prevents double-handling; raw-`undici.request` clients whose initialize we
  // never see fall back to bare tool names. (LLM shapes DO get response-side
  // enforcement below — see `wrapResponseHandler`.)
  if (match.shape === "mcp-jsonrpc") {
    await runMcpPreflight(dispatchOpts, handler, ctx);
    return;
  }

  let denied: { reason: string; toolName?: string } | null = null;
  try {
    const body = bodyToString(dispatchOpts.body);
    const parsed = body ? safeParseJson(body) : null;
    // GR-18: the shared extractor is keyed by `HostMatch.shape`, so Cohere,
    // Gemini and Bedrock request bodies are now covered identically to fetch.
    const calls = parsed ? extractRequestToolCalls(match, parsed) : [];
    for (const tc of calls) {
      let verdict: ToolCallEvaluation;
      try {
        verdict = await ctx.runtime.evaluator.evaluateToolCall({
          toolName: tc.name,
          arguments: tc.args,
        });
      } catch (err) {
        ctx.logger.warn(
          `[agentum] undici preflight evaluate error: ${(err as Error).message}`,
        );
        if (ctx.failMode === "deny") {
          denied = { reason: "agentum-fail-closed", toolName: tc.name };
          break;
        }
        continue;
      }
      if (verdict.decision === "deny") {
        denied = { reason: verdict.reason ?? "policy denied", toolName: tc.name };
        break;
      }
    }
  } catch (err) {
    ctx.logger.warn(
      `[agentum] undici preflight internal error: ${(err as Error).message}`,
    );
    // Internal error is not a policy decision — forward rather than drop.
    denied = null;
  }

  if (denied) {
    synthesizeDeny(handler, match, denied.reason, denied.toolName);
    return;
  }

  // Allow path. Forward to upstream, enforcing the RESPONSE (model-emitted)
  // tool calls — UNLESS the fetch plane already owns this request's response
  // (marker was present, see `skipResponseEnforce`). Response-side coverage
  // mirrors the fetch + node:http planes via the shared `_response-enforce`
  // core.
  if (ctx.skipResponseEnforce) {
    ctx.originalDispatch(dispatchOpts, handler);
    return;
  }
  const wrapped = wrapResponseHandler(handler, match, ctx);
  ctx.originalDispatch(dispatchOpts, wrapped);
}

// ── response-side enforcement: wrapped undici handler ────────────────────────

/** 2xx? Only enforce successful responses; error bodies pass through. */
function isEnforceableStatus(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * Read the response content-type from undici's `onHeaders` header
 * representation (flat `[k, v, ...]` string/Buffer array, or null).
 */
function readResponseContentType(headers: string[] | Buffer[] | null): string {
  if (!headers || headers.length === 0) return "";
  for (let i = 0; i + 1 < headers.length; i += 2) {
    const k = headers[i];
    const key = typeof k === "string" ? k : k?.toString("utf8");
    if (key && key.toLowerCase() === "content-type") {
      const v = headers[i + 1];
      return (typeof v === "string" ? v : v?.toString("utf8") ?? "").toLowerCase();
    }
  }
  return "";
}

/**
 * Return a copy of undici's flat header array with `content-length` replaced by
 * `newLen`. undici headers on `onHeaders` are `string[] | Buffer[]`; we
 * normalise to `string[]` (the AWS/undici stack accepts either).
 */
function withContentLength(
  headers: string[] | Buffer[] | null,
  newLen: number,
): string[] {
  const out: string[] = [];
  let replaced = false;
  if (headers) {
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const k = headers[i];
      const key = typeof k === "string" ? k : k?.toString("utf8") ?? "";
      const v = headers[i + 1];
      const val = typeof v === "string" ? v : v?.toString("utf8") ?? "";
      if (key.toLowerCase() === "content-length") {
        out.push(key, String(newLen));
        replaced = true;
        continue;
      }
      out.push(key, val);
    }
  }
  if (!replaced) out.push("content-length", String(newLen));
  out.push("x-agentum-policy", "sdk-enforced");
  return out;
}

/**
 * Return a copy of undici's flat header array with `content-length` REMOVED.
 * Used on the STREAMING enforce path: a deny-rewrite drops the tool-call frames
 * and splices a notice, changing the body byte count, so a stale upstream
 * `content-length` would truncate/error the reassembled stream. Chunked SSE
 * never carries one, but a Bedrock binary event-stream
 * (`application/vnd.amazon.eventstream`) response can — and that is the path the
 * spliced notice corrupts. Mirrors the fetch plane's
 * `headers.delete("content-length")` on its streaming rewrite. Safe on allow
 * too: the body is forwarded verbatim and the consumer reads until onComplete.
 */
function withoutContentLength(headers: string[] | Buffer[] | null): string[] {
  const out: string[] = [];
  if (headers) {
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const k = headers[i];
      const key = typeof k === "string" ? k : k?.toString("utf8") ?? "";
      const v = headers[i + 1];
      const val = typeof v === "string" ? v : v?.toString("utf8") ?? "";
      if (key.toLowerCase() === "content-length") continue;
      out.push(key, val);
    }
  }
  return out;
}

/**
 * Wrap an undici handler so the upstream RESPONSE is enforced. Decided by the
 * response content-type in `onHeaders`:
 *   - `text/event-stream` / `application/vnd.amazon.eventstream` → STREAMING:
 *     pass headers through immediately (chunked, no content-length), transform
 *     each `onData` chunk through the streaming enforcer, flush on `onComplete`.
 *   - `application/json` → NON-STREAMING: BUFFER headers + all `onData`; on
 *     `onComplete` run the buffered-body enforcer, set the corrected
 *     content-length, then replay original `onHeaders`/`onData`/`onComplete`.
 *   - anything else, non-2xx, or no streaming parser → pass through untouched
 *     (fail-OPEN on shape-unrecognized; fail-CLOSED only on an actual deny/
 *     evaluator error inside the enforcer).
 * `onError` always passes through.
 */
function wrapResponseHandler(
  handler: UndiciDispatchHandler,
  match: HostMatch,
  ctx: PreflightCtx,
): UndiciDispatchHandler {
  const cfg: ResponseEnforceConfig = {
    match,
    evaluator: ctx.runtime.evaluator,
    failMode: ctx.failMode,
    logger: ctx.logger,
  };
  const hasStreamParser = streamProviderForShape(match.shape) !== null;

  // Decided in onHeaders; null until then.
  let mode: "stream" | "buffer" | "passthrough" = "passthrough";
  let streamEnforcer:
    | { feed(chunk: Uint8Array): Promise<void>; end(): Promise<void> }
    | null = null;
  // Serialize async stream feeds so chunks emit in order.
  let streamChain: Promise<void> = Promise.resolve();

  // Buffer-mode state.
  let bufferedStatus = 0;
  let bufferedHeaders: string[] | Buffer[] | null = null;
  let bufferedResume: () => void = () => {};
  let bufferedStatusText: string | undefined;
  const bufferedChunks: Uint8Array[] = [];

  const wrapped: UndiciDispatchHandler = {
    ...handler,
    onConnect(abort: (err?: Error) => void): void {
      handler.onConnect?.(abort);
    },
    onHeaders(
      statusCode: number,
      headers: string[] | Buffer[] | null,
      resume: () => void,
      statusText?: string,
    ): boolean {
      const ct = readResponseContentType(headers);
      if (!isEnforceableStatus(statusCode)) {
        mode = "passthrough";
        return handler.onHeaders?.(statusCode, headers, resume, statusText) ?? true;
      }
      if (
        (ct.includes("text/event-stream") ||
          ct.includes("application/vnd.amazon.eventstream")) &&
        hasStreamParser
      ) {
        // STREAMING: headers flow immediately; body is chunked (no length).
        mode = "stream";
        const emit = (bytes: Uint8Array): void => {
          if (bytes.byteLength > 0) handler.onData?.(bytes);
        };
        streamEnforcer = createStreamingEnforcer(cfg, emit);
        if (!streamEnforcer) {
          mode = "passthrough";
        }
        // Strip content-length on the streaming-enforce path: a deny-rewrite
        // changes the body byte count, so a stale length (which a Bedrock binary
        // event-stream response can carry, unlike chunked SSE) would corrupt the
        // reassembled stream. Mirrors the fetch streaming rewrite. On the
        // passthrough fallback (enforcer unavailable) keep headers verbatim.
        return (
          handler.onHeaders?.(
            statusCode,
            mode === "stream" ? withoutContentLength(headers) : headers,
            resume,
            statusText,
          ) ?? true
        );
      }
      if (ct.includes("application/json")) {
        // NON-STREAMING: buffer headers; do NOT call original onHeaders yet.
        mode = "buffer";
        bufferedStatus = statusCode;
        bufferedHeaders = headers;
        bufferedResume = resume;
        bufferedStatusText = statusText;
        // Keep the pipe flowing while we buffer.
        return true;
      }
      mode = "passthrough";
      return handler.onHeaders?.(statusCode, headers, resume, statusText) ?? true;
    },
    onData(chunk: Uint8Array): boolean {
      if (mode === "stream" && streamEnforcer) {
        const enforcer = streamEnforcer;
        // COPY the chunk: undici may reuse the underlying buffer across
        // onData calls, and we feed it asynchronously (deferred via
        // streamChain) — a non-copied view could be mutated before the feed
        // reads it. `.slice()` allocates a fresh backing buffer.
        const view = (chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)).slice();
        streamChain = streamChain.then(() => enforcer.feed(view)).catch((err) => {
          ctx.logger.warn(
            `[agentum] undici stream enforce feed error: ${(err as Error).message ?? String(err)}`,
          );
        });
        return true;
      }
      if (mode === "buffer") {
        // COPY for the same buffer-reuse reason (we hold chunks until onComplete).
        bufferedChunks.push((chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)).slice());
        return true;
      }
      return handler.onData?.(chunk) ?? true;
    },
    onComplete(trailers: string[] | null): void {
      if (mode === "stream" && streamEnforcer) {
        const enforcer = streamEnforcer;
        streamChain = streamChain.then(() => enforcer.end());
        streamChain
          .then(() => handler.onComplete?.(trailers))
          .catch((err) => {
            ctx.logger.warn(
              `[agentum] undici stream enforce end error: ${(err as Error).message ?? String(err)}`,
            );
            handler.onComplete?.(trailers);
          });
        return;
      }
      if (mode === "buffer") {
        const raw = concatChunks(bufferedChunks);
        enforceNonStreamingBody(cfg, raw)
          .then((result) => {
            const outHeaders = result.rewritten
              ? withContentLength(bufferedHeaders, result.body.byteLength)
              : bufferedHeaders;
            handler.onHeaders?.(bufferedStatus, outHeaders, bufferedResume, bufferedStatusText);
            if (result.body.byteLength > 0) handler.onData?.(result.body);
            handler.onComplete?.(trailers);
          })
          .catch((err) => {
            ctx.logger.warn(
              `[agentum] undici json enforce error: ${(err as Error).message ?? String(err)}`,
            );
            // Fail-OPEN on internal enforcer error: replay original bytes.
            handler.onHeaders?.(bufferedStatus, bufferedHeaders, bufferedResume, bufferedStatusText);
            if (raw.byteLength > 0) handler.onData?.(raw);
            handler.onComplete?.(trailers);
          });
        return;
      }
      handler.onComplete?.(trailers);
    },
    onError(err: Error): void {
      handler.onError?.(err);
    },
  };
  return wrapped;
}

/** Concatenate Uint8Array chunks into one (edge-safe, no `Buffer`). */
function concatChunks(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/**
 * MCP-over-HTTP request-side pre-flight for the undici plane. Parses the
 * JSON-RPC body, checks `tools/call` fail-CLOSED, and on deny synthesizes the
 * JSON-RPC deny envelope through the handler callbacks. `initialize`,
 * notifications, `tools/list`, and any non-checked method forward untouched.
 */
async function runMcpPreflight(
  dispatchOpts: UndiciDispatchOptions,
  handler: UndiciDispatchHandler,
  ctx: PreflightCtx,
): Promise<void> {
  const url = reconstructUrl(dispatchOpts);
  const endpointKey = url ? mcpEndpointKey(url) : "";
  const oldTransport = url ? isOldTransportEndpoint(url) : false;
  const sessionId = endpointKey ? lookupMcpServer(endpointKey)?.sessionId : undefined;
  const evaluator = ctx.runtime.evaluator;

  let parsed: McpParsed = null;
  try {
    const body = bodyToString(dispatchOpts.body);
    parsed = body ? parseMcpBody(body) : null;
  } catch (err) {
    ctx.logger.warn(`[agentum] undici mcp parse error: ${(err as Error).message}`);
    // Internal error is not a policy decision — forward untouched.
    ctx.originalDispatch(dispatchOpts, handler);
    return;
  }

  if (parsed === null || parsed.kind === "other" || parsed.kind === "initialize") {
    ctx.originalDispatch(dispatchOpts, handler);
    return;
  }

  if (parsed.kind === "batch") {
    let anyDeny = false;
    for (const call of parsed.calls) {
      const action = mcpActionFor(endpointKey, call.toolName);
      const verdict = await evalMcpUndici(ctx, action, call.args);
      if (verdict === "deny") {
        anyDeny = true;
        emitMcpHttpAudit(evaluator, { outcome: "deny", action, callArgs: call.args, endpointKey, reason: "policy denied", sessionId });
      } else {
        emitMcpHttpAudit(evaluator, { outcome: "allow", action, callArgs: call.args, endpointKey, sessionId });
      }
    }
    if (anyDeny) {
      const arr = parsed.calls
        .map((c) => buildMcpDenyResult(c.id, "policy denied"))
        .concat(parsed.otherIds.map((id) => buildMcpDenyError(id, "policy denied")));
      synthesizeMcpDeny(handler, arr, oldTransport ? 403 : 200);
      return;
    }
    ctx.originalDispatch(dispatchOpts, handler);
    return;
  }

  // single tools/call
  const action = mcpActionFor(endpointKey, parsed.toolName);
  if (consumeMcpCallEvaluated(action, parsed.args)) {
    ctx.originalDispatch(dispatchOpts, handler);
    return;
  }
  const verdict = await evalMcpUndici(ctx, action, parsed.args);
  if (verdict === "deny") {
    emitMcpHttpAudit(evaluator, { outcome: "deny", action, callArgs: parsed.args, endpointKey, reason: "policy denied", sessionId });
    const env = oldTransport
      ? buildMcpDenyError(parsed.id, "policy denied")
      : buildMcpDenyResult(parsed.id, "policy denied");
    synthesizeMcpDeny(handler, env, oldTransport ? 403 : 200);
    return;
  }
  emitMcpHttpAudit(evaluator, { outcome: "allow", action, callArgs: parsed.args, endpointKey, sessionId });
  ctx.originalDispatch(dispatchOpts, handler);
}

async function evalMcpUndici(
  ctx: PreflightCtx,
  action: string,
  args: Record<string, unknown> | undefined,
): Promise<"allow" | "deny"> {
  try {
    const v = await ctx.runtime.evaluator.evaluateToolCall({ toolName: action, arguments: args });
    return v.decision === "deny" ? "deny" : "allow";
  } catch (err) {
    ctx.logger.warn(`[agentum] undici mcp evaluate error: ${(err as Error).message}`);
    return ctx.failMode === "deny" ? "deny" : "allow";
  }
}

/** Read the `Accept` header from undici's header representation. */
function readDispatchAccept(headers: UndiciDispatchOptions["headers"]): string | undefined {
  return readDispatchHeader(headers, "accept");
}

/** Read a single header (case-insensitive) from undici's header representation. */
function readDispatchHeader(
  headers: UndiciDispatchOptions["headers"],
  name: string,
): string | undefined {
  if (headers == null) return undefined;
  const lower = name.toLowerCase();
  if (Array.isArray(headers)) {
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const k = headers[i];
      if (typeof k === "string" && k.toLowerCase() === lower) {
        return headers[i + 1];
      }
    }
    return undefined;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== lower) continue;
    if (Array.isArray(v)) return v.join(", ");
    if (v == null) return undefined;
    return String(v);
  }
  return undefined;
}

/**
 * Read-and-strip the cross-plane marker header from undici's request headers,
 * mutating `dispatchOpts.headers` in place so the upstream never sees it.
 * Returns `true` when the marker was present (the fetch plane is the enforcer
 * for this request → the dispatcher must NOT re-enforce the response).
 */
function consumePlaneMarker(dispatchOpts: UndiciDispatchOptions): boolean {
  const headers = dispatchOpts.headers;
  const present = readDispatchHeader(headers, AGENTUM_PLANE_HEADER) !== undefined;
  if (!present || headers == null) return present;
  if (Array.isArray(headers)) {
    const out: string[] = [];
    for (let i = 0; i + 1 < headers.length; i += 2) {
      const k = headers[i];
      if (typeof k === "string" && k.toLowerCase() === AGENTUM_PLANE_HEADER) continue;
      out.push(headers[i]!, headers[i + 1]!);
    }
    dispatchOpts.headers = out;
    return true;
  }
  const out: Record<string, string | string[] | undefined> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === AGENTUM_PLANE_HEADER) continue;
    out[k] = v;
  }
  dispatchOpts.headers = out;
  return true;
}

/**
 * Emit an MCP JSON-RPC deny (single object or batch array) through the undici
 * handler callbacks, never contacting upstream. Mirrors `synthesizeDeny`'s
 * callback mechanics.
 */
function synthesizeMcpDeny(
  handler: UndiciDispatchHandler,
  bodyObj: unknown,
  status: number,
): void {
  const payload = new TextEncoder().encode(JSON.stringify(bodyObj));
  const headers = [
    "content-type",
    "application/json",
    "content-length",
    String(payload.byteLength),
    "x-agentum-policy",
    "sdk-denied",
  ];
  try {
    handler.onConnect?.(() => {});
    const resume = (): void => {};
    handler.onHeaders?.(status, headers, resume, status === 200 ? "OK" : "Forbidden");
    handler.onData?.(payload);
    handler.onComplete?.(null);
  } catch (err) {
    handler.onError?.(err as Error);
  }
}

/**
 * Emit a provider-shaped 200 deny response through the undici handler
 * callbacks, never contacting upstream. Mirrors the fetch-interceptor's
 * `shortCircuitDeny` envelopes so the calling SDK parses a normal completion
 * whose only content is the block notice. Keyed by `HostMatch.shape` (GR-18)
 * so Bedrock Converse gets its own envelope and anthropic-on-bedrock invoke
 * reuses the Anthropic message envelope.
 */
function synthesizeDeny(
  handler: UndiciDispatchHandler,
  match: HostMatch,
  reason: string,
  toolName?: string,
): void {
  const notice = makeBlockNoticeText(toolName ?? "request", "{}", reason);
  let bodyObj: unknown;
  if (match.shape === "bedrock-converse") {
    bodyObj = {
      output: { message: { role: "assistant", content: [{ text: notice }] } },
      stopReason: "end_turn",
      usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    };
  } else if (match.shape === "anthropic-messages" || match.shape === "bedrock-invoke") {
    bodyObj = {
      id: `msg_agentum_deny_${Date.now()}`,
      type: "message",
      role: "assistant",
      model: "agentum-policy",
      content: [{ type: "text", text: notice }],
      stop_reason: "end_turn",
      usage: { input_tokens: 0, output_tokens: 0 },
    };
  } else if (match.shape === "gemini-generate") {
    // Mirror geminiRewrite: denied functionCall → text part, finishReason "STOP".
    bodyObj = {
      candidates: [{
        content: { role: "model", parts: [{ text: notice }] },
        finishReason: "STOP",
      }],
    };
  } else if (match.shape === "cohere-chat") {
    // Mirror cohereRewrite (v2): drop tool_calls, append text content block,
    // finish_reason "COMPLETE".
    bodyObj = {
      id: `cohere-agentum-deny-${Date.now()}`,
      message: { role: "assistant", content: [{ type: "text", text: notice }] },
      finish_reason: "COMPLETE",
    };
  } else {
    bodyObj = {
      id: `chatcmpl-agentum-deny-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: "agentum-policy",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: notice },
          finish_reason: "stop",
        },
      ],
      usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    };
  }
  const payload = new TextEncoder().encode(JSON.stringify(bodyObj));
  const headers = [
    "content-type",
    "application/json",
    "content-length",
    String(payload.byteLength),
    "x-agentum-policy",
    "sdk-denied",
  ];
  try {
    handler.onConnect?.(() => {});
    const resume = (): void => {};
    handler.onHeaders?.(200, headers, resume, "OK");
    handler.onData?.(payload);
    handler.onComplete?.(null);
  } catch (err) {
    handler.onError?.(err as Error);
  }
}

// GR-18: request-body tool_call extraction now lives in the shared
// `provider-extractors.ts` (imported above), keyed by `HostMatch.shape`. The
// previous local fork here was keyed by `Provider` and only covered
// openai/anthropic; the shared module adds Cohere, Gemini and Bedrock with no
// drift.

// ── helpers ─────────────────────────────────────────────────────────────────

function bodyToString(body: unknown): string | null {
  if (body == null) return null;
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(body as unknown)) {
    return (body as Buffer).toString("utf8");
  }
  return null;
}

function safeParseJson(s: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

