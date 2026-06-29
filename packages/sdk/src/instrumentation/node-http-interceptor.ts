/**
 * Layer-1.5 Node `http` / `https` interceptor.
 *
 * Stage 4 Concern 1 — `globalThis.fetch` interception MISSES legacy SDK
 * shims that talk through `node-fetch` / `http(s).request` directly. The
 * canonical example is `openai@4.x` on Node, which routes through
 * `_shims/auto/runtime-node.mjs` -> `node-fetch` -> `http.request`.
 *
 * Combined coverage:
 *   - `globalThis.fetch` wrap (fetch-interceptor.ts)        -> undici / modern fetch users
 *   - `http.request` / `https.request` wrap (this module)   -> node-fetch / axios / got / superagent /
 *                                                              direct ClientRequest users
 *
 * Bundler-proof: Node never bundles its own `node:http` / `node:https`
 * built-ins. `require('node:http')` always returns the singleton, so a
 * wrap installed in `init()` is observed by every CommonJS / ESM consumer
 * downstream regardless of bundling.
 *
 * Failure model (mirrors `fetch-interceptor.ts`):
 *   - The wrapper NEVER throws out. Internal errors log and pass-through.
 *   - Non-LLM hosts: cheap `HostRegistry.matches()` check, then call the
 *     original with no observation.
 *   - LLM hosts: capture request body (intercept `.write()` / `.end()`),
 *     run pre-flight evaluation; on deny, emit a synthetic
 *     `IncomingMessage` with provider-shaped refusal JSON without ever
 *     opening a socket to the upstream.
 *   - Streaming SSE: incremental parse via wire-parsers; tool-call frames
 *     trigger evaluation, deny splices a notice frame.
 *   - On any exception in the wrapper itself: log, fall back to original.
 *
 * Coexistence with the gateway MITM: the gateway stamps
 * `x-agentum-policy: enforced` on responses. We see that header on the
 * `'response'` event and let the IncomingMessage flow through unmodified.
 */

// `node:http` / `node:https` / `node:stream` are acquired via dynamic
// `await import(...)` inside `installNodeHttpInterceptor` (P01). Top-level
// static `import "node:..."` statements would be hoisted by esbuild into
// the universal `dist/index.mjs` (because tsup runs with `splitting: false`,
// every file in the reachable graph is inlined), and those imports throw
// at module-load on Cloudflare Workers / Vercel Edge / browser bundlers
// before any user code runs. Only **type** imports survive here — they
// erase at compile time and never appear in the emitted bundle.
//
// We mutate `.request` / `.get` on the module object to install our
// patches. Synthetic ESM namespace proxies (created by ts-jest's CJS
// interop, and by Node's own ESM loader for CJS builtins under some
// configurations) expose those properties as non-configurable getters,
// so direct assignment AND `Object.defineProperty` both fail. The real
// CJS module object — whether obtained via `require("node:http")` or via
// `await import("node:http")` (Node returns the same singleton, with the
// CJS exports surfaced under `.default` for ESM consumers) — has mutable
// properties on every Node version we support. We resolve the namespace
// shape at install time and unwrap `.default` if present.
import type * as NodeHttpType from "node:http";
import type * as NodeHttpsType from "node:https";
import type * as NodeStreamType from "node:stream";
type Readable = NodeStreamType.Readable;
type PassThrough = NodeStreamType.PassThrough;
// `globalThis.URL` is identical to `new URL` from `node:url` on every
// runtime we target — Node, Edge, Workers, browsers — so we don't need a
// dedicated import or shim.
const URL = globalThis.URL;

import { classifyUrl, HostRegistry, type HostMatch } from "./host-registry.js";
import { contextToProxyHeaders, getAgentumContext } from "./context.js";
import { makeBlockNoticeText } from "./_parsers.js";
import {
  OpenAISSEParser,
  AnthropicSSEParser,
  CohereV2SSEParser,
  GeminiSSEParser,
  BedrockConverseStreamParser,
  BedrockInvokeStreamParser,
  encodeOpenAIDataFrame,
  encodeAnthropicEventFrame,
  encodeCohereEventFrame,
  encodeGeminiDataFrame,
  encodeBedrockEventStreamMessage,
  encodeBedrockInvokeChunk,
  OPENAI_DONE_FRAME,
  type WireEvent,
} from "./wire-parsers.js";
import {
  extractRequestToolCalls,
  extractResponseToolCalls,
  rewriteResponseBody,
} from "./provider-extractors.js";
import {
  isMcpWireCandidate,
  isOldTransportEndpoint,
  parseMcpBody,
  buildMcpDenyResult,
  buildMcpDenyError,
  mcpEndpointKey,
  mcpActionFor,
  recordMcpServer,
  lookupMcpServer,
  extractServerInfo,
  scanInitializeSse,
  SSE_SCAN_CAP_BYTES,
  consumeMcpCallEvaluated,
  emitMcpHttpAudit,
  type McpParsed,
} from "./mcp-http.js";

/**
 * Streaming wire provider for the node:http path. Mirrors the same
 * taxonomy as fetch-interceptor.ts so the deny rewrite sequences stay in
 * sync between the two interceptors (A13: SDK-side parity with the
 * cloud-side `agentum-llm-filter` deny rewriter). The two Bedrock variants
 * (GR-18) consume the binary AWS event-stream framing rather than SSE.
 */
type StreamProvider =
  | "openai"
  | "anthropic"
  | "cohere"
  | "gemini"
  | "bedrock-converse"
  | "bedrock-invoke";

function streamProviderForShape(
  shape: string | null | undefined,
): StreamProvider | null {
  switch (shape) {
    case "openai-chat":
    case "openai-responses":
      return "openai";
    case "anthropic-messages":
      return "anthropic";
    case "cohere-chat":
      return "cohere";
    case "gemini-generate":
      return "gemini";
    case "bedrock-converse":
      return "bedrock-converse";
    case "bedrock-invoke":
      return "bedrock-invoke";
    default:
      return null;
  }
}

// The SSE parsers and the binary event-stream parsers share the structural
// `feed`/`flush`→WireEvent[] interface, so the streaming pipeline treats them
// uniformly.
type StreamWireParser = { feed(b: Uint8Array): WireEvent[]; flush(): WireEvent[] };

function newParserFor(provider: StreamProvider): StreamWireParser {
  switch (provider) {
    case "anthropic":
      return new AnthropicSSEParser();
    case "cohere":
      return new CohereV2SSEParser();
    case "gemini":
      return new GeminiSSEParser();
    case "bedrock-converse":
      return new BedrockConverseStreamParser();
    case "bedrock-invoke":
      return new BedrockInvokeStreamParser();
    case "openai":
    default:
      return new OpenAISSEParser();
  }
}
import type { CedarToolCallClient, FeatureState, ToolCallEvaluation } from "../evaluation/cedar-client.js";
import type { PromptCaptureMode } from "../types.js";
import { warnHitlUnsupportedOnce } from "./hitl-unsupported.js";
import {
  resolvePromptCaptureMode,
  maskObserveContent,
  PII_ADVANCED_ADDON,
} from "./prompt-capture.js";

const PATCHED_TAG = Symbol.for("agentum.http.patched");
const ORIGINAL_HTTP_REQUEST = Symbol.for("agentum.http.request.original");
const ORIGINAL_HTTPS_REQUEST = Symbol.for("agentum.https.request.original");

export interface NodeHttpInterceptorRuntime {
  baseUrl: string;
  apiKey: string;
  evaluator: CedarToolCallClient;
}

export interface NodeHttpInterceptorOptions {
  runtime: NodeHttpInterceptorRuntime;
  agentId: string;
  hosts?: HostRegistry;
  /**
   * PDP reverse-proxy base URL (R22). When the agent app routes a provider
   * through the proxy by base-URL (e.g. `DEEPSEEK_PROXY_URL=
   * http://127.0.0.1:7081/proxy/deepseek/v1`) and that traffic goes over
   * `node:http`/`node:https` (e.g. the OpenAI SDK's `node-fetch` transport,
   * which bypasses the undici global dispatcher), this interceptor injects the
   * `X-Agentum-*` identity headers so session/user/dimensions reach the proxy.
   * Unset → no proxy header injection (only the undici-dispatcher plane does).
   */
  pdpProxyUrl?: string;
  failMode?: "allow" | "deny";
  /**
   * **Legacy** — `false` disables prompt capture (maps to
   * `promptCaptureMode: "off"`). Prefer `promptCaptureMode`.
   */
  capturePrompts?: boolean;
  /**
   * R40 — how the observe-prompt POST treats raw `messages` /
   * `tools_advertised` content. `"masked"` (default) runs the S5 PII pipeline
   * before send; `"raw"` sends unmasked; `"off"` sends no observe POST.
   * Legacy `capturePrompts === false` overrides to `"off"`.
   */
  promptCaptureMode?: PromptCaptureMode;
  promptTruncationBytes?: number;
  /** Block on observe-prompt POST (test hook). */
  syncObserve?: boolean;
  /** Timeout (ms) for observe-prompt POST. Default 1500. */
  observePromptTimeoutMs?: number;
  /** Max retries for observe-prompt on transient failure. Default 1. */
  observePromptMaxRetries?: number;
  logger?: Pick<Console, "log" | "warn" | "error">;
}

type RequestFn = typeof NodeHttpType.request;

/**
 * Module-level installer; idempotent via Symbol on the http module object.
 *
 * Async because the `node:http` / `node:https` / `node:stream` builtins are
 * loaded via dynamic `await import(...)` (P01) — the literal-string specifiers
 * keep these out of the static module graph of `dist/index.mjs`, so the
 * universal entry remains edge-runtime safe even when bundlers fail to
 * tree-shake this file out.
 */
export async function installNodeHttpInterceptor(
  opts: NodeHttpInterceptorOptions,
): Promise<() => void> {
  const logger = opts.logger ?? console;
  // Lazy-load the Node builtins. esbuild leaves dynamic `import("node:*")`
  // calls with literal specifiers as runtime requires, so they do NOT end
  // up as static imports in the emitted bundle.
  const [httpNs, httpsNs, streamNs] = await Promise.all([
    import("node:http"),
    import("node:https"),
    import("node:stream"),
  ]);
  // Some bundler/loader combinations expose CJS builtins as ESM namespaces
  // with the actual module object under `.default`. We need the mutable CJS
  // module object to install our `.request` / `.get` overrides, so unwrap
  // when `.default` carries the `request` function.
  const nodeHttp = ((httpNs as unknown as { default?: typeof NodeHttpType }).default
    ?? httpNs) as typeof NodeHttpType;
  const nodeHttps = ((httpsNs as unknown as { default?: typeof NodeHttpsType }).default
    ?? httpsNs) as typeof NodeHttpsType;
  const nodeStream = ((streamNs as unknown as { default?: typeof NodeStreamType }).default
    ?? streamNs) as typeof NodeStreamType;
  const { Readable, PassThrough } = nodeStream;
  const httpMod = nodeHttp as unknown as Record<symbol | string, unknown>;
  const httpsMod = nodeHttps as unknown as Record<symbol | string, unknown>;

  if (httpMod[PATCHED_TAG]) {
    return () => {
      // No-op: another install owns this slot.
    };
  }

  const hosts = opts.hosts ?? new HostRegistry();
  const failMode = opts.failMode ?? "deny";
  // OPEN-22 — resolve the prompt-capture mode PER REQUEST, not once at install
  // time. The R45b PII gate upgrades "raw" → "masked" once a non-empty bundle
  // lacking `addon.policy.pii-advanced` is observed, but the evaluator's addon
  // snapshot is `[]` at install time (no PDP authorize has returned yet).
  // Freezing the mode here meant the gate never activated. Static parts ARE
  // safe to freeze; only the addon snapshot is dynamic, re-read in the thunk.
  const staticCaptureModeOpts: {
    capturePrompts?: boolean;
    promptCaptureMode?: PromptCaptureMode;
  } = {};
  if (opts.capturePrompts !== undefined) staticCaptureModeOpts.capturePrompts = opts.capturePrompts;
  if (opts.promptCaptureMode !== undefined)
    staticCaptureModeOpts.promptCaptureMode = opts.promptCaptureMode;
  // Short-circuit: `capturePrompts: false` maps to "off" now and forever.
  const isForeverOff = opts.capturePrompts === false;
  const resolveMode = (): PromptCaptureMode => {
    if (isForeverOff) return "off";
    // INTEG-B1 — resolve the live tri-state of the advanced-PII addon.
    // `"unknown"` (no snapshot yet) and `"disabled"` both force raw→masked;
    // only `"enabled"` honors raw. Defensive: an evaluator that predates the
    // accessor is treated as `"unknown"` (the SAFE default → masked) rather
    // than throwing.
    const piiAdvanced: FeatureState =
      typeof opts.runtime.evaluator.featureState === "function"
        ? opts.runtime.evaluator.featureState(PII_ADVANCED_ADDON)
        : "unknown";
    return resolvePromptCaptureMode({ ...staticCaptureModeOpts, piiAdvanced });
  };
  const truncationBytes = opts.promptTruncationBytes ?? 8 * 1024;
  const syncObserve = opts.syncObserve === true;
  const observeTimeoutMs = opts.observePromptTimeoutMs ?? 1500;
  const observeMaxRetries = opts.observePromptMaxRetries ?? 1;

  const originalHttpRequest = nodeHttp.request.bind(nodeHttp) as RequestFn;
  const originalHttpsRequest = nodeHttps.request.bind(nodeHttps) as RequestFn;
  const originalHttpGet = nodeHttp.get.bind(nodeHttp);
  const originalHttpsGet = nodeHttps.get.bind(nodeHttps);

  httpMod[ORIGINAL_HTTP_REQUEST] = originalHttpRequest;
  httpsMod[ORIGINAL_HTTPS_REQUEST] = originalHttpsRequest;

  const ctx: WrapContext = {
    runtime: opts.runtime,
    agentId: opts.agentId,
    hosts,
    ...(opts.pdpProxyUrl !== undefined ? { pdpProxyUrl: opts.pdpProxyUrl } : {}),
    failMode,
    resolvePromptCaptureMode: resolveMode,
    truncationBytes,
    syncObserve,
    observeTimeoutMs,
    observeMaxRetries,
    logger,
    originalHttpRequest,
    originalHttpsRequest,
    Readable,
    PassThrough,
  };

  const patchedHttpRequest = makePatchedRequest("http:", ctx, originalHttpRequest);
  const patchedHttpsRequest = makePatchedRequest("https:", ctx, originalHttpsRequest);

  // `http.get` is documented to call `http.request` then `req.end()` and
  // return the request — re-implement that on top of our patched request
  // rather than letting the original .get reach the unpatched .request.
  const patchedHttpGet: typeof nodeHttp.get = ((...args: Parameters<typeof nodeHttp.get>) => {
    const req = (patchedHttpRequest as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(
      ...(args as unknown as unknown[]),
    );
    req.end();
    return req;
  }) as typeof nodeHttp.get;
  const patchedHttpsGet: typeof nodeHttps.get = ((...args: Parameters<typeof nodeHttps.get>) => {
    const req = (patchedHttpsRequest as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(
      ...(args as unknown as unknown[]),
    );
    req.end();
    return req;
  }) as typeof nodeHttps.get;

  (nodeHttp as unknown as { request: RequestFn }).request = patchedHttpRequest;
  (nodeHttps as unknown as { request: RequestFn }).request = patchedHttpsRequest;
  (nodeHttp as unknown as { get: typeof nodeHttp.get }).get = patchedHttpGet;
  (nodeHttps as unknown as { get: typeof nodeHttps.get }).get = patchedHttpsGet;

  httpMod[PATCHED_TAG] = true;
  httpsMod[PATCHED_TAG] = true;

  // Mark the original symbols so internal Agentum API calls (which we
  // resolve via getOriginalRequest) cannot recurse.

  return () => {
    if (httpMod[PATCHED_TAG]) {
      (nodeHttp as unknown as { request: RequestFn }).request = originalHttpRequest;
      (nodeHttps as unknown as { request: RequestFn }).request = originalHttpsRequest;
      (nodeHttp as unknown as { get: typeof nodeHttp.get }).get = originalHttpGet;
      (nodeHttps as unknown as { get: typeof nodeHttps.get }).get = originalHttpsGet;
      delete httpMod[PATCHED_TAG];
      delete httpsMod[PATCHED_TAG];
    }
  };
}

interface WrapContext {
  runtime: NodeHttpInterceptorRuntime;
  agentId: string;
  hosts: HostRegistry;
  pdpProxyUrl?: string;
  failMode: "allow" | "deny";
  /** OPEN-22 — per-request thunk re-reading the evaluator addon snapshot. */
  resolvePromptCaptureMode: () => PromptCaptureMode;
  truncationBytes: number;
  syncObserve: boolean;
  observeTimeoutMs: number;
  observeMaxRetries: number;
  logger: Pick<Console, "log" | "warn" | "error">;
  originalHttpRequest: RequestFn;
  originalHttpsRequest: RequestFn;
  /** Lazy-loaded `node:stream` constructors (P01 — keeps the universal
   *  bundle free of static `node:*` imports). Threaded through
   *  WrapContext so module-scope helpers can construct PassThrough /
   *  Readable without re-importing. */
  Readable: typeof NodeStreamType.Readable;
  PassThrough: typeof NodeStreamType.PassThrough;
}

// ── argument normalisation ─────────────────────────────────────────────────

interface NormalizedArgs {
  url: string | undefined;
  options: NodeHttpType.RequestOptions;
  callback: ((res: NodeHttpType.IncomingMessage) => void) | undefined;
}

function normalizeArgs(scheme: "http:" | "https:", args: unknown[]): NormalizedArgs {
  // Node accepts:
  //   request(options[, callback])
  //   request(url[, callback])
  //   request(url, options[, callback])
  let urlArg: string | URL | undefined;
  let optsArg: NodeHttpType.RequestOptions = {};
  let cb: ((res: NodeHttpType.IncomingMessage) => void) | undefined;

  let i = 0;
  if (typeof args[i] === "string" || args[i] instanceof URL) {
    urlArg = args[i] as string | URL;
    i++;
  }
  if (args[i] && typeof args[i] === "object" && !(args[i] instanceof URL)) {
    optsArg = args[i] as NodeHttpType.RequestOptions;
    i++;
  }
  if (typeof args[i] === "function") {
    cb = args[i] as (res: NodeHttpType.IncomingMessage) => void;
  }

  const urlString = urlArg
    ? typeof urlArg === "string"
      ? urlArg
      : urlArg.toString()
    : buildUrlFromOptions(scheme, optsArg);
  return { url: urlString, options: optsArg, callback: cb };
}

function buildUrlFromOptions(
  scheme: "http:" | "https:",
  o: NodeHttpType.RequestOptions,
): string | undefined {
  const host = (o.hostname ?? o.host) as string | undefined;
  if (!host) return undefined;
  const port = o.port ? `:${o.port}` : "";
  const path = (o.path ?? "/") as string;
  return `${scheme}//${host}${port}${path}`;
}

/** Same-origin test used by the app-native proxy-routing branch. */
function proxyOriginMatches(url: string, proxyBase: string): boolean {
  try {
    return new URL(url).origin === new URL(proxyBase).origin;
  } catch {
    return false;
  }
}

/**
 * Merge the current Agentum context's `X-Agentum-*` headers into a node:http
 * request options object, in place. node:http expects `options.headers` to be
 * a plain record; node-fetch normalises to that before calling `http.request`,
 * so we mutate the same object the original transport will read.
 */
function injectProxyHeaders(options: NodeHttpType.RequestOptions): void {
  const injected = contextToProxyHeaders(getAgentumContext());
  if (Object.keys(injected).length === 0) return;
  const headers = (options.headers ?? {}) as Record<string, string | string[] | number>;
  for (const [k, v] of Object.entries(injected)) headers[k] = v;
  options.headers = headers as NodeHttpType.OutgoingHttpHeaders;
}

// ── the wrap ───────────────────────────────────────────────────────────────

function makePatchedRequest(
  scheme: "http:" | "https:",
  ctx: WrapContext,
  original: RequestFn,
): RequestFn {
  const patched = function patchedRequest(
    ...args: unknown[]
  ): NodeHttpType.ClientRequest {
    let norm: NormalizedArgs;
    try {
      norm = normalizeArgs(scheme, args);
    } catch (err) {
      ctx.logger.warn(`[agentum] http normalize error: ${(err as Error).message}`);
      return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    }
    const url = norm.url;

    // App-native PDP-proxy routing: the agent app points a provider base-URL
    // at the proxy (e.g. `DEEPSEEK_PROXY_URL=http://127.0.0.1:7081/proxy/...`)
    // and the transport is node:http/https (e.g. openai SDK's node-fetch). The
    // destination is already the proxy, so we never evaluate/intercept — we
    // inject the X-Agentum-* identity headers in place so session/user/
    // dimensions reach the proxy's Cedar context + audit events, then forward.
    if (ctx.pdpProxyUrl && url && proxyOriginMatches(url, ctx.pdpProxyUrl)) {
      try {
        if (new URL(url).pathname.startsWith("/proxy/")) {
          injectProxyHeaders(norm.options);
        }
      } catch {
        // Never break the request on header-injection failure.
      }
      return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    }

    // Cheap host check.
    let hostname: string | undefined;
    if (url) {
      try {
        hostname = new URL(url).hostname.toLowerCase();
      } catch {
        // fall through — pass-through path
      }
    }
    // GR-19: MCP Streamable-HTTP gate. Runs regardless of host-registry match
    // (MCP servers live on arbitrary hosts) — but only when we have a URL.
    const mcpGateHit =
      !!url &&
      isMcpWireCandidate(
        readNodeMethod(norm.options),
        readNodeAcceptHeader(norm.options),
        url,
      );

    if (!hostname || !ctx.hosts.matches(hostname)) {
      if (mcpGateHit && url) {
        try {
          return interceptMcpRequest(ctx, original, scheme, url, norm);
        } catch (err) {
          ctx.logger.warn(
            `[agentum] http mcp interceptor internal error: ${(err as Error).message ?? String(err)}`,
          );
          return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
        }
      }
      return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    }

    const match = url ? classifyUrl(url) : { provider: null, shape: null };
    if (!match.shape) {
      if (mcpGateHit && url) {
        try {
          return interceptMcpRequest(ctx, original, scheme, url, norm);
        } catch (err) {
          ctx.logger.warn(
            `[agentum] http mcp interceptor internal error: ${(err as Error).message ?? String(err)}`,
          );
          return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
        }
      }
      return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    }

    try {
      return interceptRequest(ctx, original, scheme, url!, match, norm);
    } catch (err) {
      ctx.logger.warn(
        `[agentum] http interceptor internal error: ${(err as Error).message ?? String(err)}`,
      );
      return (original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    }
  } as RequestFn;
  return patched;
}

// ── per-LLM-request orchestration ──────────────────────────────────────────

function interceptRequest(
  ctx: WrapContext,
  original: RequestFn,
  scheme: "http:" | "https:",
  url: string,
  match: HostMatch,
  norm: NormalizedArgs,
): NodeHttpType.ClientRequest {
  // We expose a "facade" ClientRequest to the caller — a PassThrough whose
  // writes we capture. We do NOT open the upstream socket until we've made
  // the pre-flight evaluation decision; on deny, we never open it at all.
  const facade = new FacadeClientRequest(ctx, scheme, original, url, match, norm);
  return facade.req as unknown as NodeHttpType.ClientRequest;
}

// ── facade ─────────────────────────────────────────────────────────────────

class FacadeClientRequest {
  // The PassThrough is what user code receives. It looks Writable enough
  // for `.write()` / `.end()` / `.setHeader()` and emits 'response' /
  // 'error' / 'close' on completion.
  public req: PassThrough & {
    setHeader?: (n: string, v: string) => void;
    getHeader?: (n: string) => unknown;
    removeHeader?: (n: string) => void;
    flushHeaders?: () => void;
  };
  private bodyChunks: Buffer[] = [];
  private ended = false;
  private upstream?: NodeHttpType.ClientRequest;
  private extraHeaders: Record<string, string> = {};

  constructor(
    private ctx: WrapContext,
    private scheme: "http:" | "https:",
    private original: RequestFn,
    private url: string,
    private match: HostMatch,
    private norm: NormalizedArgs,
  ) {
    const pass = new this.ctx.PassThrough() as PassThrough & {
      setHeader?: (n: string, v: string) => void;
      getHeader?: (n: string) => unknown;
      removeHeader?: (n: string) => void;
      flushHeaders?: () => void;
    };
    this.req = pass;

    // Belt-and-suspenders against unhandled 'error' emission. The
    // facade's dispatch() is fire-and-forget from the caller's frame:
    // user code receives the request synchronously and may not install
    // 'error' listeners until later (in their .on('response') handler,
    // typically). If dispatch() rejects before the user wires up
    // listeners, EventEmitter would otherwise throw on emit('error',
    // ...). The try/catch around the existing emit already swallows
    // that throw, but adding a default no-op listener (overridable by
    // user code via .on/.once) is cleaner and ensures no telemetry
    // noise from "unhandled error event" warnings.
    pass.on("error", () => {
      /* default — real consumers attach their own listener */
    });

    pass.setHeader = (n: string, v: string) => {
      this.extraHeaders[n.toLowerCase()] = String(v);
    };
    pass.getHeader = (n: string) => this.extraHeaders[n.toLowerCase()];
    pass.removeHeader = (n: string) => {
      delete this.extraHeaders[n.toLowerCase()];
    };
    pass.flushHeaders = () => {};

    // Capture writes; do NOT forward yet — we need the full body for
    // pre-flight tool-call evaluation.
    const origWrite = pass.write.bind(pass);
    pass.write = ((chunk: unknown, encoding?: unknown, cb?: unknown) => {
      try {
        if (chunk !== undefined && chunk !== null) {
          const buf = toBuffer(chunk, encoding);
          if (buf) this.bodyChunks.push(buf);
        }
      } catch (err) {
        this.ctx.logger.warn(`[agentum] http write capture error: ${(err as Error).message}`);
      }
      // Call origWrite to keep PassThrough internal counters happy; the
      // bytes go nowhere observable.
      return origWrite(chunk as never, encoding as never, cb as never) as boolean;
    }) as typeof pass.write;

    const origEnd = pass.end.bind(pass);
    pass.end = ((chunk?: unknown, encoding?: unknown, cb?: unknown) => {
      if (this.ended) return pass;
      this.ended = true;
      if (chunk !== undefined && chunk !== null && typeof chunk !== "function") {
        try {
          const buf = toBuffer(chunk, encoding);
          if (buf) this.bodyChunks.push(buf);
        } catch (err) {
          this.ctx.logger.warn(`[agentum] http end capture error: ${(err as Error).message}`);
        }
      }
      origEnd(undefined as never);
      // Kick off the orchestration. Errors in this async flow are caught
      // and emitted via the facade's 'error' event.
      this.dispatch().catch((err) => {
        this.ctx.logger.warn(`[agentum] http dispatch error: ${(err as Error).message}`);
        try { pass.emit("error", err); } catch {}
      });
      if (typeof cb === "function") (cb as () => void)();
      return pass;
    }) as typeof pass.end;
  }

  private async dispatch(): Promise<void> {
    const body = Buffer.concat(this.bodyChunks).toString("utf8");
    const parsed = safeParseJson(body);
    const requestId = randomUuid();
    const { sessionId, userId } = getAgentumContext();

    // OPEN-22 — resolve per-request so the R45b PII gate sees the live addon
    // snapshot (raw→masked once the PDP bundle is known).
    const promptCaptureMode = this.ctx.resolvePromptCaptureMode();
    if (promptCaptureMode !== "off" && parsed) {
      const p = postObservePrompt({
        runtime: this.ctx.runtime,
        agentId: this.ctx.agentId,
        requestId,
        match: this.match,
        body: parsed,
        sessionId,
        userId,
        promptCaptureMode,
        truncationBytes: this.ctx.truncationBytes,
        timeoutMs: this.ctx.observeTimeoutMs,
        maxRetries: this.ctx.observeMaxRetries,
        logger: this.ctx.logger,
      });
      if (this.ctx.syncObserve) {
        await p.catch(() => undefined);
      } else {
        p.catch(() => undefined);
      }
    }

    // Pre-flight tool-call evaluation on declared request tool_calls.
    if (parsed) {
      const reqTools = extractRequestToolCalls(this.match, parsed);
      for (const tc of reqTools) {
        let verdict: ToolCallEvaluation;
        try {
          verdict = await this.ctx.runtime.evaluator.evaluateToolCall({
            toolName: tc.name,
            arguments: tc.args,
          });
        } catch (err) {
          this.ctx.logger.warn(`[agentum] http preflight evaluate: ${(err as Error).message}`);
          if (this.ctx.failMode === "deny") {
            this.emitSyntheticDeny("agentum-fail-closed", tc.name, tc.args);
            return;
          }
          continue;
        }
        if (verdict.decision === "deny") {
          // HITL-8: require_hitl preflight deny has no session to suspend on
          // the node:http plane — warn once, then deny (no retry).
          warnHitlUnsupportedOnce("node-http", verdict);
          this.emitSyntheticDeny(verdict.reason ?? "policy denied", tc.name, tc.args);
          return;
        }
      }
    }

    // Forward to upstream.
    this.forwardUpstream(body);
  }

  private forwardUpstream(body: string): void {
    const opts: NodeHttpType.RequestOptions = { ...this.norm.options };
    opts.headers = {
      ...(opts.headers ?? {}),
      ...this.extraHeaders,
    };
    let upstream: NodeHttpType.ClientRequest;
    try {
      const args: unknown[] = [];
      if (this.norm.url) args.push(this.norm.url);
      args.push(opts);
      upstream = (this.original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    } catch (err) {
      this.req.emit("error", err);
      return;
    }
    this.upstream = upstream;

    upstream.on("response", (res) => {
      // Coexistence: gateway already enforced — pass through verbatim.
      const enforced = (res.headers["x-agentum-policy"] as string | undefined) === "enforced";
      if (enforced) {
        this.req.emit("response", res);
        return;
      }
      const ct = (res.headers["content-type"] as string | undefined) ?? "";
      // `text/event-stream` is OpenAI/Anthropic/Cohere/Gemini SSE;
      // `application/vnd.amazon.eventstream` is Bedrock's binary AWS
      // event-stream (`/invoke-with-response-stream`, `/converse-stream`).
      // Both route into `wrapStreaming`; the parser selected by shape handles
      // framing (the feed path already passes raw bytes).
      if (
        ct.includes("text/event-stream") ||
        ct.includes("application/vnd.amazon.eventstream")
      ) {
        this.req.emit("response", this.wrapStreaming(res));
        return;
      }
      if (ct.includes("application/json")) {
        this.wrapJsonResponse(res).then((wrapped) => {
          this.req.emit("response", wrapped);
        }).catch((err) => {
          this.ctx.logger.warn(`[agentum] http json wrap error: ${(err as Error).message}`);
          this.req.emit("response", res);
        });
        return;
      }
      this.req.emit("response", res);
    });
    upstream.on("error", (err) => {
      try { this.req.emit("error", err); } catch {}
    });
    upstream.on("close", () => {
      try { this.req.emit("close"); } catch {}
    });

    if (body.length > 0) upstream.write(body);
    upstream.end();
  }

  private async wrapJsonResponse(
    res: NodeHttpType.IncomingMessage,
  ): Promise<NodeHttpType.IncomingMessage> {
    // Read the full body (small for chat-completion non-streaming).
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      res.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => resolve());
      res.on("error", (e) => reject(e));
    });
    const text = Buffer.concat(chunks).toString("utf8");
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return synthesizeIncoming(this.ctx.Readable, res, text);
    }
    const calls = extractResponseToolCalls(this.match, json);
    if (calls.length === 0) {
      return synthesizeIncoming(this.ctx.Readable, res, text);
    }
    const decisions: ToolCallEvaluation[] = await Promise.all(
      calls.map(async (c) => {
        try {
          return await this.ctx.runtime.evaluator.evaluateToolCall({
            toolName: c.name,
            arguments: c.args,
          });
        } catch (err) {
          this.ctx.logger.warn(`[agentum] http post-flight evaluate: ${(err as Error).message}`);
          if (this.ctx.failMode === "deny") {
            return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" };
          }
          return { decision: "allow", ttlMs: 0 };
        }
      }),
    );
    const denied = decisions.some((d) => d.decision === "deny");
    // HITL-8: warn once if any denied call carried require_hitl; deny stands.
    for (const d of decisions) {
      if (d.decision === "deny") warnHitlUnsupportedOnce("node-http", d);
    }
    if (!denied) return synthesizeIncoming(this.ctx.Readable, res, text);
    const rewritten = rewriteResponseBody(this.match, json, decisions, calls);
    const out = JSON.stringify(rewritten);
    return synthesizeIncoming(this.ctx.Readable, res, out, {
      "x-agentum-policy": "sdk-enforced",
      "content-length": String(Buffer.byteLength(out)),
    });
  }

  private wrapStreaming(res: NodeHttpType.IncomingMessage): NodeHttpType.IncomingMessage {
    // A13 — pick the parser by shape so Cohere v2 (`cohere-chat`) and
    // Gemini (`gemini-generate`, incl. `:streamGenerateContent`) get
    // proper tool-call enforcement on the node:http path, mirroring
    // fetch-interceptor.ts:wrapStreamingResponse. Unknown classified
    // shapes fall back to OpenAI as before to avoid corrupting an
    // unfamiliar wire format.
    const provider: StreamProvider =
      streamProviderForShape(this.match.shape) ?? "openai";
    const parser = newParserFor(provider);

    interface ToolAcc { name: string; args: string; bufferedFrames: Uint8Array[]; }
    const accs = new Map<number, ToolAcc>();
    const inFlight = new Set<number>();
    // Latches true the first time flushTool emits a synthetic terminal
    // sequence. Once set, ALL upstream terminal frames are suppressed.
    let syntheticTerminalEmitted = false;

    // Build a passthrough that mimics an IncomingMessage (event-emitting).
    const out = new this.ctx.PassThrough() as unknown as NodeHttpType.IncomingMessage & PassThrough;
    Object.defineProperty(out, "headers", { value: { ...res.headers, "x-agentum-policy": "sdk-enforced" } });
    Object.defineProperty(out, "statusCode", { value: res.statusCode });
    Object.defineProperty(out, "statusMessage", { value: res.statusMessage });

    const onEvent = async (ev: WireEvent): Promise<void> => {
      if (ev.kind === "text-delta" || ev.kind === "passthrough") {
        out.write(Buffer.from(ev.rawFrame));
        return;
      }
      if (ev.kind === "tool-call-start") {
        accs.set(ev.index, { name: ev.name ?? "", args: "", bufferedFrames: [ev.rawFrame] });
        inFlight.add(ev.index);
        return;
      }
      if (ev.kind === "tool-call-arguments") {
        const acc = accs.get(ev.index);
        if (!acc) { out.write(Buffer.from(ev.rawFrame)); return; }
        acc.args += ev.deltaJson;
        acc.bufferedFrames.push(ev.rawFrame);
        return;
      }
      if (ev.kind === "tool-call-end") {
        // Buffer the closing frame alongside its matching start/arguments so a
        // deny rewrites the entire block atomically (mirrors
        // fetch-interceptor.ts:handleEvent). The Anthropic / Cohere / Gemini /
        // Bedrock parsers emit `tool-call-end` for the terminal frame of a tool
        // block; without buffering it here the closing frame leaked through
        // verbatim on a denied call (the node:http path had drifted from the
        // fetch path). If the index doesn't belong to a tracked tool (shouldn't
        // happen but tolerate it), forward verbatim.
        const acc = accs.get(ev.index);
        if (acc) {
          acc.bufferedFrames.push(ev.rawFrame);
          return;
        }
        out.write(Buffer.from(ev.rawFrame));
        return;
      }
      if (ev.kind === "finish") {
        let anyDenyFlushed = false;
        for (const idx of inFlight) {
          const acc = accs.get(idx);
          if (!acc) continue;
          const verdict = await this.safeEval(acc.name, acc.args);
          if (verdict.decision !== "allow") anyDenyFlushed = true;
          this.flushTool(out, idx, acc, verdict, provider);
        }
        inFlight.clear();
        // When flushTool took the deny branch it already emitted a synthetic
        // finish_reason="stop" + [DONE] (or anthropic equivalent). Re-emitting
        // the upstream's raw finish frame here forwards a terminal chunk AFTER
        // the synthetic one, which leaves streaming consumers waiting forever
        // for tool output that will never come. Only emit the raw frame when
        // no deny was flushed.
        if (anyDenyFlushed) {
          syntheticTerminalEmitted = true;
          return;
        }
        if (syntheticTerminalEmitted) return;
        out.write(Buffer.from(ev.rawFrame));
      }
    };

    res.on("data", async (chunk: Buffer) => {
      try {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const events = parser.feed(new Uint8Array(buf));
        for (const ev of events) await onEvent(ev);
      } catch (err) {
        this.ctx.logger.warn(`[agentum] http stream parse: ${(err as Error).message}`);
        out.write(chunk);
      }
    });
    res.on("end", async () => {
      try {
        const events = parser.flush();
        for (const ev of events) await onEvent(ev);
        for (const idx of inFlight) {
          const acc = accs.get(idx);
          if (!acc) continue;
          const verdict = await this.safeEval(acc.name, acc.args);
          this.flushTool(out, idx, acc, verdict, provider);
        }
      } catch (err) {
        this.ctx.logger.warn(`[agentum] http stream flush: ${(err as Error).message}`);
      }
      out.end();
    });
    res.on("error", (e) => out.emit("error", e));

    return out;
  }

  private async safeEval(name: string, rawArgs: string): Promise<ToolCallEvaluation> {
    // Mirror of fetch-interceptor.ts — partial / unparseable tool-call
    // JSON is treated as deny regardless of failMode. See that file for
    // the full rationale; the short version: streaming SSE concatenates
    // `function.arguments` across many frames, and a truncated stream
    // would otherwise let the call through with `{_raw: "<half>"}`,
    // which never matches a policy that keys on argument content.
    const parsed = safeJsonParse(rawArgs);
    if (isPartialJson(parsed, rawArgs)) {
      return {
        decision: "deny",
        ttlMs: 0,
        reason: "agentum-partial-tool-args",
      };
    }
    try {
      return await this.ctx.runtime.evaluator.evaluateToolCall({
        toolName: name,
        arguments: parsed,
      });
    } catch (err) {
      this.ctx.logger.warn(`[agentum] http stream eval: ${(err as Error).message}`);
      if (this.ctx.failMode === "deny") {
        return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" };
      }
      return { decision: "allow", ttlMs: 0 };
    }
  }

  private flushTool(
    out: PassThrough,
    index: number,
    acc: { name: string; args: string; bufferedFrames: Uint8Array[] },
    verdict: ToolCallEvaluation,
    provider: StreamProvider,
  ): void {
    if (verdict.decision === "allow") {
      for (const f of acc.bufferedFrames) out.write(Buffer.from(f));
      return;
    }
    // HITL-8: a require_hitl deny cannot suspend on the node:http plane —
    // warn once, then drop the tool frames (fail-CLOSED; no retry).
    warnHitlUnsupportedOnce("node-http", verdict);
    const notice = makeBlockNoticeText(acc.name, acc.args, verdict.reason);
    if (provider === "anthropic") {
      out.write(Buffer.from(encodeAnthropicEventFrame("content_block_start", {
        type: "content_block_start", index,
        content_block: { type: "text", text: "" },
      })));
      out.write(Buffer.from(encodeAnthropicEventFrame("content_block_delta", {
        type: "content_block_delta", index,
        delta: { type: "text_delta", text: notice },
      })));
      out.write(Buffer.from(encodeAnthropicEventFrame("content_block_stop", {
        type: "content_block_stop", index,
      })));
      return;
    }
    if (provider === "cohere") {
      // Cohere v2 deny: open a content block, write the notice, close
      // the block, then emit message-end with finish_reason=COMPLETE so
      // the consumer's stream finishes cleanly. Mirrors
      // fetch-interceptor.ts flushToolBuffer.
      out.write(Buffer.from(encodeCohereEventFrame("content-start", {
        index,
        delta: { message: { content: { type: "text", text: "" } } },
      })));
      out.write(Buffer.from(encodeCohereEventFrame("content-delta", {
        index,
        delta: { message: { content: { text: notice } } },
      })));
      out.write(Buffer.from(encodeCohereEventFrame("content-end", { index })));
      out.write(Buffer.from(encodeCohereEventFrame("message-end", {
        delta: { finish_reason: "COMPLETE" },
      })));
      return;
    }
    if (provider === "gemini") {
      // Gemini deny: replace the functionCall chunk with a text chunk
      // carrying the notice, normalising finishReason to STOP. Mirrors
      // fetch-interceptor.ts flushToolBuffer.
      out.write(Buffer.from(encodeGeminiDataFrame({
        candidates: [{
          content: {
            role: "model",
            parts: [{ text: notice }],
          },
          finishReason: "STOP",
          index: 0,
        }],
      })));
      return;
    }
    if (provider === "bedrock-converse") {
      // Bedrock Converse-stream deny: write the notice as a text delta on the
      // tool's content block, close the block, then a clean messageStop. CRCs
      // are computed by the encoder (the AWS SDK validates them). Mirrors
      // fetch-interceptor.ts flushToolBuffer.
      out.write(Buffer.from(encodeBedrockEventStreamMessage("contentBlockDelta", {
        contentBlockIndex: index,
        delta: { text: notice },
      })));
      out.write(Buffer.from(encodeBedrockEventStreamMessage("contentBlockStop", {
        contentBlockIndex: index,
      })));
      out.write(Buffer.from(encodeBedrockEventStreamMessage("messageStop", {
        stopReason: "end_turn",
      })));
      return;
    }
    if (provider === "bedrock-invoke") {
      // Anthropic-on-bedrock: wrap the anthropic deny triplet in chunk frames.
      out.write(Buffer.from(encodeBedrockInvokeChunk({
        type: "content_block_start",
        index,
        content_block: { type: "text", text: "" },
      })));
      out.write(Buffer.from(encodeBedrockInvokeChunk({
        type: "content_block_delta",
        index,
        delta: { type: "text_delta", text: notice },
      })));
      out.write(Buffer.from(encodeBedrockInvokeChunk({
        type: "content_block_stop",
        index,
      })));
      return;
    }
    // Default: OpenAI / OpenAI-compatible.
    out.write(Buffer.from(encodeOpenAIDataFrame({
      choices: [{ index: 0, delta: { role: "assistant", content: notice }, finish_reason: null }],
    })));
    out.write(Buffer.from(encodeOpenAIDataFrame({
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    })));
    out.write(Buffer.from(OPENAI_DONE_FRAME));
  }

  private emitSyntheticDeny(reason: string, toolName: string, toolArgs: unknown): void {
    const notice = makeBlockNoticeText(toolName, safeStringify(toolArgs), reason);
    let body: string;
    if (this.match.shape === "bedrock-converse") {
      // Bedrock Converse non-streaming envelope (GR-18). Anthropic-on-bedrock
      // invoke (`bedrock-invoke`) falls through to the anthropic-messages
      // branch below since those clients parse Anthropic message JSON.
      body = JSON.stringify({
        output: { message: { role: "assistant", content: [{ text: notice }] } },
        stopReason: "end_turn",
        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
      });
    } else if (this.match.shape === "anthropic-messages" || this.match.shape === "bedrock-invoke") {
      body = JSON.stringify({
        id: `msg_agentum_deny_${Date.now()}`,
        type: "message", role: "assistant", model: "agentum-policy",
        content: [{ type: "text", text: notice }],
        stop_reason: "end_turn",
        usage: { input_tokens: 0, output_tokens: 0 },
      });
    } else if (this.match.shape === "gemini-generate") {
      // Mirror geminiRewrite: denied functionCall → text part, finishReason "STOP".
      body = JSON.stringify({
        candidates: [{
          content: { role: "model", parts: [{ text: notice }] },
          finishReason: "STOP",
        }],
      });
    } else if (this.match.shape === "cohere-chat") {
      // Mirror cohereRewrite (v2): drop tool_calls, append text content block,
      // finish_reason "COMPLETE".
      body = JSON.stringify({
        id: `cohere-agentum-deny-${Date.now()}`,
        message: { role: "assistant", content: [{ type: "text", text: notice }] },
        finish_reason: "COMPLETE",
      });
    } else {
      body = JSON.stringify({
        id: `chatcmpl-agentum-deny-${Date.now()}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: "agentum-policy",
        choices: [{ index: 0, message: { role: "assistant", content: notice }, finish_reason: "stop" }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      });
    }
    const fake = new this.ctx.PassThrough() as unknown as NodeHttpType.IncomingMessage & PassThrough;
    Object.defineProperty(fake, "headers", {
      value: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
        "content-length": String(Buffer.byteLength(body)),
      },
    });
    Object.defineProperty(fake, "statusCode", { value: 200 });
    Object.defineProperty(fake, "statusMessage", { value: "OK" });
    process.nextTick(() => {
      this.req.emit("response", fake);
      fake.end(body);
    });
  }
}

// ── MCP Streamable-HTTP path (GR-19) ───────────────────────────────────────

function readNodeMethod(options: NodeHttpType.RequestOptions): string | undefined {
  return typeof options.method === "string" ? options.method : undefined;
}

function readNodeAcceptHeader(options: NodeHttpType.RequestOptions): string | undefined {
  const headers = options.headers;
  if (!headers) return undefined;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== "accept") continue;
    if (Array.isArray(v)) return v.join(", ");
    if (v == null) return undefined;
    return String(v);
  }
  return undefined;
}

function interceptMcpRequest(
  ctx: WrapContext,
  original: RequestFn,
  scheme: "http:" | "https:",
  url: string,
  norm: NormalizedArgs,
): NodeHttpType.ClientRequest {
  const facade = new McpFacadeClientRequest(ctx, scheme, original, url, norm);
  return facade.req as unknown as NodeHttpType.ClientRequest;
}

/**
 * Facade for MCP-over-HTTP on the node:http plane. Reuses the same
 * capture-then-decide mechanics as `FacadeClientRequest`: writes are buffered,
 * the upstream socket is NOT opened until the pre-flight decision is made, and
 * on deny it never opens at all. On allow / non-checked methods it forwards
 * and (for initialize) sniffs the response non-destructively.
 */
class McpFacadeClientRequest {
  public req: PassThrough & {
    setHeader?: (n: string, v: string) => void;
    getHeader?: (n: string) => unknown;
    removeHeader?: (n: string) => void;
    flushHeaders?: () => void;
  };
  private bodyChunks: Buffer[] = [];
  private ended = false;
  private extraHeaders: Record<string, string> = {};

  constructor(
    private ctx: WrapContext,
    private scheme: "http:" | "https:",
    private original: RequestFn,
    private url: string,
    private norm: NormalizedArgs,
  ) {
    const pass = new this.ctx.PassThrough() as PassThrough & {
      setHeader?: (n: string, v: string) => void;
      getHeader?: (n: string) => unknown;
      removeHeader?: (n: string) => void;
      flushHeaders?: () => void;
    };
    this.req = pass;
    pass.on("error", () => {
      /* default — real consumers attach their own listener */
    });
    pass.setHeader = (n: string, v: string) => {
      this.extraHeaders[n.toLowerCase()] = String(v);
    };
    pass.getHeader = (n: string) => this.extraHeaders[n.toLowerCase()];
    pass.removeHeader = (n: string) => {
      delete this.extraHeaders[n.toLowerCase()];
    };
    pass.flushHeaders = () => {};

    const origWrite = pass.write.bind(pass);
    pass.write = ((chunk: unknown, encoding?: unknown, cb?: unknown) => {
      try {
        if (chunk !== undefined && chunk !== null) {
          const buf = toBuffer(chunk, encoding);
          if (buf) this.bodyChunks.push(buf);
        }
      } catch (err) {
        this.ctx.logger.warn(`[agentum] mcp write capture error: ${(err as Error).message}`);
      }
      return origWrite(chunk as never, encoding as never, cb as never) as boolean;
    }) as typeof pass.write;

    const origEnd = pass.end.bind(pass);
    pass.end = ((chunk?: unknown, encoding?: unknown, cb?: unknown) => {
      if (this.ended) return pass;
      this.ended = true;
      if (chunk !== undefined && chunk !== null && typeof chunk !== "function") {
        try {
          const buf = toBuffer(chunk, encoding);
          if (buf) this.bodyChunks.push(buf);
        } catch (err) {
          this.ctx.logger.warn(`[agentum] mcp end capture error: ${(err as Error).message}`);
        }
      }
      origEnd(undefined as never);
      this.dispatch().catch((err) => {
        this.ctx.logger.warn(`[agentum] mcp dispatch error: ${(err as Error).message}`);
        try { pass.emit("error", err); } catch {}
      });
      if (typeof cb === "function") (cb as () => void)();
      return pass;
    }) as typeof pass.end;
  }

  private async dispatch(): Promise<void> {
    const body = Buffer.concat(this.bodyChunks).toString("utf8");
    const endpointKey = mcpEndpointKey(this.url);

    // SDK-own endpoints never get governed.
    if (this.isSdkOwnOrigin()) {
      this.forwardPlain(body);
      return;
    }

    const parsed: McpParsed = parseMcpBody(body);
    if (parsed === null || parsed.kind === "other") {
      this.forwardPlain(body);
      return;
    }

    if (parsed.kind === "initialize") {
      this.forwardInitialize(body, endpointKey);
      return;
    }

    const oldTransport = isOldTransportEndpoint(this.url);
    const sessionId = lookupMcpServer(endpointKey)?.sessionId;
    const evaluator = this.ctx.runtime.evaluator;

    if (parsed.kind === "batch") {
      let anyDeny = false;
      for (const call of parsed.calls) {
        const action = mcpActionFor(endpointKey, call.toolName);
        const verdict = await this.evalCall(action, call.args);
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
        this.emitSyntheticJson(arr, oldTransport ? 403 : 200);
        return;
      }
      this.forwardPlain(body);
      return;
    }

    // single tools/call
    const action = mcpActionFor(endpointKey, parsed.toolName);
    if (consumeMcpCallEvaluated(action, parsed.args)) {
      this.forwardPlain(body);
      return;
    }
    const verdict = await this.evalCall(action, parsed.args);
    if (verdict === "deny") {
      emitMcpHttpAudit(evaluator, { outcome: "deny", action, callArgs: parsed.args, endpointKey, reason: "policy denied", sessionId });
      if (oldTransport) {
        this.emitSyntheticJson(buildMcpDenyError(parsed.id, "policy denied"), 403);
      } else {
        this.emitSyntheticJson(buildMcpDenyResult(parsed.id, "policy denied"), 200);
      }
      return;
    }
    emitMcpHttpAudit(evaluator, { outcome: "allow", action, callArgs: parsed.args, endpointKey, sessionId });
    this.forwardPlain(body);
  }

  private async evalCall(
    action: string,
    args: Record<string, unknown> | undefined,
  ): Promise<"allow" | "deny"> {
    try {
      const v = await this.ctx.runtime.evaluator.evaluateToolCall({ toolName: action, arguments: args });
      if (v.decision === "deny") {
        // HITL-8: MCP-over-node:http has no session to suspend — warn once.
        warnHitlUnsupportedOnce("node-http", v);
        return "deny";
      }
      return "allow";
    } catch (err) {
      this.ctx.logger.warn(`[agentum] mcp evaluate error: ${(err as Error).message}`);
      return this.ctx.failMode === "deny" ? "deny" : "allow";
    }
  }

  private isSdkOwnOrigin(): boolean {
    const base = this.ctx.runtime.baseUrl;
    try {
      if (base && new URL(this.url).origin === new URL(base).origin) return true;
    } catch {
      /* fall through */
    }
    return false;
  }

  /** Forward the request to upstream untouched, relaying the response. */
  private forwardPlain(body: string): void {
    const opts: NodeHttpType.RequestOptions = { ...this.norm.options };
    opts.headers = { ...(opts.headers ?? {}), ...this.extraHeaders };
    let upstream: NodeHttpType.ClientRequest;
    try {
      const args: unknown[] = [];
      if (this.norm.url) args.push(this.norm.url);
      args.push(opts);
      upstream = (this.original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    } catch (err) {
      this.req.emit("error", err);
      return;
    }
    upstream.on("response", (res) => this.req.emit("response", res));
    upstream.on("error", (err) => { try { this.req.emit("error", err); } catch {} });
    upstream.on("close", () => { try { this.req.emit("close"); } catch {} });
    if (body.length > 0) upstream.write(body);
    upstream.end();
  }

  /**
   * Forward an `initialize` request and non-destructively sniff the response
   * (through a PassThrough) for `Mcp-Session-Id` + `serverInfo.name`.
   */
  private forwardInitialize(body: string, endpointKey: string): void {
    const opts: NodeHttpType.RequestOptions = { ...this.norm.options };
    opts.headers = { ...(opts.headers ?? {}), ...this.extraHeaders };
    let upstream: NodeHttpType.ClientRequest;
    try {
      const args: unknown[] = [];
      if (this.norm.url) args.push(this.norm.url);
      args.push(opts);
      upstream = (this.original as unknown as (...a: unknown[]) => NodeHttpType.ClientRequest)(...args);
    } catch (err) {
      this.req.emit("error", err);
      return;
    }
    upstream.on("response", (res) => {
      const sessionId = (res.headers["mcp-session-id"] as string | undefined) ?? undefined;
      const ct = (res.headers["content-type"] as string | undefined) ?? "";
      // Non-consuming sniff: pipe upstream through a PassThrough that we ALSO
      // observe. The consumer receives the PassThrough as the response.
      const out = new this.ctx.PassThrough() as unknown as NodeHttpType.IncomingMessage & PassThrough;
      Object.defineProperty(out, "headers", { value: { ...res.headers } });
      Object.defineProperty(out, "statusCode", { value: res.statusCode });
      Object.defineProperty(out, "statusMessage", { value: res.statusMessage });
      const isSse = ct.includes("text/event-stream");
      const isJson = ct.includes("application/json");
      let acc = "";
      let bytes = 0;
      let captured = false;
      res.on("data", (chunk: Buffer) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        out.write(buf);
        if (captured || (!isSse && !isJson)) return;
        if (bytes < SSE_SCAN_CAP_BYTES) {
          bytes += buf.byteLength;
          acc += buf.toString("utf8");
          if (isSse) {
            const name = scanInitializeSse(acc);
            if (name) { recordMcpServer(endpointKey, name, sessionId); captured = true; }
          }
        }
      });
      res.on("end", () => {
        if (!captured && isJson) {
          try {
            const json = JSON.parse(acc) as Record<string, unknown>;
            recordMcpServer(endpointKey, extractServerInfo(json), sessionId);
            captured = true;
          } catch {
            /* incomplete / non-JSON */
          }
        }
        if (!captured && sessionId) recordMcpServer(endpointKey, undefined, sessionId);
        out.end();
      });
      res.on("error", (e) => out.emit("error", e));
      this.req.emit("response", out);
    });
    upstream.on("error", (err) => { try { this.req.emit("error", err); } catch {} });
    upstream.on("close", () => { try { this.req.emit("close"); } catch {} });
    if (body.length > 0) upstream.write(body);
    upstream.end();
  }

  /** Emit a synthetic JSON response on the facade without opening a socket. */
  private emitSyntheticJson(bodyObj: unknown, status: number): void {
    const body = JSON.stringify(bodyObj);
    const fake = new this.ctx.PassThrough() as unknown as NodeHttpType.IncomingMessage & PassThrough;
    Object.defineProperty(fake, "headers", {
      value: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
        "content-length": String(Buffer.byteLength(body)),
      },
    });
    Object.defineProperty(fake, "statusCode", { value: status });
    Object.defineProperty(fake, "statusMessage", { value: status === 200 ? "OK" : "Forbidden" });
    process.nextTick(() => {
      this.req.emit("response", fake);
      fake.end(body);
    });
  }
}

// ── helpers shared with fetch-interceptor wire format ──────────────────────
//
// GR-18: the request/response tool-call extraction + deny rewrite for every
// provider shape now lives in `provider-extractors.ts` (imported above), the
// single source of truth shared with fetch + undici. The previous local forks
// here were stale (missing Cohere/Gemini non-streaming response handling and
// Bedrock entirely); deleting them closes those gaps and adopts fetch's
// `{denyCode, ruleId}` block-notice meta for free.

// ── observe-prompt sidecar (uses original http/https.request to avoid recursion)

async function postObservePrompt(args: {
  runtime: NodeHttpInterceptorRuntime;
  agentId: string;
  requestId: string;
  match: HostMatch;
  body: Record<string, unknown>;
  sessionId: string | undefined;
  userId: string | undefined;
  promptCaptureMode: Exclude<PromptCaptureMode, "off">;
  truncationBytes: number;
  timeoutMs: number;
  maxRetries: number;
  logger: Pick<Console, "log" | "warn" | "error">;
}): Promise<void> {
  const provider = args.match.provider ?? "other";
  const model = typeof args.body["model"] === "string" ? (args.body["model"] as string) : "unknown";
  let messages: unknown = normalizeMessagesForObserve(args.match, args.body, args.truncationBytes);
  let tools: unknown = args.body["tools"] ?? [];

  // R40 — mirror fetch-interceptor.ts: scrub raw prompt + tool content
  // before send. "masked" runs the S5 PII pipeline; "raw" passes through.
  // On any pipeline error fail-CLOSED: drop the observe POST.
  try {
    const masked = await maskObserveContent(args.promptCaptureMode, {
      messages,
      tools_advertised: tools,
    });
    messages = masked.messages;
    tools = masked.tools_advertised;
  } catch (err) {
    args.logger.warn(
      `[agentum] http observe-prompt dropped (PII masking failed, fail-closed): ${
        (err as Error).message ?? String(err)
      }`,
    );
    return;
  }

  const params: Record<string, unknown> = {};
  for (const k of ["temperature", "max_tokens", "top_p", "stream"]) {
    if (k in args.body) params[k] = args.body[k];
  }
  const payload = JSON.stringify({
    agent_id: args.agentId,
    request_id: args.requestId,
    provider, model, params, messages,
    tools_advertised: tools,
    session_id: args.sessionId ?? null,
    user_id: args.userId ?? null,
    client_ts: new Date().toISOString(),
  });
  const url = `${args.runtime.baseUrl.replace(/\/$/, "")}/api/v1/sdk/observe-prompt`;

  // Retry path mirrors fetch-interceptor.ts:postObservePrompt — same
  // idempotency contract on the server (60s window keyed by
  // (agent_id, request_id)) makes the retry safe.
  const attempts = Math.max(1, args.maxRetries + 1);
  let lastError: string | undefined;
  for (let i = 0; i < attempts; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), args.timeoutMs);
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Api-Key": args.runtime.apiKey },
        body: payload,
        signal: ac.signal,
      });
      if (resp.ok) return;
      if (resp.status >= 400 && resp.status < 500) {
        args.logger.warn(`[agentum] http observe-prompt HTTP ${resp.status} (no retry)`);
        return;
      }
      lastError = `HTTP ${resp.status}`;
    } catch (err) {
      lastError = (err as Error).message;
    } finally {
      clearTimeout(timer);
    }
    if (i < attempts - 1) {
      await new Promise<void>((r) => setTimeout(r, 50 * Math.pow(4, i)));
    }
  }
  args.logger.warn(
    `[agentum] http observe-prompt dropped after ${attempts} attempt(s): ${lastError}`,
  );
}

interface ObserveMessage { role: string; content: string; name?: string; byte_count?: number; truncated?: boolean }
function normalizeMessagesForObserve(
  match: HostMatch, body: Record<string, unknown>, cap: number,
): ObserveMessage[] {
  const out: ObserveMessage[] = [];
  if (match.shape === "anthropic-messages") {
    const sys = body["system"];
    if (typeof sys === "string" && sys.length > 0) {
      out.push(buildObserveMsg("system", sys, undefined, cap));
    } else if (Array.isArray(sys)) {
      for (const s of sys as Array<Record<string, unknown>>) {
        if (typeof s["text"] === "string") {
          out.push(buildObserveMsg("system", s["text"] as string, undefined, cap));
        }
      }
    }
  }
  const messages = body["messages"];
  if (!Array.isArray(messages)) return out;
  for (const m of messages as Array<Record<string, unknown>>) {
    const role = String(m["role"] ?? "user");
    const content = m["content"];
    let text: string;
    if (typeof content === "string") text = content;
    else if (Array.isArray(content)) {
      text = content.map((c: unknown) => {
        if (typeof c === "string") return c;
        const cb = c as Record<string, unknown>;
        if (cb["type"] === "text" && typeof cb["text"] === "string") return cb["text"] as string;
        return JSON.stringify(c);
      }).join("\n");
    } else text = safeStringify(content);
    const name = typeof m["name"] === "string" ? (m["name"] as string) : undefined;
    out.push(buildObserveMsg(role, text, name, cap));
  }
  return out;
}
function buildObserveMsg(role: string, content: string, name: string | undefined, cap: number): ObserveMessage {
  const bytes = Buffer.byteLength(content, "utf8");
  if (bytes <= cap) {
    const o: ObserveMessage = { role, content, byte_count: bytes };
    if (name) o.name = name;
    return o;
  }
  const sliced = Buffer.from(content, "utf8").subarray(0, cap).toString("utf8");
  const o: ObserveMessage = { role, content: sliced, byte_count: bytes, truncated: true };
  if (name) o.name = name;
  return o;
}

// ── tiny utilities ─────────────────────────────────────────────────────────

function toBuffer(chunk: unknown, encoding: unknown): Buffer | null {
  if (chunk == null) return null;
  if (Buffer.isBuffer(chunk)) return chunk;
  if (chunk instanceof Uint8Array) return Buffer.from(chunk);
  if (typeof chunk === "string") {
    const enc = (typeof encoding === "string" ? encoding : "utf8") as BufferEncoding;
    return Buffer.from(chunk, enc);
  }
  return null;
}

function safeParseJson(s: string): Record<string, unknown> | null {
  if (!s) return null;
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch { return null; }
}
function safeJsonParse(s: string): unknown {
  if (!s) return {};
  try { return JSON.parse(s); } catch { return { _raw: s }; }
}
function isPartialJson(parsed: unknown, raw: string): boolean {
  if (raw.length === 0) return true;
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;
    const keys = Object.keys(obj);
    if (keys.length === 1 && keys[0] === "_raw" && typeof obj["_raw"] === "string") {
      return true;
    }
  }
  return false;
}
function safeStringify(v: unknown): string {
  try { return typeof v === "string" ? v : JSON.stringify(v ?? {}); }
  catch { return String(v); }
}
function randomUuid(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 14)}`;
}

/**
 * Build a Readable that quacks like an IncomingMessage with mutated body
 * + headers. Used by the post-flight rewrite path.
 */
function synthesizeIncoming(
  ReadableCtor: typeof NodeStreamType.Readable,
  base: NodeHttpType.IncomingMessage,
  body: string,
  headerOverrides: Record<string, string> = {},
): NodeHttpType.IncomingMessage {
  const out = ReadableCtor.from([Buffer.from(body, "utf8")]) as unknown as NodeHttpType.IncomingMessage & Readable;
  Object.defineProperty(out, "headers", {
    value: { ...base.headers, ...headerOverrides },
  });
  Object.defineProperty(out, "statusCode", { value: base.statusCode });
  Object.defineProperty(out, "statusMessage", { value: base.statusMessage });
  Object.defineProperty(out, "httpVersion", { value: base.httpVersion });
  return out;
}
