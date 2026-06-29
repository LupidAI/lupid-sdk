/**
 * Layer-1 fetch interceptor.
 *
 * Wraps `globalThis.fetch` so any LLM HTTP traffic — regardless of which
 * client library produced it — passes through Agentum's policy engine
 * before reaching the upstream provider AND before the response is
 * returned to the caller.
 *
 * Why a fetch wrap (vs. only the per-SDK prototype patches): customers
 * use raw `fetch`, axios-on-fetch, lobechat, langchain-with-custom-fetch,
 * etc. The prototype patches catch the common `openai`/`@anthropic-ai/sdk`
 * paths; this interceptor catches everything else, classified by host
 * registry.
 *
 * Coexistence with the gateway MITM: when the request actually traverses
 * the Agentum HTTPS forward proxy, the gateway stamps
 * `x-agentum-policy: enforced` on the response. We see that header and
 * do NOT re-evaluate (avoid double-deny / double-audit).
 *
 * Failure model: the wrapper NEVER throws. On transport error or unknown
 * response shape the default is to short-circuit with a deny-shaped
 * response (`failMode: "deny"`). Pass `failMode: "allow"` explicitly to opt
 * into pass-through behaviour for dev environments only. Non-LLM URLs are
 * routed straight to the underlying fetch with a single `Set.has()` check —
 * measured zero-impact on hot paths.
 */

import { classifyUrl, HostRegistry, type HostMatch } from "./host-registry.js";
import { getAgentumContext } from "./context.js";
import { AGENTUM_PLANE_HEADER } from "./undici-dispatcher-interceptor.js";
import {
  VAULT_PLACEHOLDER_PREFIX,
  resolveHeaderPlaceholders,
} from "../vault/resolver.js";
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
import { makeBlockNoticeText } from "./_parsers.js";
import {
  extractRequestToolCalls,
  extractResponseToolCalls,
  rewriteResponseBody,
  type ResponseToolCall,
} from "./provider-extractors.js";
import {
  resolvePromptCaptureMode,
  maskObserveContent,
  PII_ADVANCED_ADDON,
} from "./prompt-capture.js";
import {
  isMcpWireCandidate,
  isOldTransportEndpoint,
  parseMcpBody,
  buildMcpDenyResult,
  buildMcpDenyError,
  mcpEndpointKey,
  mcpActionFor,
  mcpServerInfoFor,
  recordMcpServer,
  lookupMcpServer,
  extractServerInfo,
  scanInitializeSse,
  SSE_SCAN_CAP_BYTES,
  consumeMcpCallEvaluated,
  emitMcpHttpAudit,
  type McpParsed,
} from "./mcp-http.js";
import type { CedarToolCallClient, FeatureState, ToolCallEvaluation } from "../evaluation/cedar-client.js";
import type { PromptCaptureMode } from "../types.js";
import { warnHitlUnsupportedOnce } from "./hitl-unsupported.js";

const PATCHED_TAG = Symbol.for("agentum.fetch.patched");
const ORIGINAL_TAG = Symbol.for("agentum.fetch.original");

/** Minimal contract the interceptor needs from the SDK runtime. */
export interface FetchInterceptorRuntime {
  baseUrl: string;
  apiKey: string;
  evaluator: CedarToolCallClient;
}

export interface FetchInterceptorOptions {
  runtime: FetchInterceptorRuntime;
  agentId: string;
  hosts?: HostRegistry;
  failMode?: "allow" | "deny";
  /**
   * PDPC-A4 — the configured R22 reverse-proxy origin (`init` threads
   * `opts.pdpProxyUrl` / `AGENTUM_PDP_PROXY_URL`). When a request destination
   * matches this origin, in-process vault placeholder resolution is SKIPPED:
   * R22 resolves `agentum://SECRET/<lease>` out-of-process before forwarding
   * upstream (`crates/agentum-pdp/src/proxy.rs`), so pulling plaintext into
   * the agent process here would re-open the window we are closing. Undefined
   * when the agent is not routed through R22 (Bedrock / node:http / no proxy),
   * in which case in-process resolution is retained.
   */
  pdpProxyUrl?: string;
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
  /** Per-message byte cap for `observe-prompt` payloads. Default 8KB. */
  promptTruncationBytes?: number;
  /** Block on `observe-prompt` POST instead of fire-and-forget. Test hook. */
  syncObserve?: boolean;
  /** Timeout (ms) for the observe-prompt POST. Default 1500. */
  observePromptTimeoutMs?: number;
  /** Max retries for observe-prompt on transient failure. Default 1. */
  observePromptMaxRetries?: number;
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Test injection — replaces the captured underlying fetch. */
  fetchImpl?: typeof fetch;
}

interface PatchedFetch {
  (input: string | Request | URL, init?: RequestInit): Promise<Response>;
  [PATCHED_TAG]?: boolean;
  [ORIGINAL_TAG]?: typeof fetch;
}

const DEFAULT_TRUNCATION_BYTES = 8 * 1024;

export function installFetchInterceptor(opts: FetchInterceptorOptions): () => void {
  const logger = opts.logger ?? console;
  const hosts = opts.hosts ?? new HostRegistry();
  const failMode = opts.failMode ?? "deny";
  // OPEN-22 — the prompt-capture mode must be resolved PER REQUEST, not once
  // at install time. The R45b PII gate upgrades "raw" → "masked" once a
  // non-empty bundle lacking `addon.policy.pii-advanced` is observed, but the
  // evaluator's addon snapshot is `[]` at install time (no PDP authorize has
  // returned yet). Freezing the mode here meant the gate never activated.
  // Static parts (capturePrompts / promptCaptureMode) ARE safe to freeze; only
  // the addon snapshot is dynamic, so we re-read it inside the thunk.
  const staticCaptureModeOpts: {
    capturePrompts?: boolean;
    promptCaptureMode?: PromptCaptureMode;
  } = {};
  if (opts.capturePrompts !== undefined) staticCaptureModeOpts.capturePrompts = opts.capturePrompts;
  if (opts.promptCaptureMode !== undefined)
    staticCaptureModeOpts.promptCaptureMode = opts.promptCaptureMode;
  // Short-circuit: `capturePrompts: false` maps to "off" now and forever — no
  // bundle snapshot can change that, so skip the per-request re-read.
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
  const truncationBytes = opts.promptTruncationBytes ?? DEFAULT_TRUNCATION_BYTES;
  const observeTimeoutMs = opts.observePromptTimeoutMs ?? 1500;
  const observeMaxRetries = opts.observePromptMaxRetries ?? 1;
  // PDPC-A4 — parse the configured R22 reverse-proxy origin ONCE at install
  // time. `undefined` when the agent is not routed through R22 (Bedrock /
  // node:http / no proxy), in which case in-process vault resolution is
  // retained for every destination.
  const pdpProxyOrigin = parseOrigin(opts.pdpProxyUrl);

  const g = globalThis as typeof globalThis & { fetch: PatchedFetch };
  const existing = g.fetch as PatchedFetch | undefined;

  if (existing && existing[PATCHED_TAG]) {
    return () => {
      // No-op: another install owns this slot.
    };
  }

  const original = (opts.fetchImpl ?? existing) as typeof fetch | undefined;
  if (!original) {
    logger.warn("[agentum] installFetchInterceptor: no upstream fetch available");
    return () => {};
  }

  const patched: PatchedFetch = async function patchedFetch(
    input: string | Request | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const url = extractUrl(input);
    if (!url) return original(input as string | Request, init);

    // Vault placeholder pre-flight — applies to ALL outgoing fetches,
    // not just LLM hosts. Agent code can put `agentum://SECRET/<lease>`
    // in any Authorization / X-Api-Key / cookie header; we swap it for
    // the real secret before the request leaves the process. Skips
    // cleanly when no placeholder is present (a single substring check
    // per header value). Fail-CLOSED: on resolver error the request
    // never goes out — the agent sees the thrown error and can react.
    let resolvedInit: RequestInit | undefined = init;
    // PDPC-A4 — when the destination origin matches the configured R22
    // reverse-proxy origin, SKIP in-process resolution: R22 resolves the
    // `agentum://SECRET/<lease>` placeholder out-of-process before forwarding
    // upstream (proven live), so the placeholder is forwarded to R22 verbatim.
    // Resolving here would pull plaintext into the agent process — the exact
    // window PDPC-A closes. Origin comparison (not string-prefix) so a spoofed
    // path can't dodge or trigger the gate. For non-R22 destinations
    // (`pdpProxyOrigin === undefined`, or a different origin) in-process
    // resolution is retained unchanged.
    const isR22Destination =
      pdpProxyOrigin !== undefined && parseOrigin(url) === pdpProxyOrigin;
    const headersHaveVault =
      !isR22Destination && init?.headers != null && headersContainPlaceholder(init.headers);
    if (headersHaveVault) {
      try {
        resolvedInit = await resolveHeaderPlaceholders(init, {
          apiBaseUrl: opts.runtime.baseUrl,
          apiKey: opts.runtime.apiKey,
          fetchImpl: original,
        });
      } catch (err) {
        logger.warn(
          `[agentum] vault placeholder resolve failed: ${(err as Error).message ?? String(err)}`,
        );
        throw err;
      }
    }

    // R50 — body placeholder fail-CLOSED. Body resolution is NOT supported
    // (see vault/resolver.ts scope note). Without this guard a placeholder
    // in a JSON/text body is forwarded upstream verbatim — a silent
    // credential-exposure footgun. Detect a placeholder in scannable body
    // types and refuse to send. Non-scannable bodies (FormData /
    // ReadableStream / Blob) cannot be inspected safely and pass through;
    // that limitation is documented in `bodyContainsPlaceholder`.
    if (await bodyContainsPlaceholder(input, resolvedInit)) {
      const msg =
        "agentum vault: request body contains an agentum://SECRET/... placeholder; " +
        "body resolution is not supported — put the secret in a header or pre-resolve it.";
      logger.warn(`[agentum] ${msg}`);
      throw new Error(msg);
    }

    let host: string;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return original(input as string | Request, resolvedInit);
    }

    // GR-19: MCP Streamable-HTTP gate. MCP servers live on arbitrary hosts,
    // so the wire-level detection runs BEFORE (and independent of) the host
    // registry — both when the host is unregistered AND when a registered host
    // yields no LLM shape. Two cheap header substring checks gate it.
    const { method: reqMethod, accept: reqAccept } = readMethodAndAccept(input, resolvedInit);
    const mcpGateHit = isMcpWireCandidate(reqMethod, reqAccept, url);

    if (!hosts.matches(host)) {
      if (mcpGateHit) {
        return interceptMcpFetch({
          url,
          input,
          init: resolvedInit,
          original,
          runtime: opts.runtime,
          failMode,
          logger,
        });
      }
      return original(input as string | Request, resolvedInit);
    }
    // From here on `resolvedInit` is what the rest of the interceptor
    // sees — host-classified LLM/MCP paths get the post-resolve headers.
    init = resolvedInit;

    const match = classifyUrl(url);
    if (!match.shape) {
      if (mcpGateHit) {
        return interceptMcpFetch({
          url,
          input,
          init,
          original,
          runtime: opts.runtime,
          failMode,
          logger,
        });
      }
      return original(input as string | Request, init);
    }

    try {
      return await intercept({
        url,
        input,
        init,
        match,
        original,
        runtime: opts.runtime,
        agentId: opts.agentId,
        resolvePromptCaptureMode: resolveMode,
        truncationBytes,
        syncObserve: opts.syncObserve === true,
        observeTimeoutMs,
        observeMaxRetries,
        failMode,
        logger,
      });
    } catch (err) {
      logger.warn(
        `[agentum] fetch interceptor internal error: ${(err as Error).message ?? String(err)}`,
      );
      if (failMode === "deny") {
        return shortCircuitDeny(match, "agentum-internal-error");
      }
      return original(input as string | Request, init);
    }
  } as PatchedFetch;

  patched[PATCHED_TAG] = true;
  patched[ORIGINAL_TAG] = original;
  g.fetch = patched;

  return () => {
    if (g.fetch === patched) {
      g.fetch = original as PatchedFetch;
    }
  };
}

interface InterceptArgs {
  url: string;
  input: string | Request | URL;
  init: RequestInit | undefined;
  match: HostMatch;
  original: typeof fetch;
  runtime: FetchInterceptorRuntime;
  agentId: string;
  /** OPEN-22 — per-request thunk re-reading the evaluator addon snapshot. */
  resolvePromptCaptureMode: () => PromptCaptureMode;
  truncationBytes: number;
  syncObserve: boolean;
  observeTimeoutMs: number;
  observeMaxRetries: number;
  failMode: "allow" | "deny";
  logger: Pick<Console, "log" | "warn" | "error">;
}

async function intercept(a: InterceptArgs): Promise<Response> {
  const requestId = randomUuid();
  const { sessionId, userId } = getAgentumContext();
  const reqBody = await readRequestBody(a.input, a.init);
  const parsedBody = safeParseJson(reqBody);

  // 1. Pre-flight: observe + evaluate declared tool_calls in the request.
  // R40 — "off" suppresses the observe POST entirely; "masked"/"raw" send
  // it (masked scrubs PII from the content before send).
  // OPEN-22 — resolve per-request so the R45b PII gate sees the live addon
  // snapshot (raw→masked once the PDP bundle is known).
  const promptCaptureMode = a.resolvePromptCaptureMode();
  if (promptCaptureMode !== "off" && parsedBody) {
    const observePromise = postObservePrompt({
      runtime: a.runtime,
      agentId: a.agentId,
      requestId,
      match: a.match,
      body: parsedBody,
      sessionId,
      userId,
      promptCaptureMode,
      truncationBytes: a.truncationBytes,
      timeoutMs: a.observeTimeoutMs,
      maxRetries: a.observeMaxRetries,
      logger: a.logger,
    });
    if (a.syncObserve) {
      await observePromise.catch(() => undefined);
    } else {
      observePromise.catch(() => undefined);
    }
  }

  const requestToolCalls = parsedBody ? extractRequestToolCalls(a.match, parsedBody) : [];
  for (const tc of requestToolCalls) {
    let verdict: ToolCallEvaluation;
    try {
      verdict = await a.runtime.evaluator.evaluateToolCall({
        toolName: tc.name,
        arguments: tc.args,
      });
    } catch (err) {
      a.logger.warn(`[agentum] preflight evaluate error: ${(err as Error).message}`);
      if (a.failMode === "deny") return shortCircuitDeny(a.match, "agentum-fail-closed");
      continue;
    }
    if (verdict.decision === "deny") {
      // HITL-8: require_hitl preflight deny has no session to suspend — warn
      // once, then short-circuit (fail-CLOSED; no retry).
      warnHitlUnsupportedOnce("fetch", verdict);
      return shortCircuitDeny(a.match, verdict.reason ?? "policy denied", tc.name, tc.args);
    }
  }

  // 2. Forward to upstream.
  //
  // Cross-plane double-enforcement suppression: this request rides the undici
  // global dispatcher (Node `fetch` → undici). The dispatcher plane ALSO
  // enforces responses; without a marker it would re-enforce the very response
  // we are about to enforce here. Stamp `x-agentum-plane: fetch` so the
  // dispatcher reads it, strips it (upstream never sees it), and skips its own
  // response-side enforcement. We build a single merged Headers (effective
  // request headers + the marker) and always pass it on the init so the marker
  // survives regardless of whether `a.input` is a string or a `Request`.
  const stampedInit = stampPlaneMarker(a.input, a.init, reqBody);
  const upstream = await a.original(a.input as string | Request, stampedInit);

  // 3. Coexistence: gateway already enforced — do not re-evaluate.
  if (upstream.headers.get("x-agentum-policy") === "enforced") {
    return upstream;
  }

  const isStream = isEventStream(upstream);
  if (isStream && upstream.body) {
    return wrapStreamingResponse(upstream, a);
  }
  return wrapNonStreamingResponse(upstream, a);
}

/**
 * Build a forward init carrying the `x-agentum-plane: fetch` cross-plane marker
 * (read+stripped by the undici dispatcher to suppress double response-side
 * enforcement). We merge the EFFECTIVE request headers — the `Request`'s own
 * headers (when `input` is a `Request`) UNION the `init.headers` override — and
 * add the marker. The merged `Headers` is set on the returned init so the
 * marker survives even when `input` is a `Request` (where an init without a
 * `headers` field would otherwise leave the Request's headers untouched and our
 * marker absent). Provider auth headers are preserved (init wins on collision,
 * matching `fetch`'s own merge order). `reqBody`, when non-null, is set as the
 * body (the original interceptor already re-attaches the buffered body).
 */
function stampPlaneMarker(
  input: string | Request | URL,
  init: RequestInit | undefined,
  reqBody: string | null,
): RequestInit {
  const merged = new Headers();
  // Base: the Request's own headers (only meaningful when input is a Request).
  if (typeof Request !== "undefined" && input instanceof Request) {
    input.headers.forEach((v, k) => merged.set(k, v));
  }
  // Override: the init's headers (fetch applies init headers on top of Request).
  if (init?.headers) {
    new Headers(init.headers).forEach((v, k) => merged.set(k, v));
  }
  merged.set(AGENTUM_PLANE_HEADER, "fetch");
  const out: RequestInit = { ...(init ?? {}), headers: merged };
  if (reqBody !== null) out.body = reqBody;
  return out;
}

// ── post-flight: non-streaming evaluation ──────────────────────────────────

async function wrapNonStreamingResponse(
  upstream: Response,
  a: InterceptArgs,
): Promise<Response> {
  const ct = upstream.headers.get("content-type") ?? "";
  if (!ct.includes("application/json")) return upstream;

  const text = await upstream.clone().text();
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return new Response(text, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  }

  const calls = extractResponseToolCalls(a.match, json);
  if (calls.length === 0) {
    return new Response(text, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  }

  const decisions = await evaluateAll(a, calls);
  const denied = decisions
    .map((d, i) => ({ d, call: calls[i]! }))
    .filter((x) => x.d.decision === "deny");
  // HITL-8: warn once if any denied call carried require_hitl; deny stands.
  for (const x of denied) warnHitlUnsupportedOnce("fetch", x.d);

  if (denied.length === 0) {
    return new Response(text, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  }

  const rewritten = rewriteResponseBody(a.match, json, decisions, calls);
  const body = JSON.stringify(rewritten);
  const headers = new Headers(upstream.headers);
  // TextEncoder (not Node-only `Buffer`) so the deny-rewrite path is edge-safe.
  headers.set("content-length", String(new TextEncoder().encode(body).byteLength));
  headers.set("x-agentum-policy", "sdk-enforced");
  return new Response(body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

async function evaluateAll(
  a: InterceptArgs,
  calls: ResponseToolCall[],
): Promise<ToolCallEvaluation[]> {
  return Promise.all(
    calls.map(async (c) => {
      try {
        return await a.runtime.evaluator.evaluateToolCall({
          toolName: c.name,
          arguments: c.args,
        });
      } catch (err) {
        a.logger.warn(`[agentum] post-flight evaluate error: ${(err as Error).message}`);
        if (a.failMode === "deny") {
          return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" } as ToolCallEvaluation;
        }
        return { decision: "allow", ttlMs: 0 } as ToolCallEvaluation;
      }
    }),
  );
}

// ── streaming provider routing ─────────────────────────────────────────────

type StreamProvider =
  | "openai"
  | "anthropic"
  | "cohere"
  | "gemini"
  | "bedrock-converse"
  | "bedrock-invoke";

function streamProviderForShape(shape: string | null | undefined): StreamProvider | null {
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

/**
 * Map a host-registry `shape` to the `AGENTUM_STREAM_PASSTHROUGH` env-var
 * keyword set so operators can disable enforcement per provider during
 * roll-out without touching code. Keys are coarser than shapes: both
 * `openai-chat` and `openai-responses` resolve to `openai`.
 */
function streamShapeKey(shape: string | null | undefined): string {
  if (shape === "openai-chat" || shape === "openai-responses") return "openai";
  if (shape === "anthropic-messages") return "anthropic";
  if (shape === "cohere-chat") return "cohere";
  if (shape === "gemini-generate") return "gemini";
  // Both bedrock shapes share a single `AGENTUM_STREAM_PASSTHROUGH=bedrock`
  // rollout opt-out keyword.
  if (shape === "bedrock-converse" || shape === "bedrock-invoke") return "bedrock";
  return String(shape ?? "");
}

let _passthroughCache: { source: string; set: Set<string> } | null = null;

/**
 * Parse `AGENTUM_STREAM_PASSTHROUGH=cohere,gemini` into a Set the
 * interceptor can probe. Cached so we don't re-parse on every request.
 * Reading `process.env` directly works in Node and Edge runtimes that
 * polyfill `process`; on environments without `process` the cache stays
 * empty and enforcement runs as default.
 */
function streamPassthroughSet(): Set<string> {
  const raw: string | undefined =
    typeof process !== "undefined" && process && process.env
      ? process.env["AGENTUM_STREAM_PASSTHROUGH"]
      : undefined;
  const src: string = raw ?? "";
  if (_passthroughCache && _passthroughCache.source === src) {
    return _passthroughCache.set;
  }
  const set = new Set<string>(
    src
      .split(",")
      .map((s: string) => s.trim().toLowerCase())
      .filter((s: string) => s.length > 0),
  );
  _passthroughCache = { source: src, set };
  return set;
}

// ── post-flight: streaming evaluation (TransformStream) ────────────────────

function wrapStreamingResponse(
  upstream: Response,
  a: InterceptArgs,
): Response {
  if (!upstream.body) return upstream;

  // Streaming enforcement covers OpenAI, Anthropic, Cohere v2 and
  // Gemini. Operators can opt back into the legacy passthrough behaviour
  // per-provider via `AGENTUM_STREAM_PASSTHROUGH=cohere,gemini` (comma
  // list of `cohere` / `gemini` / `openai` / `anthropic`) for safe
  // rollout. When passthrough is engaged the `audit.streaming_unenforced`
  // event is still emitted so observability surfaces the bypass.
  const passthrough = streamPassthroughSet();
  const shape = a.match.shape;
  if (shape && passthrough.has(streamShapeKey(shape))) {
    void emitStreamingUnenforced(a);
    return upstream;
  }

  const maybeProvider = streamProviderForShape(shape);
  if (!maybeProvider) {
    // Unknown classified shape with streaming response — degrade to
    // passthrough with the audit marker rather than risk corrupting
    // an unfamiliar wire format.
    void emitStreamingUnenforced(a);
    return upstream;
  }
  const provider: StreamProvider = maybeProvider;
  const parser = newParserFor(provider);

  // Buffered tool-call accumulators keyed by index.
  interface ToolAcc {
    name: string;
    args: string;
    bufferedFrames: Uint8Array[];
  }
  const accs = new Map<number, ToolAcc>();
  const inFlightTool = new Set<number>();
  // Latches true the first time flushToolBuffer emits a synthetic terminal
  // sequence (finish_reason="stop" + [DONE] for OpenAI, or text triplet for
  // Anthropic). Once set, ALL upstream terminal frames are suppressed so we
  // never double-emit after the synthetic close.
  let syntheticTerminalEmitted = false;

  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform: async (chunk, controller) => {
      const events = parser.feed(chunk);
      for (const ev of events) {
        await handleEvent(ev, controller);
      }
    },
    flush: async (controller) => {
      const events = parser.flush();
      for (const ev of events) {
        await handleEvent(ev, controller);
      }
      // Resolve any still-buffered tool calls (no finish frame).
      for (const idx of inFlightTool) {
        const acc = accs.get(idx);
        if (!acc) continue;
        const verdict = await safeEval(a, acc.name, acc.args);
        flushToolBuffer(controller, idx, acc, verdict, provider);
      }
      inFlightTool.clear();
    },
  });

  async function handleEvent(
    ev: WireEvent,
    controller: TransformStreamDefaultController<Uint8Array>,
  ): Promise<void> {
    if (ev.kind === "text-delta" || ev.kind === "passthrough") {
      if (ev.rawFrame.byteLength > 0) controller.enqueue(ev.rawFrame);
      return;
    }
    if (ev.kind === "tool-call-start") {
      const acc: ToolAcc = {
        name: ev.name ?? "",
        args: "",
        bufferedFrames: ev.rawFrame.byteLength > 0 ? [ev.rawFrame] : [],
      };
      accs.set(ev.index, acc);
      inFlightTool.add(ev.index);
      return;
    }
    if (ev.kind === "tool-call-arguments") {
      const acc = accs.get(ev.index);
      if (!acc) {
        if (ev.rawFrame.byteLength > 0) controller.enqueue(ev.rawFrame);
        return;
      }
      acc.args += ev.deltaJson;
      if (ev.rawFrame.byteLength > 0) acc.bufferedFrames.push(ev.rawFrame);
      return;
    }
    if (ev.kind === "tool-call-end") {
      // Buffer the closing frame alongside its matching start/arguments so a
      // deny rewrites the entire block atomically. If the index doesn't
      // belong to a tracked tool (shouldn't happen but tolerate it),
      // forward verbatim.
      const acc = accs.get(ev.index);
      if (acc) {
        if (ev.rawFrame.byteLength > 0) acc.bufferedFrames.push(ev.rawFrame);
        return;
      }
      if (ev.rawFrame.byteLength > 0) controller.enqueue(ev.rawFrame);
      return;
    }
    if (ev.kind === "finish") {
      // Resolve all in-flight tool buffers before emitting finish.
      let anyDenyFlushed = false;
      for (const idx of inFlightTool) {
        const acc = accs.get(idx);
        if (!acc) continue;
        const verdict = await safeEval(a, acc.name, acc.args);
        if (verdict.decision !== "allow") anyDenyFlushed = true;
        flushToolBuffer(controller, idx, acc, verdict, provider);
      }
      inFlightTool.clear();
      // When flushToolBuffer took the deny branch it already emitted a synthetic
      // finish_reason="stop" + [DONE] (or the provider equivalent). Re-emitting
      // the upstream's raw finish frame here forwards a chunk with
      // finish_reason="tool_calls"/"TOOL_CALL" AFTER the synthetic terminator,
      // which leaves streaming consumers waiting forever for tool output that
      // will never come. Only emit the raw frame when no deny was flushed.
      if (anyDenyFlushed) {
        syntheticTerminalEmitted = true;
        return;
      }
      // Also suppress any upstream terminal frames that arrive after we already
      // emitted a synthetic terminal sequence (e.g. the upstream [DONE] that
      // follows finish_reason="tool_calls" in OpenAI SSE).
      if (syntheticTerminalEmitted) return;
      if (ev.rawFrame.byteLength > 0) controller.enqueue(ev.rawFrame);
      return;
    }
  }

  function flushToolBuffer(
    controller: TransformStreamDefaultController<Uint8Array>,
    index: number,
    acc: ToolAcc,
    verdict: ToolCallEvaluation,
    p: StreamProvider,
  ): void {
    if (verdict.decision === "allow") {
      for (const f of acc.bufferedFrames) controller.enqueue(f);
      return;
    }
    // HITL-8: a require_hitl deny cannot suspend on the fetch plane — warn
    // once, then drop the tool frames (fail-CLOSED; no retry).
    warnHitlUnsupportedOnce("fetch", verdict);
    const notice = makeBlockNoticeText(acc.name, acc.args, verdict.reason, {
      denyCode: verdict.denyCode,
      ruleId: verdict.ruleId,
    });
    if (p === "anthropic") {
      controller.enqueue(encodeAnthropicEventFrame("content_block_start", {
        type: "content_block_start",
        index,
        content_block: { type: "text", text: "" },
      }));
      controller.enqueue(encodeAnthropicEventFrame("content_block_delta", {
        type: "content_block_delta",
        index,
        delta: { type: "text_delta", text: notice },
      }));
      controller.enqueue(encodeAnthropicEventFrame("content_block_stop", {
        type: "content_block_stop",
        index,
      }));
      return;
    }
    if (p === "cohere") {
      // Cohere v2 deny sequence: open a content block, write the notice
      // text, close the block, then emit a clean message-end so the
      // consumer's stream finishes cleanly.
      controller.enqueue(encodeCohereEventFrame("content-start", {
        index,
        delta: { message: { content: { type: "text", text: "" } } },
      }));
      controller.enqueue(encodeCohereEventFrame("content-delta", {
        index,
        delta: { message: { content: { text: notice } } },
      }));
      controller.enqueue(encodeCohereEventFrame("content-end", { index }));
      controller.enqueue(encodeCohereEventFrame("message-end", {
        delta: { finish_reason: "COMPLETE" },
      }));
      return;
    }
    if (p === "gemini") {
      // Gemini deny sequence: replace the chunk that carried the
      // functionCall with a chunk that has the notice as a text part,
      // normalising finishReason to STOP so downstream consumers don't
      // wait on a non-existent tool turn.
      controller.enqueue(encodeGeminiDataFrame({
        candidates: [{
          content: {
            role: "model",
            parts: [{ text: notice }],
          },
          finishReason: "STOP",
          index: 0,
        }],
      }));
      return;
    }
    if (p === "bedrock-converse") {
      // Bedrock Converse-stream deny: write the notice as a text delta on the
      // tool's content block, close the block, then a clean messageStop. CRCs
      // computed by the encoder (the AWS SDK validates them).
      controller.enqueue(encodeBedrockEventStreamMessage("contentBlockDelta", {
        contentBlockIndex: index,
        delta: { text: notice },
      }));
      controller.enqueue(encodeBedrockEventStreamMessage("contentBlockStop", {
        contentBlockIndex: index,
      }));
      controller.enqueue(encodeBedrockEventStreamMessage("messageStop", {
        stopReason: "end_turn",
      }));
      return;
    }
    if (p === "bedrock-invoke") {
      // Anthropic-on-bedrock: wrap the anthropic deny triplet in chunk frames.
      controller.enqueue(encodeBedrockInvokeChunk({
        type: "content_block_start",
        index,
        content_block: { type: "text", text: "" },
      }));
      controller.enqueue(encodeBedrockInvokeChunk({
        type: "content_block_delta",
        index,
        delta: { type: "text_delta", text: notice },
      }));
      controller.enqueue(encodeBedrockInvokeChunk({
        type: "content_block_stop",
        index,
      }));
      return;
    }
    // Default: OpenAI / OpenAI-compatible.
    controller.enqueue(encodeOpenAIDataFrame({
      choices: [{
        index: 0,
        delta: { role: "assistant", content: notice },
        finish_reason: null,
      }],
    }));
    controller.enqueue(encodeOpenAIDataFrame({
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    }));
    controller.enqueue(OPENAI_DONE_FRAME);
  }

  const piped = upstream.body.pipeThrough(transform);
  const headers = new Headers(upstream.headers);
  headers.set("x-agentum-policy", "sdk-enforced");
  headers.delete("content-length");
  return new Response(piped, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

async function safeEval(
  a: InterceptArgs,
  name: string,
  rawArgs: string,
): Promise<ToolCallEvaluation> {
  // Partial / unparseable tool-call JSON is a SECURITY signal, not a
  // recoverable parse error. The OpenAI / Anthropic streaming wire
  // formats accumulate `function.arguments` as a string concatenated
  // across many SSE deltas; if a `finish` event arrives before all
  // argument deltas (network glitch, truncated stream, premature
  // upstream close), we end up evaluating `{_raw: "<half-json>"}`.
  // A policy that keys on `context.arguments.url like "..."` cannot
  // match an unparsed blob and falls back to whatever the default
  // permits. Deny-by-default here is the correct posture: we'd rather
  // refuse a tool call we couldn't fully observe than let it through
  // because the bytes never finished arriving.
  const parsed = safeJsonParse(rawArgs);
  if (isPartialJson(parsed, rawArgs)) {
    return {
      decision: "deny",
      ttlMs: 0,
      reason: "agentum-partial-tool-args",
    };
  }
  try {
    return await a.runtime.evaluator.evaluateToolCall({
      toolName: name,
      arguments: parsed,
    });
  } catch (err) {
    a.logger.warn(`[agentum] stream evaluate error: ${(err as Error).message}`);
    if (a.failMode === "deny") {
      return { decision: "deny", ttlMs: 0, reason: "agentum-fail-closed" };
    }
    return { decision: "allow", ttlMs: 0 };
  }
}

/**
 * Detect the deny-default sentinel emitted by `safeJsonParse` when the
 * argument string couldn't be parsed (`{_raw: "<half>"}`). An empty-string
 * input is also treated as partial — a streaming tool call that finished
 * with zero argument bytes is almost certainly a truncated stream rather
 * than a deliberate no-arg call (no-arg OpenAI tool calls emit `"{}"`
 * not `""`). This is intentionally narrower than "any object containing
 * a `_raw` key" because policies are free to use that key name.
 */
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

// ── audit sidecar: streaming-unenforced event ──────────────────────────────

/**
 * Fire-and-forget POST to `/api/v1/audit/ingest` recording that a streaming
 * response from Cohere/Gemini bypassed SDK-side enforcement (no parser
 * exists for their SSE shapes yet). Observability hook for that gap; do
 * not throw, do not block. Mirrors the fire-and-forget posture of
 * `postObservePrompt` and uses the un-patched fetch to avoid recursing.
 */
async function emitStreamingUnenforced(a: InterceptArgs): Promise<void> {
  try {
    const { sessionId, userId } = getAgentumContext();
    const url = `${a.runtime.baseUrl.replace(/\/$/, "")}/api/v1/audit/ingest`;
    const payload = JSON.stringify({
      agent_id: a.agentId,
      session_id: sessionId ?? "",
      event_type: "audit.streaming_unenforced",
      outcome: "passthrough",
      detail: {
        reason: "no-sdk-side-sse-parser",
        provider: a.match.provider,
        shape: a.match.shape,
        url: a.url,
        ...(userId ? { user_id: userId } : {}),
      },
    });
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), a.observeTimeoutMs);
    try {
      await fetchOriginal()(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": a.runtime.apiKey,
        },
        body: payload,
        signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    a.logger.warn(
      `[agentum] audit.streaming_unenforced emit failed: ${(err as Error).message}`,
    );
  }
}

// ── observe-prompt sidecar POST ────────────────────────────────────────────

async function postObservePrompt(args: {
  runtime: FetchInterceptorRuntime;
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

  // R40 — scrub raw prompt + tool content before it leaves the agent.
  // "masked" runs the S5 PII pipeline; "raw" passes through. On any
  // pipeline error we fail-CLOSED: drop the observe POST so raw PII never
  // leaks (actionable telemetry is sacrificed for this single event only).
  try {
    const masked = await maskObserveContent(args.promptCaptureMode, {
      messages,
      tools_advertised: tools,
    });
    messages = masked.messages;
    tools = masked.tools_advertised;
  } catch (err) {
    args.logger.warn(
      `[agentum] observe-prompt dropped (PII masking failed, fail-closed): ${
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
    provider,
    model,
    params,
    messages,
    tools_advertised: tools,
    session_id: args.sessionId ?? null,
    user_id: args.userId ?? null,
    client_ts: new Date().toISOString(),
  });
  const url = `${args.runtime.baseUrl.replace(/\/$/, "")}/api/v1/sdk/observe-prompt`;

  // Retry with exponential backoff on transport / 5xx. The server's
  // observe-prompt endpoint is idempotent on (agent_id, request_id) for
  // 60s (sdk.rs:OBSERVE_PROMPT_IDEMPOTENCY_TTL), so safe to retry. 4xx
  // is a client error — no retry. We still drop on full exhaustion to
  // preserve fire-and-forget semantics, but a single network blip no
  // longer silently loses an audit event.
  const attempts = Math.max(1, args.maxRetries + 1);
  let lastError: string | undefined;
  for (let i = 0; i < attempts; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), args.timeoutMs);
    try {
      const resp = await fetchOriginal()(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Api-Key": args.runtime.apiKey,
        },
        body: payload,
        signal: ac.signal,
      });
      if (resp.ok) return;
      // 4xx is permanent — don't retry.
      if (resp.status >= 400 && resp.status < 500) {
        args.logger.warn(`[agentum] observe-prompt HTTP ${resp.status} (no retry)`);
        return;
      }
      lastError = `HTTP ${resp.status}`;
    } catch (err) {
      lastError = (err as Error).message;
    } finally {
      clearTimeout(timer);
    }
    if (i < attempts - 1) {
      // Exponential backoff: 50ms, 200ms, 800ms, ...
      await sleep(50 * Math.pow(4, i));
    }
  }
  args.logger.warn(
    `[agentum] observe-prompt dropped after ${attempts} attempt(s): ${lastError}`,
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface ObserveMessage {
  role: string;
  content: string;
  name?: string;
  byte_count?: number;
  truncated?: boolean;
}

function normalizeMessagesForObserve(
  match: HostMatch,
  body: Record<string, unknown>,
  truncationBytes: number,
): ObserveMessage[] {
  const out: ObserveMessage[] = [];
  if (match.shape === "anthropic-messages") {
    const sys = body["system"];
    if (typeof sys === "string" && sys.length > 0) {
      out.push(buildObserveMsg("system", sys, undefined, truncationBytes));
    } else if (Array.isArray(sys)) {
      for (const s of sys as Array<Record<string, unknown>>) {
        if (typeof s["text"] === "string") {
          out.push(buildObserveMsg("system", s["text"] as string, undefined, truncationBytes));
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
    if (typeof content === "string") {
      text = content;
    } else if (Array.isArray(content)) {
      text = content
        .map((c: unknown) => {
          if (typeof c === "string") return c;
          const cb = c as Record<string, unknown>;
          if (cb["type"] === "text" && typeof cb["text"] === "string") return cb["text"] as string;
          return JSON.stringify(c);
        })
        .join("\n");
    } else {
      text = safeStringify(content);
    }
    const name = typeof m["name"] === "string" ? (m["name"] as string) : undefined;
    out.push(buildObserveMsg(role, text, name, truncationBytes));
  }
  return out;
}

function buildObserveMsg(
  role: string,
  content: string,
  name: string | undefined,
  cap: number,
): ObserveMessage {
  // `Buffer` is a Node-only global; this file is in the edge-safe bundle
  // (exported from index.ts), so use TextEncoder/TextDecoder which exist on
  // every runtime (Node, Workers, Edge, browser).
  const encoded = new TextEncoder().encode(content);
  const bytes = encoded.byteLength;
  if (bytes <= cap) {
    const out: ObserveMessage = { role, content, byte_count: bytes };
    if (name) out.name = name;
    return out;
  }
  // Truncate at the byte cap; TextDecoder emits U+FFFD for any split
  // multi-byte sequence, keeping the result valid utf-8 (matches the prior
  // `Buffer.subarray().toString("utf8")` behavior).
  const sliced = new TextDecoder("utf-8").decode(encoded.subarray(0, cap));
  const out: ObserveMessage = {
    role,
    content: sliced,
    byte_count: bytes,
    truncated: true,
  };
  if (name) out.name = name;
  return out;
}

// ── helpers ────────────────────────────────────────────────────────────────

/**
 * PDPC-A4 — parse a URL string to its `origin` (scheme + host + port),
 * returning `undefined` on empty/invalid input. Used to compare a request
 * destination against the configured R22 reverse-proxy origin so in-process
 * vault resolution is skipped only for an exact origin match (never a
 * spoofable string prefix).
 */
function parseOrigin(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    return new URL(raw).origin;
  } catch {
    return undefined;
  }
}

function extractUrl(input: string | Request | URL): string | null {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  if (typeof input === "object" && input && "url" in input) {
    return (input as Request).url;
  }
  return null;
}

/**
 * Resolve the HTTP method + `Accept` header for the MCP wire gate. `init`
 * wins over a `Request` input (fetch semantics: init overrides). Edge-safe —
 * no Node access.
 */
function readMethodAndAccept(
  input: string | Request | URL,
  init: RequestInit | undefined,
): { method: string | undefined; accept: string | undefined } {
  let method: string | undefined;
  let accept: string | undefined;
  // Request-derived defaults.
  if (typeof input === "object" && input && "headers" in input && "method" in input) {
    const req = input as Request;
    method = req.method;
    try {
      accept = req.headers?.get?.("accept") ?? undefined;
    } catch {
      /* ignore */
    }
  }
  // init overrides.
  if (init?.method) method = init.method;
  if (init?.headers != null) {
    const fromInit = headerValueFrom(init.headers, "accept");
    if (fromInit !== undefined) accept = fromInit;
  }
  return { method, accept };
}

function headerValueFrom(
  headers: RequestInit["headers"],
  name: string,
): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  if (headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }
  if (Array.isArray(headers)) {
    for (const pair of headers) {
      if (pair.length >= 2 && typeof pair[0] === "string" && pair[0].toLowerCase() === lower) {
        return pair[1];
      }
    }
    return undefined;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return String(v);
  }
  return undefined;
}

// ── MCP Streamable-HTTP path (GR-19) ───────────────────────────────────────

interface McpFetchArgs {
  url: string;
  input: string | Request | URL;
  init: RequestInit | undefined;
  original: typeof fetch;
  runtime: FetchInterceptorRuntime;
  failMode: "allow" | "deny";
  logger: Pick<Console, "log" | "warn" | "error">;
}

/**
 * MCP Streamable-HTTP interception for the fetch plane. Parses the JSON-RPC
 * body, evaluates `tools/call` (the only checked method), denies fail-CLOSED
 * with a spec-legal `CallToolResult { isError: true }`, captures the server
 * name + session id from `initialize` responses, and forwards everything else
 * byte-identically.
 */
async function interceptMcpFetch(a: McpFetchArgs): Promise<Response> {
  const endpointKey = mcpEndpointKey(a.url);

  // SDK-own endpoints (central / PDP) never get governed.
  if (isMcpSdkOwnOrigin(a.url, a.runtime)) {
    return a.original(a.input as string | Request, a.init);
  }

  let rawBody: string | null;
  try {
    rawBody = await readRequestBody(a.input, a.init);
  } catch {
    rawBody = null;
  }
  if (rawBody === null) {
    // No scannable body — nothing to check. Forward untouched.
    return a.original(a.input as string | Request, a.init);
  }

  const parsed: McpParsed = parseMcpBody(rawBody);
  if (parsed === null || parsed.kind === "other") {
    // Not JSON-RPC 2.0, or a method we don't check (notifications/responses/
    // tools-list/etc) — forward byte-identically.
    return a.original(a.input as string | Request, a.init);
  }

  if (parsed.kind === "initialize") {
    return forwardMcpInitialize(a, endpointKey);
  }

  // tools/call (single or batch) — evaluate fail-CLOSED.
  const oldTransport = isOldTransportEndpoint(a.url);
  const sessionId = lookupMcpServer(endpointKey)?.sessionId;

  if (parsed.kind === "batch") {
    let anyDeny = false;
    for (const call of parsed.calls) {
      const action = mcpActionFor(endpointKey, call.toolName);
      const verdict = await evalMcpCall(a, action, call.args, endpointKey);
      if (verdict === "deny") {
        anyDeny = true;
        emitMcpHttpAudit(a.runtime.evaluator, {
          outcome: "deny",
          action,
          callArgs: call.args,
          endpointKey,
          reason: "policy denied",
          sessionId,
        });
      } else if (verdict === "allow") {
        emitMcpHttpAudit(a.runtime.evaluator, {
          outcome: "allow",
          action,
          callArgs: call.args,
          endpointKey,
          sessionId,
        });
      }
    }
    if (anyDeny) {
      // Fail-CLOSED on the whole batch — partial forwarding is impossible
      // without splitting the batch (official SDKs never batch tools/call).
      const arr: Record<string, unknown>[] = parsed.calls
        .map((c) => buildMcpDenyResult(c.id, "policy denied"))
        .concat(parsed.otherIds.map((id) => buildMcpDenyError(id, "policy denied")));
      return mcpJsonResponse(arr, oldTransport ? 403 : 200);
    }
    return a.original(a.input as string | Request, a.init);
  }

  // single tools/call
  const action = mcpActionFor(endpointKey, parsed.toolName);
  // Suppression: the official SDK's Client.callTool patch already evaluated
  // this exact call before the transport POST. Skip eval + audit, forward.
  if (consumeMcpCallEvaluated(action, parsed.args)) {
    return a.original(a.input as string | Request, a.init);
  }
  const verdict = await evalMcpCall(a, action, parsed.args, endpointKey);
  if (verdict === "deny") {
    emitMcpHttpAudit(a.runtime.evaluator, {
      outcome: "deny",
      action,
      callArgs: parsed.args,
      endpointKey,
      reason: "policy denied",
      sessionId,
    });
    if (oldTransport) {
      return mcpJsonResponse(buildMcpDenyError(parsed.id, "policy denied"), 403);
    }
    return mcpJsonResponse(buildMcpDenyResult(parsed.id, "policy denied"), 200);
  }
  emitMcpHttpAudit(a.runtime.evaluator, {
    outcome: "allow",
    action,
    callArgs: parsed.args,
    endpointKey,
    sessionId,
  });
  return a.original(a.input as string | Request, a.init);
}

/** Evaluate a single MCP tool call, honoring failMode on evaluator error. */
async function evalMcpCall(
  a: McpFetchArgs,
  action: string,
  args: Record<string, unknown> | undefined,
  endpointKey: string,
): Promise<"allow" | "deny"> {
  try {
    // MCP-REDESIGN Phase 2b — pass the endpoint URL (origin + pathname) and
    // the recorded `serverInfo.name` so central can resolve the canonical
    // `server_id`. The namespaced `action` stays the dual-accept subject.
    const info = mcpServerInfoFor(endpointKey);
    const v = await a.runtime.evaluator.evaluateToolCall({
      toolName: action,
      arguments: args,
      ...(info.url !== undefined ? { mcpServerUrl: info.url } : {}),
      ...(info.name !== undefined ? { mcpServerName: info.name } : {}),
    });
    if (v.decision === "deny") {
      // HITL-8: MCP-over-HTTP has no session to suspend — warn once, deny.
      warnHitlUnsupportedOnce("fetch", v);
      return "deny";
    }
    return "allow";
  } catch (err) {
    a.logger.warn(`[agentum] mcp-http evaluate error: ${(err as Error).message}`);
    return a.failMode === "deny" ? "deny" : "allow";
  }
}

/**
 * Forward an MCP `initialize` request, then capture `serverInfo.name` +
 * `Mcp-Session-Id` from the response so subsequent tools/call namespacing
 * resolves the server name.
 */
async function forwardMcpInitialize(a: McpFetchArgs, endpointKey: string): Promise<Response> {
  const upstream = await a.original(a.input as string | Request, a.init);
  const sessionId = upstream.headers.get("mcp-session-id") ?? undefined;
  const ct = upstream.headers.get("content-type") ?? "";

  if (ct.includes("text/event-stream") && upstream.body) {
    // Tee: scan one branch for serverInfo.name (detach at first hit or cap),
    // return a Response wrapping the other branch untouched.
    const [scanBranch, passBranch] = upstream.body.tee();
    void scanInitializeStream(scanBranch, endpointKey, sessionId);
    return new Response(passBranch, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  }

  if (ct.includes("application/json")) {
    const text = await upstream.clone().text();
    try {
      const json = JSON.parse(text) as Record<string, unknown>;
      const serverName = extractServerInfo(json);
      recordMcpServer(endpointKey, serverName, sessionId);
    } catch {
      if (sessionId) recordMcpServer(endpointKey, undefined, sessionId);
    }
    return new Response(text, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  }

  if (sessionId) recordMcpServer(endpointKey, undefined, sessionId);
  return upstream;
}

/** Scan a teed SSE branch for the server name, with a 64 KiB hard cap. */
async function scanInitializeStream(
  branch: ReadableStream<Uint8Array>,
  endpointKey: string,
  sessionId: string | undefined,
): Promise<void> {
  const reader = branch.getReader();
  const decoder = new TextDecoder();
  let acc = "";
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        bytes += value.byteLength;
        acc += decoder.decode(value, { stream: true });
        const name = scanInitializeSse(acc);
        if (name) {
          recordMcpServer(endpointKey, name, sessionId);
          return;
        }
        if (bytes >= SSE_SCAN_CAP_BYTES) break;
      }
    }
    // Cap hit / stream ended with no serverInfo — still record the session id.
    if (sessionId) recordMcpServer(endpointKey, undefined, sessionId);
  } catch {
    if (sessionId) recordMcpServer(endpointKey, undefined, sessionId);
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* best-effort detach */
    }
  }
}

function isMcpSdkOwnOrigin(url: string, runtime: FetchInterceptorRuntime): boolean {
  try {
    const o = new URL(url).origin;
    if (runtime.baseUrl && o === new URL(runtime.baseUrl).origin) return true;
  } catch {
    /* fall through */
  }
  return false;
}

function mcpJsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-agentum-policy": "sdk-denied",
    },
  });
}

/**
 * Fast check: does any header value contain an `agentum://SECRET/...`
 * placeholder? Returns true on the first match. Used as the gate for
 * the vault-resolve pre-flight so requests without any placeholders
 * skip the resolver entirely.
 */
function headersContainPlaceholder(
  headers: RequestInit["headers"] | undefined,
): boolean {
  if (!headers) return false;
  if (headers instanceof Headers) {
    let found = false;
    headers.forEach(v => {
      if (!found && v.includes(VAULT_PLACEHOLDER_PREFIX)) found = true;
    });
    return found;
  }
  if (Array.isArray(headers)) {
    for (const pair of headers) {
      if (pair.length >= 2 && pair[1] != null && pair[1].includes(VAULT_PLACEHOLDER_PREFIX)) {
        return true;
      }
    }
    return false;
  }
  for (const v of Object.values(headers)) {
    if (String(v).includes(VAULT_PLACEHOLDER_PREFIX)) return true;
  }
  return false;
}

/**
 * R50 — does the request body contain an `agentum://SECRET/...` placeholder?
 *
 * Body placeholder resolution is NOT supported (see `vault/resolver.ts`).
 * This guard exists so a placeholder that landed in a body is rejected
 * fail-CLOSED rather than forwarded upstream verbatim (a credential-exposure
 * footgun). Scannable body types:
 *  - `string` → substring check.
 *  - `Uint8Array` / Node `Buffer` → decode utf-8 then substring check.
 *  - `Request` (when `init.body` is absent) → async-read its cloned text.
 *
 * Non-scannable body types — `FormData`, `ReadableStream`, `Blob`,
 * `URLSearchParams`, `ArrayBuffer` views we don't special-case — return
 * `false`: we cannot inspect them without consuming/altering the body, so
 * they pass through. This is a documented limitation: a placeholder hidden
 * inside a streamed or multipart body is not detected.
 */
async function bodyContainsPlaceholder(
  input: string | Request | URL,
  init: RequestInit | undefined,
): Promise<boolean> {
  const body = init?.body;
  if (body !== undefined && body !== null) {
    if (typeof body === "string") {
      return body.includes(VAULT_PLACEHOLDER_PREFIX);
    }
    if (body instanceof Uint8Array) {
      return new TextDecoder().decode(body).includes(VAULT_PLACEHOLDER_PREFIX);
    }
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(body as unknown)) {
      return (body as Buffer).toString("utf8").includes(VAULT_PLACEHOLDER_PREFIX);
    }
    // FormData / ReadableStream / Blob / URLSearchParams / ArrayBuffer:
    // not safely scannable without consuming the body — pass through.
    return false;
  }
  // No explicit `init.body` — the body may live on a `Request` input.
  if (typeof input === "object" && input && "clone" in input) {
    try {
      const text = await (input as Request).clone().text();
      return text.includes(VAULT_PLACEHOLDER_PREFIX);
    } catch {
      return false;
    }
  }
  return false;
}

async function readRequestBody(
  input: string | Request | URL,
  init: RequestInit | undefined,
): Promise<string | null> {
  if (init?.body !== undefined && init.body !== null) {
    if (typeof init.body === "string") return init.body;
    if (init.body instanceof Uint8Array) return new TextDecoder().decode(init.body);
    if (typeof Buffer !== "undefined" && Buffer.isBuffer(init.body as unknown)) {
      return (init.body as Buffer).toString("utf8");
    }
    return null;
  }
  if (typeof input === "object" && input && "clone" in input) {
    try {
      return await (input as Request).clone().text();
    } catch {
      return null;
    }
  }
  return null;
}

function safeParseJson(s: string | null): Record<string, unknown> | null {
  if (!s) return null;
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function safeJsonParse(s: string): unknown {
  if (!s) return {};
  try { return JSON.parse(s); } catch { return { _raw: s }; }
}

function safeStringify(v: unknown): string {
  try { return typeof v === "string" ? v : JSON.stringify(v ?? {}); }
  catch { return String(v); }
}

function isEventStream(resp: Response): boolean {
  const ct = resp.headers.get("content-type") ?? "";
  // `text/event-stream` covers OpenAI/Anthropic/Cohere/Gemini SSE;
  // `application/vnd.amazon.eventstream` is Bedrock's binary AWS event-stream
  // (`/invoke-with-response-stream`, `/converse-stream`). Both route into
  // `wrapStreamingResponse`; the parser selected by shape handles framing.
  return (
    ct.includes("text/event-stream") || ct.includes("application/vnd.amazon.eventstream")
  );
}

function randomUuid(): string {
  // crypto.randomUUID exists on Node 16+; the SDK targets >=18.
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 14)}`;
}

/**
 * Resolve the underlying (un-patched) fetch for sidecar calls so our own
 * `observe-prompt` POST doesn't recurse through the interceptor.
 */
function fetchOriginal(): typeof fetch {
  const g = globalThis as typeof globalThis & { fetch: PatchedFetch };
  const cur = g.fetch as PatchedFetch | undefined;
  if (cur && cur[ORIGINAL_TAG]) return cur[ORIGINAL_TAG] as typeof fetch;
  return fetch;
}

// ── deny short-circuit ─────────────────────────────────────────────────────

function shortCircuitDeny(
  match: HostMatch,
  reason: string,
  toolName?: string,
  toolArgs?: unknown,
): Response {
  const notice = makeBlockNoticeText(toolName ?? "request", safeStringify(toolArgs ?? {}), reason);
  if (match.shape === "bedrock-converse") {
    // Bedrock Converse non-streaming envelope. Anthropic-on-bedrock invoke
    // (`bedrock-invoke`) falls through to the anthropic-messages branch below
    // since those clients parse Anthropic message JSON.
    const body = {
      output: { message: { role: "assistant", content: [{ text: notice }] } },
      stopReason: "end_turn",
      usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
      },
    });
  }
  if (match.shape === "anthropic-messages" || match.shape === "bedrock-invoke") {
    const body = {
      id: `msg_agentum_deny_${Date.now()}`,
      type: "message",
      role: "assistant",
      model: "agentum-policy",
      content: [{ type: "text", text: notice }],
      stop_reason: "end_turn",
      usage: { input_tokens: 0, output_tokens: 0 },
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
      },
    });
  }
  if (match.shape === "gemini-generate") {
    // Mirror geminiRewrite in provider-extractors.ts: the denied functionCall
    // part becomes a plain text part and finishReason normalises to "STOP".
    const body = {
      candidates: [{
        content: { role: "model", parts: [{ text: notice }] },
        finishReason: "STOP",
      }],
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
      },
    });
  }
  if (match.shape === "cohere-chat") {
    // Mirror cohereRewrite in provider-extractors.ts (v2 envelope): the denied
    // tool_calls are dropped and the notice is appended as a text content block
    // with finish_reason normalised to "COMPLETE".
    const body = {
      id: `cohere-agentum-deny-${Date.now()}`,
      message: { role: "assistant", content: [{ type: "text", text: notice }] },
      finish_reason: "COMPLETE",
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: {
        "content-type": "application/json",
        "x-agentum-policy": "sdk-denied",
      },
    });
  }
  // OpenAI-shaped (chat.completions / responses fallback).
  const body = {
    id: `chatcmpl-agentum-deny-${Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "agentum-policy",
    choices: [{
      index: 0,
      message: { role: "assistant", content: notice },
      finish_reason: "stop",
    }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "x-agentum-policy": "sdk-denied",
    },
  });
}
