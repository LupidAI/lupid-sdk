/**
 * `agentum.init()` — top-level drop-in for TS/JS agents.
 *
 * Single line of integration:
 *
 *   import agentum from '@lupid/sdk';
 *   await agentum.init();
 *
 *   // ...later, anywhere in the app, vanilla SDK calls just work:
 *   const oai  = new OpenAI();
 *   const ant  = new Anthropic();
 *   await oai.chat.completions.create({...});       // monkeypatched
 *   await ant.messages.create({...});               // monkeypatched
 *
 * Behaviour:
 *   - Reads from env (or the matching option-bag key on `init({...})`):
 *       AGENTUM_BASE_URL          required — gateway URL (e.g. http://localhost:7071)
 *       AGENTUM_API_KEY           required — provisioned via `agentum keys create`
 *       AGENTUM_AGENT_NAME        required — stable identifier for this agent
 *       AGENTUM_AGENT_FRAMEWORK   optional — default "agentum-sdk"
 *       AGENTUM_DECLARED_TOOLS    optional — CSV of tool names declared at register
 *       AGENTUM_DEFAULT_SESSION_ID  optional — pin a default session_id (test/CI)
 *       AGENTUM_DEFAULT_USER_ID     optional — pin a default user_id for context
 *       AGENTUM_EXTRA_LLM_HOSTS     optional — comma/whitespace-separated extra
 *                                   LLM host patterns to classify+enforce
 *                                   (same syntax as built-ins, incl. `*.`/`.*.`
 *                                   wildcards). Merged with `init({ llmHosts })`.
 *   - Calls `ensureAgent` to resolve a stable agent_id.
 *   - Stores a process-level singleton holding the resolved config + a
 *     shared `CedarToolCallClient` evaluator.
 *   - Dynamically imports `openai` and `@anthropic-ai/sdk`; if either is
 *     installed in the importing project, monkeypatches its respective
 *     `create` method.
 *   - Idempotent: repeat calls return the same singleton (and refresh
 *     the evaluator thunk on the patched prototypes).
 */

import { resolveAnonymousClientId } from "./anonymous-id.js";
import type { PromptCaptureMode } from "./types.js";
import {
  extractBindingMode,
  runPerModeScan,
  type BindingMode,
} from "./binding/index.js";
import { ensureAgent, type EnsureAgentResult } from "./ensure-agent.js";
import { CedarToolCallClient } from "./evaluation/cedar-client.js";
import { AdminHttpClient } from "./admin/http.js";
import {
  discoverManifest,
  loadAndParse,
  parseAndValidate,
  getLiveSchema,
  reconcileVersions,
  _setActiveSchema,
  InitError,
  SchemaSubscriber,
  __resetSchemaSubscriberForTest,
  type TenantSchema,
} from "./manifest/index.js";
import {
  installOpenAIPatch,
  uninstallOpenAIPatch,
} from "./instrumentation/openai-patch.js";
import {
  installAnthropicPatch,
  uninstallAnthropicPatch,
} from "./instrumentation/anthropic-patch.js";
import {
  installMcpStdioPatch,
  uninstallMcpStdioPatch,
} from "./instrumentation/mcp-stdio-patch.js";
import { installFetchInterceptor } from "./instrumentation/fetch-interceptor.js";
import { resolvePromptCaptureMode } from "./instrumentation/prompt-capture.js";
import { installUndiciDispatcherInterceptor } from "./instrumentation/undici-dispatcher-interceptor.js";
import {
  HostRegistry,
  _setActiveHostRegistry,
  parseExtraLlmHosts,
} from "./instrumentation/host-registry.js";
import { setAgentumDefaults, clearAgentumDefaults } from "./instrumentation/context.js";
import {
  loadPiiSecrets,
  setPiiSecretsForModule,
  assertSecretsForActiveSchema,
  _resetPiiSecretsForTests,
} from "./pii/secrets.js";
import { parsePiiManifestBlock } from "./pii/manifest-block.js";
import {
  _setActivePiiBlock,
  _resetActivePiiBlockForTests,
} from "./pii/pii-state.js";
import { compileFieldRuleTrie } from "./pii/field-rule-trie.js";
import {
  _setActiveFieldRuleTrie,
  _resetActiveFieldRuleTrieForTests,
} from "./pii/trie-state.js";
import { compileScanner } from "./pii/text-scanner.js";
import {
  _setActiveTextScanner,
  _resetActiveTextScannerForTests,
} from "./pii/scanner-state.js";

/**
 * Cross-runtime UUID generator. Prefers Web Crypto (`globalThis.crypto.randomUUID`,
 * available on Node ≥19, Cloudflare Workers, Vercel Edge, and modern browsers).
 * Falls back to a dynamic `await import("node:crypto")` only when Web Crypto is
 * absent (Node ≤18.18 without `--experimental-global-webcrypto`). The dynamic
 * specifier is a literal string, which esbuild leaves as a runtime require, so
 * it does NOT appear in the static module graph of `dist/index.mjs` — keeping
 * the universal entry edge-runtime safe.
 */
async function crossRuntimeUUID(): Promise<string> {
  const wc = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto?.randomUUID?.();
  if (wc) return wc;
  const { randomUUID } = await import("node:crypto");
  return randomUUID();
}

export interface InitOptions {
  baseUrl?: string;
  apiKey?: string;
  agentName?: string;
  framework?: string;
  declaredTools?: string | string[];
  /** Override timeout for tool-call evaluation (default 200ms). */
  evaluationTimeoutMs?: number;
  /** Default `"deny"` — fail closed on transport failure. */
  failMode?: "deny" | "allow";
  /** Skip auto-monkeypatching (e.g. for callers that only want
   *  `ensureAgent` + a configured `CedarToolCallClient`). */
  disableAutoPatch?: boolean;
  /** Skip the global `fetch` interceptor; the prototype patches still run. */
  disableFetchInterceptor?: boolean;
  /** Skip the undici global-dispatcher interceptor (R24). The dispatcher
   *  plane catches Next.js route-handler traffic the `fetch` wrapper misses
   *  (G18a). Defaults to false on Node; always a no-op on edge/browser. */
  disableUndiciDispatcherInterceptor?: boolean;
  /** PDP reverse-proxy base URL (R22/R24). When set (or via
   *  `AGENTUM_PDP_PROXY_URL`), the undici-dispatcher plane rewrites
   *  known-LLM-host traffic to `${url}/proxy/<provider>/<path>` and skips
   *  in-process evaluation — the PDP proxy is the enforcement point. Distinct
   *  from `pdpUrl` (the decision plane, ADR-0017). e.g.
   *  `http://127.0.0.1:7081`.
   *
   *  **Coverage is NOT universal.** The R22 proxy has native upstreams for
   *  `openai`, `anthropic`, `deepseek`, `cohere` and `gemini`, so only those
   *  providers are routed through the proxy. **Bedrock is excluded**: its
   *  SigV4 request signing is bound to the original host, so proxy-rewriting
   *  the request would invalidate the signature. Bedrock traffic continues to
   *  be governed in-process by the fetch / node:http interceptors. */
  pdpProxyUrl?: string;
  /** Skip the Node `http`/`https.request` interceptor.
   *  Defaults to false on Node, true elsewhere (browser/edge). */
  disableNodeHttpInterceptor?: boolean;
  /** Extra LLM hosts to merge into the default registry. */
  llmHosts?: readonly string[];
  /**
   * **Legacy** — capture and POST prompt content to `/sdk/observe-prompt`.
   * Retained for back-compat. `capturePrompts === false` ⇒
   * `promptCaptureMode: "off"`; otherwise `promptCaptureMode` is honored.
   * Prefer {@link InitOptions.promptCaptureMode}.
   */
  capturePrompts?: boolean;
  /**
   * R40 — how the observe-prompt sidecar treats the **raw sensitive content**
   * (`messages` + `tools_advertised`). Actionable telemetry (decision, tool
   * names, dims, risk, event type) always flows regardless. Default
   * `"masked"`: the S5 PII pipeline scrubs prompt/tool-arg content before it
   * leaves the agent (a no-op when no PII config is present — masked mode still
   * sends content). `"raw"` is an explicit opt-in to send unmasked content
   * (logs a one-time warning at init). `"off"` is the only no-send mode.
   * Legacy `capturePrompts === false` overrides this to `"off"`.
   */
  promptCaptureMode?: PromptCaptureMode;
  /** Timeout (ms) for the `observe-prompt` POST. Default 1500ms. Increase
   *  on high-latency networks where the previous hardcoded 1500ms was
   *  silently dropping audit events. */
  observePromptTimeoutMs?: number;
  /** Max retries for the `observe-prompt` POST on transient failure
   *  (network error / 5xx). Default 1. Set 0 to keep the legacy
   *  fire-and-forget behaviour. */
  observePromptMaxRetries?: number;
  /** Local-PDP sidecar URL. **Opt-in** per ADR-0017: unset or empty
   *  disables PDP routing entirely (all decisions go to central, Mode A).
   *  Set to a TCP URL (`http://127.0.0.1:7080`) or a UDS URL
   *  (`unix:///run/agentum/pdp.sock`) to enable. The URL's presence is the
   *  single toggle — there is no separate `AGENTUM_PDP_ENABLED` flag. */
  pdpUrl?: string;
  /** Bearer token sent on PDP `/v1/authorize{,/batch}` requests. Required
   *  unless the PDP was started with `--allow-unauthenticated`. */
  pdpServiceToken?: string;
  /** Test-injection: process.env clone. */
  env?: Record<string, string | undefined>;
  /** Test-injection. */
  fetchImpl?: typeof fetch;
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Optional process-default anonymous client ID. Stored on the runtime so
   *  `startSession` callers without a per-call override can fall back to it.
   *  Almost always you want auto-resolution via the tiered ladder in
   *  `anonymous-id.ts`; this is the escape hatch for apps that already track
   *  a stable anonymous identity (e.g. a client-side cookie they want to
   *  reuse). The backend prefixes `anon:` on receipt — do not prefix here. */
  anonymousClientId?: string;
  /**
   * Optional path to a local `*.lupid.yaml` tenant-schema file. Despite the
   * `.lupid.yaml` extension (which Spec 2 reserves for the full AgentManifest),
   * the SDK today only consumes the **tenant-schema** shape from this file
   * (Spec 1 — `version`, `dimensions`, `scoping_dimension`). A full Spec-2
   * AgentManifest is processed server-side via `lupid revision push`, not
   * here.
   *
   * When unset, the SDK walks the 4-step discovery order:
   *   1. this option
   *   2. `LUPID_MANIFEST_PATH` env var
   *   3. unique `./*.lupid.yaml` in cwd
   *   4. `./lupid/agent.yaml` fallback
   *
   * NOTE: there is intentionally no `tenantId` override on `InitOptions` —
   * `tenantId` is authoritative from `ensureAgent`. An init-time override
   * would let a misconfigured caller silently push schemas/events against
   * the wrong tenant.
   */
  manifest?: string;
  /**
   * Policy for when `agentum.init()` detects that `openai` or
   * `@anthropic-ai/sdk` was imported before init resolves.
   *
   * Prototype patching applied by `init()` is retroactive for the
   * common case: any instance constructed before init still resolves
   * its method via the prototype chain and hits the patched function.
   * The remaining bypass surface is narrow — a method reference
   * explicitly captured before init (`const fn = c.foo.bar.bind(c)`)
   * will permanently invoke the unpatched function.
   *
   * Modes:
   *   - `"warn"` (default) — log a warning at init time so operators
   *     notice; preserves the original behaviour.
   *   - `"throw"` — reject `init()` with `AgentumInitError` if any
   *     at-risk modules are already in `require.cache`. The fail-CLOSED
   *     posture; recommended for production deployments where
   *     governance must be provably installed before any client code
   *     runs.
   *   - `"ignore"` — silence the detection entirely (no warning, no
   *     throw). For environments where the false-positive rate is too
   *     high to tolerate.
   */
  requirePreInitImport?: "warn" | "throw" | "ignore";
  /**
   * Test-injection only: a synthetic `require.cache` shape. Live runs
   * walk `globalThis.require.cache` themselves; tests pass a synthetic
   * map so the pre-init detection can be exercised under Jest where
   * `globalThis.require` is unavailable.
   * @internal
   */
  _requireCacheForTest?: Record<string, unknown>;
}

/**
 * Thrown by `init()` in `requirePreInitImport: "throw"` mode when at
 * least one at-risk LLM SDK module is already present in the runtime's
 * require cache at init time. The error message includes the detected
 * paths so the operator can move `await agentum.init()` to the right
 * place in their entrypoint.
 */
export class AgentumInitError extends Error {
  constructor(
    message: string,
    public readonly detectedModules: readonly string[],
  ) {
    super(message);
    this.name = "AgentumInitError";
  }
}

export interface AgentumRuntime {
  agentId:    string;
  tenantId:   string;
  baseUrl:    string;
  apiKey:     string;
  agentName:  string;
  framework:  string;
  /** Process-default session_id used when no `withAgentumContext` wrapper is
   *  active. Threaded into observe-prompt and evaluate-tool-call so the
   *  Sessions UI populates for SDK-direct agents that don't manage their own
   *  conversation ids. */
  defaultSessionId: string;
  evaluator:  CedarToolCallClient;
  ensureResult: EnsureAgentResult;
  patchedOpenAI: boolean;
  patchedAnthropic: boolean;
  patchedMcpStdio: boolean;
  patchedFetch: boolean;
  patchedNodeHttp: boolean;
  /** True when the undici global-dispatcher interceptor is installed (R24). */
  patchedUndiciDispatcher: boolean;
  /** Tear-down hook for the fetch interceptor. */
  uninstallFetchInterceptor?: () => void;
  /** Tear-down hook for the undici dispatcher interceptor. */
  uninstallUndiciDispatcherInterceptor?: () => void;
  /** Tear-down hook for the Node http/https interceptor. */
  uninstallNodeHttpInterceptor?: () => void;
  /** Resolved anonymous client ID for client-side contexts. Threaded into
   *  `AgentumClient.startSession` as the fallback when no per-call override
   *  is provided. Server-SDK contexts leave this undefined and pass the
   *  value per-request via `ConnectOptions.anonymousClientId`. */
  anonymousClientId?: string;
  /** Long-lived SSE subscriber for schema-install events. Attached so a
   *  future shutdown hook can call `.close()`; today no graceful-shutdown
   *  path exists in the SDK, so the field is informational and the
   *  subscriber lives until process exit. */
  schemaSubscriber?: SchemaSubscriber;
  /** The resolved binding mode for this agent. Defaults to
   *  `"orchestrator"` when the manifest is absent or does not declare
   *  the field. MVP-3 modes (`per_subagent`, `acl_edge`,
   *  `actor_per_instance`) fail-fast at init via
   *  `BindingModeNotYetSupportedError` and never appear here. */
  bindingMode: BindingMode;
}

let SINGLETON: AgentumRuntime | undefined;
let IN_FLIGHT: Promise<AgentumRuntime> | undefined;

/**
 * Idempotent. Returns the live runtime singleton; concurrent callers
 * coalesce on the in-flight promise.
 */
export async function init(opts: InitOptions = {}): Promise<AgentumRuntime> {
  if (SINGLETON) {
    // Refresh evaluator thunk on patched prototypes so a re-init under
    // a new key still routes through the new evaluator.
    return SINGLETON;
  }
  if (IN_FLIGHT) return IN_FLIGHT;

  const env = opts.env ?? process.env;
  const baseUrl   = opts.baseUrl   ?? env["AGENTUM_BASE_URL"];
  const apiKey    = opts.apiKey    ?? env["AGENTUM_API_KEY"];
  const agentName = opts.agentName ?? env["AGENTUM_AGENT_NAME"];
  const framework = opts.framework ?? env["AGENTUM_AGENT_FRAMEWORK"] ?? "agentum-sdk";
  const declaredTools =
    opts.declaredTools ?? env["AGENTUM_DECLARED_TOOLS"];
  const logger = opts.logger ?? console;

  // Extra LLM hosts: programmatic `init({ llmHosts })` merged with the
  // operator-configurable `AGENTUM_EXTRA_LLM_HOSTS` env var. The SDK ships no
  // company-specific hosts in `DEFAULT_LLM_HOSTS`; deployments add their own here.
  const llmHosts = [
    ...(opts.llmHosts ?? []),
    ...parseExtraLlmHosts(env["AGENTUM_EXTRA_LLM_HOSTS"]),
  ];

  // R40 — resolve the observe-prompt capture mode once. Precedence:
  // legacy `capturePrompts === false` ⇒ "off"; else explicit
  // `promptCaptureMode` (option or AGENTUM_PROMPT_CAPTURE_MODE env);
  // default "masked". An unrecognized env value is ignored (falls back to
  // the option / default) with a warn — never silently downgrades to raw.
  const envCaptureMode = env["AGENTUM_PROMPT_CAPTURE_MODE"];
  let optionCaptureMode = opts.promptCaptureMode;
  if (optionCaptureMode === undefined && envCaptureMode !== undefined) {
    if (
      envCaptureMode === "masked" ||
      envCaptureMode === "raw" ||
      envCaptureMode === "off"
    ) {
      optionCaptureMode = envCaptureMode;
    } else {
      logger.warn(
        `[agentum] ignoring invalid AGENTUM_PROMPT_CAPTURE_MODE=${JSON.stringify(
          envCaptureMode,
        )} (expected "masked" | "raw" | "off"); using default`,
      );
    }
  }
  const captureModeOpts: { capturePrompts?: boolean; promptCaptureMode?: PromptCaptureMode } = {};
  if (opts.capturePrompts !== undefined) captureModeOpts.capturePrompts = opts.capturePrompts;
  if (optionCaptureMode !== undefined) captureModeOpts.promptCaptureMode = optionCaptureMode;
  const promptCaptureMode = resolvePromptCaptureMode(captureModeOpts);
  if (promptCaptureMode === "raw") {
    // Explicit opt-in: raw prompt/tool-arg content leaves the agent
    // unmasked. Warn once at init so this is never a silent default.
    logger.warn(
      "[agentum] promptCaptureMode=\"raw\": raw prompt + tool-arg content " +
        "will be sent to central UNMASKED. PII is NOT scrubbed in this mode.",
    );
  }

  // PDP reverse-proxy plane (R22/R24). Distinct from the decision plane
  // (`AGENTUM_PDP_URL`). When set, the undici-dispatcher interceptor rewrites
  // known-LLM-host traffic to the PDP proxy and skips in-process evaluation.
  // Unset/empty → in-process pre-flight in the dispatcher plane.
  const pdpProxyUrlRaw = opts.pdpProxyUrl ?? env["AGENTUM_PDP_PROXY_URL"] ?? "";
  const pdpProxyUrl = pdpProxyUrlRaw === "" ? undefined : pdpProxyUrlRaw;

  // Local-PDP wiring. PDP is **opt-in** per ADR-0017
  // (`docs/decisions/ADR-0017-pdp-default-opt-in.md`): the presence of
  // `AGENTUM_PDP_URL` (or `opts.pdpUrl`) is the single toggle. Unset or
  // empty → no PDP, all decisions go straight to central (Mode A). Set to
  // a TCP URL (e.g. `http://127.0.0.1:7080`) to route through a loopback
  // PDP sidecar — `AGENTUM_PDP_SERVICE_TOKEN` is required on the TCP path.
  // Set to `unix:///run/agentum/pdp.sock` to opt into UDS transport (peer-
  // credential auth via L08, service token ignored).
  //
  // No separate `AGENTUM_PDP_ENABLED` flag exists — see ADR-0017 §Decision
  // for why URL-presence is the canonical truth (two flags for one decision
  // invites a bug class where they disagree).
  const pdpUrlRaw = opts.pdpUrl ?? env["AGENTUM_PDP_URL"] ?? "";
  let pdpUrl = pdpUrlRaw === "" ? undefined : pdpUrlRaw;
  const pdpServiceToken = opts.pdpServiceToken ?? env["AGENTUM_PDP_SERVICE_TOKEN"];
  // If pdpUrl is `unix://`, build a UDS fetch shim and inject it as
  // `fetchImpl` on the CedarToolCallClient. The shim is lazy-loaded so
  // `cedar-client.ts` never reaches `node:http` directly (edge safety).
  let pdpFetchImpl: typeof fetch | undefined;
  if (pdpUrl && pdpUrl.startsWith("unix://")) {
    const socketPath = pdpUrl.slice("unix://".length);
    if (!socketPath.startsWith("/")) {
      logger.error(
        `[agentum] AGENTUM_PDP_URL=unix:// requires an absolute socket path ` +
        `(e.g. unix:///run/agentum/pdp.sock). Got: ${pdpUrl}. PDP disabled; ` +
        `falling back to central evaluation for this process.`,
      );
      // Soft-fail: keep init alive but disable the PDP path so the SDK
      // still boots. Misconfig surfaces as "decisionSource: central" in
      // audit until the operator fixes the URL.
      pdpUrl = undefined;
    } else {
      try {
        const { makeUdsFetch } = await import("./evaluation/uds-fetch.js");
        pdpFetchImpl = await makeUdsFetch(socketPath);
      } catch (err) {
        // Fail-closed at the init boundary: if we can't construct the UDS
        // shim (e.g. edge runtime where `process.versions.node` is
        // undefined), surface the error rather than silently downgrading
        // to TCP. The operator asked for unix:// — give them a loud signal.
        logger.error(
          `[agentum] failed to build UDS fetch shim for ${pdpUrl}: ${(err as Error).message}. ` +
          `PDP disabled; falling back to central evaluation for this process.`,
        );
        pdpUrl = undefined;
      }
    }
  }
  if (pdpUrl && !pdpServiceToken && !pdpUrl.startsWith("unix://")) {
    // UDS path is gated by peer-cred auth, not the service token — so the
    // warning only applies on the TCP path where a missing token means
    // certain 401 from the PDP auth middleware.
    logger.warn(
      "[agentum] AGENTUM_PDP_URL is set but AGENTUM_PDP_SERVICE_TOKEN is not. " +
      "If your PDP requires a token, requests will fail with 401 (fail-closed). " +
      "Pass --allow-unauthenticated to the PDP for local dev only.",
    );
  }

  const HINT =
    "See https://github.com/lupidai/lupid-sdk/tree/main/packages/sdk#environment-variables " +
    "for setup. Programmatic callers can pass these as options to init({...}).";

  if (!baseUrl) {
    throw new Error(
      "agentum.init: AGENTUM_BASE_URL is required. " +
      "Self-hosted: point at your gateway (e.g. http://localhost:7071). " +
      "Hosted Agentum Cloud is not yet GA. " + HINT,
    );
  }
  if (!apiKey) {
    throw new Error(
      "agentum.init: AGENTUM_API_KEY is required. " +
      "Ask an administrator to mint one (`agentum admin api-keys mint " +
      "--email <your-email> --agent <agent-name>`) or provision via the " +
      "dashboard under Settings → API Keys. " + HINT,
    );
  }
  if (!agentName) {
    throw new Error(
      "agentum.init: AGENTUM_AGENT_NAME is required. " +
      "Pick a stable identifier for this agent (e.g. \"checkout-bot-prod\"). " +
      "It will be auto-registered on first call via /sdk/register. " + HINT,
    );
  }

  // Pre-init bypass detection. Prototype patches applied below modify the
  // OpenAI / Anthropic class prototypes — that's retroactive for any
  // instance that resolves its method via the chain. The narrow bypass
  // surface is an explicitly captured method reference
  // (`const fn = c.foo.bar.bind(c)` before init); the detection here
  // surfaces the at-risk module being loaded so operators notice.
  //
  // CommonJS require.cache exposes resolved module paths; ESM imports
  // via tsx / ts-node populate the same cache because Node's loader
  // collapses both into the underlying module record. Pure-ESM
  // environments without a CJS bridge won't expose this — there we
  // silently skip rather than false-positive.
  const preInitMode = opts.requirePreInitImport ?? "warn";
  if (preInitMode !== "ignore") {
    const flagged = detectPreInitImports(opts._requireCacheForTest);
    if (flagged.length > 0) {
      const message = preInitMessage(flagged);
      if (preInitMode === "throw") {
        // Fail-CLOSED: do NOT set IN_FLIGHT — rejecting here leaves the
        // singleton state untouched so a corrected entrypoint can call
        // init() again cleanly.
        throw new AgentumInitError(`[agentum] ${message}`, flagged);
      }
      // Default: warn loudly.
      logger.warn(`[agentum] WARNING: ${message}`);
    }
  }

  IN_FLIGHT = (async () => {
    // Per-mode init scan.
    //
    // Read the local *.lupid.yaml ONCE up front so the dispatcher can
    // fail-CLOSED on MVP-3 binding modes (`per_subagent`, `acl_edge`,
    // `actor_per_instance`) BEFORE any network call — no JWKS handshake,
    // no `/sdk/register` round-trip, no patch install. The raw parsed
    // value is reused by the schema pipeline below so we do not re-read
    // the file. Manifests without `spec.runtime.binding_mode` default to
    // `"orchestrator"` with a one-line warn (legacy manifests stay
    // bootable).
    const manifestPath = await discoverManifest({
      ...(opts.manifest !== undefined ? { manifest: opts.manifest } : {}),
      ...(env ? { env } : {}),
    });
    let rawManifest: unknown = null;
    if (manifestPath) {
      rawManifest = await loadAndParse(manifestPath);
    }
    const declaredBindingMode = extractBindingMode(rawManifest);
    const scan = runPerModeScan(declaredBindingMode, logger);
    const bindingMode = scan.bindingMode;

    const ensureOpts: Parameters<typeof ensureAgent>[0] = {
      baseUrl, apiKey, name: agentName, framework, logger,
    };
    if (declaredTools !== undefined) ensureOpts.declaredTools = declaredTools;
    if (opts.fetchImpl) ensureOpts.fetchImpl = opts.fetchImpl;
    const ensureResult = await ensureAgent(ensureOpts);

    // Manifest discovery → parse → validate → live fetch → reconcile.
    // Runs after `ensureAgent` (tenantId is authoritative from that call) and
    // before evaluator construction (the active schema is read via module
    // state).
    //
    // The `AdminHttpClient` constructor takes a config bag matching the public
    // `AgentumClientConfig` shape (`admin/http.ts:71-99`); the constructor key
    // is `fetch` (not `fetchImpl`).
    const adminHttp = new AdminHttpClient({
      baseUrl,
      apiKey,
      ...(opts.fetchImpl ? { fetch: opts.fetchImpl } : {}),
    });

    let localSchema: TenantSchema | null = null;
    if (rawManifest !== null) {
      // Validation / parse errors are caller-actionable: let them propagate
      // rather than silently degrading to live-only. The error type is
      // already `ManifestError` / `ManifestValidationError`.
      localSchema = parseAndValidate(rawManifest);
    }

    let liveSchema: TenantSchema | null = null;
    try {
      liveSchema = await getLiveSchema(adminHttp, ensureResult.agentId);
    } catch (err) {
      if (!localSchema) {
        throw new InitError(
          `no local manifest and live schema fetch failed: ${(err as Error).message}`,
        );
      }
      logger.warn(
        `[agentum] live schema fetch failed; booting against local manifest: ` +
          `${(err as Error).message}`,
      );
      liveSchema = null;
    }

    const activeSchema = reconcileVersions(localSchema, liveSchema, logger);
    _setActiveSchema(activeSchema);

    // Y02 — parse the manifest's `pii:` block (field rules + text
    // scanners) and publish via `_setActivePiiBlock`. Runs BEFORE the
    // PII secrets check so `assertSecretsForActiveSchema` can also gate
    // on field-rule modes (e.g. `mode: hash` without `LUPID_PII_HASH_SECRET`
    // throws). Invalid shape → `PiiManifestValidationError` propagates
    // out of init() — fail-CLOSED at the init boundary rather than
    // silently disabling masking under a typo.
    //
    // Manifests with no `pii:` section (or a `null` value) yield an
    // empty `PiiManifestBlock`, so legacy manifests continue to boot.
    const rawManifestObj =
      rawManifest !== null && typeof rawManifest === "object" && !Array.isArray(rawManifest)
        ? (rawManifest as Record<string, unknown>)
        : null;
    const piiBlock = parsePiiManifestBlock(rawManifestObj?.["pii"]);
    _setActivePiiBlock(piiBlock);

    // Y03 Sub-C — compile the validated field rules into the runtime
    // trie and publish via `_setActiveFieldRuleTrie`. Runs immediately
    // after the manifest is published so Y05's audit pipeline
    // (`ingestAuditEvent`) can consume the trie on first emit. Empty
    // input compiles to the empty trie, which `applyTrie` short-circuits
    // on — legacy manifests with no `pii.field_rules` stay free.
    _setActiveFieldRuleTrie(
      compileFieldRuleTrie(piiBlock.field_rules ?? []),
    );

    // Y04 — compile the text scanner (Layer 2) from the manifest's first
    // `text_scanners[]` entry and publish via `_setActiveTextScanner`.
    // The spec accepts an array of stanzas; v1 consumes only the first
    // entry (multi-scanner stacking is v1.1). A missing `text_scanners`
    // section yields the default-enabled scanner with all 14 canonical
    // patterns — fail-CLOSED by default, operators opt out explicitly
    // via `{ enabled: false }` in the manifest.
    _setActiveTextScanner(
      compileScanner(piiBlock.text_scanners?.[0]),
    );
    if ((piiBlock.text_scanners?.length ?? 0) > 1) {
      console.warn(
        `[agentum] pii.text_scanners has ${piiBlock.text_scanners!.length} entries; ` +
        "v1 consumes only index 0. Multi-scanner stacking is planned for v1.1.",
      );
    }

    // PII secrets loader. Runs after the manifest is live so
    // `assertSecretsForActiveSchema` can scan the active schema's
    // dimensions, and BEFORE any patch installation so a missing-secret
    // throw aborts before observability is partially wired. Fail-CLOSED:
    // when the manifest declares `pii: "hash"` or `pii: "tokenize"` on
    // any dimension and the corresponding env var is missing / wrong
    // length, `assertSecretsForActiveSchema` throws and init aborts.
    const piiSecrets = loadPiiSecrets(env);
    setPiiSecretsForModule(piiSecrets);
    assertSecretsForActiveSchema();

    // Stable default session id for this process. Threaded into the
    // context-fallback chain so SDK-direct calls without an ALS wrapper
    // still carry a session_id — which is what the server requires to
    // upsert into `sessions` (see crates/agentum-api/src/routes/sdk.rs:
    // upsert_sdk_session). Env override lets test/CI pin a known id.
    const defaultSessionId =
      env["AGENTUM_DEFAULT_SESSION_ID"] ?? `sdk:${await crossRuntimeUUID()}`;
    const defaultUserId = env["AGENTUM_DEFAULT_USER_ID"];
    setAgentumDefaults({
      sessionId: defaultSessionId,
      ...(defaultUserId ? { userId: defaultUserId } : {}),
    });

    const evaluatorOpts: ConstructorParameters<typeof CedarToolCallClient>[0] = {
      baseUrl,
      apiKey,
      agentId: ensureResult.agentId,
      // Belt-and-suspenders: interceptors already default to deny; pin it explicitly.
      failMode: opts.failMode ?? "deny",
      logger,
    };
    if (opts.evaluationTimeoutMs !== undefined) {
      evaluatorOpts.timeoutMs = opts.evaluationTimeoutMs;
    }
    if (opts.observePromptTimeoutMs !== undefined) {
      evaluatorOpts.observePromptTimeoutMs = opts.observePromptTimeoutMs;
    }
    if (opts.observePromptMaxRetries !== undefined) {
      evaluatorOpts.observePromptMaxRetries = opts.observePromptMaxRetries;
    }
    if (pdpUrl !== undefined) {
      evaluatorOpts.pdpUrl = pdpUrl;
    }
    if (pdpServiceToken !== undefined) {
      evaluatorOpts.pdpServiceToken = pdpServiceToken;
    }
    // When the UDS shim is in play we want PDP traffic (and only PDP
    // traffic) to use it. The CedarToolCallClient uses `fetchImpl` for ALL
    // outbound HTTP though (central + audit + PDP), so wrap the shim with a
    // dispatcher that routes `unix://` URLs to the UDS shim and everything
    // else to the regular fetch (or the test-injected `opts.fetchImpl`).
    if (pdpFetchImpl) {
      const fallback = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
      const dispatcher: typeof fetch = ((url: string | URL, init?: RequestInit) => {
        const u = typeof url === "string" ? url : url.toString();
        return u.startsWith("unix://")
          ? pdpFetchImpl!(url, init)
          : fallback(url, init);
      }) as typeof fetch;
      evaluatorOpts.fetchImpl = dispatcher;
    } else if (opts.fetchImpl) {
      evaluatorOpts.fetchImpl = opts.fetchImpl;
    }
    const evaluator = new CedarToolCallClient(evaluatorOpts);

    // Open a long-lived SSE connection so subsequent schema installs
    // (POST /agents/:agent_id/schema → broadcast) propagate to this
    // process within ~100ms instead of the 60s ScopeIndexPopulator tick
    // floor. The schema stream is per-agent. W05 extends the subscriber
    // to also subscribe to the tenant-wide `/api/v1/policy/stream` and
    // invalidate `evaluator`'s decision cache on `policy` /
    // `capability_effective_set_changed` /
    // `capability_set_invalidate_all_scopes` events. Node-only —
    // non-Node runtimes silently no-op inside SchemaSubscriber.start().
    // Start failures NEVER throw out of init(); the SDK keeps booting
    // without push-based reload (the init-time getLiveSchema + the
    // ScopeIndexPopulator polling path remain as belt-and-suspenders).
    const schemaSubscriber = new SchemaSubscriber();
    const subscriberStart = schemaSubscriber
      .start({
        baseUrl,
        tenantId: ensureResult.tenantId,
        agentId: ensureResult.agentId,
        adminHttp,
        localSchema: activeSchema,
        logger,
        cedarClient: evaluator,
      })
      .catch((err: unknown) => {
        logger.warn(
          `[agentum] schema subscriber start failed: ${
            (err as Error).message
          }`,
        );
      });
    // Don't block init on the subscriber connect — it lives for the
    // lifetime of the process and the SDK is functional without it.
    void subscriberStart;

    const getEvaluator = (): CedarToolCallClient | undefined =>
      SINGLETON?.evaluator;

    let patchedOpenAI = false;
    let patchedAnthropic = false;
    let patchedMcpStdio = false;
    let patchedFetch = false;
    let patchedNodeHttp = false;
    let patchedUndiciDispatcher = false;
    let uninstallFetchInterceptor: (() => void) | undefined;
    let uninstallNodeHttpInterceptor: (() => void) | undefined;
    let uninstallUndiciDispatcherInterceptor: (() => void) | undefined;
    if (!opts.disableAutoPatch) {
      patchedOpenAI = await installOpenAIPatch(getEvaluator);
      patchedAnthropic = await installAnthropicPatch(getEvaluator);
      // Stdio MCPs never traverse HTTPS_PROXY — patch them directly. Quiet
      // no-op if `@modelcontextprotocol/sdk` is not installed.
      patchedMcpStdio = installMcpStdioPatch({
        gateway: baseUrl,
        apiKey,
        agentId: ensureResult.agentId,
        // CL-2 — thread the shared evaluator so MCP enforcement routes
        // PDP-first-with-central-fallback (same path as LLM tool calls).
        // Thunk-based so the patch picks up the live SINGLETON.evaluator
        // after this IIFE publishes it.
        getEvaluator,
      });
      if (!opts.disableFetchInterceptor) {
        const hosts = new HostRegistry(llmHosts);
        _setActiveHostRegistry(hosts);
        const interceptorOpts: Parameters<typeof installFetchInterceptor>[0] = {
          runtime: { baseUrl, apiKey, evaluator },
          agentId: ensureResult.agentId,
          hosts,
          failMode: opts.failMode ?? "deny",
          promptCaptureMode,
          ...(opts.observePromptTimeoutMs !== undefined
            ? { observePromptTimeoutMs: opts.observePromptTimeoutMs }
            : {}),
          ...(opts.observePromptMaxRetries !== undefined
            ? { observePromptMaxRetries: opts.observePromptMaxRetries }
            : {}),
          // PDPC-A4 — thread the R22 reverse-proxy origin so the fetch plane
          // SKIPS in-process vault resolution for R22-bound requests (R22
          // resolves `agentum://SECRET/<lease>` out-of-process before
          // forwarding upstream).
          ...(pdpProxyUrl !== undefined ? { pdpProxyUrl } : {}),
          logger,
        };
        uninstallFetchInterceptor = installFetchInterceptor(interceptorOpts);
        patchedFetch = true;
      }
      // undici global-dispatcher interception (R24, fixes G18a). Catches
      // Next.js route-handler traffic the `globalThis.fetch` wrap misses
      // because route handlers run with a different `fetch` binding while the
      // undici global dispatcher is shared process-wide. Defense in depth —
      // the fetch + node:http planes stay installed and the dispatcher plane
      // exempts the SDK's own endpoints by destination. No-op on edge/browser.
      if (!opts.disableUndiciDispatcherInterceptor) {
        try {
          const undiciHosts = new HostRegistry(llmHosts);
          const undiciOpts: Parameters<typeof installUndiciDispatcherInterceptor>[0] = {
            runtime: { baseUrl, apiKey, evaluator },
            agentId: ensureResult.agentId,
            hosts: undiciHosts,
            failMode: opts.failMode ?? "deny",
            logger,
            ...(pdpProxyUrl !== undefined ? { pdpProxyUrl } : {}),
          };
          uninstallUndiciDispatcherInterceptor =
            installUndiciDispatcherInterceptor(undiciOpts);
          patchedUndiciDispatcher = true;
        } catch (err) {
          logger.warn(
            `[agentum] undici dispatcher interceptor install failed: ${(err as Error).message}`,
          );
        }
      }
      // Node-only http/https.request interception.
      // Bundler-proof: hits node:http and node:https built-ins which Node
      // never bundles. Catches openai@4 -> node-fetch -> http.request,
      // anthropic-sdk on Node, axios, got, superagent, direct
      // ClientRequest users — every legacy SDK-shim path the fetch
      // wrapper misses. Skipped on browser/edge where the modules don't
      // exist.
      const isNode =
        typeof process !== "undefined" && Boolean((process as { versions?: { node?: string } }).versions?.node);
      if (isNode && !opts.disableNodeHttpInterceptor) {
        const hosts = new HostRegistry(llmHosts);
        // We may have already created a registry above; re-using one would
        // pin both wrappers to the same instance (so addLlmHosts() applies
        // to both). Cheap to construct fresh either way.
        // Lazy-load the node-http interceptor: it transitively imports
        // `node:module`/`node:http`/`node:https`/`node:stream`, which would
        // otherwise pull static `node:*` imports into the universal
        // `dist/index.mjs` and break edge runtimes.
        try {
          const { installNodeHttpInterceptor } = await import(
            "./instrumentation/node-http-interceptor.js"
          );
          const nodeOpts: Parameters<typeof installNodeHttpInterceptor>[0] = {
            runtime: { baseUrl, apiKey, evaluator },
            agentId: ensureResult.agentId,
            hosts,
            ...(pdpProxyUrl !== undefined ? { pdpProxyUrl } : {}),
            failMode: opts.failMode ?? "deny",
            promptCaptureMode,
            ...(opts.observePromptTimeoutMs !== undefined
              ? { observePromptTimeoutMs: opts.observePromptTimeoutMs }
              : {}),
            ...(opts.observePromptMaxRetries !== undefined
              ? { observePromptMaxRetries: opts.observePromptMaxRetries }
              : {}),
            logger,
          };
          uninstallNodeHttpInterceptor = await installNodeHttpInterceptor(nodeOpts);
          patchedNodeHttp = true;
        } catch (err) {
          logger.warn(
            `[agentum] node-http interceptor install failed: ${(err as Error).message}`,
          );
        }
      }
    }

    // Resolve anonymous client ID once at init for client-side contexts
    // (browser localStorage / CLI ~/.config/agentum/anon_id). In server SDK
    // contexts this resolves to undefined and the application must pass
    // anonymousClientId per-request via ConnectOptions instead.
    const resolvedAnonymousClientId = await resolveAnonymousClientId(
      opts.anonymousClientId,
    );

    SINGLETON = {
      agentId:    ensureResult.agentId,
      tenantId:   ensureResult.tenantId,
      baseUrl,
      apiKey,
      agentName,
      framework,
      defaultSessionId,
      evaluator,
      ensureResult,
      patchedOpenAI,
      patchedAnthropic,
      patchedMcpStdio,
      patchedFetch,
      patchedNodeHttp,
      patchedUndiciDispatcher,
      ...(uninstallFetchInterceptor ? { uninstallFetchInterceptor } : {}),
      ...(uninstallNodeHttpInterceptor ? { uninstallNodeHttpInterceptor } : {}),
      ...(uninstallUndiciDispatcherInterceptor
        ? { uninstallUndiciDispatcherInterceptor }
        : {}),
      ...(resolvedAnonymousClientId ? { anonymousClientId: resolvedAnonymousClientId } : {}),
      schemaSubscriber,
      bindingMode,
    };
    // Surface fetch=/http= flags so silent misses are visible in the
    // operator log line (previously fetch was set but not logged).
    // `bindingMode=` is appended so operators can see at a glance which
    // archetype the SDK booted under. `pdp=` reports the resolved PDP URL
    // (or `disabled`) so Mode-B operators get positive confirmation that
    // PDP routing is active — per ADR-0017 A3.
    logger.log(
      `[agentum] init complete: agent_id=${ensureResult.agentId} ` +
      `(bindingMode=${bindingMode}, pdp=${pdpUrl ?? "disabled"}, ` +
      `pdp_proxy=${pdpProxyUrl ? `${pdpProxyUrl} (coverage: openai, anthropic, deepseek, cohere, gemini)` : "disabled"}, ` +
      `openai=${patchedOpenAI}, anthropic=${patchedAnthropic}, ` +
      `mcp_stdio=${patchedMcpStdio}, fetch=${patchedFetch}, http=${patchedNodeHttp}, ` +
      `undici_dispatcher=${patchedUndiciDispatcher})`,
    );
    return SINGLETON;
  })();

  try {
    return await IN_FLIGHT;
  } finally {
    IN_FLIGHT = undefined;
  }
}

/** Current runtime, or `undefined` if `init()` hasn't completed. */
export function getRuntime(): AgentumRuntime | undefined {
  return SINGLETON;
}

/**
 * Release every long-lived resource `init()` allocated, so the host
 * process can exit cleanly. Calling code: CLI tools, scripted tests,
 * one-shot batch jobs, any context whose lifecycle is shorter than the
 * SDK's default "live until process exit" assumption.
 *
 * Long-running services (HTTP servers, daemons) do not need to call
 * this — every background timer the SDK opens already calls `unref()`
 * on Node so they don't hold the loop open by themselves; it is the
 * SSE `EventSource` connections that prevent natural exit.
 *
 * What this does:
 *   * closes the schema SSE subscriber (and the per-tenant policy
 *     subscriber it bound)
 *   * uninstalls the `fetch` and `node:http`/`https` interceptors
 *   * flushes any pending audit POSTs queued by the cedar client
 *
 * What this does NOT do:
 *   * uninstall the OpenAI / Anthropic / MCP-stdio monkeypatches —
 *     those leave method-pointers re-wrapped on user-held instances and
 *     unpatching mid-process is a foot-gun; restart the host process
 *     instead. (`_resetForTests` does unpatch them; it is test-only
 *     because tests own the whole process lifecycle.)
 *   * tear down the runtime singleton — call this then exit, or call
 *     `_resetForTests` if you genuinely need to `init()` again.
 *
 * Idempotent: safe to call multiple times, safe to call before `init()`.
 */
export async function shutdown(): Promise<void> {
  const rt = SINGLETON;
  if (!rt) return;
  try {
    rt.schemaSubscriber?.close();
  } catch {
    // Subscriber close is best-effort — see SchemaSubscriber.close().
  }
  try {
    rt.uninstallFetchInterceptor?.();
  } catch {
    // Uninstall is fail-soft by contract; ignore.
  }
  try {
    rt.uninstallNodeHttpInterceptor?.();
  } catch {
    // Same.
  }
  try {
    rt.uninstallUndiciDispatcherInterceptor?.();
  } catch {
    // Same.
  }
  try {
    await rt.evaluator.flushPendingAudits();
  } catch {
    // Audit flush is fire-and-forget by design; swallow.
  }
}

/**
 * Walk Node's CommonJS require.cache for `openai` / `@anthropic-ai/sdk`
 * paths. Returns the list of flagged module paths.
 *
 * The check is best-effort: never throws, silently returns an empty
 * array in environments without a CommonJS require (browser / pure
 * ESM / Deno). The shape "agent imported its LLM client before
 * agentum.init()" is the single biggest correctness foot-gun for the
 * SDK and is worth surfacing even at the cost of an occasional
 * false-positive.
 *
 * The function used to log a warning directly; that policy now lives in
 * `init()` so it can branch on `requirePreInitImport`
 * (warn / throw / ignore).
 */
function detectPreInitImports(
  /** Test injection: synthetic require.cache. When undefined, the
   *  function walks the live `globalThis.require.cache`. */
  cacheOverride?: Record<string, unknown>,
): string[] {
  try {
    let cache: Record<string, unknown> | undefined;
    if (cacheOverride) {
      cache = cacheOverride;
    } else {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const req = (
        globalThis as { require?: NodeJS.Require }
      ).require;
      cache = (req as { cache?: Record<string, unknown> } | undefined)
        ?.cache;
    }
    if (!cache) return [];
    const flagged: string[] = [];
    for (const path of Object.keys(cache)) {
      // Match the package roots only — node_modules/openai/... and
      // node_modules/@anthropic-ai/sdk/... — to avoid false-positives on
      // unrelated deps that re-export a name like "openai".
      if (
        /[\\/]node_modules[\\/]openai[\\/]/.test(path) ||
        /[\\/]node_modules[\\/]@anthropic-ai[\\/]sdk[\\/]/.test(path)
      ) {
        if (path.endsWith("/index.js") || path.endsWith("\\index.js") ||
            path.endsWith("/index.mjs") || path.endsWith("\\index.mjs")) {
          flagged.push(path);
        }
      }
    }
    return flagged;
  } catch {
    // require.cache walking can throw in unusual loaders — never block init.
    return [];
  }
}

/**
 * Format the operator-facing message for pre-init module detection.
 * Shared between the warn-mode log line and the throw-mode error so the
 * user sees the same diagnostic regardless of which mode they chose.
 */
function preInitMessage(flagged: readonly string[]): string {
  const head =
    "openai / @anthropic-ai/sdk was imported BEFORE agentum.init(). " +
    "Prototype patching covers most cases (instance method lookups still " +
    "hit the patched prototype), but a method reference explicitly " +
    "captured before init (e.g. `const fn = c.foo.bar.bind(c)`) will " +
    "permanently invoke the unpatched function. Move " +
    "`await agentum.init()` to the very top of your entrypoint, before " +
    "any `new OpenAI()` / `new Anthropic()`.";
  const tail =
    `Detected: ${flagged.slice(0, 3).join(", ")}` +
    (flagged.length > 3 ? ` (+${flagged.length - 3} more)` : "");
  return `${head} ${tail}`;
}

/**
 * Test-only: tear down the singleton and uninstall all monkeypatches so
 * a subsequent `init()` starts from a clean slate.
 */
export async function _resetForTests(): Promise<void> {
  if (SINGLETON?.uninstallFetchInterceptor) {
    SINGLETON.uninstallFetchInterceptor();
  }
  if (SINGLETON?.uninstallNodeHttpInterceptor) {
    SINGLETON.uninstallNodeHttpInterceptor();
  }
  if (SINGLETON?.uninstallUndiciDispatcherInterceptor) {
    SINGLETON.uninstallUndiciDispatcherInterceptor();
  }
  if (SINGLETON?.schemaSubscriber) {
    SINGLETON.schemaSubscriber.close();
  }
  // Drain fire-and-forget audit POSTs queued by the shared evaluator so
  // they don't race the test boundary (Jest "Cannot log after tests are
  // done" / "worker failed to exit gracefully" notices). Self-evicting
  // Set, safe to call when empty.
  if (SINGLETON?.evaluator) {
    await SINGLETON.evaluator.flushPendingAudits();
  }
  __resetSchemaSubscriberForTest();
  _setActiveHostRegistry(null);
  clearAgentumDefaults();
  _setActiveSchema(null);
  _resetPiiSecretsForTests();
  _resetActivePiiBlockForTests();
  _resetActiveFieldRuleTrieForTests();
  _resetActiveTextScannerForTests();
  SINGLETON = undefined;
  IN_FLIGHT = undefined;
  await uninstallOpenAIPatch();
  await uninstallAnthropicPatch();
  uninstallMcpStdioPatch();
}
