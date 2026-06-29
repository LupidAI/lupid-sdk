/**
 * Agentum SDK — Shared TypeScript types.
 *
 * All API request/response shapes are defined here so framework
 * wrappers can import types without pulling in the HTTP client.
 */

// ── Agent ──────────────────────────────────────────────────────────────────

export type TrustLevel = "low" | "medium" | "high";
export type AgentStatus =
  | "provisioning"
  | "active"
  | "inactive"
  | "suspended"
  | "quarantined"
  | "decommissioned";
export type AgentFramework =
  | "langchain"
  | "crewai"
  | "autogen"
  | "vercel-ai"
  | "openai-assistants"
  | "custom";

/**
 * Controls how the observe-prompt sidecar (the `/sdk/observe-prompt` POST that
 * powers Sessions / behavior analytics / alerts) treats the **raw sensitive
 * content** (`messages` + `tools_advertised`) before it leaves the agent
 * process. Actionable telemetry (decision, tool names, dims, risk, event type)
 * always flows regardless of this mode — only the prompt/tool-arg content is
 * affected.
 *
 * - `"masked"` (default) — run the S5 PII pipeline (`runPiiPipeline`) over the
 *   content before sending. When no PII config is present this is a no-op and
 *   the content is sent verbatim ("masked" means "PII pipeline applied if
 *   configured"). On a pipeline error the observe POST is dropped (fail-CLOSED)
 *   so raw PII never leaks.
 * - `"raw"` — explicit opt-in to send unmasked content. The SDK logs a one-time
 *   warning at init when raw capture is enabled. Use only where the central
 *   plane is trusted with raw prompt content.
 * - `"off"` — no observe-prompt POST at all. This is the only no-send mode and
 *   disables the actionable-telemetry flow for prompts.
 *
 * Back-compat: the legacy `capturePrompts` boolean maps as
 * `capturePrompts === false` ⇒ `"off"`; otherwise `promptCaptureMode` is
 * honored (default `"masked"`).
 */
export type PromptCaptureMode = "masked" | "raw" | "off";

export interface RegisterAgentRequest {
  name: string;
  owner_email: string;
  purpose: string;
  owner_team?: string;
  framework?: AgentFramework;
  declared_tools?: string[];
  data_classes?: string[];
  trust_level?: TrustLevel;
}

export interface RegisterAgentResponse {
  agent_id: string;
  name: string;
  status: AgentStatus;
  public_key_pem: string;
  /** Short-lived Bearer JWT for the initial session. */
  session_jwt: string;
}

export interface Agent {
  agent_id: string;
  name: string;
  owner_email: string;
  owner_team: string | null;
  purpose: string;
  framework: string;
  declared_tools: string[];
  data_classes: string[];
  trust_level: TrustLevel;
  status: AgentStatus;
  version: number;
  public_key_pem: string;
  created_at: string;
  updated_at: string;
  last_active: string | null;
  /** Tenant UUID this agent belongs to. Optional for backward compatibility. */
  tenant_id?: string;
}

export interface UpdateAgentRequest {
  owner_email?: string;
  owner_team?: string;
  purpose?: string;
  framework?: string;
  declared_tools?: string[];
  data_classes?: string[];
  trust_level?: TrustLevel;
}

// ── Sessions ───────────────────────────────────────────────────────────────

export interface Session {
  session_id: string;
  agent_id: string;
  /**
   * Bearer JWT for the session. Present in `startSession` responses but
   * **absent** in `getSession` responses (the server does not re-vend JWTs
   * on retrieval). Always access this field through an `AgentumSession`
   * instance rather than raw `Session` objects from `getSession`.
   */
  jwt?: string;
  started_at: string;
  ended_at: string | null;
  status: "active" | "ended";
  /** Tenant UUID for this session. Optional for backward compatibility. */
  tenant_id?: string;
}

// ── Policy ─────────────────────────────────────────────────────────────────

export type PolicyOutcome = "Allow" | "Deny";

export interface PolicySimulateRequest {
  agent_id: string;
  action: string;
  resource: string;
  /**
   * Optional Cedar context record (e.g. `{ path: "/api/orders/42" }`).
   * The runtime gateway populates the same shape from the active request;
   * setting it explicitly lets callers probe path-gated policies.
   */
  context?: Record<string, unknown>;
  /**
   * Optional "test as user" binding that mirrors `context.user` at runtime.
   * Useful for validating policies that key on `context.user.email` without
   * first minting a session-bound JWT.
   */
  user?: {
    id: string;
    email: string;
    trust?: "trusted" | "verified";
    attributes?: Record<string, string>;
  };
}

export interface PolicySimulateResponse {
  outcome: PolicyOutcome;
  rule_id: string | null;
  reason: string | null;
  /**
   * Values of every `@advice("…")` annotation on the
   * Cedar policies that contributed to the decision. Framework middleware
   * scans this for a `"require_hitl[:approvals=N,timeout=S]"` entry and
   * auto-escalates a Deny via `session.requestApproval(...)` instead of
   * returning 403.
   *
   * Absent or empty ⇒ no HITL escalation. Backend serialises the field as
   * an empty array (or omits it) when no matching policy carried advice.
   */
  advice?: string[];
  /**
   * HITL-1 — additive derived flag from the engine: `true` iff the Cedar
   * decision was `deny` AND `advice` carried a `require_hitl` directive AND no
   * live grant short-circuited the call. Framework guards prefer this flag
   * over re-parsing `advice` when present; absent on older API versions
   * (`#[serde(default)]` server-side), so callers MUST fall back to
   * {@link parseHitlAdvice}(`advice`) when it is `undefined`. Never `true`
   * on an Allow.
   */
  hitl_pending?: boolean;
  /**
   * `true` when the decision was produced by evaluating
   * an inline `policy_source` supplied via
   * {@link AgentumAdminClient#policies.simulateWithSource}. Absent on the
   * deployed-policy path so older callers see no wire change.
   */
  compiled?: boolean;
  /**
   * sha256 hex of the tenant's policy bundle at decision time.
   * Absent on older API versions and on pre-Cedar-eval denies
   * (e.g. declared_tools mismatch — that path never consults the policy
   * bundle, so attributing a hash to it would be misleading).
   */
  policy_hash?: string;
  /**
   * Wire-vocabulary provenance from `DecisionSource::as_str()`. From
   * the simulate endpoint this is always one of the four `"central_*" /
   * "local_pdp_*"` values — preserved as long-form (no
   * `mapDecisionSourceToAudit` collapse) so operators querying ClickHouse
   * keep the `*_cache_hit` distinction.
   */
  decision_source?:
    | "central_evaluated"
    | "central_cache_hit"
    | "local_pdp_evaluated"
    | "local_pdp_cache_hit";
}

/**
 * Request body for inline simulate. Same shape as
 * {@link PolicySimulateRequest} minus `agent_id` (path-bound) and plus
 * the mandatory Cedar source under `policy_source`.
 */
export interface PolicySimulateInlineRequest {
  action: string;
  resource: string;
  context?: Record<string, unknown>;
  user?: {
    id: string;
    email: string;
    trust?: "trusted" | "verified";
    attributes?: Record<string, string>;
  };
}

/**
 * Parsed `require_hitl[:params]` directive extracted from an advice string.
 * `null` when no advice value is a `require_hitl` entry.
 */
export interface HitlAdvice {
  /** From `approvals=N`. Undefined ⇒ server default (1 = single-approver). */
  requiredApprovals?: number;
  /** From `timeout=S`. Undefined ⇒ server default (60s). */
  timeoutSeconds?: number;
}

/**
 * Extract the first `require_hitl[:params]` directive from a simulate
 * response's `advice` list. Used by framework middleware (express, fastify,
 * nestjs, nextjs) to decide whether a Deny should escalate to HITL.
 *
 * Accepts both the bare `"require_hitl"` form and the
 * `"require_hitl:approvals=N,timeout=S"` form; any advice value that does
 * not start with `require_hitl` is ignored. Returns `null` when no
 * `require_hitl` entry is present.
 */
export function parseHitlAdvice(advice: string[] | undefined): HitlAdvice | null {
  if (!advice || advice.length === 0) return null;
  for (const raw of advice) {
    if (raw === "require_hitl") return {};
    const rest = raw.startsWith("require_hitl:")
      ? raw.slice("require_hitl:".length)
      : null;
    if (rest === null) continue;
    const out: HitlAdvice = {};
    for (const pair of rest.split(",")) {
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      const key = pair.slice(0, eq).trim();
      const val = pair.slice(eq + 1).trim();
      if (key === "approvals") {
        const n = Number.parseInt(val, 10);
        if (Number.isFinite(n) && n > 0) out.requiredApprovals = n;
      } else if (key === "timeout") {
        const n = Number.parseInt(val, 10);
        if (Number.isFinite(n) && n > 0) out.timeoutSeconds = n;
      }
    }
    return out;
  }
  return null;
}

// ── PII manifest block ────────────────────────────────────────────────────

/**
 * One field-level masking rule from the manifest's `pii.field_rules`
 * section.
 *
 * `tool` is a tool name (`"*"` matches all tools); `path` is a JSONPath
 * expression rooted at `$.` (e.g. `"$.args.email"`). Full JSONPath
 * traversal lands in Y03 — at Y02 the SDK only does syntactic validation
 * (`$.` prefix + balanced brackets). `mode` is the masking action applied
 * by the Stage B field-rule trie when the rule matches.
 */
export interface PiiFieldRule {
  tool: string;
  /** JSONPath expression, e.g. `"$.args.email"`. */
  path: string;
  mode: "drop" | "hash" | "tokenize" | "mask";
}

/**
 * One text-scanner stanza from the manifest's `pii.text_scanners` section.
 *
 * `patterns` references pattern IDs from `pii-patterns/default.yaml` (Y01)
 * by string; the YAML is loaded by Y04. `custom` carries per-agent
 * regex additions tagged with severity. The SDK validates structural
 * shape here; pattern-ID resolution is Y04's job.
 */
export interface PiiTextScannerConfig {
  enabled: boolean;
  patterns?: string[];
  custom?: Array<{
    id: string;
    pattern: string;
    severity?: "low" | "medium" | "high";
  }>;
}

/**
 * Parsed `pii:` block of the agent manifest. Mirrors the wire shape under
 * `manifest.pii` after `parsePiiManifestBlock` has validated it.
 *
 * Both top-level fields are optional — an empty `{}` is a valid block
 * (semantically: "no field rules, no text scanners"). Y03 consumes
 * `field_rules` to build the masking trie; Y04 consumes `text_scanners`.
 */
export interface PiiManifestBlock {
  field_rules?: PiiFieldRule[];
  /**
   * Text-scanner stanzas (Layer 2 PII detection).
   *
   * **v1 contract: only index 0 is consumed.** The manifest schema accepts an
   * array so that multi-scanner *stacking* can land in v1.1 without a wire
   * break, but the v1 runtime compiles and activates only `text_scanners[0]`.
   * Supplying more than one entry logs an init-time `console.warn` and the
   * trailing entries are inert.
   */
  text_scanners?: PiiTextScannerConfig[];
}

// ── Audit ──────────────────────────────────────────────────────────────────

export interface AuditEvent {
  event_id: string;
  event_type: string;
  ts: string;
  agent_id: string | null;
  session_id: string | null;
  actor: string | null;
  tool: string | null;
  resource: string | null;
  outcome: string | null;
  risk_score: number;
  detail?: Record<string, unknown>;
}

export interface AuditIngestRequest {
  agent_id: string;
  session_id: string;
  event_type: string;
  outcome?: string;
  tool?: string;
  resource?: string;
  /** Developer-supplied resource identifier (e.g. patient_id, order_id). */
  resource_id?: string;
  detail?: Record<string, unknown>;
  /** W3C trace id (32 lowercase hex chars) correlating this
   *  event with the distributed trace that produced it. The SDK
   *  auto-populates this from the active OpenTelemetry span (or a
   *  minted fallback) when absent. */
  trace_id?: string;
  /** Span id (16 lowercase hex chars) within the trace. */
  span_id?: string;
  /** Optional RFC3339 timestamp. When absent, the server stamps at
   *  ingest time. */
  ts?: string;
  /**
   * sha256 hex of the policy bundle the SDK used to make the decision
   * this event records. Threaded so analytics can detect drift between
   * SDK-side and central-side policy generations. Absent on legacy callers;
   * server-side dashboards interpret a missing value as `"central"` for
   * back-compat.
   */
  policy_hash?: string;
  /**
   * Provenance of the decision this event records.
   *
   * Two vocabularies are accepted on the wire (the server-side column is
   * just a string) — readers should normalise as needed:
   *
   * Short form (used by `evaluate-tool-call` flow, mapped via
   * `mapDecisionSourceToAudit`):
   *   - `"inproc"`: the SDK autopatch plane intercepted in-process (ADR-0010 /
   *     ADR-0014 §80). Emitted regardless of whether the underlying engine
   *     ran in the local PDP sidecar, the central evaluator, or was served
   *     from cache — the cache semantic moves to the separate `cache_hit`
   *     field (ADR-0014 §5).
   *   - `"local_pdp"` / `"central"` / `"cache"`: legacy short-form values,
   *     retained on the type so older callers / persisted rows still parse.
   *     `mapDecisionSourceToAudit` no longer emits these — it collapses all
   *     three onto `"inproc"`.
   *
   * Long form (used by simulate-side framework-guard audits,
   * matching the wire vocabulary of `DecisionSource::as_str()`):
   *   - `"central_evaluated"` / `"central_cache_hit"` /
   *     `"local_pdp_evaluated"` / `"local_pdp_cache_hit"`.
   *
   * Absent on events that are not authorization decisions (e.g.
   * ingest-time heartbeats) and on legacy callers; readers should treat
   * `undefined` as `"inproc"` for back-compat.
   */
  decision_source?:
    | "inproc"
    | "local_pdp"
    | "central"
    | "cache"
    | "central_evaluated"
    | "central_cache_hit"
    | "local_pdp_evaluated"
    | "local_pdp_cache_hit"
    | "approval_grant";
  /**
   * Resolved tenant-schema dimensions for this event. Mirrors the
   * Rust `AuditEvent.dimensions` (`BTreeMap<String, DimensionValue>`).
   * Optional during rollout: older Rust gateways
   * tolerate the absence; newer dashboards filter on declared dimension
   * names.
   */
  dimensions?: Record<string, string | null>;
  /**
   * Z07 / ADR-0014 — UUID (hyphenated text form) of the HITL approval
   * grant whose `ApprovalGrantCache` short-circuit produced this event.
   * Populated by `evaluateToolCall` on the grant-hit path; absent on every
   * other emit site. Persists to `audit_events.hitl_grant_id`
   * (`Nullable(UUID)`); older gateways tolerate the absence.
   */
  hitl_grant_id?: string;
  /**
   * Z07 / ADR-0014 — `true` when the SDK served this decision from cache
   * (the in-process `DecisionCache` or the approval-grant cache) rather
   * than evaluating against a live policy bundle. Pulled out of
   * `decision_source` by ADR-0014 §5 — `decision_source` continues to
   * carry the plane id; `cache_hit` carries the cache semantic. Defaults
   * to `false` on the wire; older gateways tolerate the absence.
   */
  cache_hit?: boolean;
  /**
   * Y06 — fingerprint of the active hash/tokenize secret that produced
   * the masked values in `detail`. Populated by the Y05 PII pipeline
   * (`runPiiPipeline`) only when Stage 1 actually dispatched
   * `mode: hash` or `mode: tokenize` on at least one path; absent on
   * drop-only / mask-only / scanner-only / no-op pipelines.
   *
   * Value is `SHA-256(LUPID_PII_HASH_SECRET)[:16]` hex (16 hex chars =
   * 64 bits) when the hash secret is set, falling back to the tokenize
   * key fingerprint when only the tokenize secret is configured. The
   * raw secret never leaves the customer process — the fingerprint is
   * the only key-material derivative on the wire.
   *
   * Persists to `audit_events.pii_key_id` (`Nullable(String)`) so
   * post-rotation forensics can disambiguate rows hashed under
   * different secret epochs. Older gateways tolerate the absence (the
   * column defaults to NULL).
   *
   * Callers MUST NOT set this field manually — the pipeline is the
   * canonical populator.
   */
  pii_key_id?: string;
}

/**
 * Query options for `AgentumAgentAdminClient.audit.list()`.
 *
 * `agent_id` is pinned to the client's `config.agentId` and cannot be
 * overridden — that's the whole point of the scoped client.
 */
export interface AgentAuditQuery {
  event_type?: string;
  from?: string;
  to?: string;
  user_email?: string;
  user_trust?: "trusted" | "verified" | "service";
  resource_id?: string;
  limit?: number;
  offset?: number;
}

/** Response envelope from `GET /audit` — the shape the SDK normalises to. */
export interface AuditListResponse {
  events: AuditEvent[];
  total: number;
  page_count: number;
  limit: number;
  offset: number;
}

/** Response from `GET /whoami` — caller identity snapshot. */
export interface WhoAmIResponse {
  email: string;
  role: string;
  tenant_id: string;
  agent_scope: string | null;
  scope_features: string[] | null;
  expires_at: string | null;
}

// ── Alerts ─────────────────────────────────────────────────────────────────

export type AlertSeverity = "info" | "warning" | "critical";

export interface Alert {
  alert_id: string;
  ts: string;
  agent_id: string | null;
  alert_type: string;
  severity: AlertSeverity;
  title: string;
  detail: Record<string, unknown>;
  acked: boolean;
  acked_by: string | null;
  acked_at: string | null;
}

// ── Vault / Credentials ────────────────────────────────────────────────────

export interface CredentialLease {
  lease_id: string;
  agent_id: string;
  service_name: string;
  value: string;
  expires_at: string;
}

export interface IssueCredentialRequest {
  agent_id: string;
  service_name: string;
}

// ── Shadow Agents ──────────────────────────────────────────────────────────

export interface ShadowAgent {
  shadow_id: string;
  source_ip: string | null;
  detected_framework: string | null;
  endpoint: string | null;
  first_seen: string;
  last_seen: string;
  request_count: number;
  promoted: boolean;
}

// ── MCP Servers ────────────────────────────────────────────────────────────

export interface McpServer {
  server_id: string;
  name: string;
  description: string;
  url: string;
  auth_type: "none" | "bearer" | "header";
  status: "active" | "disabled";
  created_at: string;
  updated_at: string;
}

// ── Health ─────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: "ok" | "degraded" | "down";
  version?: string;
  uptime_seconds?: number;
}

// ── Pagination ─────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ListAgentsQuery {
  status?: AgentStatus;
  team?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

// ── Client config ──────────────────────────────────────────────────────────

/**
 * Branded string for runtime (non-admin) API keys. Plain `string` is still
 * accepted for back-compat, but new code is encouraged to brand runtime keys
 * so the type system catches mismatches between runtime and admin surfaces.
 *
 * Admin/management keys belong on `AgentumAdminClient`.
 *
 * @example
 * const key: RuntimeApiKey = process.env.AGENTUM_API_KEY as RuntimeApiKey;
 * const client = new AgentumClient({ baseUrl, apiKey: key });
 */
export type RuntimeApiKey = string & { readonly __brand: "runtime" };

export interface AgentumClientConfig {
  /** Base URL of the Agentum API, e.g. "http://localhost:7071". */
  baseUrl: string;
  /** Bearer JWT for authenticated requests. */
  token?: string;
  /**
   * API key for management API authentication (sent as `X-API-Key` header).
   * Required when calling management endpoints without the dashboard proxy.
   *
   * Plain `string` is accepted for back-compat; new code is encouraged to
   * brand the value as {@link RuntimeApiKey} so admin keys cannot be passed
   * to the runtime client by mistake.
   */
  apiKey?: string | RuntimeApiKey;
  /** Request timeout in milliseconds (default: 15_000). */
  timeoutMs?: number;
  /** Custom fetch implementation (default: global fetch). */
  fetch?: typeof globalThis.fetch;
  /** Additional default headers merged into every request. */
  defaultHeaders?: Record<string, string>;
  /**
   * Number of times to retry a failed request on transient errors
   * (429, 502, 503, 504). Default: 3.
   */
  retries?: number;
  /**
   * Base delay in milliseconds for the first retry.
   * Each subsequent retry doubles the delay plus random jitter.
   * Default: 250.
   */
  retryDelayMs?: number;
  /**
   * Tenant UUID to scope all requests to.
   * When set, injects `X-Tenant-ID: <tenantId>` on every request.
   * This is a hint — the server-side effective tenant is determined by
   * the API key's configured `tenant_id`. Omit for system-tenant access.
   */
  tenantId?: string;
  /**
   * Maximum number of audit events held in the in-process ring buffer
   * before the oldest event is dropped. Default: 1000.
   */
  auditBufferSize?: number;
  /**
   * Interval (in milliseconds) between background audit-buffer flushes.
   * Default: 2000.
   */
  auditFlushIntervalMs?: number;
  /**
   * Maximum events delivered in a single flush POST. The server ingests
   * events individually, so each event is POSTed in sequence until the
   * batch size is met or the buffer is empty. Default: 100.
   */
  auditFlushBatchSize?: number;
  /**
   * Upper bound on the exponential-backoff delay applied after transient
   * ingest failures. Default: 60_000 (60s).
   */
  auditMaxBackoffMs?: number;
  /**
   * Called when the audit buffer overflows or ingest repeatedly fails.
   * Default: structured `console.warn` emission. Pass `() => {}` to silence.
   */
  onAuditError?: (info: AuditErrorInfo) => void;
  /**
   * When `true`, `ingestAuditEvent` POSTs synchronously and errors are
   * swallowed silently. Intended for test shims that
   * want to observe a single POST per call.
   */
  disableAuditBuffer?: boolean;
  /**
   * Reject TLS connections whose certificate does not verify. Defaults to
   * `true`. Set `false` only for local development against self-signed
   * certs — production deployments must leave this enabled.
   */
  tlsRejectUnauthorized?: boolean;
  /**
   * Path to an extra CA bundle (PEM) appended to the Node default trust
   * store for HTTPS requests. Only honoured in Node.js.
   */
  tlsCaPath?: string;
  /**
   * Called by the SDK when the cached session JWT fails with `401`. If
   * it resolves to a new JWT, the request (or audit flush) is retried
   * once with the new token.
   *
   * Normally set internally by `AgentumSession`; exposed for advanced
   * callers who manage their own refresh flow.
   */
  tokenRefreshFn?: () => Promise<string>;
  /**
   * Explicit tracing provider, overriding the SDK's
   * default `@opentelemetry/api` probe + random-id fallback. Supply this
   * when the caller owns their own tracing context and wants exact
   * control over the `traceparent` header injected on every outbound
   * Agentum call.
   *
   * The provider's `getActiveContext()` is called once per outbound
   * request (not per retry). Returning `null` tells the SDK to fall
   * back to the default probe.
   *
   * See `src/tracing.ts` for the `TracingProvider` contract.
   */
  tracingProvider?: {
    getActiveContext(): {
      traceId: string;
      spanId: string;
      flags: string;
    } | null;
  } | null;
  /**
   * Client-side Cedar decision cache for {@link
   * PolicySimulateResponse}. Defaults to enabled with up to 512 entries;
   * server advertises the per-entry TTL via `Cache-Control: max-age=N`.
   * Set `{enabled: false}` to bypass caching entirely (e.g. CI pipelines
   * where a fresh decision is required on every probe).
   *
   * The cache is automatically invalidated when the server's
   * `X-Agentum-Policy-Generation` header increments, so policy reloads
   * propagate without manual eviction.
   */
  policyCache?: {
    enabled?: boolean;
    maxSize?: number;
  };
}

/**
 * Passed to `onAuditError`. `reason` describes which failure mode was
 * detected; fields are populated opportunistically.
 */
export interface AuditErrorInfo {
  reason: "overflow" | "ingest_failed" | "dropped_on_close";
  dropped?: number;
  bufferedRemaining?: number;
  attempt?: number;
  error?: unknown;
}

/**
 * End-user identity bound to a session.
 *
 * Three modes, auto-selected by shape:
 *
 * - **Trusted** — `{ id, email, attributes? }`. The SDK caller asserts the
 *   user's identity; Agentum trusts the webapp's own auth layer. The API-key
 *   boundary keeps the assertion scoped to the caller's own tenant. Use this
 *   when your webapp has already authenticated the user (Next-Auth / Rails
 *   session / Django session) and you are forwarding Agentum calls on their
 *   behalf.
 *
 * - **Verified** — `{ token }`. The SDK forwards an end-user JWT; Agentum
 *   verifies the signature, `exp`, `aud`, and `iss` against the tenant's
 *   configured IdP (Auth0, Okta, Zitadel, Cognito, …). Use this for regulated
 *   surfaces where Cedar policies must not accept a forgeable user claim.
 *
 * - **Service** — `{ service, source? }`. The session is owned by a non-human
 *   identity (GitHub webhook, scheduled task, CI bot). The caller asserts
 *   a service name; the API-key tenant boundary scopes the assertion. Cedar
 *   policies gate on `context.user.trust === "service"` and
 *   `context.user.id === "<service-name>"`.
 *
 * If both `user` and `token` shapes are passed (they shouldn't be — the type
 * union forbids it), the backend prefers `token` and logs a warning. Cedar
 * policies can inspect `context.user.trust` to enforce strict-verified gating.
 */
export type UserBinding =
  | { id: string; email: string; attributes?: Record<string, string> }
  | { token: string }
  | { service: string; source?: string };

/**
 * Options passed to `AgentumClient.connect()`.
 * Same shape as `RegisterAgentRequest` plus lifecycle options.
 */
export interface ConnectOptions extends RegisterAgentRequest {
  /**
   * When `true`, skips the post-connect Cedar policy check.
   * Set this if you know the agent has no policy yet and want to suppress
   * the "no Cedar policy" warning. Default: `false`.
   */
  skipPolicyCheck?: boolean;
  /**
   * End-user identity bound to this session. See [[UserBinding]].
   */
  user?: UserBinding;
  /**
   * Tenant UUID override — forwarded as `X-Tenant-ID` on this session's
   * requests, independent of the outer client's default tenant.
   */
  tenantId?: string;
  /**
   * Caller IP address to attach to the session record (forwarded as
   * `source_ip` in the StartSession request body). Useful when the SDK
   * is fronting an end-user request and the IP is known.
   */
  sourceIp?: string;
  /**
   * Anonymous client ID to attach to the session record (forwarded as
   * `anonymous_client_id` in the StartSession request body). When omitted,
   * the SDK resolves a value via the tiered ladder in `anonymous-id.ts`
   * (browser localStorage or CLI ~/.config/agentum/anon_id); server-SDK
   * contexts must pass this explicitly per-request to avoid pinning every
   * caller to a single `agent_users` row. The backend prefixes with
   * `anon:` on receipt — do not prefix here.
   */
  anonymousClientId?: string;
}

// ── Errors ─────────────────────────────────────────────────────────────────

export class AgentumError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly body?: unknown,
  ) {
    super(message);
    this.name = "AgentumError";
  }
}

export class AgentumAuthError extends AgentumError {
  constructor(message: string, body?: unknown) {
    super(message, 401, body);
    this.name = "AgentumAuthError";
  }
}

export class AgentumPermissionError extends AgentumError {
  constructor(message: string, body?: unknown) {
    super(message, 403, body);
    this.name = "AgentumPermissionError";
  }
}

/**
 * Thrown on HTTP 403 when the server's response body carries
 * `code: "role_insufficient"`. Distinct from a policy-driven
 * `AgentumPermissionError` so callers can distinguish "you need a higher
 * role" (fix: mint an admin key) from "you're forbidden by policy" (fix:
 * amend the Cedar policy). Carries the `required` / `actual` role strings
 * exactly as emitted by the server.
 */
export class AgentumRoleInsufficientError extends AgentumPermissionError {
  constructor(
    public readonly required: string,
    public readonly actual: string,
    body?: unknown,
  ) {
    super(`requires ${required} role, caller has ${actual}`, body);
    this.name = "AgentumRoleInsufficientError";
  }
}

export class AgentumNotFoundError extends AgentumError {
  constructor(resource: string, body?: unknown) {
    super(`Not found: ${resource}`, 404, body);
    this.name = "AgentumNotFoundError";
  }
}

export class AgentumConflictError extends AgentumError {
  constructor(message: string, body?: unknown) {
    super(message, 409, body);
    this.name = "AgentumConflictError";
  }
}

/**
 * Thrown by `AgentumAgentAdminClient` when the provided API key's
 * `agent_scope` does not match the `agentId` passed to the constructor.
 *
 * The client pins every call to `config.agentId`, so an unscoped or
 * mis-scoped key would silently allow cross-agent operations on the
 * server if unchecked. Verification runs lazily on first use (or
 * eagerly via `AgentumAgentAdminClient.create()` / `verify()`).
 */
export class AgentumScopeMismatchError extends AgentumError {
  constructor(
    public readonly expected: string,
    public readonly actual: string | null,
    body?: unknown,
  ) {
    super(
      actual === null
        ? `API key is not scoped to any agent, expected scope '${expected}'`
        : `API key is scoped to agent '${actual}', expected '${expected}'`,
      403,
      body,
    );
    this.name = "AgentumScopeMismatchError";
  }
}

/**
 * Thrown by {@link AgentumSession.requestApproval} when the server-side
 * approval request does not reach a terminal status within the caller's
 * `timeout` window. The request remains live on the server until the
 * server-side sweeper marks it timed-out — operators may still see and
 * act on it via the dashboard, but the SDK call has already rejected.
 */
export class AgentumHitlTimeoutError extends AgentumError {
  constructor(
    public readonly requestId: string,
    public readonly timeoutMs: number,
  ) {
    super(
      `HITL approval request ${requestId} timed out after ${timeoutMs}ms`,
      408,
    );
    this.name = "AgentumHitlTimeoutError";
  }
}

/**
 * Thrown by {@link AgentumSession.requestApproval} when the human
 * reviewer denies the request. Carries the reviewer-supplied reason
 * (when present) so callers can surface it to the agent operator.
 */
export class AgentumHitlDeniedError extends AgentumError {
  constructor(
    public readonly requestId: string,
    public readonly decidedBy: string[],
    public readonly reason?: string,
  ) {
    super(
      reason
        ? `HITL approval request ${requestId} denied: ${reason}`
        : `HITL approval request ${requestId} denied`,
      403,
    );
    this.name = "AgentumHitlDeniedError";
  }
}

/**
 * Thrown when a policy evaluator returns `decision: "deny"` and the
 * caller has opted into throw-on-deny behaviour (e.g.
 * `enforceAllTools({ onDeny: "throw" })`). Carries the structured
 * deny payload — `denyCode` for categorical branching, `policyId`
 * for traceability — alongside the human-readable `reason`. Pairs
 * with `ToolCallEvaluation.denyCode` from `evaluation/cedar-client.ts`.
 *
 * The plain `reason` string remains the primary user-facing message
 * for backward compatibility with consumers that parse it.
 */
export class AgentumDeniedError extends AgentumError {
  constructor(
    /** Tool name that the agent attempted to call. */
    public readonly toolName: string,
    /** Free-text reason from the policy engine (back-compat). */
    public readonly reason: string,
    /**
     * Categorical deny code. One of the wire strings emitted by
     * the policy engine's `DenyCode` enum (`deny_cedar_policy`,
     * `deny_invalid_context`, `deny_fail_closed`, …). Undefined for
     * legacy denies that predate this contract.
     */
    public readonly denyCode?: string,
    /**
     * Cedar policy id that produced the decision. On allow this is the
     * matching `permit` rule; on deny the matching `forbid` rule. May
     * be undefined for short-circuit denies (no policy loaded, context
     * parse failure).
     */
    public readonly policyId?: string,
  ) {
    super(
      denyCode
        ? `Tool ${toolName} denied by policy (${denyCode}): ${reason}`
        : `Tool ${toolName} denied by policy: ${reason}`,
      403,
    );
    this.name = "AgentumDeniedError";
  }
}

// ── HITL (Human-in-the-Loop) ───────────────────────────────────────────────────

export interface HitlRequest {
  request_id: string;
  agent_id: string;
  session_id: string | null;
  action: string;
  resource: string;
  reason: string | null;
  status: "pending" | "approved" | "denied";
  decided_by: string | null;
  decision_reason: string | null;
  created_at: string;
  decided_at: string | null;
}

export interface HitlDecision {
  decision: "approve" | "deny";
  reason?: string;
}

export interface HitlDecisionResponse {
  request_id: string;
  status: "approved" | "denied";
  decided_by: string | null;
  decision_reason: string | null;
  decided_at: string;
}

/**
 * Options for {@link AgentumSession.requestApproval}.
 *
 * The agent SDK creates an approval request server-side and polls for
 * a terminal status. `timeout` and `pollIntervalMs` are client-side
 * controls; the server enforces its own bounded timeout independently
 * (the smaller of the two wins).
 */
export interface RequestApprovalOptions {
  /** Cedar action being requested (e.g. `"http.post"`). Required. */
  action: string;
  /** Cedar resource being requested (e.g. `"api.codeforge.io"`). Required. */
  resource: string;
  /**
   * Optional Cedar context — surfaced to the dashboard reviewer and
   * stored with the audit event so the reviewer can see *why* the
   * agent paused.
   */
  context?: Record<string, unknown>;
  /**
   * Human-readable reason shown in the dashboard approval queue.
   * Recommended; defaults to a stringified `context` if absent.
   */
  reason?: string;
  /**
   * Client-side timeout in milliseconds. Defaults to 60_000 (60s).
   * If the request does not reach a terminal status within this window,
   * `requestApproval()` rejects with {@link HitlTimeoutError}.
   */
  timeout?: number;
  /**
   * Number of independent approvers required. Defaults to `1`.
   * Multi-approver enforcement (`>= 2`) is a later addition;
   * the field is accepted now so callers can opt in early.
   */
  requiredApprovals?: number;
  /**
   * Poll interval in milliseconds. Defaults to 1000ms.  Bounded to
   * [250, 10_000] to stay polite to the server while still being
   * responsive enough for human-in-the-loop UX.
   */
  pollIntervalMs?: number;
  /**
   * Optional `AbortSignal` — if signalled mid-poll, the request rejects
   * with the signal's reason (or a generic `AbortError`).
   */
  signal?: AbortSignal;
  /**
   * Tool name this approval is gated on. When provided AND the
   * approval resolves to `status: "approved"`, the SDK records a
   * grant-cache entry keyed on `(agentId, toolName, argsHash)` so the next
   * identical tool call within the grant TTL skips re-escalation. When
   * absent, no grant is recorded (back-compat with older callers).
   */
  toolName?: string;
  /**
   * Tool-call arguments the approval covers. Hashed (canonical-JSON
   * SHA-256) into the grant key alongside `toolName`, so the post-approval
   * short-circuit only fires for a retry carrying these exact logical
   * arguments. MUST be the same value passed as `arguments` to the
   * `evaluateToolCall` that triggered the HITL escalation. When absent the
   * grant only matches an `evaluateToolCall` with no `arguments`
   * (both canonicalise to JSON `null`). Only consulted when `toolName`
   * is also set.
   */
  toolArgs?: unknown;
  /**
   * Cedar `@advice` strings from the prior PDP/central decision
   * that triggered this approval flow. Scanned for a
   * `require_hitl:timeout=NNN` directive to derive the grant TTL. If
   * absent or no `timeout=` is parseable, the grant TTL defaults to
   * 300_000 ms (5 minutes). Only consulted when `toolName` is also set.
   */
  advice?: string[];
}

/**
 * Result returned by {@link AgentumSession.requestApproval} on a
 * non-timeout terminal decision.
 *
 * `decided_by` is always an array — single-approver returns `[email]`,
 * multi-approver returns `[email1, email2, ...]`.
 */
export interface ApprovalResult {
  status: "approved" | "denied";
  /** All approvers who weighed in. Empty array if none recorded yet. */
  decided_by: string[];
  /** Optional reviewer-supplied reason. */
  reason?: string;
  request_id: string;
}

// ── Delegation ─────────────────────────────────────────────────────────────────

export interface IssueDelegationRequest {
  delegate_id: string;
  scope: string[];
  ttl_seconds?: number;
}

export interface DelegationResponse {
  delegation_token: string;
  expires_at: string;
}

export interface DelegationVerifyResponse {
  valid: boolean;
  delegator_id: string | null;
  delegate_id: string | null;
  scope: string[];
  expires_at: string | null;
}

// ── Compliance ──────────────────────────────────────────────────────────────

export interface ComplianceReport {
  agent_id: string;
  compliant: boolean;
  issues: string[];
  checked_at: string;
}

// ── Token / Elevation ───────────────────────────────────────────────────────

/** Response from a token-issue or token-refresh call. */
export interface TokenResponse {
  token: string;
  expires_at: string;
}

/** Response from an operator-elevation call (short-lived elevated JWT). */
export interface ElevateTokenResponse {
  token: string;
  expires_at: string;
  role: string;
}

// ── Admin surface ───────────────────────────────────────────────────────────

/** Shared shape for admin list endpoints that support pagination. */
export interface ListOpts {
  limit?: number;
  offset?: number;
}

/**
 * Request body for `AgentumAdminClient.apiKeys.mint()`.
 *
 * Mirrors server-side `CreateApiKeyRequest` in `routes/admin_keys.rs`.
 * `email`, `role`, and (for non-SuperAdmin callers) `tenant_id` are required
 * by policy; the SDK forwards whatever the caller provides.
 */
export interface MintApiKeyRequest {
  email: string;
  /** One of `superadmin` | `admin` | `operator` | `viewer` | `auditor`. */
  role: string;
  /** Defaults to the caller's tenant server-side if omitted. */
  tenant_id?: string;
  /** Bind this key to a specific agent; forbids cross-agent calls. */
  agent_scope?: string;
  /** Absolute expiry as RFC 3339 timestamp. */
  expires_at?: string;
  /** CIDR strings (e.g. `"10.0.0.0/8"`) — requests from other IPs return 401. */
  ip_allow_cidrs?: string[];
  /** Feature flags interpreted per-route (e.g. `"read_only"`). */
  scope_features?: string[];
}

/**
 * Response from `AgentumAdminClient.apiKeys.mint()`. `plaintext` is returned
 * **exactly once** — there is no way to recover it later.
 */
export interface MintApiKeyResponse {
  id: string;
  plaintext: string;
  tenant_id: string;
  email: string;
  role: string;
  agent_scope: string | null;
  expires_at: string | null;
  created_at: string;
}

/** One row of `AgentumAdminClient.apiKeys.list()`. */
export interface ApiKeyMetadata {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  created_by: string | null;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
  agent_scope: string | null;
  expires_at: string | null;
  ip_allow_cidrs: string | null;
  scope_features: string | null;
  rotated_to_id: string | null;
  grace_until: string | null;
}

/** Response from `AgentumAdminClient.apiKeys.rotate()`. */
export interface RotateApiKeyResponse {
  newKeyId: string;
  newPlaintext: string;
  oldKeyId: string;
  oldGraceUntil: string;
}

/**
 * `auth_type` supported values. `"oauth2_cc"` triggers the RFC 6749
 * client-credentials flow; the gateway fetches and
 * auto-refreshes the bearer token without the agent ever seeing a 401.
 */
export type McpAuthType = "none" | "bearer" | "header" | "oauth2_cc";

/**
 * External secrets-manager source token for an MCP server credential.
 * When set to anything other than `"static"` the
 * gateway resolves the upstream credential at injection time from the
 * named backend instead of the encrypted `api_key` field.
 */
export type McpCredentialSource = "static" | "aws_sm" | "hashicorp" | "azure_kv";

/** Request body for `AgentumAdminClient.mcp.registerServer()`. */
export interface RegisterMcpServerRequest {
  name: string;
  url: string;
  description?: string;
  auth_type?: McpAuthType;
  auth_header_name?: string;
  api_key?: string;
  status?: "active" | "disabled";
  // ── OAuth 2.0 client-credentials ──
  // Required together when `auth_type === "oauth2_cc"`.
  oauth_client_id?: string;
  /** Plaintext secret. Sent over TLS; stored AES-256-GCM encrypted at rest. */
  oauth_client_secret?: string;
  oauth_token_url?: string;
  /** Space-separated scope list, passed verbatim to the token endpoint. */
  oauth_scopes?: string;
  // ── External secrets manager ──
  /** Defaults to `"static"`. When external, requires `credential_ref`. */
  credential_source?: McpCredentialSource;
  /** Backend-specific reference (AWS ARN/name, Vault path, Key Vault URL). */
  credential_ref?: string;
  /** Per-server cache TTL. Default 300 s. */
  credential_cache_ttl_seconds?: number;
}

/** Partial update body for `AgentumAdminClient.mcp.updateServer()`. */
export interface UpdateMcpServerRequest {
  name?: string;
  url?: string;
  description?: string;
  auth_type?: McpAuthType;
  auth_header_name?: string;
  api_key?: string;
  status?: "active" | "disabled";
}

/** Result of `AgentumAdminClient.mcp.registerServer()`. */
export interface RegisterMcpServerResponse {
  server_id: string;
  name: string;
  url: string;
  auth_type: string;
  status: string;
  has_api_key: boolean;
  /** True when the server is configured for OAuth client-credentials. */
  has_oauth_config?: boolean;
  oauth_token_url?: string | null;
  oauth_scopes?: string | null;
  /** Credential source for this server. */
  credential_source?: McpCredentialSource;
  credential_ref?: string | null;
  credential_cache_ttl_seconds?: number;
  /** True when `credential_source` is anything other than `"static"`. */
  has_external_credential?: boolean;
  created_at: string;
}

/** Per-agent access grant returned by MCP access operations. */
export interface McpAccessGrant {
  server_id: string;
  agent_id: string;
  allowed_tools: string[];
  created_at: string;
}

/**
 * Declarative policy DSL — compiled to Cedar server-side by
 * `agentum-policy-dsl`. See `POST /policies/declarative/:agent_id`.
 *
 * Field names are `snake_case` to match the wire format exactly (no client-
 * side translation), matching every other wire type in this file. The
 * ergonomic camelCase surface lives on `PolicyBuilder`.
 */
export interface DeclarativePolicySpec {
  agent_id: string;
  rules: DeclarativeRule[];
  /**
   * Optional RBAC role shortcut section. Each role maps
   * to `allow` / `deny` pattern lists; the server expands every role into
   * concrete rules with an injected `when_user` attribute-equals guard on
   * `user_role_field` (default `"role"`).
   *
   * Omit or leave empty for policies that don't use the role shortcut. Mix
   * freely with explicit `rules`; forbid-before-permit ordering is preserved
   * across both sources.
   */
  roles?: Record<string, DeclarativeRoleDefinition>;
  /**
   * Attribute key on `context.user.attributes` that carries the caller's
   * role string. Defaults to `"role"` when omitted.
   */
  user_role_field?: string;
}

/**
 * One role's allow / deny policy lists. Either list may be the literal
 * string `"*"` (all actions / all resources) or an array of pattern strings
 * in the `<action>:<target>` grammar.
 */
export interface DeclarativeRoleDefinition {
  allow?: DeclarativeRolePatternList;
  deny?: DeclarativeRolePatternList;
}

/**
 * Pattern list for a role's allow/deny section. `"*"` expands to a single
 * god-mode rule (any action, any resource); an array expands one rule per
 * pattern. Pattern grammar:
 *
 * - `"*"` (as an array element) → all actions, all resources.
 * - `"http.<verb>:<host>[/<path>]"` (verb = GET/POST/PUT/DELETE/PATCH) → HTTP rule.
 * - `"http.*:<host>[/<path>]"` → HTTP rule matching any method.
 * - `"mcp.tool.call:<server>::<tool>"` → MCP rule with server gate.
 * - `"mcp.tool.call:<tool>"` (no `::`) → MCP rule, any server.
 * - `"mcp.*:..."` (synonym for `mcp.tool.call:...`).
 */
export type DeclarativeRolePatternList = "*" | string[];

/**
 * A single authorization rule. HTTP rules compile to `http.<method>` action
 * with `host` as the Cedar resource; MCP rules compile to `mcp.tool.call`
 * action with `tool` as the resource.
 */
export type DeclarativeRule =
  | DeclarativeHttpRule
  | DeclarativeMcpToolRule
  | DeclarativeAllActionsRule;

/**
 * "God-mode" rule. Matches any action against any
 * resource — typically used with a `when_user` attribute-equals guard so it
 * only applies to callers in a specific role.
 */
export interface DeclarativeAllActionsRule {
  kind: "all_actions";
  permit: boolean;
  when_user?: DeclarativeUserCondition;
  /**
   * Gate on developer-extracted request-body fields (e.g.
   * `amount > 10000`). The framework middleware populates `context.request_data`
   * via its `contextFromBody` callback; the compiled Cedar guards the access
   * with `context has request_data && context.request_data has "<field>"` so
   * non-middleware callers deterministically fail the clause closed.
   */
  when_context?: DeclarativeContextCondition;
  /**
   * Escalate to HITL instead of plain deny. Only valid on
   * forbid rules (`permit: false`). When the middleware sees a Deny whose
   * advice contains `require_hitl[:params]`, it auto-calls
   * `session.requestApproval(...)` instead of returning 403.
   */
  require_approval?: boolean;
  approval_config?: DeclarativeApprovalConfig;
}

/**
 * HTTP verb mapped by the gateway enforcer. `"*"` is the
 * wildcard form — the compiler expands it to `action in [http.get, ...,
 * http.patch]` covering all five canonical verbs in a single rule.
 */
export type DeclarativeHttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "DELETE"
  | "PATCH"
  | "*";

export interface DeclarativeHttpRule {
  kind: "http";
  permit: boolean;
  method: DeclarativeHttpMethod;
  host: string;
  path_like?: string;
  when_user?: DeclarativeUserCondition;
  /** See {@link DeclarativeContextCondition}. */
  when_context?: DeclarativeContextCondition;
  /** See {@link DeclarativeAllActionsRule.require_approval}. */
  require_approval?: boolean;
  approval_config?: DeclarativeApprovalConfig;
}

export interface DeclarativeMcpToolRule {
  kind: "mcp_tool";
  permit: boolean;
  /**
   * Registered MCP server name. Optional: omit to match ANY server.
   * When present, the compiled Cedar gates on
   * `context.mcp_server_name == "<server>"`, which the gateway populates
   * from the server registration. Send the field as absent (not `""` or
   * `null`) to signal "any server".
   */
  server?: string;
  tool: string;
  when_user?: DeclarativeUserCondition;
  /** See {@link DeclarativeContextCondition}. */
  when_context?: DeclarativeContextCondition;
  /** See {@link DeclarativeAllActionsRule.require_approval}. */
  require_approval?: boolean;
  approval_config?: DeclarativeApprovalConfig;
}

/**
 * Per-rule HITL configuration. Parameters feed into the
 * emitted `@advice("require_hitl[:params]")` Cedar annotation. Both fields
 * are optional — omitting them tells the server to apply its own defaults
 * when the approval request is actually created.
 */
export interface DeclarativeApprovalConfig {
  /** Distinct approvers required. Default: 1. */
  required_approvals?: number;
  /** Wait timeout in seconds before the server marks the request as timed out. */
  timeout_seconds?: number;
}

/**
 * User predicate evaluated against `context.user.*` at decision time. All
 * variants short-circuit with `context has user` on the server so a session
 * minted without user binding deterministically fails the guard.
 */
export type DeclarativeUserCondition =
  | DeclarativeEmailLikeCondition
  | DeclarativeAttributeEqualsCondition
  | DeclarativeTrustEqualsCondition;

export interface DeclarativeEmailLikeCondition {
  kind: "email_like";
  /** Cedar `like` pattern; `*` matches any run of characters. */
  pattern: string;
}

export interface DeclarativeAttributeEqualsCondition {
  kind: "attribute_equals";
  key: string;
  value: string;
}

export interface DeclarativeTrustEqualsCondition {
  kind: "trust_equals";
  trust: "trusted" | "verified" | "service";
}

/**
 * Predicate evaluated against `context.request_data.*` at decision time — a
 * record of developer-extracted request-body fields forwarded by the
 * framework middleware via `contextFromBody`.
 *
 * The numeric variants use integers because Cedar's only numeric type is
 * `Long` (signed 64-bit integer); Cedar rejects fractional JSON numbers at
 * context-construction time. Pass `value` as an integer on the wire.
 *
 * Every variant is short-circuited server-side with `context has request_data
 * && context.request_data has "<field>"` so a request that bypassed the
 * middleware (or a middleware that chose not to extract the field)
 * deterministically fails the clause closed.
 */
export type DeclarativeContextCondition =
  | DeclarativeFieldEqualsCondition
  | DeclarativeFieldNotEqualsCondition
  | DeclarativeFieldGreaterThanCondition
  | DeclarativeFieldLessThanCondition;

export interface DeclarativeFieldEqualsCondition {
  kind: "field_equals";
  field: string;
  value: string;
}

export interface DeclarativeFieldNotEqualsCondition {
  kind: "field_not_equals";
  field: string;
  value: string;
}

export interface DeclarativeFieldGreaterThanCondition {
  kind: "field_greater_than";
  field: string;
  /** Integer — Cedar has no float type. */
  value: number;
}

export interface DeclarativeFieldLessThanCondition {
  kind: "field_less_than";
  field: string;
  /** Integer — Cedar has no float type. */
  value: number;
}

/**
 * Arguments for `AgentumAdminClient.policies.importFromOpenAPI()`.
 * Exactly one of `spec` (inline JSON/YAML) or `specUrl` (server-side
 * fetch) must be provided; supplying both or neither is a client-side 400.
 *
 * The server deduplicates endpoints by `(method, normalised path)`, groups
 * paths sharing a two-segment prefix into one `pathLike: '/prefix/*'` rule
 * when three or more share it, and compiles the result to Cedar. Overrides
 * run after grouping — the first matching override flips the rule's effect.
 */
export interface OpenApiImportOptions {
  /** Target agent UUID. Must exist; the caller must have scope access. */
  agentId: string;
  /** Inline JSON or YAML spec. Mutually exclusive with `specUrl`. */
  spec?: string;
  /**
   * URL the server fetches over HTTPS/HTTP. Loopback, `localhost`, and the
   * AWS/GCP metadata IP are refused for SSRF safety. Body is capped at 2 MiB
   * and the fetch times out after 10 s.
   */
  specUrl?: string;
  /** `"permit"` (default) or `"forbid"` — decision for every generated rule before overrides. */
  defaultEffect?: "permit" | "forbid";
  /** Override the Cedar `host` used for every generated HTTP rule. Useful when the
   *  spec's `servers[].url` differs from the DNS name the agent will actually hit. */
  hostOverride?: string;
  /** Applied in order after generation; first match wins per rule. */
  overrides?: OpenApiOverride[];
  /**
   * When `true` (default) the server returns the preview without persisting.
   * Set `false` to compile + write `{agentId}.cedar` + reload + audit in a
   * single call (equivalent to a subsequent `applyDeclarative`).
   */
  dryRun?: boolean;
}

/**
 * A single rule-effect override. `pathPattern` accepts either `"/admin/*"` or
 * the two-word `"DELETE /admin/*"` form; `*` and `**` both match any
 * substring (override globs are intentionally lenient — use specific paths
 * for strict matching).
 */
export interface OpenApiOverride {
  pathPattern: string;
  effect: "permit" | "forbid";
  /** `"GET"` / `"POST"` / ... / `"*"`. Omit for any method. */
  method?: string;
}

/**
 * Response from `importFromOpenAPI`. The `rules` array is the exact
 * {@link DeclarativeRule} list the server compiled — safe to pass into
 * `applyDeclarative` unchanged. `endpointCount` is pre-grouping (distinct
 * method+path pairs discovered in the spec). On `dryRun: false` responses
 * `appliedAt` and `policyId` are present.
 */
export interface OpenApiImportResult {
  rules: DeclarativeRule[];
  compiledCedar: string;
  endpointCount: number;
  appliedAt?: string;
  policyId?: string;
  dryRun: boolean;
}

/**
 * `admin.bootstrap()` spec — atomic idempotent bulk provisioning for an
 * agent plus its MCP servers, grants, policies, and API keys. Safe to
 * re-run from IaC — every sub-resource is upserted by stable key
 * (agent.name, mcp_server.name, api_key.label) and the backend rolls
 * back partial work on failure.
 *
 * One call provisions ONE agent. Loop the call for multi-agent fleets.
 */
export interface BootstrapSpec {
  agent: BootstrapAgentSpec;
  mcpServers?: BootstrapMcpServerSpec[];
  grants?: BootstrapGrantSpec[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  policies?: Record<string, any>;
  apiKeys?: BootstrapApiKeySpec[];
}

export interface BootstrapAgentSpec {
  name: string;
  ownerEmail: string;
  purpose: string;
  framework: string;
  ownerTeam?: string;
  declaredTools?: string[];
  dataClasses?: string[];
  /** `"default_observe"` (default) or `"empty"`. */
  policyProfile?: string;
}

export interface BootstrapMcpServerSpec {
  name: string;
  url: string;
  description?: string;
  auth?: {
    type: string;
    token?: string;
    headerName?: string;
  };
  status?: string;
}

export interface BootstrapGrantSpec {
  mcpServerName: string;
  allowedTools?: string[];
}

export interface BootstrapApiKeySpec {
  /**
   * Role for the minted key. Defaults server-side to `"admin"` (tenant
   * admin) — the right level for tenant self-service automation. Minting
   * a `"superadmin"` key requires `platformAction: true` as a tripwire
   * against accidental cross-tenant credential creation.
   */
  role?: "viewer" | "operator" | "admin" | "owner" | "superadmin";
  /**
   * Stable label — the backend dedupes active keys by (tenant_id, label)
   * so Terraform re-runs don't mint duplicate keys per apply.
   */
  label?: string;
  /**
   * Bind the key to the bootstrapped agent's UUID. Pass `"__SELF__"` to
   * have the server substitute the just-provisioned agent_id.
   */
  agentScope?: string;
  expiresAt?: string;
  ipAllowCidrs?: string[];
  scopeFeatures?: string[];
  /** Defaults to the caller's email when omitted. */
  email?: string;
  /**
   * Required to be `true` when `role: "superadmin"`. Tenant-admin and
   * lower keys do not need this flag. Acts as a tripwire against
   * accidental platform-credential creation from tenant-shaped IaC.
   */
  platformAction?: boolean;
}

export interface BootstrapResult {
  agent: {
    agentId: string;
    name: string;
    created: boolean;
  };
  mcpServers: Array<{
    serverId: string;
    name: string;
    created: boolean;
  }>;
  grants: Array<{
    mcpServerName: string;
    serverId: string;
    allowedTools: string[];
    created: boolean;
  }>;
  policy?: {
    policyId: string;
    applied: boolean;
    ruleCount: number;
  };
  apiKeys: Array<{
    id: string;
    label?: string;
    role: string;
    agentScope?: string;
    created: boolean;
    /** Plaintext — only present on `created: true`. */
    plaintextKey?: string;
  }>;
}

// ── Policy proposals ───────────────────────────────────────────────────────

export type ProposalStatus = "pending" | "approved" | "rejected" | "withdrawn";

/**
 * Payload for `POST /policies/proposals`. Callers MUST set exactly one of
 * `cedar_source` or `declarative_spec`; the server returns 422 otherwise
 * (`routes/policy_proposals.rs:283-333`). `note` is optional reviewer
 * context stored alongside the pending row.
 */
export interface CreateProposalRequest {
  agent_id: string;
  cedar_source?: string | null;
  declarative_spec?: DeclarativePolicySpec | null;
  note?: string | null;
}

export interface CreateProposalResponse {
  proposal_id: string;
  tenant_id: string;
  agent_id: string;
  proposed_by: string;
  proposed_at: string;
  status: ProposalStatus;
  author_mode: "manual" | "declarative";
  reviewer_note?: string | null;
}

export interface PolicyProposal {
  proposal_id: string;
  tenant_id: string;
  agent_id: string;
  proposed_by: string;
  proposed_at: string;
  /** Exactly one of the two payload fields is populated; the other is absent. */
  cedar_source?: string | null;
  declarative_spec?: DeclarativePolicySpec | null;
  status: ProposalStatus;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  reviewer_note?: string | null;
}

export interface ListProposalsQuery {
  status?: ProposalStatus;
  agent_id?: string;
}

export interface ListProposalsResponse {
  proposals: PolicyProposal[];
  total: number;
}

export interface ReviewProposalRequest {
  reviewer_note?: string | null;
}

export interface ApproveProposalResponse {
  proposal_id: string;
  status: "approved";
  reviewed_by: string;
  reviewed_at: string;
  applied_path: string;
}

export interface RejectProposalResponse {
  proposal_id: string;
  status: "rejected";
  reviewed_by: string;
  reviewed_at: string;
}

export interface WithdrawProposalResponse {
  proposal_id: string;
  status: "withdrawn";
}

// ── MITM proxy configuration ───────────────────────────────────────────────

/**
 * How the Agentum CA should be trusted by the process.
 *
 * - `env-only` (default): write the CA to disk and expose its path via
 *   `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`. No trust-store mutation.
 * - `never`: write the CA to disk and return the path, but do not touch
 *   any env var. Callers opt into their own trust wiring.
 * - `system`: best-effort install into the OS trust store (not yet
 *   implemented — currently falls back to `env-only` with a warning).
 */
export type MitmInstallCa = "system" | "env-only" | "never";

/** Options for {@link AgentumClient.configureMitmProxy}. */
export interface MitmProxyOptions {
  /**
   * Full proxy URL override. When omitted, Agentum derives it from
   * the client's `baseUrl` (swapping the REST API port for the MITM
   * gateway port, default 7070) and injects the per-session
   * `proxy_token` as basic-auth credentials.
   */
  proxyUrl?: string;
  /** CA-install strategy. Defaults to `"env-only"`. */
  installCa?: MitmInstallCa;
  /** When true (default), mutate `process.env.HTTPS_PROXY` / friends. */
  setProcessEnv?: boolean;
  /** Path to write the downloaded CA cert. Defaults to `~/.agentum/ca.pem`. */
  caPath?: string;
  /** Management API key used for enrollment. Defaults to the client's configured `apiKey`. */
  apiKey?: string;
  /** Agent display name used during enrollment. Defaults to script name. */
  name?: string;
  /** Human-readable purpose used during enrollment. */
  purpose?: string;
  /**
   * Port for the MITM gateway when deriving `proxyUrl`. Defaults to `7070`.
   * Ignored when {@link MitmProxyOptions.proxyUrl} is set explicitly.
   */
  proxyPort?: number;
}

/**
 * Result of {@link AgentumClient.configureMitmProxy}.
 *
 * All fields are present on success. The `proxyUrl` already contains the
 * short-lived `proxy_token` as basic-auth credentials, so most HTTP clients
 * only need `HTTPS_PROXY` + a trusted CA path to route through the gateway.
 */
export interface MitmProxyConfig {
  agentId: string;
  sessionId: string;
  sessionJwt: string;
  proxyToken: string;
  proxyTokenExpiresAt: string;
  proxyUrl: string;
  caPath: string;
}

