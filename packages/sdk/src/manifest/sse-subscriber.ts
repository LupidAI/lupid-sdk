/**
 * Long-lived SSE subscriber for schema-install events.
 *
 * Wired from `init()` after `_setActiveSchema(activeSchema)`. Subscribes to
 * `GET {baseUrl}/api/v1/agents/{agentId}/schema/stream` and on every
 * matching `schema_installed` event re-fetches the live schema via the
 * existing `getLiveSchema()` REST path and calls `_setActiveSchema(...)`.
 *
 * Identity schemas are per-agent; the SSE topic is per-agent
 * (`schema:<agent_id>`). The subscriber tracks both `tenantId`
 * and `agentId` so the defence-in-depth event filter can drop any
 * cross-agent payload it sees.
 *
 * Design notes:
 *   - The `eventsource` npm polyfill is dynamic-imported inside `start()` —
 *     the universal entry must stay free of any static `eventsource` import
 *     so edge bundles don't pull `node:*` transitives at load.
 *   - On non-Node runtimes (no `process.versions.node`) the subscriber is
 *     a quiet no-op. Edge / Lambda / browser consumers fall back to the
 *     init-time `getLiveSchema()` call and the existing 60s
 *     `ScopeIndexPopulator` tick path.
 *   - We don't trust the SSE payload as the source of truth — payload is
 *     used only to detect that *something* changed; the source of truth
 *     remains `GET /schema`. Defence-in-depth: we filter on
 *     `wire.agent_id === opts.agentId` even though the server is
 *     already agent-scoped.
 *   - `eventsource@^3` implements WHATWG auto-reconnect honouring the
 *     server's `retry:` directive (the server sends `retry: 3000` with
 *     jitter) and `Last-Event-ID` headers. We do NOT add an extra
 *     reconnect loop.
 *   - On `lagged` events the server is telling us the broadcast queue
 *     overflowed and we may have missed an install. Same code path as
 *     `schema_installed`: refetch live schema, reconcile, swap.
 */

import { getLiveSchema } from "./client.js";
import { _setActiveSchema } from "./state.js";
import type { AdminHttpClient } from "../admin/http.js";
import type { TenantSchema } from "./types.js";
import type { CedarToolCallClient } from "../evaluation/cedar-client.js";

/**
 * Wire shape of the `schema_installed` SSE event payload. Mirrors
 * `SchemaInstalledEvent` in `crates/agentum-api/src/routes/schema.rs`.
 *
 * The payload carries both `tenant_id` and `agent_id`; the subscriber
 * filters on `agent_id` because the stream is per-agent.
 */
interface SchemaInstalledWire {
  tenant_id: string;
  agent_id: string;
  version: number;
  previous_version: number | null;
  added_columns: string[];
  manifest_revision_id: string | null;
  installed_at: string;
}

/**
 * Wire shape of the `policy` SSE event payload published on
 * `/api/v1/policy/stream`. Mirrors `UrgentEvent::Policy` in
 * `crates/agentum-api/src/routes/policy_distribution.rs` — tenant-wide,
 * no `agent_id`.
 */
interface PolicyWire {
  kind: "policy";
  version: number;
  bundle_hash_hex: string;
  reason: string;
}

/**
 * Wire shape of `capability_effective_set_changed`. Mirrors
 * `UrgentEvent::CapabilityEffectiveSetChanged` — tenant-wide, no
 * `agent_id`, no `scope_dimension`.
 */
interface CapabilityEffectiveSetChangedWire {
  kind: "capability_effective_set_changed";
  scope_value: string;
  capability_set_hash: string;
}

/**
 * Wire shape of the `agent_suspended` / `agent_activated` SSE events. Mirrors
 * `UrgentEvent::AgentSuspended` / `UrgentEvent::AgentActivated` in
 * `crates/agentum-api/src/routes/policy_distribution.rs:179-184` — both carry
 * the owning `tenant_id` (GR-01 tenant-scoping) and the `agent_id`.
 */
interface AgentLifecycleWire {
  kind: "agent_suspended" | "agent_activated";
  tenant_id: string;
  agent_id: string;
}

/**
 * Wire shape of the `hitl_grant` SSE event. Mirrors `UrgentEvent::HitlGrant`
 * (`crates/agentum-api/src/routes/policy_distribution.rs:191-199`). `args_hash`
 * is the canonical-JSON SHA-256 of the tool-call `arguments` already computed
 * by the PDP (`agentum-pdp/src/hitl.rs::hash_args`); the SDK pre-populates its
 * `ApprovalGrantCache` keyed on that hash (GR-08).
 */
interface HitlGrantWire {
  kind: "hitl_grant";
  tenant_id: string;
  agent_id: string;
  tool: string;
  args_hash: string;
  granted_by: string;
  /** RFC3339 timestamp at which the grant expires. */
  expires_at: string;
  request_id: string;
}

/**
 * Logger surface used by the subscriber. Matches the `init()`
 * `Pick<Console, "log" | "warn" | "error">` shape so callers can pass
 * `opts.logger` straight through.
 */
export interface SchemaSubscriberLogger {
  log(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

export interface SchemaSubscriberOptions {
  /** Gateway base URL, e.g. `http://localhost:7071`. */
  baseUrl: string;
  /** Authoritative tenant id from `ensureAgent`. Retained for log
   *  context and so future cross-agent observability hooks can correlate
   *  events back to the owning tenant; the URL is keyed on `agentId`. */
  tenantId: string;
  /** Authoritative agent id from `ensureAgent`. Used to build the
   *  per-agent SSE URL (`/api/v1/agents/{agentId}/schema/stream`) and as
   *  the defence-in-depth filter for incoming `schema_installed`
   *  payloads. The SDK plane is keyed on agent_id; the server resolves
   *  agent_id → tenant_id internally. */
  agentId: string;
  /** Pre-built admin HTTP client. Reused for `getLiveSchema(...)` so the
   *  subscriber inherits whatever auth + retry + TLS config the rest of
   *  the SDK uses (`X-API-Key`, retry-after handling, custom CA, ...).
   *  We do NOT construct a parallel fetch with hand-rolled auth — same
   *  destination, less code, no second credential surface. */
  adminHttp: AdminHttpClient;
  /** The schema active at init time. Used as the starting anchor so a
   *  refresh that observes a live version older than this value is
   *  flagged as an out-of-order broadcast (and ignored) rather than
   *  silently regressing the active schema. */
  localSchema: TenantSchema | null;
  /** Same shape as `init()`'s `logger` option. */
  logger: SchemaSubscriberLogger;
  /** Evaluator whose decision cache should be invalidated on incoming
   *  `policy` / `capability_effective_set_changed` /
   *  `capability_set_invalidate_all_scopes` events. Optional — when
   *  omitted (e.g. unit tests focused on schema events only) the
   *  policy/capability subscriber is skipped. Wired by `init.ts` to the
   *  same `CedarToolCallClient` the patches use, so an invalidation
   *  pushed by central reaches every in-process tool-call evaluation
   *  within ~100 ms instead of the 60s `ScopeIndexPopulator` floor. */
  cedarClient?: CedarToolCallClient;
}

// Mock type for tests: we only call `.close()` on the `EventSource`
// instance and `addEventListener` + `onerror` setter. Avoiding a hard
// `import type { EventSource } from "eventsource"` here would keep us
// fully decoupled from the polyfill, but the type-only import is erased
// by tsc and is therefore safe vs. the edge-entry grep (which scans
// runtime imports, not type-only ones).
type EventSourceLike = {
  addEventListener: (type: string, listener: (ev: { data: string }) => void) => void;
  close: () => void;
  onerror: ((ev: unknown) => void) | null;
};

/**
 * Module-level handle on the active subscriber. There is at most one per
 * process (init() is idempotent — see `init.ts:181`). Tests reset via
 * `__resetSchemaSubscriberForTest()`.
 */
let ACTIVE: SchemaSubscriber | null = null;

export class SchemaSubscriber {
  private es: EventSourceLike | null = null;
  // Second long-lived EventSource bound to the tenant-wide
  // `/api/v1/policy/stream`. Carries `policy`,
  // `capability_effective_set_changed`,
  // `capability_set_invalidate_all_scopes` (+ `lagged`) events from
  // `crates/agentum-api/src/routes/policy_distribution.rs::live_stream`.
  // Held separately from `es` because central exposes schema events on a
  // per-agent endpoint and policy/capability events on a tenant-wide one;
  // collapsing onto a single stream would require a server-side rework.
  private policyEs: EventSourceLike | null = null;
  private closed = false;
  private reconnectAttempts = 0;
  private policyReconnectAttempts = 0;
  private opts: SchemaSubscriberOptions | null = null;
  // Track the most-recently-applied schema so `reconcileVersions` on
  // subsequent events sees the latest local-side anchor.
  private currentSchema: TenantSchema | null = null;

  async start(opts: SchemaSubscriberOptions): Promise<void> {
    // Edge-runtime guard: non-Node runtimes don't have a usable
    // `eventsource` (the polyfill itself requires Node). Quiet no-op
    // preserves the universal-entry contract.
    if (
      typeof process === "undefined" ||
      !(process as { versions?: { node?: string } }).versions?.node
    ) {
      opts.logger.log(
        "[agentum] schema subscriber: non-node runtime; not starting",
      );
      return;
    }

    this.opts = opts;
    this.currentSchema = opts.localSchema;

    // Dynamic import keeps `eventsource` out of edge bundles per
    // `.claude/rules/typescript.md` §1 lazy-import contract.
    let EventSourceCtor: new (
      url: string,
      init?: { fetch?: unknown },
    ) => EventSourceLike;
    try {
      const mod = (await import("eventsource")) as {
        EventSource: typeof EventSourceCtor;
      };
      EventSourceCtor = mod.EventSource;
    } catch (err) {
      opts.logger.warn(
        `[agentum] schema subscriber: eventsource import failed: ${
          (err as Error).message
        }`,
      );
      return;
    }

    const url = `${opts.baseUrl.replace(/\/$/, "")}/api/v1/agents/${
      opts.agentId
    }/schema/stream`;

    // Auth: piggy-back on the `AdminHttpClient` request semantics by using
    // its private `fetch` field would be a layering violation. Instead we
    // wrap `globalThis.fetch` and inject the same `X-API-Key` header the
    // admin client already sends on every call. The token shape is
    // resolved once per connect; reconnects re-run the wrapper so a
    // future rotated key is picked up automatically.
    const apiKey = readAdminApiKey(opts.adminHttp);
    const fetchWrapper = async (
      target: string | URL,
      init: { headers: Record<string, string> } & Record<string, unknown>,
    ): Promise<unknown> => {
      const headers: Record<string, string> = { ...init.headers };
      if (apiKey) headers["X-API-Key"] = apiKey;
      return globalThis.fetch(target, { ...init, headers } as RequestInit);
    };

    try {
      this.es = new EventSourceCtor(url, { fetch: fetchWrapper });
    } catch (err) {
      opts.logger.warn(
        `[agentum] schema subscriber: connect failed: ${(err as Error).message}`,
      );
      return;
    }

    this.es.addEventListener("schema_installed", (ev) => {
      void this.handleEvent(ev.data, "schema_installed");
    });
    this.es.addEventListener("lagged", () => {
      // Force a refresh — server overflowed its broadcast queue and we
      // may have missed an install. Same code path as schema_installed
      // but without a payload to filter on.
      void this.refreshSchema("lagged");
    });
    this.es.onerror = () => {
      this.reconnectAttempts++;
      // Don't spam at warn/error: the polyfill auto-reconnects honouring
      // the server's `retry:` directive. A reconnect during an API
      // restart is expected and benign.
      opts.logger.log(
        `[agentum] schema subscriber: connection error (attempt ${this.reconnectAttempts}); auto-reconnecting`,
      );
    };

    // W05 — tenant-wide policy/capability stream. Only wired when the
    // caller supplied a `cedarClient`; tests that exercise schema-only
    // behavior can omit it and this block is a no-op. The two streams
    // are independent: a failure here must not tear down the schema
    // subscriber.
    if (opts.cedarClient) {
      const policyUrl = `${opts.baseUrl.replace(/\/$/, "")}/api/v1/policy/stream`;
      let policyEs: EventSourceLike | null = null;
      try {
        policyEs = new EventSourceCtor(policyUrl, { fetch: fetchWrapper });
      } catch (err) {
        opts.logger.warn(
          `[agentum] policy subscriber: connect failed: ${(err as Error).message}`,
        );
      }

      if (policyEs) {
        const cedarClient = opts.cedarClient;
        policyEs.addEventListener("policy", (ev) => {
          this.handlePolicyEvent(ev.data, cedarClient);
        });
        policyEs.addEventListener("capability_effective_set_changed", (ev) => {
          this.handleCapabilityChangedEvent(ev.data, cedarClient);
        });
        policyEs.addEventListener("capability_set_invalidate_all_scopes", () => {
          // Bulk-flush variant carries no payload. Drop every cached
          // decision; the next call repopulates from PDP / central.
          this.handleCapabilityInvalidateAll(cedarClient);
        });
        // PASS2-SDK-01 Item C — lifecycle fast-paths. Suspend already
        // propagates via the `policy` reload event (which invalidates the
        // decision cache + re-pulls a deny bundle), so these listeners are a
        // latency optimisation, not the only enforcement of suspend.
        policyEs.addEventListener("agent_suspended", (ev) => {
          this.handleAgentSuspended(ev.data, cedarClient);
        });
        policyEs.addEventListener("agent_activated", (ev) => {
          this.handleAgentActivated(ev.data, cedarClient);
        });
        policyEs.addEventListener("hitl_grant", (ev) => {
          this.handleHitlGrant(ev.data, cedarClient);
        });
        policyEs.addEventListener("lagged", () => {
          // Broadcast queue overflowed — we may have missed a policy or
          // capability event. Conservative reaction: drop the whole
          // decision cache.
          opts.logger.warn(
            "[agentum] policy subscriber: lagged event — invalidating decision cache",
          );
          cedarClient.invalidatePolicyCache();
          cedarClient.invalidateCapabilityCache();
        });
        policyEs.onerror = () => {
          this.policyReconnectAttempts++;
          opts.logger.log(
            `[agentum] policy subscriber: connection error (attempt ${this.policyReconnectAttempts}); auto-reconnecting`,
          );
        };
        this.policyEs = policyEs;
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-this-alias -- single-instance registry handle; close() resets ACTIVE === this
    ACTIVE = this;
  }

  /**
   * Handle a `policy` event from `/api/v1/policy/stream`. The payload
   * shape mirrors `UrgentEvent::Policy` — tenant-wide, no `agent_id`.
   * The client we're invalidating is bound to one agent, so a
   * tenant-wide policy churn always invalidates this client's cache.
   */
  private handlePolicyEvent(
    rawData: string,
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    let wire: PolicyWire;
    try {
      wire = JSON.parse(rawData) as PolicyWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: malformed policy payload: ${
          (err as Error).message
        }`,
      );
      // Conservative: invalidate anyway. A malformed event we can't
      // parse is still a signal that something changed; fail-CLOSED.
      cedarClient.invalidatePolicyCache();
      return;
    }
    cedarClient.invalidatePolicyCache();
    this.opts.logger.log(
      `[agentum] policy subscriber: invalidated cache on policy v${wire.version} (${wire.reason})`,
    );
  }

  /**
   * Handle a `capability_effective_set_changed` event. Payload shape:
   * `{ kind, scope_value, capability_set_hash }` — no `agent_id`, no
   * `scope_dimension`, so we invalidate the whole decision cache.
   */
  private handleCapabilityChangedEvent(
    rawData: string,
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    let wire: CapabilityEffectiveSetChangedWire;
    try {
      wire = JSON.parse(
        rawData,
      ) as CapabilityEffectiveSetChangedWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: malformed capability payload: ${
          (err as Error).message
        }`,
      );
      cedarClient.invalidateCapabilityCache();
      return;
    }
    cedarClient.invalidateCapabilityCache(wire.scope_value);
    this.opts.logger.log(
      `[agentum] policy subscriber: invalidated cache on capability change (scope=${wire.scope_value}, hash=${wire.capability_set_hash})`,
    );
  }

  /**
   * Handle a bulk `capability_set_invalidate_all_scopes` event. Drops
   * every cached decision since any scope's capabilities could have
   * shifted.
   */
  private handleCapabilityInvalidateAll(
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    cedarClient.invalidateCapabilityCache();
    this.opts.logger.log(
      "[agentum] policy subscriber: invalidated cache on capability_set_invalidate_all_scopes",
    );
  }

  /**
   * Handle an `agent_suspended` event. Tenant-guarded (`payload.tenant_id ===
   * cfg.tenantId`) and agent-guarded (the deny-set is keyed by agent_id and the
   * client ignores a mismatched agent) so a cross-tenant or cross-agent event
   * can never populate this client's local deny-set. Records the agent in the
   * evaluator's fail-CLOSED suspend deny-set so the next `evaluateToolCall`
   * denies in-process without a wasted round-trip.
   */
  private handleAgentSuspended(
    rawData: string,
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    let wire: AgentLifecycleWire;
    try {
      wire = JSON.parse(rawData) as AgentLifecycleWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: malformed agent_suspended payload: ${
          (err as Error).message
        }`,
      );
      return;
    }
    if (wire.tenant_id !== this.opts.tenantId) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: dropping cross-tenant agent_suspended (got ${wire.tenant_id}, expected ${this.opts.tenantId})`,
      );
      return;
    }
    cedarClient.markSuspended(wire.agent_id);
    this.opts.logger.log(
      `[agentum] policy subscriber: marked agent ${wire.agent_id} suspended (fail-closed deny-set)`,
    );
  }

  /**
   * Handle an `agent_activated` event. Tenant-guarded; clears the agent from
   * the evaluator's suspend deny-set so subsequent calls evaluate normally.
   */
  private handleAgentActivated(
    rawData: string,
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    let wire: AgentLifecycleWire;
    try {
      wire = JSON.parse(rawData) as AgentLifecycleWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: malformed agent_activated payload: ${
          (err as Error).message
        }`,
      );
      return;
    }
    if (wire.tenant_id !== this.opts.tenantId) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: dropping cross-tenant agent_activated (got ${wire.tenant_id}, expected ${this.opts.tenantId})`,
      );
      return;
    }
    cedarClient.clearSuspended(wire.agent_id);
    this.opts.logger.log(
      `[agentum] policy subscriber: cleared suspend deny-set for agent ${wire.agent_id}`,
    );
  }

  /**
   * Handle a `hitl_grant` event (GR-08). Tenant-guarded; pre-populates the
   * evaluator's `ApprovalGrantCache` with the canonical-JSON SHA-256
   * `args_hash` from the payload so the next identical tool call short-circuits
   * to `allow` without re-escalating. The grant key includes `args_hash`
   * (mirroring the PDP's `HitlGrantKey`), so an approval for one args shape
   * cannot unlock a different one. Derives the per-entry TTL from
   * `expires_at - now`; a non-positive remaining window is dropped.
   */
  private handleHitlGrant(
    rawData: string,
    cedarClient: CedarToolCallClient,
  ): void {
    if (this.closed || !this.opts) return;
    let wire: HitlGrantWire;
    try {
      wire = JSON.parse(rawData) as HitlGrantWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: malformed hitl_grant payload: ${
          (err as Error).message
        }`,
      );
      return;
    }
    if (wire.tenant_id !== this.opts.tenantId) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: dropping cross-tenant hitl_grant (got ${wire.tenant_id}, expected ${this.opts.tenantId})`,
      );
      return;
    }
    if (!wire.tool || !wire.args_hash) {
      this.opts.logger.warn(
        "[agentum] policy subscriber: hitl_grant missing tool / args_hash; ignoring",
      );
      return;
    }
    const expiresMs = Date.parse(wire.expires_at);
    if (Number.isNaN(expiresMs)) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: hitl_grant has unparseable expires_at "${wire.expires_at}"; ignoring`,
      );
      return;
    }
    const ttlMs = expiresMs - Date.now();
    if (ttlMs <= 0) {
      this.opts.logger.warn(
        `[agentum] policy subscriber: hitl_grant already expired (expires_at=${wire.expires_at}); ignoring`,
      );
      return;
    }
    cedarClient.recordApprovalGrantByHash({
      agentId: wire.agent_id,
      toolName: wire.tool,
      argsHash: wire.args_hash,
      ttlMs,
      requestId: wire.request_id,
    });
    this.opts.logger.log(
      `[agentum] policy subscriber: pre-populated HITL grant for ${wire.tool} (agent=${wire.agent_id}, expires=${wire.expires_at})`,
    );
  }

  private async handleEvent(
    rawData: string,
    source: "schema_installed",
  ): Promise<void> {
    if (this.closed || !this.opts) return;
    let wire: SchemaInstalledWire;
    try {
      wire = JSON.parse(rawData) as SchemaInstalledWire;
    } catch (err) {
      this.opts.logger.warn(
        `[agentum] schema subscriber: malformed ${source} payload: ${
          (err as Error).message
        }`,
      );
      return;
    }
    // Defence-in-depth: server-side agent scope filter is the source of
    // truth, but if a future refactor swaps the per-agent route for a
    // tenant-wide or global stream we don't want to silently apply a
    // cross-agent schema. Filter here too.
    if (wire.agent_id !== this.opts.agentId) {
      this.opts.logger.warn(
        `[agentum] schema subscriber: dropping cross-agent event (got ${wire.agent_id}, expected ${this.opts.agentId})`,
      );
      return;
    }
    await this.refreshSchema(`v${wire.version}`);
  }

  private async refreshSchema(reason: string): Promise<void> {
    if (this.closed || !this.opts) return;
    const opts = this.opts;
    try {
      const live = await getLiveSchema(opts.adminHttp, opts.agentId);
      // Refresh-time semantics differ from boot-time `reconcileVersions`:
      // boot is strict (`local < live` throws because the SDK would emit
      // unschema'd events). At refresh time we know init succeeded — a
      // bump from `currentSchema.version` → higher is the *expected*
      // case and we adopt it. A 404 (live === null) means the schema was
      // un-installed between events; we keep the current value and log,
      // matching the spec's "source of truth remains GET /schema" rule.
      // A version regression (live < current) we treat as an
      // out-of-order push (broadcast race or replay) and ignore.
      if (live === null) {
        opts.logger.warn(
          `[agentum] schema subscriber: live schema unavailable on refresh (${reason}); keeping v${
            this.currentSchema?.version ?? "?"
          }`,
        );
        return;
      }
      if (
        this.currentSchema &&
        live.version < this.currentSchema.version
      ) {
        opts.logger.warn(
          `[agentum] schema subscriber: ignoring out-of-order live v${live.version} < current v${this.currentSchema.version} (${reason})`,
        );
        return;
      }
      this.currentSchema = live;
      _setActiveSchema(live);
      opts.logger.log(
        `[agentum] schema subscriber: applied v${live.version} (${reason})`,
      );
    } catch (err) {
      // Refresh failures are non-fatal — keep listening so the next
      // event (or reconnect) recovers. The init-time fetch + the 60s
      // ScopeIndexPopulator tick remain as belt-and-suspenders.
      opts.logger.warn(
        `[agentum] schema subscriber: refresh failed (${reason}): ${
          (err as Error).message
        }`,
      );
    }
  }

  /** Idempotent close. Safe to call multiple times. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.es?.close();
    } catch {
      // ignore — close on an already-closed EventSource is fine
    }
    this.es = null;
    try {
      this.policyEs?.close();
    } catch {
      // ignore
    }
    this.policyEs = null;
    if (ACTIVE === this) ACTIVE = null;
  }
}

/**
 * Read the `apiKey` that the AdminHttpClient was configured with.
 * `apiKey` is `private readonly` on the class, but we already control
 * both sides of this edge (same package, same dist). The alternative is
 * to thread the api key separately through `SchemaSubscriberOptions`,
 * which adds another credential surface for callers to misconfigure.
 *
 * Returns `null` when the client is token-only (no api key).
 */
function readAdminApiKey(client: AdminHttpClient): string | null {
  const raw = (client as unknown as { apiKey: string | null }).apiKey;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Test-only: close any active subscriber and reset module state so a
 * subsequent test starts from a clean slate. Mirrors the pattern from
 * `pii/secrets.ts::_resetPiiSecretsForTests` and `enrichment` reset
 * helpers.
 */
export function __resetSchemaSubscriberForTest(): void {
  if (ACTIVE) {
    ACTIVE.close();
    ACTIVE = null;
  }
}
