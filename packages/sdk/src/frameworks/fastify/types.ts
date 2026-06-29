/**
 * Public types for the Fastify framework integration.
 *
 * Duck-typed against `fastify` — the structural shapes here match the
 * `FastifyRequest`, `FastifyReply`, and `FastifyInstance` surfaces we need
 * without taking a runtime dependency on the `fastify` package. Callers can
 * pass real Fastify types and TypeScript will accept them.
 */

import type { AgentumClient } from "../../client.js";
import type { AgentumSession } from "../../session.js";
import type { DecisionCache } from "../express/decision-cache.js";
import type { CircuitBreaker } from "../express/circuit-breaker.js";
import type { HealthMonitor } from "../express/health-check.js";
import type {
  AgentumUser,
  CircuitBreakerOptions,
  DecisionCacheOptions,
  FailMode,
  GuardDecision,
  HealthCheckOptions,
  ResolvedAgentIdentity,
  SessionCacheOptions,
} from "../express/types.js";

// Re-export the shared primitives so consumers don't cross-import.
export type {
  AgentumUser,
  CircuitBreakerOptions,
  DecisionCacheOptions,
  FailMode,
  GuardDecision,
  HealthCheckOptions,
  ResolvedAgentIdentity,
  SessionCacheOptions,
} from "../express/types.js";

// ── Structural request / reply / instance ──────────────────────────────────────

/**
 * Structural subset of `FastifyRequest`. `FastifyRequest.url` is the full path
 * + query string (e.g. `/orders?limit=10`); the SDK derives `path` from it.
 */
export interface FastifyRequestLike {
  readonly method: string;
  readonly url: string;
  /** Route template, e.g. `/orders/:id`. Populated by Fastify after routing. */
  readonly routerPath?: string;
  readonly headers: Record<string, string | string[] | undefined>;
  agentum?: AgentumRequestContext;
}

/**
 * Structural subset of `FastifyReply`. Both `code()` and `status()` are
 * aliases in real Fastify; we expose both so callers' handlers and our
 * defaults can coexist.
 */
export interface FastifyReplyLike {
  code(status: number): FastifyReplyLike;
  status(status: number): FastifyReplyLike;
  send(body?: unknown): FastifyReplyLike | void;
  readonly sent?: boolean;
  statusCode?: number;
}

/**
 * Structural subset of `FastifyInstance`. We use `addHook` to register the
 * plugin-level `preHandler`, and optionally `decorateRequest` to add a typed
 * `agentum` accessor (best-effort — absent in very old Fastify versions).
 */
export interface FastifyInstanceLike {
  addHook(
    name: "preHandler" | "onClose",
    handler: (...args: unknown[]) => unknown,
  ): unknown;
  decorateRequest?(name: string, value: unknown): unknown;
}

// ── Agent + user binding ───────────────────────────────────────────────────────

/**
 * Context injected into `request.agentum` by the plugin. Mirrors the Express
 * shape so the same user-code can branch on `request.agentum?.session`.
 */
export interface AgentumRequestContext {
  session: AgentumSession;
  agentId: string;
  sessionId: string;
  tenantId?: string;
  user?: AgentumUser;
  /** @internal — do not depend on this shape. */
  _internals?: AgentumRequestInternals;
}

/** @internal */
export interface AgentumRequestInternals {
  agentId: string;
  user?: AgentumUser;
  decisionCache: DecisionCache | null;
  circuitBreaker: CircuitBreaker | null;
  healthMonitor: HealthMonitor | null;
  failMode: FailMode;
}

// ── Plugin options ─────────────────────────────────────────────────────────────

export interface AgentumFastifyPluginOptions {
  /** Pre-configured `AgentumClient` with `apiKey` set. */
  runtime?: AgentumClient;
  /** Alias for `runtime` (legacy name). */
  client?: AgentumClient;

  /** Pre-bound agent ID. Mutually exclusive with `resolveAgent`. */
  agentId?: string;

  /**
   * Resolve the agent identity per-request (legacy shape). If absent, the
   * plugin uses `agentId` from options. Return `{ agentId }` to pin an
   * existing agent, or `{ name, ownerEmail, purpose }` to auto-register.
   */
  resolveAgent?: (
    req: FastifyRequestLike,
  ) => ResolvedAgentIdentity | Promise<ResolvedAgentIdentity>;

  /**
   * Extract the authenticated user for the current request. Returning `null`
   * signals unauthenticated — the plugin calls `onUnauthenticated` (or 401
   * JSON by default) instead of minting a session.
   */
  userFromRequest?: (
    req: FastifyRequestLike,
  ) => AgentumUser | null | Promise<AgentumUser | null>;

  /** Called when `userFromRequest` returns `null`. Default: 401 JSON. */
  onUnauthenticated?: (req: FastifyRequestLike, reply: FastifyReplyLike) => void;
  /** Called when session mint throws. Default: 502 JSON. */
  onSessionMintError?: (err: unknown, req: FastifyRequestLike, reply: FastifyReplyLike) => void;

  /** Session LRU pool size. Default: `256`. */
  maxPoolSize?: number;
  sessionCache?: SessionCacheOptions;

  decisionCache?: DecisionCacheOptions;
  failMode?: FailMode;
  circuitBreaker?: CircuitBreakerOptions;
  healthCheck?: HealthCheckOptions;
}

/**
 * Shape of an `agentumGuard` call. A Fastify `preHandler` hook function is
 * returned — attach it to routes via `{ preHandler: agentumGuard({...}) }`.
 */
export interface AgentumGuardFastifyOptions {
  /** Cedar action string, e.g. `"http.get"`. */
  action: string;
  /** Cedar resource string. */
  resource: string;
  /** Path sent as `context.path`. Defaults to `request.routerPath` or URL path. */
  pathLike?: string | ((req: FastifyRequestLike) => string);
  /** Extra Cedar context — merged into `{ path }`. */
  contextExtra?: (req: FastifyRequestLike) => Record<string, unknown>;
  /** Called on Deny. Default: 403 JSON body. */
  onDeny?: (decision: GuardDecision, req: FastifyRequestLike, reply: FastifyReplyLike) => void;
  /** Bypass the decision cache. */
  skipCache?: boolean;
  /** Per-route fail-mode override. */
  failModeOverride?: FailMode;
  /** Task 1.5.9 (G37) — auto-escalate Deny+`require_hitl` to HITL. Default true. */
  autoEscalateHitl?: boolean;
  /** Hook invoked before `session.requestApproval()` fires. */
  onHitlRequested?: (
    info: import("../express/types.js").HitlRequestInfo,
    req: FastifyRequestLike,
  ) =>
    | import("../express/types.js").HitlRequestOverride
    | null
    | Promise<import("../express/types.js").HitlRequestOverride | null>;
}

/** The async preHandler function returned by `agentumGuard()`. */
export type FastifyPreHandler = (
  req: FastifyRequestLike,
  reply: FastifyReplyLike,
) => Promise<void>;

/**
 * The plugin wrapper returned by `agentumPlugin()`. Callable as a Fastify
 * plugin function and also exposes `close()` to tear down the background
 * health monitor / session pool on shutdown.
 */
export type AgentumFastifyPlugin = ((
  fastify: FastifyInstanceLike,
  opts: AgentumFastifyPluginOptions,
) => Promise<void>) & {
  close(): Promise<void>;
};
