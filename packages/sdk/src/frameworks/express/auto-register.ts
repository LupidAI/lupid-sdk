/**
 * Drop-in auto-registering Agentum middleware for any Express webapp.
 *
 * Reduces customer-side onboarding code to roughly:
 *
 * ```js
 * const { autoRegisterMiddleware } = require('@lupid/sdk/frameworks/express');
 * router.use(autoRegisterMiddleware());
 * ```
 *
 * This is the generic counterpart to `agentumMiddleware`. It is
 * **framework-agnostic** — LibreChat, Express copilots,
 * custom internal tools, vanilla Express agents — they all use the
 * same call. The only Express-specific bit is the HTTP middleware
 * shape itself; FastAPI / Fastify / NestJS / NextJS adapters call the
 * underlying `ensureAgent()` primitive (in `@lupid/sdk`) the same way.
 *
 * What this preset bakes in:
 *
 *   1. Reads config from `process.env` (no SDK constructor required).
 *      Same env var names work for any other adapter: `AGENTUM_BASE_URL`,
 *      `AGENTUM_API_KEY`, `AGENTUM_AGENT_NAME`, `AGENTUM_DECLARED_TOOLS`,
 *      `AGENTUM_AGENT_FRAMEWORK`.
 *   2. Lazy `ensureAgent()` call — name → agent_id resolution is
 *      idempotent + retried on failure + cached after first success.
 *   3. Optional declared_tools sync (server diffs caller-supplied vs
 *      stored, patches in place).
 *   4. Default `userFromRequest` follows the Passport / JWT convention
 *      (`req.user.{id, email}`) — works unchanged across virtually every
 *      passport-based Express app. Override via the `userFromRequest`
 *      option for non-Passport apps; pass `null` to disable per-user
 *      session binding entirely.
 *   5. SIGTERM / SIGINT graceful session-pool drain (5s cap).
 *
 * When required env vars are missing the preset returns a no-op
 * middleware so non-Agentum dev environments boot unchanged. The
 * decision is logged once on process start so operators can confirm
 * whether the integration is live.
 */

import { AgentumClient } from "../../client.js";
import { ensureAgent } from "../../ensure-agent.js";
import { agentumMiddleware } from "./index.js";
import type {
  AgentumMiddleware,
  AgentumNext,
  AgentumRequest,
  AgentumResponse,
  AgentumUser,
} from "./types.js";

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Per-instance overrides. Almost every deployment leaves these unset and
 * lets `process.env` drive everything — the overrides exist for tests
 * and for embedding in webapps that read config from somewhere other
 * than env vars.
 */
export interface AutoRegisterOptions {
  /** Defaults to `process.env.AGENTUM_BASE_URL`. */
  baseUrl?: string;
  /** Defaults to `process.env.AGENTUM_API_KEY`. */
  apiKey?: string;
  /** Stable agent name. Defaults to `process.env.AGENTUM_AGENT_NAME`. */
  agentName?: string;
  /**
   * Pre-resolved UUID. When set, the preset skips the `/sdk/register`
   * roundtrip. Useful for tests and for back-compat with deployments
   * that still ship the legacy `AGENTUM_AGENT_ID` env.
   */
  agentId?: string;
  /** Declared tools to sync. CSV string or string[]. Defaults to
   *  parsing `process.env.AGENTUM_DECLARED_TOOLS` if set. */
  declaredTools?: string | string[];
  /** Framework label written to the agent row on first-create. Examples
   *  matching the Agentum dashboard chips: `'langchain'`, `'langgraph'`,
   *  `'autogen'`, `'crewai'`, `'openai'`, `'anthropic'`, `'llamaindex'`,
   *  `'custom'`. Defaults to `process.env.AGENTUM_AGENT_FRAMEWORK` or
   *  `'agentum-sdk'`. */
  framework?: string;
  /** Free-text purpose written to the agent row on first-create.
   *  Defaults to `'Agentum SDK auto-registered agent'`. */
  purpose?: string;
  /**
   * Per-request user resolver. Defaults to the Passport / JWT convention
   * (`req.user.{id, email}`). Pass an explicit `null` to disable user
   * binding entirely (sessions become shared agent-wide rather than
   * scoped per end-user).
   */
  userFromRequest?:
    | ((req: AgentumRequest) => AgentumUser | null | Promise<AgentumUser | null>)
    | null;
  /** Custom logger; defaults to `console`. */
  logger?: Pick<Console, "log" | "warn" | "error">;
}

/**
 * Build the auto-registering Agentum middleware. See module doc.
 */
export function autoRegisterMiddleware(
  options: AutoRegisterOptions = {},
): AgentumMiddleware {
  const logger = options.logger ?? console;

  const baseUrl = options.baseUrl ?? process.env.AGENTUM_BASE_URL;
  const apiKey = options.apiKey ?? process.env.AGENTUM_API_KEY;
  const agentName = options.agentName ?? process.env.AGENTUM_AGENT_NAME;
  const explicitAgentId = options.agentId ?? process.env.AGENTUM_AGENT_ID;

  if (!baseUrl || !apiKey || (!agentName && !explicitAgentId)) {
    logger.log(
      "[agentum] autoRegisterMiddleware: env not configured (need AGENTUM_BASE_URL, " +
        "AGENTUM_API_KEY, AGENTUM_AGENT_NAME) — installing no-op middleware",
    );
    return makeNoopMiddleware();
  }

  const runtime = new AgentumClient({ baseUrl, apiKey });

  // ── Lazy agent_id resolution via the universal primitive ─────────────────
  let resolvedAgentId: string | null = explicitAgentId ?? null;
  let resolveInflight: Promise<string> | null = null;

  const resolveAgentId = async (): Promise<string> => {
    if (resolvedAgentId) return resolvedAgentId;
    if (resolveInflight) return resolveInflight;

    resolveInflight = (async () => {
      const ensureOpts: import("../../ensure-agent.js").EnsureAgentOptions = {
        baseUrl,
        apiKey,
        name: agentName!,
        sharedUserModel: true,
        logger,
      };
      if (options.framework !== undefined) ensureOpts.framework = options.framework;
      if (options.purpose !== undefined) ensureOpts.purpose = options.purpose;
      if (options.declaredTools !== undefined)
        ensureOpts.declaredTools = options.declaredTools;
      const result = await ensureAgent(ensureOpts);
      resolvedAgentId = result.agentId;
      return resolvedAgentId;
    })().catch((err) => {
      // Don't pin a poison value — allow retry on the next request.
      resolveInflight = null;
      throw err;
    });
    return resolveInflight;
  };

  // Eager kick-off so the first inbound request doesn't pay the
  // registration latency. Errors are deferred to the per-request resolver.
  resolveAgentId().catch((err) => {
    logger.warn(
      `[agentum] eager registration failed (will retry on first request): ${
        (err as Error).message
      }`,
    );
  });

  // ── User resolver: default to Passport convention ────────────────────────
  // Set to `null` explicitly in options to disable per-user session binding.
  const userResolver:
    | ((req: AgentumRequest) => AgentumUser | null | Promise<AgentumUser | null>)
    | undefined =
    options.userFromRequest === null
      ? undefined
      : options.userFromRequest ?? defaultUserFromRequest;

  // ── Wrap the generic express middleware ──────────────────────────────────
  const middleware = agentumMiddleware({
    runtime,
    resolveAgent: async () => {
      const agentId = await resolveAgentId();
      return { agentId };
    },
    ...(userResolver ? { userFromRequest: userResolver } : {}),
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────
  installDrainHandlers(middleware, logger);

  return middleware;
}

// ── Internal helpers ─────────────────────────────────────────────────────

/**
 * Default user resolver — keys off `req.user.{id, email}`, the shape
 * Passport.js + every common Express JWT auth middleware produces.
 * Returns `null` for unauthenticated requests so the upstream
 * `agentumMiddleware` routes them through `onUnauthenticated`.
 */
function defaultUserFromRequest(req: AgentumRequest): AgentumUser | null {
  const u = (req as unknown as { user?: { id?: string | number; email?: string } }).user;
  if (!u || u.id === undefined || u.id === null) return null;
  const id = String(u.id);
  return {
    id,
    email: u.email ?? `${id}@unknown.local`,
  };
}

function makeNoopMiddleware(): AgentumMiddleware {
  const handler = (
    _req: AgentumRequest,
    _res: AgentumResponse,
    next: AgentumNext,
  ) => {
    next();
  };
  return Object.assign(handler, {
    async close(): Promise<void> {
      /* no-op */
    },
  });
}

/**
 * Hook SIGTERM (Docker stop) and SIGINT (Ctrl-C in dev) so the per-user
 * session pool drains cleanly on shutdown. Without this, every container
 * restart leaves a generation of ACTIVE rows in the Agentum `sessions`
 * table.
 *
 * Capped at 5s so a slow Agentum API doesn't block container shutdown
 * past Docker's 10s default stop timeout.
 */
const DRAIN_TIMEOUT_MS = 5000;

function installDrainHandlers(
  middleware: AgentumMiddleware,
  logger: Pick<Console, "log" | "warn" | "error">,
): void {
  let closeStarted = false;
  const drain = (signal: string): void => {
    if (closeStarted) return;
    closeStarted = true;
    const timer = setTimeout(() => {
      logger.warn(
        `[agentum] session pool drain timed out after ${DRAIN_TIMEOUT_MS}ms on ${signal}`,
      );
      process.exit(0);
    }, DRAIN_TIMEOUT_MS);
    timer.unref();
    Promise.resolve()
      .then(() =>
        typeof middleware.close === "function" ? middleware.close() : undefined,
      )
      .catch((err) => {
        logger.warn(
          `[agentum] session pool drain error on ${signal}: ${
            (err as Error)?.message ?? err
          }`,
        );
      })
      .finally(() => {
        clearTimeout(timer);
      });
  };
  process.once("SIGTERM", () => drain("SIGTERM"));
  process.once("SIGINT", () => drain("SIGINT"));
}
