/**
 * Drop-in auto-registering Agentum plugin for any Fastify webapp.
 *
 * Reduces customer-side onboarding code to roughly:
 *
 * ```ts
 * import { autoRegisterPlugin } from "@lupid/sdk/frameworks/fastify";
 * await app.register(autoRegisterPlugin);
 * ```
 *
 * The framework-agnostic counterpart of the Express `autoRegisterMiddleware`.
 * Reads config from `process.env` (`AGENTUM_BASE_URL`, `AGENTUM_API_KEY`,
 * `AGENTUM_AGENT_NAME`, `AGENTUM_AGENT_FRAMEWORK`, `AGENTUM_DECLARED_TOOLS`)
 * and lazily resolves the agent_id via the universal `ensureAgent()`
 * primitive. The wrapped `agentumPlugin` is registered exactly once after
 * resolution; on missing env vars the plugin installs a no-op preHandler
 * so non-Agentum dev environments boot unchanged.
 */

import { AgentumClient } from "../../client.js";
import { ensureAgent } from "../../ensure-agent.js";
import { agentumPlugin } from "./index.js";
import type {
  AgentumFastifyPlugin,
  AgentumFastifyPluginOptions,
  AgentumUser,
  FastifyInstanceLike,
  FastifyRequestLike,
} from "./types.js";

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Per-instance overrides. Almost every deployment leaves these unset and
 * lets `process.env` drive everything — the overrides exist for tests and
 * for embedding in webapps that read config from somewhere other than env
 * vars.
 */
export interface AutoRegisterPluginOptions
  extends Omit<
    AgentumFastifyPluginOptions,
    "runtime" | "client" | "agentId" | "resolveAgent" | "userFromRequest"
  > {
  /** Defaults to `process.env.AGENTUM_BASE_URL`. */
  baseUrl?: string;
  /** Defaults to `process.env.AGENTUM_API_KEY`. */
  apiKey?: string;
  /** Stable agent name. Defaults to `process.env.AGENTUM_AGENT_NAME`. */
  agentName?: string;
  /**
   * Pre-resolved UUID. When set, the preset skips the `/sdk/register`
   * roundtrip. Useful for tests and for back-compat with deployments that
   * still ship the legacy `AGENTUM_AGENT_ID` env.
   */
  agentId?: string;
  /** Declared tools to sync. CSV string or string[]. Defaults to parsing
   *  `process.env.AGENTUM_DECLARED_TOOLS` if set. */
  declaredTools?: string | string[];
  /** Framework label written to the agent row on first-create. Defaults
   *  to `process.env.AGENTUM_AGENT_FRAMEWORK` or `'agentum-sdk'`. */
  framework?: string;
  /** Free-text purpose written to the agent row on first-create. */
  purpose?: string;
  /**
   * Per-request user resolver. Defaults to a Fastify-flavoured Passport
   * convention (`request.user.{id, email}`) — works unchanged across
   * `@fastify/passport`, `@fastify/jwt`, and most custom auth plugins.
   * Pass an explicit `null` to disable per-user session binding.
   */
  userFromRequest?:
    | ((req: FastifyRequestLike) => AgentumUser | null | Promise<AgentumUser | null>)
    | null;
  /** Custom logger; defaults to `console`. */
  logger?: Pick<Console, "log" | "warn" | "error">;
  /**
   * Override the `ensureAgent` implementation. Test-only; production code
   * should leave this unset.
   */
  ensureAgentImpl?: typeof ensureAgent;
}

/**
 * Build the auto-registering Agentum Fastify plugin. The returned value is
 * a Fastify plugin function (callable as `app.register(autoRegisterPlugin)`)
 * with a `close()` method that tears down the underlying session pool +
 * health monitor on shutdown.
 */
export function autoRegisterPlugin(
  options: AutoRegisterPluginOptions = {},
): AgentumFastifyPlugin {
  const logger = options.logger ?? console;

  const baseUrl = options.baseUrl ?? process.env.AGENTUM_BASE_URL;
  const apiKey = options.apiKey ?? process.env.AGENTUM_API_KEY;
  const agentName = options.agentName ?? process.env.AGENTUM_AGENT_NAME;
  const explicitAgentId = options.agentId ?? process.env.AGENTUM_AGENT_ID;
  const ensureAgentFn = options.ensureAgentImpl ?? ensureAgent;

  if (!baseUrl || !apiKey || (!agentName && !explicitAgentId)) {
    logger.log(
      "[agentum] autoRegisterPlugin: env not configured (need AGENTUM_BASE_URL, " +
        "AGENTUM_API_KEY, AGENTUM_AGENT_NAME) — installing no-op plugin",
    );
    return makeNoopPlugin();
  }

  const runtime = new AgentumClient({ baseUrl, apiKey });

  // ── Lazy agent_id resolution ─────────────────────────────────────────────
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
      const fwk = options.framework ?? process.env.AGENTUM_AGENT_FRAMEWORK;
      if (fwk !== undefined) ensureOpts.framework = fwk;
      if (options.purpose !== undefined) ensureOpts.purpose = options.purpose;
      const tools = options.declaredTools ?? process.env.AGENTUM_DECLARED_TOOLS;
      if (tools !== undefined) ensureOpts.declaredTools = tools;
      const result = await ensureAgentFn(ensureOpts);
      resolvedAgentId = result.agentId;
      return resolvedAgentId;
    })().catch((err) => {
      resolveInflight = null;
      throw err;
    });
    return resolveInflight;
  };

  // Eager kick-off so the first inbound request doesn't pay registration latency.
  resolveAgentId().catch((err) => {
    logger.warn(
      `[agentum] eager registration failed (will retry on first request): ${
        (err as Error).message
      }`,
    );
  });

  // ── User resolver ────────────────────────────────────────────────────────
  const userResolver:
    | ((req: FastifyRequestLike) => AgentumUser | null | Promise<AgentumUser | null>)
    | undefined =
    options.userFromRequest === null
      ? undefined
      : options.userFromRequest ?? defaultUserFromRequest;

  // ── Wrap the underlying agentumPlugin ────────────────────────────────────
  const inner = agentumPlugin();

  // Carry over forwardable options (caches, fail-mode, etc.) but strip the
  // ones we own (`runtime`, `agentId`, `resolveAgent`, `userFromRequest`).
  const passThrough: AgentumFastifyPluginOptions = {
    runtime,
    resolveAgent: async () => ({ agentId: await resolveAgentId() }),
    ...(userResolver ? { userFromRequest: userResolver } : {}),
    ...(options.maxPoolSize !== undefined ? { maxPoolSize: options.maxPoolSize } : {}),
    ...(options.sessionCache ? { sessionCache: options.sessionCache } : {}),
    ...(options.decisionCache ? { decisionCache: options.decisionCache } : {}),
    ...(options.failMode ? { failMode: options.failMode } : {}),
    ...(options.circuitBreaker ? { circuitBreaker: options.circuitBreaker } : {}),
    ...(options.healthCheck ? { healthCheck: options.healthCheck } : {}),
    ...(options.onUnauthenticated ? { onUnauthenticated: options.onUnauthenticated } : {}),
    ...(options.onSessionMintError ? { onSessionMintError: options.onSessionMintError } : {}),
  };

  const plugin = Object.assign(
    async (fastify: FastifyInstanceLike, _opts: AgentumFastifyPluginOptions = {}): Promise<void> => {
      await inner(fastify, passThrough);
    },
    {
      async close(): Promise<void> {
        await inner.close();
      },
    },
  ) as AgentumFastifyPlugin;

  installDrainHandlers(plugin, logger);

  return plugin;
}

// ── Internal helpers ─────────────────────────────────────────────────────

/**
 * Default user resolver — keys off `request.user.{id, email}`. Matches the
 * `@fastify/passport` and `@fastify/jwt` conventions out of the box.
 */
function defaultUserFromRequest(req: FastifyRequestLike): AgentumUser | null {
  const u = (req as unknown as { user?: { id?: string | number; email?: string } }).user;
  if (!u || u.id === undefined || u.id === null) return null;
  const id = String(u.id);
  return {
    id,
    email: u.email ?? `${id}@unknown.local`,
  };
}

function makeNoopPlugin(): AgentumFastifyPlugin {
  const plugin = Object.assign(
    async (_fastify: FastifyInstanceLike, _opts: AgentumFastifyPluginOptions): Promise<void> => {
      /* no-op — Agentum env not configured */
    },
    {
      async close(): Promise<void> {
        /* no-op */
      },
    },
  ) as AgentumFastifyPlugin;
  return plugin;
}

const DRAIN_TIMEOUT_MS = 5000;

function installDrainHandlers(
  plugin: AgentumFastifyPlugin,
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
      .then(() => plugin.close())
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
