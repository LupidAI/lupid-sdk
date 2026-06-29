/**
 * Drop-in auto-registering Agentum middleware + route-handler HOF for any
 * Next.js webapp (App Router or Pages API).
 *
 * Reduces customer-side onboarding code to roughly:
 *
 * ```ts
 * // middleware.ts
 * import { autoRegisterMiddleware } from "@lupid/sdk/frameworks/nextjs";
 * export default autoRegisterMiddleware();
 * export const config = { matcher: ["/api/:path*"] };
 *
 * // app/api/orders/route.ts
 * import { withAgentumAutoRegister } from "@lupid/sdk/frameworks/nextjs";
 * export const POST = withAgentumAutoRegister(async (req) => Response.json({...}));
 * ```
 *
 * The framework-agnostic counterpart of the Express `autoRegisterMiddleware`.
 * Reads config from `process.env` (`AGENTUM_BASE_URL`, `AGENTUM_API_KEY`,
 * `AGENTUM_AGENT_NAME`, `AGENTUM_AGENT_FRAMEWORK`, `AGENTUM_DECLARED_TOOLS`)
 * and lazily resolves the agent_id via the universal `ensureAgent()`
 * primitive.
 *
 * The resulting handler is compatible with **both** Next.js middleware
 * (Edge runtime) and App Router route handlers — it accepts a Web `Request`
 * and returns `Response | undefined`. For route handlers, prefer
 * `withAgentumAutoRegister(handler)` because it propagates the wrapped
 * handler's response through unchanged on Allow.
 *
 * **Edge-runtime caveat:** `ensureAgent()` performs a `fetch` to the Agentum
 * API. The Edge runtime supports `fetch`, but NOT long-lived state across
 * isolate boundaries. The agent_id resolution is therefore re-attempted
 * within each isolate's lifetime — the call is idempotent, so multiple
 * cold-starts simply hit the same row.
 */

import { AgentumError } from "../../types.js";
import { ensureAgent } from "../../ensure-agent.js";
import { agentumMiddleware } from "./middleware.js";
import type {
  AgentumNextMiddlewareOptions,
  AgentumUser,
  GuardDecision,
  NextRequestLike,
  NextRouteHandler,
  RouteHandlerContext,
} from "./types.js";
import { AgentumClient } from "../../client.js";

// ── Public API ─────────────────────────────────────────────────────────────

/** Per-instance overrides. See module doc; defaults read from `process.env`. */
export interface AutoRegisterMiddlewareOptions
  extends Omit<
    AgentumNextMiddlewareOptions,
    "runtime" | "agentId" | "userFromRequest"
  > {
  /** Defaults to `process.env.AGENTUM_BASE_URL`. */
  baseUrl?: string;
  /** Defaults to `process.env.AGENTUM_API_KEY`. */
  apiKey?: string;
  /** Stable agent name. Defaults to `process.env.AGENTUM_AGENT_NAME`. */
  agentName?: string;
  /** Pre-resolved UUID. Skips the `/sdk/register` roundtrip. */
  agentId?: string;
  /** Declared tools to sync. CSV string or string[]. */
  declaredTools?: string | string[];
  /** Framework label written on first-create. */
  framework?: string;
  /** Free-text purpose written on first-create. */
  purpose?: string;
  /**
   * Per-request user resolver. Defaults to:
   *   1. `x-user-id` (+ optional `x-user-email`) header — works for any
   *      reverse-proxy that injects the authenticated user as headers.
   *   2. `next-auth.session-token` cookie + dynamic `getServerSession()`
   *      lookup if `next-auth` is importable in the host runtime.
   *   3. Returns `null` (unauthenticated) if neither matches.
   *
   * Pass an explicit `null` to allow ALL requests through unauthenticated
   * (sessions become shared agent-wide).
   */
  userFromRequest?:
    | ((req: NextRequestLike) => AgentumUser | null | Promise<AgentumUser | null>)
    | null;
  /** Custom logger; defaults to `console`. */
  logger?: Pick<Console, "log" | "warn" | "error">;
  /** Test-only override of the universal `ensureAgent` primitive. */
  ensureAgentImpl?: typeof ensureAgent;
}

/** Options for `withAgentumAutoRegister`. Inherits the same shape. */
export type AutoRegisterRouteHandlerOptions = AutoRegisterMiddlewareOptions;

/**
 * Build the auto-registering Next.js middleware. Returns a handler suitable
 * for both `middleware.ts` (Edge) and arbitrary App Router route handlers
 * that want a one-line drop-in.
 */
export function autoRegisterMiddleware(
  options: AutoRegisterMiddlewareOptions = {},
): (req: NextRequestLike) => Promise<Response | undefined> {
  const logger = options.logger ?? console;

  const baseUrl = options.baseUrl ?? process.env.AGENTUM_BASE_URL;
  const apiKey = options.apiKey ?? process.env.AGENTUM_API_KEY;
  const agentName = options.agentName ?? process.env.AGENTUM_AGENT_NAME;
  const explicitAgentId = options.agentId ?? process.env.AGENTUM_AGENT_ID;

  if (!baseUrl || !apiKey || (!agentName && !explicitAgentId)) {
    logger.log(
      "[agentum] autoRegisterMiddleware: env not configured (need AGENTUM_BASE_URL, " +
        "AGENTUM_API_KEY, AGENTUM_AGENT_NAME) — installing pass-through middleware",
    );
    return async () => undefined;
  }

  const ensureAgentFn = options.ensureAgentImpl ?? ensureAgent;
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

  // Eager kick-off — Node runtime only. In the Edge runtime this still works
  // (fetch is available); errors are deferred to the per-request resolver.
  resolveAgentId().catch((err) => {
    logger.warn(
      `[agentum] eager registration failed (will retry on first request): ${
        (err as Error).message
      }`,
    );
  });

  installDrainHandlers(logger);

  // ── User resolver ────────────────────────────────────────────────────────
  const userResolver: NonNullable<AgentumNextMiddlewareOptions["userFromRequest"]> =
    options.userFromRequest === null
      ? () => ({ id: "anonymous", email: "anonymous@unknown.local" })
      : options.userFromRequest ?? defaultUserFromRequest;

  // ── Build a per-call middleware bound to the resolved agentId ────────────
  // We can't call `agentumMiddleware` until we have an agentId, but each call
  // is cheap (just builds a closure) and we want to preserve the underlying
  // simulate/error semantics. So we lazily build it once and cache.
  let bound: ((req: NextRequestLike) => Promise<Response | undefined>) | null = null;

  return async (req: NextRequestLike): Promise<Response | undefined> => {
    let agentId: string;
    try {
      agentId = await resolveAgentId();
    } catch (err) {
      logger.warn(
        `[agentum] autoRegisterMiddleware: registration failed for this request: ${
          (err as Error).message
        }`,
      );
      // Fail-open: pass the request through. Customer-side onError can be
      // installed for stricter behaviour.
      return undefined;
    }

    if (!bound) {
      const buildOpts: AgentumNextMiddlewareOptions = {
        runtime,
        agentId,
        userFromRequest: userResolver,
        ...(options.deriveRequest ? { deriveRequest: options.deriveRequest } : {}),
        ...(options.matcher !== undefined ? { matcher: options.matcher } : {}),
        ...(options.onUnauthenticated ? { onUnauthenticated: options.onUnauthenticated } : {}),
        ...(options.onDeny ? { onDeny: options.onDeny } : {}),
        ...(options.onError ? { onError: options.onError } : {}),
      };
      bound = agentumMiddleware(buildOpts);
    }
    return bound(req);
  };
}

/**
 * Higher-order function for App Router route handlers. Wraps a handler so
 * that authorization runs first; on Allow the wrapped handler is invoked
 * and its `Response` is returned unchanged. On Deny / unauthenticated /
 * error the auto-register middleware's response is returned instead.
 */
export function withAgentumAutoRegister<
  Req extends NextRequestLike = NextRequestLike,
  Ctx extends RouteHandlerContext = RouteHandlerContext,
>(
  handler: NextRouteHandler<Req, Ctx>,
  options: AutoRegisterRouteHandlerOptions = {},
): NextRouteHandler<Req, Ctx> {
  const middleware = autoRegisterMiddleware(options);
  return async (req: Req, ctx: Ctx): Promise<Response> => {
    const denial = await middleware(req);
    if (denial) return denial;
    return handler(req, ctx);
  };
}

// ── Internal helpers ─────────────────────────────────────────────────────

/**
 * Default user resolver — header-based first (works for any reverse-proxy
 * that injects the authenticated user), with a graceful fallback to NextAuth
 * if the host has it installed.
 */
async function defaultUserFromRequest(
  req: NextRequestLike,
): Promise<AgentumUser | null> {
  const headerId = req.headers.get("x-user-id");
  if (headerId) {
    const headerEmail = req.headers.get("x-user-email") ?? `${headerId}@unknown.local`;
    return { id: headerId, email: headerEmail };
  }

  // Optional NextAuth lookup — only fires if the host has next-auth installed.
  // Wrapped in a guarded import so callers without next-auth don't pay the
  // dependency cost.
  const sessionCookie =
    req.headers.get("cookie")?.includes("next-auth.session-token") ||
    req.headers.get("cookie")?.includes("__Secure-next-auth.session-token");
  if (sessionCookie) {
    try {
      const mod = (await tryImport("next-auth/next")) as
        | { getServerSession?: () => Promise<{ user?: { id?: string; email?: string } } | null> }
        | null;
      const getServerSession = mod?.getServerSession;
      if (typeof getServerSession === "function") {
        const session = await getServerSession();
        if (session?.user?.email) {
          const id = session.user.id ?? session.user.email;
          return { id, email: session.user.email };
        }
      }
    } catch {
      /* next-auth not present — drop through */
    }
  }
  return null;
}

async function tryImport(spec: string): Promise<unknown | null> {
  try {
    // Indirect to avoid bundlers resolving at compile time.
    const dynamicImport = new Function("s", "return import(s)") as (
      s: string,
    ) => Promise<unknown>;
    return await dynamicImport(spec);
  } catch {
    return null;
  }
}

const DRAIN_TIMEOUT_MS = 5000;

let drainInstalled = false;

function installDrainHandlers(
  logger: Pick<Console, "log" | "warn" | "error">,
): void {
  if (drainInstalled) return;
  // `process` is undefined in Edge runtime; gate accordingly.
  if (typeof process === "undefined" || typeof process.once !== "function") return;
  drainInstalled = true;
  let closeStarted = false;
  const drain = (signal: string): void => {
    if (closeStarted) return;
    closeStarted = true;
    const timer = setTimeout(() => {
      logger.warn(
        `[agentum] drain timed out after ${DRAIN_TIMEOUT_MS}ms on ${signal}`,
      );
      process.exit(0);
    }, DRAIN_TIMEOUT_MS);
    timer.unref();
  };
  process.once("SIGTERM", () => drain("SIGTERM"));
  process.once("SIGINT", () => drain("SIGINT"));
}

// Re-export the deny decision shape for ergonomic typing in caller-supplied
// `onDeny` overrides.
export type { GuardDecision };

// Re-export so callers don't have to dig into the framework types.
export { AgentumError };
