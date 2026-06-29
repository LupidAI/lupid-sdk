/**
 * Edge-compatible Next.js middleware.
 *
 * Usage (`middleware.ts` at project root):
 *
 * ```ts
 * import { AgentumClient } from "@lupid/sdk";
 * import { agentumMiddleware } from "@lupid/sdk/frameworks/nextjs";
 *
 * const runtime = new AgentumClient({ baseUrl: process.env.AGENTUM_BASE_URL!, apiKey: process.env.AGENTUM_API_KEY! });
 *
 * export default agentumMiddleware({
 *   runtime,
 *   agentId: process.env.AGENTUM_AGENT_ID!,
 *   userFromRequest: (req) => {
 *     const email = req.headers.get("x-demo-user");
 *     return email ? { id: email, email } : null;
 *   },
 * });
 *
 * export const config = { matcher: ["/api/:path*"] };
 * ```
 *
 * Runs in the Edge runtime per request. Stateless: no session pool, no
 * decision cache, no circuit breaker — those require long-lived state,
 * which the Edge runtime cannot guarantee (isolates may be recycled
 * between requests). For stateful gating, use `withAgentumGuard` in a
 * Node-runtime route handler.
 *
 * **Return value:** `undefined` means "allow through" (Next.js continues to
 * the matched route handler). A `Response` short-circuits — Next.js returns
 * it to the client without invoking the handler. This matches the Next.js
 * middleware contract exactly.
 *
 * If your Agentum endpoint is unreachable, this middleware fails **closed**
 * (403) by default. Override `onError` to change that policy.
 */

import { AgentumError } from "../../types.js";
import { warnHitlUnsupportedOnce } from "../../instrumentation/hitl-unsupported.js";
import type {
  AgentumNextMiddlewareOptions,
  GuardDecision,
  NextRequestLike,
} from "./types.js";

const JSON_HEADERS = { "content-type": "application/json" };

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/**
 * Build the default middleware. Returns a handler compatible with Next.js
 * App Router middleware: `(req) => Response | undefined | Promise<...>`.
 *
 * Returning `undefined` means "continue"; returning a `Response` short-
 * circuits with that response.
 */
export function agentumMiddleware(
  opts: AgentumNextMiddlewareOptions,
): (req: NextRequestLike) => Promise<Response | undefined> {
  if (!opts.runtime) {
    throw new AgentumError("agentumMiddleware: `runtime` is required");
  }
  if (!opts.agentId) {
    throw new AgentumError("agentumMiddleware: `agentId` is required");
  }
  if (typeof opts.userFromRequest !== "function") {
    throw new AgentumError("agentumMiddleware: `userFromRequest` must be a function");
  }

  const onUnauthenticated =
    opts.onUnauthenticated ?? (() => jsonResponse(401, { error: "unauthenticated" }));
  const onDeny =
    opts.onDeny ??
    ((_req, decision) =>
      jsonResponse(403, {
        error: "forbidden",
        rule_id: decision.rule_id,
        reason: decision.reason,
        source: decision.source,
      }));
  const onError =
    opts.onError ??
    ((_req, _err) => jsonResponse(503, { error: "policy_check_failed", fallback: "closed" }));

  return async (req: NextRequestLike): Promise<Response | undefined> => {
    // ── 1. Resolve user ────────────────────────────────────────────────────
    let user;
    try {
      user = await opts.userFromRequest(req);
    } catch (err) {
      return onError(req, err);
    }
    if (user === null) return onUnauthenticated(req);

    // ── 2. Derive (action, resource, context) ──────────────────────────────
    let derived: { action: string; resource: string; context?: Record<string, unknown> } | null;
    try {
      derived = opts.deriveRequest
        ? await opts.deriveRequest(req)
        : defaultDerive(req);
    } catch (err) {
      return onError(req, err);
    }
    // Caller opted the request out of authorization — pass through.
    if (derived === null) return undefined;

    // ── 3. simulatePolicy ──────────────────────────────────────────────────
    try {
      const result = await opts.runtime.simulatePolicy({
        agent_id: opts.agentId,
        action: derived.action,
        resource: derived.resource,
        ...(derived.context !== undefined ? { context: derived.context } : {}),
        user: { id: user.id, email: user.email, trust: user.trust ?? "trusted" },
      });

      if (result.outcome === "Allow") return undefined; // pass through

      // HITL-8: the NextJS (edge) plane has no session to suspend for human
      // approval. On a require_hitl deny, warn once then stand by the
      // fail-CLOSED deny — never hold the request, never re-simulate.
      warnHitlUnsupportedOnce("nextjs", {
        decision: "deny",
        advice: result.advice,
        hitlPending: result.hitl_pending,
      });

      const decision: GuardDecision = {
        allowed: false,
        outcome: "Deny",
        rule_id: result.rule_id,
        reason: result.reason,
        source: "network",
      };
      return onDeny(req, decision);
    } catch (err) {
      return onError(req, err);
    }
  };
}

/**
 * Default request derivation:
 *   action   = `http.<lowercase-method>`
 *   resource = `host` from the request URL
 *   context  = `{ path }`
 */
function defaultDerive(
  req: NextRequestLike,
): { action: string; resource: string; context: Record<string, unknown> } {
  const url = new URL(req.url);
  const action = `http.${req.method.toLowerCase()}`;
  const resource = url.host;
  const path = url.pathname;
  return { action, resource, context: { path } };
}
