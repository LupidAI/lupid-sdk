/**
 * HITL-8 — Autopatch / NextJS HITL honesty.
 *
 * The autopatch interceptors (OpenAI, Anthropic, fetch, node:http, MCP stdio)
 * and the NextJS middleware operate at the LLM/tool-call HTTP boundary and have
 * **no session context to suspend** — there is no per-request lifecycle these
 * planes can park while a human approves. So when a Cedar decision carries
 * `@advice("require_hitl")` (surfaced as `hitl_pending` or a `require_hitl`
 * advice string), human-approval enforcement is *unsupported in v1* on these
 * planes.
 *
 * The honest, safe posture (design §2.3 / §5, fix H-X2):
 *   - **Fail-CLOSED:** the deny STANDS. We never hang, never auto-retry, and
 *     never re-invoke the LLM. Re-invoking would produce a *different* tool
 *     call whose `args_hash` would not match any future grant — the H-X2
 *     hazard. The interceptor's existing deny rewrite is left untouched.
 *   - **Warn ONCE per plane:** emit a single `console.warn` naming the gap and
 *     pointing the operator at the planes that DO enforce human approval
 *     (Express/Fastify/NestJS guards, or repointing the LLM base URL through
 *     the R22 reverse proxy). The warn dedups so it never spams every call.
 *
 * To get human-approval enforcement, use the framework guards or R22 — see
 * `docs/architecture/HITL_PLANE_COVERAGE.md`.
 */

import { parseHitlAdvice } from "../types.js";

/**
 * Identifies the autopatch / middleware plane that observed the unsupported
 * `require_hitl` decision. Used as the dedup key so each plane warns at most
 * once per process.
 */
export type HitlUnsupportedPlane =
  | "openai"
  | "anthropic"
  | "fetch"
  | "node-http"
  | "mcp-stdio"
  | "nextjs";

/**
 * Per-plane dedup set. A plane that has already warned is skipped on every
 * subsequent call so a `require_hitl`-tagged tool invoked in a loop does not
 * spam the logs. Module-level so it survives across interceptor invocations
 * (the patches are process-singletons).
 */
const WARNED_PLANES = new Set<HitlUnsupportedPlane>();

/**
 * The decision shape these planes observe — only the fields needed to detect
 * an unsupported `require_hitl`. Both the autopatch evaluator
 * (`ToolCallEvaluation`) and the NextJS simulate response satisfy this.
 */
export interface HitlDecisionLike {
  decision: "allow" | "deny";
  /** Cedar `@advice(...)` strings from the decision. */
  advice?: string[] | undefined;
  /** Derived flag from HITL-1 (`AuthorizeResponse.hitl_pending`), when the
   *  evaluation plane surfaced it. Either signal triggers the warn. */
  hitlPending?: boolean | undefined;
}

/**
 * True when a deny decision carries a `require_hitl` directive — via the
 * derived `hitlPending` flag (HITL-1) OR a `require_hitl` advice string.
 * Only a `deny` can be HITL-pending; an `allow` (e.g. a live grant
 * short-circuit) never warns.
 */
export function isHitlPending(decision: HitlDecisionLike): boolean {
  if (decision.decision !== "deny") return false;
  if (decision.hitlPending === true) return true;
  return parseHitlAdvice(decision.advice) !== null;
}

/**
 * If `decision` is a `require_hitl` deny on a plane that cannot suspend a
 * session, emit the unsupported-gap warning ONCE for that plane. The deny is
 * unchanged by this call — the caller's existing fail-CLOSED rewrite still
 * runs. No-op when the decision is not HITL-pending or the plane already
 * warned.
 *
 * @returns `true` when a warning was emitted (first observation for the
 *          plane), `false` otherwise. Returning the flag keeps the function
 *          testable without spying on `console`.
 */
export function warnHitlUnsupportedOnce(
  plane: HitlUnsupportedPlane,
  decision: HitlDecisionLike,
  logger: Pick<Console, "warn"> = console,
): boolean {
  if (!isHitlPending(decision)) return false;
  if (WARNED_PLANES.has(plane)) return false;
  WARNED_PLANES.add(plane);
  logger.warn(
    `[agentum] ${plane}: autopatch HITL unsupported in v1 — the require_hitl ` +
      `policy was enforced as a DENY (fail-closed; the tool call was blocked ` +
      `and not retried). This plane has no session to suspend for human ` +
      `approval. Use Express/Fastify/NestJS guards or repoint via R22 to get ` +
      `human-approval enforcement.`,
  );
  return true;
}

/**
 * Test-only: clear the per-plane dedup set so each test observes the
 * first-warning behavior. Production code never calls this.
 */
export function __resetHitlUnsupportedWarnings(): void {
  WARNED_PLANES.clear();
}
