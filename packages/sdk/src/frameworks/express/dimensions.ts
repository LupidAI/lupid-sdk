/**
 * Express middleware that primes the AgentumContext ALS store with
 * `request_header`-source dimensions extracted from the inbound request.
 *
 * For each `request_header`-source dimension in the active tenant schema,
 * the adapter looks up the header on `req.headers` (Node lowercases header
 * names on parse) and seeds the `dimensions` field on the per-request ALS
 * store via `withAgentumContext`. Downstream `resolveDimensions()` calls
 * within the request chain then see the values without needing the raw `req`
 * threaded through.
 *
 * Canonical Express ALS pattern: `next()` is invoked **inside** the
 * `withAgentumContext` callback so the AsyncLocalStorage `run` boundary
 * encloses every async hop in the remaining middleware chain. Calling
 * `next()` outside the callback would escape the run and lose the store.
 *
 * Pre-init pass-through: if `getActiveSchema()` throws (init hasn't
 * resolved), the adapter pass-throughs without priming any dimensions. This
 * matters for Express apps that mount middleware at module load before
 * awaiting `init()` — the resolver itself does not pass-through (calling
 * `resolveDimensions()` pre-init is a programmer error), but the adapter
 * does so it can be configured statically.
 *
 * Node-only. `frameworks/express/` is not reached from the universal
 * `src/index.ts` entry, so this file is allowed to compose with
 * `withAgentumContext` even though that module lazy-loads
 * `node:async_hooks` — edge runtimes downgrade to fn-only execution per the
 * `context.ts` contract.
 */

import { getActiveSchema } from "../../manifest/state.js";
import { withAgentumContext } from "../../instrumentation/context.js";

interface MinimalReq {
  headers?: Record<string, string | string[] | undefined>;
}
type MinimalNext = (err?: unknown) => void;

/**
 * Returns an Express-compatible middleware that primes the per-request ALS
 * store with `request_header`-sourced dimensions from the active schema.
 *
 * The returned handler intentionally uses minimal `req`/`next` types
 * (structural, not the full `express.RequestHandler`) so the SDK does not
 * pull `@types/express` into the dependency graph.
 */
export function agentumExpressAdapter(): (
  req: MinimalReq,
  res: unknown,
  next: MinimalNext,
) => void {
  return (req, _res, next) => {
    let schema;
    try {
      schema = getActiveSchema();
    } catch {
      // SDK not initialised yet — pass through without priming dimensions.
      next();
      return;
    }

    const headerDims: Record<string, string> = {};
    const headers = req.headers ?? {};
    for (const dim of schema.dimensions) {
      if (dim.source.kind !== "request_header") continue;
      const key = dim.source.header.toLowerCase();
      const raw = headers[key];
      if (typeof raw === "string") {
        headerDims[dim.name] = raw;
      } else if (Array.isArray(raw)) {
        const first = raw[0];
        if (typeof first === "string") headerDims[dim.name] = first;
      }
    }

    // `next()` MUST be invoked inside the `withAgentumContext` callback so
    // the ALS `run` boundary propagates to the remainder of the middleware
    // chain. See JSDoc above.
    withAgentumContext({ dimensions: headerDims }, () => next());
  };
}
