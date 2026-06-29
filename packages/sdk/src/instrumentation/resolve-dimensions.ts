/**
 * Per-event dimension resolution pipeline.
 *
 * Reads the active tenant schema, walks every declared `Dimension`, and
 * produces the resolved `Record<string, string | null>` consumed by audit
 * emitters (cedar-client.ts, the ring-buffer). Four source kinds:
 *
 *   - `context`         — read from `getAgentumContext().dimensions[path]`
 *   - `request_header`  — read from `opts.request.headers[header.toLowerCase()]`
 *   - `derived`         — `evaluateTemplate(template, resolved-so-far)`
 *   - `enrichment`      — resolved via the enrichment client
 *
 * After per-dimension resolution and optional PII masking, a post-pass
 * enforces `required` + `when_missing`: missing required values with
 * `when_missing: "reject"` (the default) throw `RequiredDimensionMissingError`.
 * `when_missing: "null"` and `when_missing: "default"` both leave the slot
 * null — `default` semantics are encoded inside the derived template itself
 * via `| default "X"`.
 *
 * The resolution stages happen in declaration order. This function runs once
 * per audit event; there is no per-request cache today.
 *
 * Throws `InitError` from `getActiveSchema()` if `init()` has not run.
 */

import { getActiveSchema } from "../manifest/state.js";
import { getAgentumContext } from "./context.js";
import type { Dimension, TenantSchema } from "../manifest/types.js";
import { evaluateTemplate } from "./derived-template.js";
import { resolveEnrichment } from "../enrichment/client.js";
import { applyPii } from "../pii/mask.js";

export class RequiredDimensionMissingError extends Error {
  public readonly dimension: string;
  constructor(dimension: string) {
    super(`agentum.resolveDimensions: required dimension '${dimension}' missing`);
    this.name = "RequiredDimensionMissingError";
    this.dimension = dimension;
  }
}

/** Optional per-call inputs. ALS context is read implicitly via
 *  `getAgentumContext()` — no `als` parameter. */
export interface ResolveOptions {
  /** Inbound HTTP request, when the caller is on the inbound edge (Express
   *  adapter path or any handler that has the raw `req.headers`). */
  request?: { headers: Record<string, string | string[] | undefined> };
}

function readHeader(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string,
): string | null {
  if (!headers) return null;
  const v = headers[name.toLowerCase()];
  if (typeof v === "string") return v;
  if (Array.isArray(v)) {
    const first = v[0];
    return typeof first === "string" ? first : null;
  }
  return null;
}

async function resolveSingleDimension(
  dim: Dimension,
  ctxDims: Record<string, string>,
  resolvedSoFar: Record<string, string | null>,
  request: ResolveOptions["request"],
  schema: TenantSchema,
): Promise<string | null> {
  switch (dim.source.kind) {
    case "context": {
      const raw = ctxDims[dim.source.path];
      return typeof raw === "string" ? raw : null;
    }
    case "request_header": {
      // Two-stage lookup: the Express adapter pre-extracts headers and primes
      // them into the ALS `dimensions` slot under the dimension's own `name`
      // (so downstream code without `req` still sees them). Fall back to the
      // raw `req.headers` if the caller threaded `opts.request` directly.
      const fromCtx = ctxDims[dim.name];
      if (typeof fromCtx === "string") return fromCtx;
      return readHeader(request?.headers, dim.source.header);
    }
    case "derived":
      return evaluateTemplate(dim.source.template, resolvedSoFar);
    case "enrichment":
      return resolveEnrichment(dim.source.enrichment_ref, resolvedSoFar, schema);
    default: {
      // Exhaustiveness — `Source.kind` covers all four arms above.
      const _exhaustive: never = dim.source;
      void _exhaustive;
      return null;
    }
  }
}

/**
 * Resolve all schema-declared dimensions for the current event.
 *
 * Async because `applyPii` performs real HMAC-SHA256 / AES-256-GCM
 * crypto. Per-dimension overhead is typically <50µs; callers must await once
 * per call. The resolver itself does NO caching today — every audit-emit site
 * walks the full schema.
 *
 * Reads per-request ALS context implicitly via `getAgentumContext()`.
 * Throws `InitError` if `init()` has not run. Throws
 * `RequiredDimensionMissingError` when a required dimension's source yields
 * `null` and `when_missing` is `"reject"` (the default).
 */
export async function resolveDimensions(
  opts: ResolveOptions = {},
): Promise<Record<string, string | null>> {
  const schema = getActiveSchema();
  const ctx = getAgentumContext();
  const ctxDims = ctx.dimensions ?? {};
  const out: Record<string, string | null> = {};

  for (const dim of schema.dimensions) {
    let value = await resolveSingleDimension(dim, ctxDims, out, opts.request, schema);

    if (value !== null && dim.pii && dim.pii !== "none") {
      value = await applyPii(value, dim.pii);
    }
    out[dim.name] = value;
  }

  // Required-dimension enforcement runs as a post-pass so that derived chains
  // can resolve their inputs even if an earlier required dimension would
  // otherwise short-circuit.
  for (const dim of schema.dimensions) {
    if (!dim.required) continue;
    if (out[dim.name] !== null && out[dim.name] !== undefined) continue;
    const when = dim.when_missing ?? "reject";
    if (when === "reject") throw new RequiredDimensionMissingError(dim.name);
    // `null` and `default` both leave the slot null. `default` is encoded
    // inside the derived template (`| default "X"`); there is no separate
    // `default_value` field on the Dimension shape today.
  }

  return out;
}
