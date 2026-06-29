/**
 * Typed view of `EnrichmentDef`.
 *
 * The parser-level shape at `manifest/types.ts` mirrors the Rust struct
 * byte-for-byte and leaves the richer blocks (`cache`, `auth`, `request`,
 * `response`, `send_raw`) as `[extra: string]: unknown` passthrough. The
 * enrichment client cannot use those loose fields directly without narrowing
 * first.
 *
 * `asFullDef()` is the single place those blocks are validated and tightened
 * into the `EnrichmentDefFull` shape. Anywhere outside `src/enrichment/` keeps
 * the parser-faithful `EnrichmentDef`.
 *
 * Throws `EnrichmentConfigError` (not generic Error) when a block is missing
 * or malformed so the caller can degrade per the dimension's `on_failure`.
 */

import type { EnrichmentDef, FailureMode } from "../manifest/types.js";
import { EnrichmentConfigError } from "./errors.js";
import { warnAllowHttpOnce } from "./metrics.js";

export type { FailureMode };

export interface CacheBlock {
  key: string[];
  ttl_ms: number;
  max_entries?: number;
  negative_ttl_ms?: number;
}

export interface AuthBlock {
  /** `env:VAR_NAME` is the only supported form today. */
  secret_ref: string;
}

export interface RequestBlock {
  method?: "POST" | "GET";
  include_dimensions: string[];
}

export interface ResponseBlock {
  shape: Record<string, "string" | "string|null">;
}

export interface EnrichmentDefFull extends EnrichmentDef {
  cache: CacheBlock;
  auth: AuthBlock;
  request: RequestBlock;
  response: ResponseBlock;
  send_raw?: boolean;
  /**
   * DEV-ONLY escape hatch. When `true`, `asFullDef` accepts `http://` URLs and
   * emits a one-shot stderr warning. Default (unset or `false`) preserves the
   * strict-HTTPS rule. Production manifests MUST NOT set this; the validator
   * surfaces a runtime warning so operator review catches it.
   */
  allow_http?: boolean;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function parseDurationMs(v: unknown, field: string, ref: string): number {
  if (typeof v === "number" && Number.isFinite(v) && v > 0) return v;
  if (typeof v === "string") {
    // Accept duration strings like "5m", "30s", "250ms".
    const m = /^(\d+)\s*(ms|s|m|h)?$/.exec(v.trim());
    if (m) {
      const n = Number(m[1]);
      const unit = m[2] ?? "ms";
      const mult: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
      return n * (mult[unit] ?? 1);
    }
  }
  throw new EnrichmentConfigError(
    `enrichment '${ref}' field '${field}' must be a duration (number ms or '5m'/'30s'/'250ms')`,
    ref,
  );
}

function validateCache(raw: unknown, ref: string): CacheBlock {
  if (!isObject(raw)) {
    throw new EnrichmentConfigError(`enrichment '${ref}' missing 'cache' block`, ref);
  }
  if (!isStringArray(raw["key"])) {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' cache.key must be a string array`,
      ref,
    );
  }
  // The manifest may use `ttl` / `negative_ttl`; the typed surface uses `_ms`.
  // Accept either; if both are absent, error.
  const ttlSource = raw["ttl_ms"] ?? raw["ttl"];
  if (ttlSource === undefined) {
    throw new EnrichmentConfigError(`enrichment '${ref}' cache.ttl missing`, ref);
  }
  const ttl_ms = parseDurationMs(ttlSource, "cache.ttl", ref);
  const out: CacheBlock = { key: raw["key"], ttl_ms };
  const negSource = raw["negative_ttl_ms"] ?? raw["negative_ttl"];
  if (negSource !== undefined) {
    out.negative_ttl_ms = parseDurationMs(negSource, "cache.negative_ttl", ref);
  }
  if (typeof raw["max_entries"] === "number" && raw["max_entries"] > 0) {
    out.max_entries = raw["max_entries"];
  }
  return out;
}

function validateAuth(raw: unknown, ref: string): AuthBlock {
  if (!isObject(raw)) {
    throw new EnrichmentConfigError(`enrichment '${ref}' missing 'auth' block`, ref);
  }
  const secret_ref = raw["secret_ref"];
  if (typeof secret_ref !== "string") {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' auth.secret_ref must be a string`,
      ref,
    );
  }
  return { secret_ref };
}

function validateRequest(raw: unknown, ref: string, fallbackInclude: string[]): RequestBlock {
  // The full manifest puts include_dimensions inside `request:`. The slim Rust
  // struct hoists it to the top level. Accept both; if neither, default to [].
  if (!isObject(raw)) {
    return { include_dimensions: fallbackInclude };
  }
  const include = isStringArray(raw["include_dimensions"])
    ? raw["include_dimensions"]
    : fallbackInclude;
  let method: "POST" | "GET" | undefined;
  if (raw["method"] === "POST" || raw["method"] === "GET") {
    method = raw["method"];
  }
  const out: RequestBlock = { include_dimensions: include };
  if (method !== undefined) out.method = method;
  return out;
}

function validateResponse(raw: unknown, ref: string): ResponseBlock {
  if (!isObject(raw)) {
    throw new EnrichmentConfigError(`enrichment '${ref}' missing 'response' block`, ref);
  }
  const shapeRaw = raw["shape"];
  if (!isObject(shapeRaw)) {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' response.shape must be an object`,
      ref,
    );
  }
  const shape: Record<string, "string" | "string|null"> = {};
  for (const [k, v] of Object.entries(shapeRaw)) {
    // The manifest sometimes uses `{type: string, enum: [...]}` form. We accept
    // either the typed-string form ("string" / "string|null") or the object
    // form, in which case we map presence-of-enum to "string".
    if (v === "string" || v === "string|null") {
      shape[k] = v;
    } else if (isObject(v) && (v["type"] === "string" || v["type"] === undefined)) {
      shape[k] = "string";
    } else {
      throw new EnrichmentConfigError(
        `enrichment '${ref}' response.shape['${k}'] must be 'string' or 'string|null'`,
        ref,
      );
    }
  }
  if (Object.keys(shape).length === 0) {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' response.shape must declare at least one key`,
      ref,
    );
  }
  return { shape };
}

/**
 * Runtime-narrow a parser-faithful `EnrichmentDef` to the typed view the
 * client consumes. Throws `EnrichmentConfigError` on any malformed block.
 *
 * Enforces the HTTPS-only rule: reject `http://` URLs at config-validation
 * time unless the manifest opts in via `allow_http: true` (a DEV-ONLY escape
 * hatch). Opting in emits a one-shot stderr warning so operator review
 * surfaces the insecure URL.
 */
export function asFullDef(d: EnrichmentDef, ref: string): EnrichmentDefFull {
  if (typeof d.url !== "string" || d.url.length === 0) {
    throw new EnrichmentConfigError(`enrichment '${ref}' missing 'url'`, ref);
  }
  const allowHttp = (d as { allow_http?: unknown }).allow_http === true;
  if (!d.url.startsWith("https://")) {
    if (d.url.startsWith("http://") && allowHttp) {
      warnAllowHttpOnce(ref, d.url);
    } else {
      throw new EnrichmentConfigError(
        `enrichment URL must be https:// (got ${d.url})`,
        ref,
      );
    }
  }
  const cache = validateCache(d["cache"], ref);
  const auth = validateAuth(d["auth"], ref);
  const request = validateRequest(d["request"], ref, d.include_dimensions ?? []);
  const response = validateResponse(d["response"], ref);
  if (!Object.prototype.hasOwnProperty.call(response.shape, ref)) {
    throw new EnrichmentConfigError(
      `enrichment '${ref}' response.shape must include the enrichment ref itself as a key`,
      ref,
    );
  }
  const full: EnrichmentDefFull = {
    ...d,
    cache,
    auth,
    request,
    response,
  };
  if (typeof d["send_raw"] === "boolean") {
    full.send_raw = d["send_raw"];
  }
  if (allowHttp) {
    full.allow_http = true;
  }
  return full;
}
