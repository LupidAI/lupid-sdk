/**
 * Per-request user/session context for the fetch interceptor.
 *
 * Framework adapters call `withAgentumContext({sessionId, userId}, fn)` at
 * the inbound HTTP boundary; downstream `globalThis.fetch` calls the
 * interceptor wraps will see the same context via AsyncLocalStorage. Falls
 * back to env vars when no context store has been entered (single-tenant
 * worker / CLI use case).
 *
 * Edge-runtime contract: the universal `index.ts` re-exports the
 * accessors here, so this file MUST load cleanly on Vercel Edge and
 * Cloudflare Workers — neither of which exposes `node:async_hooks`. We
 * lazy-load `AsyncLocalStorage` via a runtime-gated `require()` so the
 * static module graph contains no `node:*` import. On non-Node runtimes
 * the per-request store is unavailable and the context falls back to env
 * vars + `setAgentumDefaults` (both work everywhere).
 */

interface AlsLike<T> {
  getStore(): T | undefined;
  run<R>(store: T, fn: () => R): R;
}

const STORE_SYM = Symbol.for("agentum.context.store");
type GlobalWithStore = typeof globalThis & {
  [STORE_SYM]?: AlsLike<AgentumContext>;
};

export interface AgentumContext {
  sessionId?: string;
  userId?: string;
  /**
   * Free-form per-request dimension overrides. Validated against the active
   * tenant schema at resolve-time by `resolveDimensions()`. Keys are
   * dimension names (e.g. `account_id`, `bot_id`); values are the raw string
   * inputs prior to PII masking. Unknown keys fall through to
   * `AuditEvent.tags`.
   */
  dimensions?: Record<string, string>;
}

function isNodeRuntime(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof (process as { versions?: { node?: string } }).versions?.node ===
      "string"
  );
}

/**
 * Synchronously try to acquire the local CJS `require`. We deliberately
 * avoid a top-level `import { createRequire } from "node:module"` because
 * the bare specifier `node:module` is unresolvable in some edge bundlers.
 * Direct `eval` evaluates in local scope, so it sees the CJS module's
 * own `require` when present (tsup's CJS output, ts-jest, plain Node CJS).
 * In ESM Node and edge runtimes the symbol is absent and we return
 * `undefined`, which downgrades the per-request store to a no-op without
 * throwing at module load.
 */
function tryAcquireRequire(): NodeJS.Require | undefined {
  try {
    // eslint-disable-next-line no-eval
    const r = eval("typeof require === 'function' ? require : undefined");
    return r as NodeJS.Require | undefined;
  } catch {
    return undefined;
  }
}

let _alsResolved = false;
let _als: AlsLike<AgentumContext> | undefined;

// OPEN-23 — one-time guard so the no-ALS warning fires once per process
// (edge isolates fire once per cold start, which is exactly when the operator
// needs the signal) and never spams the log on every request.
let _alsUnavailableWarned = false;

/**
 * Test-only — reset the one-time no-ALS warning flag so cases can re-observe
 * the first-call warning without state bleed. Mirrors `clearAgentumDefaults`.
 * Not re-exported from `index.ts`.
 */
export function _resetAlsUnavailableWarnedForTest(): void {
  _alsUnavailableWarned = false;
}

function getStore(): AlsLike<AgentumContext> | undefined {
  if (_alsResolved) {
    if (_als) return _als;
    const g = globalThis as GlobalWithStore;
    return g[STORE_SYM];
  }
  _alsResolved = true;
  if (!isNodeRuntime()) return undefined;
  try {
    const mod = loadAsyncHooks();
    if (!mod) return undefined;
    const g = globalThis as GlobalWithStore;
    if (!g[STORE_SYM]) {
      g[STORE_SYM] = new mod.AsyncLocalStorage<AgentumContext>();
    }
    _als = g[STORE_SYM];
    return _als;
  } catch {
    return undefined;
  }
}

/**
 * Load `node:async_hooks` synchronously from BOTH module systems.
 *
 * The CJS `require` probe alone is not enough: tsup emits separate ESM
 * bundles (`index.mjs`, `init.mjs`) where no lexical `require` exists, so the
 * eval probe returns `undefined` and the per-request store silently became a
 * no-op for every ESM consumer (Next.js route handlers included) —
 * `withAgentumContext` ran its callback with no ALS and dimensions never
 * reached the interceptors. Caught live in the LobeChat e2e (2026-06-10).
 * `process.getBuiltinModule` (Node ≥ 22.3) is sync and works in both module
 * systems; the `require` probe remains as the fallback for older CJS Node.
 */
function loadAsyncHooks():
  | { AsyncLocalStorage: new <T>() => AlsLike<T> }
  | undefined {
  type AsyncHooksModule = { AsyncLocalStorage: new <T>() => AlsLike<T> };
  const proc = process as NodeJS.Process & {
    getBuiltinModule?: (id: string) => unknown;
  };
  if (typeof proc.getBuiltinModule === "function") {
    try {
      const mod = proc.getBuiltinModule("node:async_hooks");
      if (mod) return mod as AsyncHooksModule;
    } catch {
      // fall through to the require probe
    }
  }
  const req = tryAcquireRequire();
  if (!req) return undefined;
  return req("node:async_hooks") as AsyncHooksModule;
}

export function withAgentumContext<T>(ctx: AgentumContext, fn: () => T): T {
  const store = getStore();
  if (!store) {
    // No ALS available (edge runtime). Fall back to running `fn` directly;
    // downstream context lookups will resolve via env / defaults.
    //
    // OPEN-23 — this fallback means per-request context isolation is INACTIVE:
    // every concurrent request in the isolate shares the process-level
    // defaults set at init(). sessionId / userId / dimensions passed here are
    // silently discarded. Warn loudly once so the operator isn't blindsided by
    // cross-request identity bleed. (Warn-only; the true fix needs a Web
    // AsyncContext polyfill or mandatory explicit threading — out of scope.)
    if (!_alsUnavailableWarned) {
      _alsUnavailableWarned = true;
      // eslint-disable-next-line no-console
      console.warn(
        "[agentum] WARNING: AsyncLocalStorage is not available in this runtime " +
          "(Vercel Edge / Cloudflare Workers detected). Per-request context " +
          "isolation (sessionId, userId, dimensions) is NOT active — all " +
          "concurrent requests share the process-level defaults set at init(). " +
          "For correct per-request attribution, run this agent on a Node.js " +
          "runtime (export const runtime = 'nodejs' in Next.js route handlers).",
      );
    }
    return fn();
  }
  // Nested-call merge semantics. The Express adapter primes
  // `dimensions` at the inbound boundary, then route handlers may layer
  // `sessionId`/`userId`/extra `dimensions` from inside the request chain.
  // Read the existing store first and shallow-merge per-key. `dimensions` is
  // merged on its own key so the inner-call's dimension values shadow outer
  // ones rather than wholesale-replacing the outer map; non-`dimensions`
  // fields follow ordinary spread semantics (inner-wins on collision).
  const existing = store.getStore() ?? {};
  const mergedDims = {
    ...(existing.dimensions ?? {}),
    ...(ctx.dimensions ?? {}),
  };
  const merged: AgentumContext = {
    ...existing,
    ...ctx,
    ...(Object.keys(mergedDims).length > 0 ? { dimensions: mergedDims } : {}),
  };
  return store.run(merged, fn);
}

// Process-wide fallback context, populated by `init()` so SDK-direct callers
// that don't wrap requests in `withAgentumContext` still produce a stable
// session_id on every observe/evaluate call. Without this the Sessions UI
// stays empty for any agent that doesn't thread its own conversation id
// through ALS.
const DEFAULTS_SYM = Symbol.for("agentum.context.defaults");
type GlobalWithDefaults = typeof globalThis & {
  [DEFAULTS_SYM]?: AgentumContext;
};

export function setAgentumDefaults(ctx: AgentumContext): void {
  const g = globalThis as GlobalWithDefaults;
  g[DEFAULTS_SYM] = { ...ctx };
}

export function clearAgentumDefaults(): void {
  const g = globalThis as GlobalWithDefaults;
  delete g[DEFAULTS_SYM];
}

export function getAgentumContext(): AgentumContext {
  const store = getStore()?.getStore();
  const env = typeof process !== "undefined" ? process.env : undefined;
  const defaults = (globalThis as GlobalWithDefaults)[DEFAULTS_SYM] ?? {};
  // Resolution order: per-request ALS → env vars → process defaults.
  const out: AgentumContext = {};
  if (defaults.sessionId) out.sessionId = defaults.sessionId;
  if (defaults.userId) out.userId = defaults.userId;
  if (env?.AGENTUM_SESSION_ID) out.sessionId = env.AGENTUM_SESSION_ID;
  if (env?.AGENTUM_USER_ID) out.userId = env.AGENTUM_USER_ID;
  if (store?.sessionId) out.sessionId = store.sessionId;
  if (store?.userId) out.userId = store.userId;
  // Surface per-request `dimensions` from the ALS store. Env vars and
  // `setAgentumDefaults` intentionally do not carry dimensions (no precedent
  // in env-var shape); the ALS path is the only source surfaced here.
  if (store?.dimensions) out.dimensions = { ...store.dimensions };
  return out;
}

/**
 * Serialize the current Agentum context to the `X-Agentum-*` request headers
 * the PDP reverse-proxy plane (R22) reads off the wire:
 *
 *   - `X-Agentum-Session-Id`   — `ctx.sessionId`
 *   - `X-Agentum-User-Id`      — `ctx.userId`
 *   - `X-Agentum-Dimensions`   — JSON object of string→string, when present
 *
 * Only non-empty values are emitted, so a context with no user-id produces no
 * `X-Agentum-User-Id` header (the PDP treats all three as optional). The PDP
 * strips every `X-Agentum-*` header before forwarding upstream — these never
 * reach the provider. Used by the undici-dispatcher interceptor's PDP-proxy
 * routing mode (R24). Never throws.
 */
export function contextToProxyHeaders(
  ctx: AgentumContext = getAgentumContext(),
): Record<string, string> {
  const headers: Record<string, string> = {};
  if (ctx.sessionId) headers["X-Agentum-Session-Id"] = ctx.sessionId;
  if (ctx.userId) headers["X-Agentum-User-Id"] = ctx.userId;
  if (ctx.dimensions && Object.keys(ctx.dimensions).length > 0) {
    try {
      headers["X-Agentum-Dimensions"] = JSON.stringify(ctx.dimensions);
    } catch {
      // A non-serializable dimensions map is dropped rather than throwing on
      // the hot path; session/user headers still ship.
    }
  }
  return headers;
}
