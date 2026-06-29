/**
 * W3C Trace Context propagation.
 *
 * The Agentum SDK injects a `traceparent` header on every outbound call
 * so that SDK operations, backend Cedar evaluations, MCP gateway
 * forwards, and tool invocations all correlate to a single trace id in
 * whatever APM/observability stack the caller is running (Jaeger,
 * Honeycomb, Datadog, Grafana Tempo, etc.).
 *
 * The SDK resolves trace context in this order:
 *
 *  1. A caller-supplied `tracingProvider` passed to the `AgentumClient`
 *     constructor. Used by callers who carry their own OTel instance
 *     (or an equivalent tracing system with access to the active
 *     context).
 *  2. The `@opentelemetry/api` package, if installed. The SDK probes it
 *     lazily so it remains an **optional** peer dep — callers who
 *     don't use OTel pay nothing.
 *  3. A fallback random trace id generator when no upstream context is
 *     available. Guarantees every outbound Agentum call is trace-able
 *     even in environments without a proper tracing stack. Every
 *     request from the same process gets a distinct trace id (cheap
 *     PRNG, not cryptographic — IDs are public).
 *
 * The `trace_id` from whichever source wins is also surfaced to audit
 * event emissions so SDK-emitted events and backend-side events land on
 * the same trace id downstream.
 */

/** Parsed / resolved W3C trace context. */
export interface TraceContext {
  /** 32 lowercase-hex chars, non-all-zero. */
  traceId: string;
  /** 16 lowercase-hex chars, non-all-zero. */
  spanId: string;
  /** 2 hex chars. `01` = sampled; `00` = unsampled. */
  flags: string;
}

/** Optional caller-supplied provider. If `getActiveContext()` returns
 *  `null`, the SDK falls back to OTel probing + random id generation. */
export interface TracingProvider {
  getActiveContext(): TraceContext | null;
}

/** Format a [`TraceContext`] to the W3C `traceparent` header value. */
export function formatTraceparent(ctx: TraceContext): string {
  return `00-${ctx.traceId}-${ctx.spanId}-${ctx.flags}`;
}

/** Parse a `traceparent` header value. Returns `null` on malformed input. */
export function parseTraceparent(value: string | null | undefined): TraceContext | null {
  if (!value) return null;
  const m = value.trim().match(/^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i);
  if (!m) return null;
  const version = m[1]!;
  const traceId = m[2]!;
  const spanId = m[3]!;
  const flags = m[4]!;
  if (version !== "00") return null;
  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) return null;
  return {
    traceId: traceId.toLowerCase(),
    spanId: spanId.toLowerCase(),
    flags: flags.toLowerCase(),
  };
}

// ── @opentelemetry/api probe ─────────────────────────────────────────────────

type OtelApi = {
  trace: {
    getSpan(ctx: unknown): {
      spanContext(): { traceId: string; spanId: string; traceFlags: number };
    } | undefined;
  };
  context: {
    active(): unknown;
  };
} | null;

// Lazily resolved. `null` means "not probed yet"; `undefined` means
// "probed and not present". We cache the result so the probe runs at
// most once per process.
let _otelApi: OtelApi | null | undefined = null;

function probeOtel(): OtelApi | undefined {
  if (_otelApi !== null) return _otelApi ?? undefined;
  try {
    // `eval('require')` would be rejected by Next.js Edge bundlers.
    // `globalThis.require` is safe where present and returns undefined on Edge.
    const req = (globalThis as { require?: NodeRequire }).require;
    if (typeof req === "function") {
      _otelApi = req("@opentelemetry/api") as OtelApi;
      return _otelApi ?? undefined;
    }
  } catch {
    // Module not installed; fall through.
  }
  _otelApi = undefined;
  return undefined;
}

/** Convert an OTel `traceFlags` number (0–255) to its 2-hex representation. */
function flagsToHex(flags: number): string {
  return (flags & 0xff).toString(16).padStart(2, "0");
}

/** Read the active OTel span context, if `@opentelemetry/api` is present. */
function readOtelContext(): TraceContext | null {
  const otel = probeOtel();
  if (!otel) return null;
  try {
    const span = otel.trace.getSpan(otel.context.active());
    if (!span) return null;
    const sc = span.spanContext();
    if (!sc.traceId || /^0+$/.test(sc.traceId)) return null;
    if (!sc.spanId || /^0+$/.test(sc.spanId)) return null;
    return {
      traceId: sc.traceId.toLowerCase(),
      spanId: sc.spanId.toLowerCase(),
      flags: flagsToHex(sc.traceFlags ?? 0),
    };
  } catch {
    return null;
  }
}

// ── Fallback random id generator ─────────────────────────────────────────────

/**
 * Generate a random W3C-compliant id in lowercase hex. Used for SDKs
 * without an OTel stack so every outbound call still carries a trace
 * id. Uses `crypto.getRandomValues` when available (Node 18+, browsers,
 * Edge) and `Math.random`-seeded fallback otherwise.
 *
 * Non-cryptographic quality is acceptable: trace ids are public
 * identifiers, not secrets.
 */
function randomHex(bytes: number): string {
  const out = new Uint8Array(bytes);
  const g = globalThis as { crypto?: { getRandomValues?(b: Uint8Array): Uint8Array } };
  if (g.crypto?.getRandomValues) {
    g.crypto.getRandomValues(out);
  } else {
    for (let i = 0; i < bytes; i++) out[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("");
}

function nonZeroHex(bytes: number): string {
  // A single retry is enough; the chance of all-zero is 1/2^(bytes*8).
  for (let i = 0; i < 4; i++) {
    const v = randomHex(bytes);
    if (!/^0+$/.test(v)) return v;
  }
  // Guaranteed-non-zero fallback.
  return "1" + "0".repeat(bytes * 2 - 1);
}

/** Mint a fresh synthetic trace context. `flags` defaults to `01` so the
 *  downstream collector records it; callers that want unsampled traces
 *  should plug in a real OTel provider. */
export function mintTraceContext(): TraceContext {
  return {
    traceId: nonZeroHex(16),
    spanId: nonZeroHex(8),
    flags: "01",
  };
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/** Resolve the trace context to attach to an outbound request.  Order:
 *  (1) caller-supplied provider, (2) `@opentelemetry/api` active span,
 *  (3) minted random id. */
export function resolveTraceContext(provider?: TracingProvider | null): TraceContext {
  if (provider) {
    const ctx = safeCall(() => provider.getActiveContext());
    if (ctx) return ctx;
  }
  const otel = readOtelContext();
  if (otel) return otel;
  return mintTraceContext();
}

function safeCall<T>(fn: () => T): T | null {
  try {
    return fn();
  } catch {
    return null;
  }
}

/** For tests only — reset the memoised OTel probe. */
export function __resetOtelProbeForTests(): void {
  _otelApi = null;
}
