/**
 * Indirect dynamic import for optional peer dependencies.
 *
 * Plain `await import("openai")` would force TypeScript to resolve the
 * specifier at compile time, which fails when the customer hasn't
 * installed `openai` (and we WANT it optional). Routing the import
 * through a typed-`unknown` indirection keeps the specifier opaque to
 * TS while preserving runtime behaviour.
 */

// Cast Function-typed `eval` so bundlers (esbuild / tsup) leave the
// dynamic import alone. This is the standard pattern used by Sentry,
// OpenTelemetry, and similar libraries for optional peer deps.
const dynImport: (spec: string) => Promise<unknown> =
  // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
  new Function("spec", "return import(spec)") as (s: string) => Promise<unknown>;

export async function loadOptional(specifier: string): Promise<unknown> {
  try {
    return await dynImport(specifier);
  } catch {
    return null;
  }
}
