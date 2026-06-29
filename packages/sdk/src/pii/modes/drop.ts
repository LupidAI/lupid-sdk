/**
 * Drop mode.
 *
 * Returns the literal `<redacted>`. Sync, no crypto. Ships the bare
 * literal rather than an enriched `<redacted:kind>` form, since the kind
 * is only known to higher layers.
 */

export const REDACTED_LITERAL = "<redacted>";

export function drop(_value: string): string {
  return REDACTED_LITERAL;
}
