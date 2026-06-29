/**
 * Live-schema fetcher.
 *
 * Calls `GET /api/v1/agents/{agent_id}/schema` — the server defaults
 * `live=true` (see `crates/agentum-api/src/routes/schema.rs`), so the SDK
 * does NOT append `?live=true` or `?live=false`. The latter without
 * `?version=` would return 422 by server design.
 *
 * Identity schemas are stored per-agent (keyed by
 * `(tenant_id, agent_id, version)`). The SDK already knows its
 * `agent_id` — it is set when `/sdk/register` returns at `init()` time.
 * The server resolves `agent_id → tenant_id` internally via the
 * `AgentResolver` LRU.
 *
 * 404 (`AgentumNotFoundError` from `AdminHttpClient.get<T>`) is special-cased
 * to mean "agent has no schema installed yet" — reconcile treats `null` as
 * "no live schema" and uses the local manifest with a warning.
 *
 * All other non-2xx errors propagate as-is — the SDK fail-CLOSED bias for
 * transport errors is preserved upstream in `init.ts`'s `.catch()` block.
 */

import type { AdminHttpClient } from "../admin/http.js";
import { AgentumNotFoundError } from "../types.js";
import { parseAndValidate } from "./validator.js";
import type { TenantSchema } from "./types.js";

/**
 * Server wire shape. Mirrors `crates/agentum-api/src/routes/schema.rs` —
 * the active-schema response is `{ tenant_id, agent_id, version, definition, ... }`
 * with the schema body nested under `definition`. We only read `definition`
 * and pass it to the validator; the rest is observability metadata.
 */
interface SchemaEnvelope {
  definition: unknown;
  version?: number;
  tenant_id?: string;
  agent_id?: string;
}

/**
 * Fetch and validate the live schema for the given agent.
 *
 * Returns `null` iff the server replied 404 (no schema installed yet);
 * returns the validated schema on 200; throws on any other failure.
 */
export async function getLiveSchema(
  http: AdminHttpClient,
  agentId: string,
): Promise<TenantSchema | null> {
  let resp: SchemaEnvelope;
  try {
    resp = await http.get<SchemaEnvelope>(`agents/${agentId}/schema`);
  } catch (e) {
    if (e instanceof AgentumNotFoundError) return null;
    throw e;
  }
  return parseAndValidate(resp.definition);
}
