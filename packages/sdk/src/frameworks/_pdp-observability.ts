/**
 * PDP observability helpers shared by the framework integrations
 * (`langchain.ts`, `openai.ts`, `vercel-ai.ts`).
 *
 * `ToolCallEvaluation` carries four observability fields the audit
 * pipeline wants to record. Two of them are top-level columns on
 * `AuditIngestRequest` (`policy_hash`, `decision_source`) — they live
 * next to `agent_id` / `session_id` so ClickHouse can index them. The
 * other two (`evaluated_locally`, `pdp_latency_us`, plus `rule_id` /
 * `reason`) live inside `detail`. Splitting the two sets is
 * load-bearing: a query filtering `WHERE policy_hash = '…'` must
 * return both `LocalPdpDecision` and framework `mcp_tool_*` /
 * `policy_deny` rows, which requires identical placement on both
 * sides of the audit pipeline (see `cedar-client.ts` —
 * `emitLocalPdpDecisionAudit`).
 */

import type { ToolCallEvaluation } from "../evaluation/cedar-client.js";
import type { PolicySimulateResponse } from "../types.js";

// One-shot guard set, keyed by framework name. When a client is
// constructed without an `apiKey`, the framework enforce paths fall
// back to the legacy `isAllowed` route and lose the four
// observability fields. We surface a single console.warn per
// framework per process so operators can audit/discover the legacy
// wiring without spamming logs.
const _warnedFrameworks = new Set<string>();

/**
 * Emit a one-shot console.warn for a framework that just fell back
 * to `isAllowed` because the underlying `AgentumClient` is missing
 * an `apiKey`. Idempotent per `framework` string.
 */
export function warnEvaluatorFallbackOnce(framework: string): void {
  if (_warnedFrameworks.has(framework)) return;
  _warnedFrameworks.add(framework);
  // eslint-disable-next-line no-console
  console.warn(
    `[agentum/${framework}] enforce path: AgentumClient is missing \`apiKey\`; ` +
      "falling back to `isAllowed` boolean check. " +
      "PDP observability fields (policy_hash, decision_source, evaluated_locally, pdp_latency_us) " +
      "will NOT be threaded into audit. " +
      "Construct AgentumClient with an `apiKey` to enable the rich evaluation path (L05a).",
  );
}

/**
 * Map the in-memory `ToolCallEvaluation.decisionSource` enum
 * (`"pdp" | "central"`) onto the wire `decision_source` used by
 * `AuditIngestRequest`.
 *
 * ADR-0014 §80: the SDK autopatch plane always intercepts in-process, so
 * every short-form value (`"pdp"`, `"central"`, `"cache"`) collapses onto
 * the single ADR-0010 plane id `"inproc"`. The cache semantic that the old
 * `"cache"` value smeared into `decision_source` now travels on a separate
 * `cache_hit: boolean` wire field (set by {@link pdpTopLevelFields}). Returns
 * `undefined` for an unknown / missing value so the helper output is omitted
 * rather than serialised as `undefined`.
 */
export function mapDecisionSourceToAudit(
  src: ToolCallEvaluation["decisionSource"],
): "inproc" | undefined {
  if (src === "pdp") return "inproc";
  if (src === "central") return "inproc";
  // cedar-client doesn't surface "cache" on ToolCallEvaluation today (cache
  // hits return the same enum the underlying entry was stamped with), but a
  // future widening would also be an in-process decision — keep the branch so
  // it maps to "inproc" rather than silently dropping the field.
  if ((src as unknown) === "cache") return "inproc";
  return undefined;
}

/**
 * Fields that go INSIDE the `detail` JSON of an audit event:
 * `evaluated_locally`, `pdp_latency_us`, plus `rule_id` / `reason`
 * mirrors for cross-event consistency with `LocalPdpDecision`. Only
 * emits keys whose value is defined so the resulting `detail` doesn't
 * carry `undefined` placeholders.
 */
export function pdpObservabilityDetail(e: ToolCallEvaluation): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (e.evaluatedLocally !== undefined) out["evaluated_locally"] = e.evaluatedLocally;
  if (e.pdpLatencyUs !== undefined) out["pdp_latency_us"] = e.pdpLatencyUs;
  if (e.ruleId !== undefined) out["rule_id"] = e.ruleId;
  if (e.reason !== undefined) out["reason"] = e.reason;
  return out;
}

/**
 * Fields that go at the TOP LEVEL of `AuditIngestRequest`:
 * `policy_hash`, `decision_source`, `cache_hit`. Maps `decisionSource`
 * through {@link mapDecisionSourceToAudit} (always `"inproc"` for the
 * autopatch plane). Per ADR-0014 §5 the cache semantic that the legacy
 * `"cache"` value smeared into `decision_source` is hoisted onto the
 * separate `cache_hit` field: a `"cache"`-sourced decision emits
 * `decision_source: "inproc"` AND `cache_hit: true`. Only emits keys whose
 * value is defined.
 */
export function pdpTopLevelFields(e: ToolCallEvaluation): {
  policy_hash?: string;
  decision_source?: "inproc";
  cache_hit?: boolean;
} {
  const out: {
    policy_hash?: string;
    decision_source?: "inproc";
    cache_hit?: boolean;
  } = {};
  if (e.policyHash !== undefined) out.policy_hash = e.policyHash;
  const mapped = mapDecisionSourceToAudit(e.decisionSource);
  if (mapped !== undefined) out.decision_source = mapped;
  if ((e.decisionSource as unknown) === "cache") out.cache_hit = true;
  return out;
}

/**
 * Raw variant of {@link pdpObservabilityDetail} that accepts a
 * `PolicySimulateResponse`-shaped (or `GuardDecision`-shaped) source
 * instead of `ToolCallEvaluation`. Used by the four server-framework
 * guards (express, fastify, nextjs route-handler & server-action,
 * nestjs) which never see a `ToolCallEvaluation`. Omits undefined keys
 * so the resulting `detail` doesn't carry placeholders.
 *
 * The simulate flow has no `evaluated_locally` / `pdp_latency_us`
 * surfaces today, but the parameters are kept for forward-compatibility
 * with a future PDP-backed simulate path.
 */
export function pdpObservabilityDetailRaw(src: {
  evaluated_locally?: boolean;
  pdp_latency_us?: number;
  rule_id?: string | null;
  reason?: string | null;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (src.evaluated_locally !== undefined) out["evaluated_locally"] = src.evaluated_locally;
  if (src.pdp_latency_us !== undefined) out["pdp_latency_us"] = src.pdp_latency_us;
  if (src.rule_id !== undefined && src.rule_id !== null) out["rule_id"] = src.rule_id;
  if (src.reason !== undefined && src.reason !== null) out["reason"] = src.reason;
  return out;
}

/**
 * Raw variant of {@link pdpTopLevelFields} that accepts a
 * `PolicySimulateResponse`-shaped (or `GuardDecision`-shaped) source
 * instead of `ToolCallEvaluation`. Crucially, this variant does **not**
 * apply {@link mapDecisionSourceToAudit} — the long-form wire vocabulary
 * (`"central_evaluated" | "central_cache_hit" | "local_pdp_evaluated"
 * | "local_pdp_cache_hit"`) is preserved on simulate-side audits so
 * operators querying ClickHouse keep the `*_cache_hit` distinction.
 * Omits undefined keys so the spread into `AuditIngestRequest` doesn't
 * serialise placeholders.
 */
export function pdpTopLevelFieldsRaw(src: {
  policy_hash?: string;
  decision_source?: NonNullable<PolicySimulateResponse["decision_source"]>;
}): {
  policy_hash?: string;
  decision_source?: NonNullable<PolicySimulateResponse["decision_source"]>;
} {
  const out: {
    policy_hash?: string;
    decision_source?: NonNullable<PolicySimulateResponse["decision_source"]>;
  } = {};
  if (src.policy_hash !== undefined) out.policy_hash = src.policy_hash;
  if (src.decision_source !== undefined) out.decision_source = src.decision_source;
  return out;
}
