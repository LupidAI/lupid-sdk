/**
 * Chainable builder for `DeclarativePolicySpec`.
 *
 * Constructed via `AgentumAdminClient#policies.builder(agentId)`. Rules are
 * accumulated in source order; `apply()` compiles them to Cedar server-side
 * via `POST /policies/declarative/:agent_id`. Use `build()` to inspect the
 * wire-shape spec without sending it (useful for testing / GitOps).
 *
 * The builder accepts camelCase argument shapes (`pathLike`, `whenUser`) for
 * ergonomics and translates to the wire format (`path_like`, `when_user`)
 * before send. That keeps calling code TypeScript-idiomatic while the over-
 * the-wire shape matches the Rust DSL struct exactly.
 *
 * Example
 * -------
 * ```ts
 * await admin.policies.builder("agent_abc")
 *   .permitHttp({ method: "GET",    host: "api.example.com", pathLike: "/orders/*" })
 *   .forbidHttp({ method: "DELETE", host: "api.example.com" })
 *   .permitMcp({
 *     server: "jira",
 *     tool: "create_issue",
 *     whenUser: { attributeEquals: { key: "role", value: "admin" } },
 *   })
 *   .apply();
 * ```
 */

import type {
  DeclarativeContextCondition,
  DeclarativePolicySpec,
  DeclarativeRule,
  DeclarativeHttpMethod,
  DeclarativeRoleDefinition,
  DeclarativeRolePatternList,
  DeclarativeUserCondition,
} from "../types.js";
import type { AdminHttpClient } from "./http.js";

/**
 * Ergonomic user-condition input accepted by `permitHttp`/`forbidHttp`/
 * `permitMcp`/`forbidMcp`. Externally-tagged — the key itself discriminates
 * the variant. Either shape may be used, including the wire-shape tagged
 * union from `types.ts`.
 */
export type WhenUserInput =
  | { emailLike: string }
  | { attributeEquals: { key: string; value: string } }
  | { trustEquals: "trusted" | "verified" | "service" }
  | DeclarativeUserCondition;

/**
 * Ergonomic request-body-field input for `whenContext` on any rule (Task
 * 1.4.8 — G38). Each key selects one variant. The wire-shape tagged form
 * (`{kind: "field_equals", ...}`) is also accepted so callers holding a
 * pre-built wire object can pass it through.
 *
 * Numeric variants take an integer — Cedar has no float type.
 */
export type WhenContextInput =
  | { fieldEquals: { field: string; value: string } }
  | { fieldNotEquals: { field: string; value: string } }
  | { fieldGreaterThan: { field: string; value: number } }
  | { fieldLessThan: { field: string; value: number } }
  | DeclarativeContextCondition;

/**
 * Task 1.5.9 (G37) — HITL escalation config on a forbid rule. Presence of
 * either field on {@link HttpRuleInput}/{@link McpRuleInput}/
 * {@link AllActionsRuleInput} only has meaning when paired with
 * `forbidHttp/forbidMcp/forbidAny` (or equivalent); the builder rejects
 * `permit*` + `requireApproval: true` at `build()` time.
 */
export interface ApprovalConfigInput {
  /** Distinct approvers required. Omitted ⇒ server default (1). */
  requiredApprovals?: number;
  /** Wait timeout in seconds. Omitted ⇒ server default (60s). */
  timeoutSeconds?: number;
}

export interface HttpRuleInput {
  method: DeclarativeHttpMethod;
  host: string;
  pathLike?: string;
  whenUser?: WhenUserInput;
  whenContext?: WhenContextInput;
  /** Task 1.5.9 (G37) — only valid on `forbid*` helpers. */
  requireApproval?: boolean;
  approvalConfig?: ApprovalConfigInput;
}

export interface McpRuleInput {
  /**
   * Registered MCP server name. Omit to match ANY server (Task 1.4.4 —
   * G23). When set, the server gates the rule via
   * `context.mcp_server_name`.
   */
  server?: string;
  tool: string;
  whenUser?: WhenUserInput;
  whenContext?: WhenContextInput;
  /** Task 1.5.9 (G37) — only valid on `forbid*` helpers. */
  requireApproval?: boolean;
  approvalConfig?: ApprovalConfigInput;
}

/**
 * Input for `permitAny` / `forbidAny` — the "god-mode" rule (Task 1.4.6 —
 * G30). Matches any action and any resource. `whenUser` is typically
 * required for a safe `permit` (e.g. an admin-only attribute equals guard)
 * but the builder does not enforce that — caller choice.
 */
export interface AllActionsRuleInput {
  whenUser?: WhenUserInput;
  whenContext?: WhenContextInput;
  /** Task 1.5.9 (G37) — only valid on `forbidAny`. */
  requireApproval?: boolean;
  approvalConfig?: ApprovalConfigInput;
}

/**
 * Input for `role()` — a named RBAC role with `allow` and/or `deny` pattern
 * lists. See [`DeclarativeRolePatternList`] for the pattern grammar. Either
 * field may be the string `"*"` (expands to an `AllActions` rule) or an
 * array of `<action>:<target>` strings.
 */
export interface RoleInput {
  allow?: DeclarativeRolePatternList;
  deny?: DeclarativeRolePatternList;
}

/**
 * Normalise the ergonomic camelCase / externally-tagged shape to the
 * wire-shape internally-tagged `DeclarativeUserCondition`. Accepts either
 * form so callers who already have a wire-shape object can pass it through.
 */
function normalizeWhenUser(input: WhenUserInput): DeclarativeUserCondition {
  // Already wire-shape (has a `kind` field).
  if ("kind" in input) return input;
  if ("emailLike" in input) {
    return { kind: "email_like", pattern: input.emailLike };
  }
  if ("attributeEquals" in input) {
    return {
      kind: "attribute_equals",
      key: input.attributeEquals.key,
      value: input.attributeEquals.value,
    };
  }
  if ("trustEquals" in input) {
    return { kind: "trust_equals", trust: input.trustEquals };
  }
  // Exhaustiveness guard — a runtime throw rather than a type error so a
  // caller building rules dynamically gets a clear message at the call site.
  throw new Error(
    `Invalid whenUser shape: expected emailLike/attributeEquals/trustEquals, got ${JSON.stringify(input)}`,
  );
}

/**
 * Normalise a `WhenContextInput` to the wire-shape
 * `DeclarativeContextCondition`. Mirrors {@link normalizeWhenUser}.
 */
function normalizeWhenContext(
  input: WhenContextInput,
): DeclarativeContextCondition {
  if ("kind" in input) return input;
  if ("fieldEquals" in input) {
    return {
      kind: "field_equals",
      field: input.fieldEquals.field,
      value: input.fieldEquals.value,
    };
  }
  if ("fieldNotEquals" in input) {
    return {
      kind: "field_not_equals",
      field: input.fieldNotEquals.field,
      value: input.fieldNotEquals.value,
    };
  }
  if ("fieldGreaterThan" in input) {
    if (!Number.isInteger(input.fieldGreaterThan.value)) {
      throw new Error(
        `whenContext.fieldGreaterThan.value must be an integer (Cedar Long), got ${input.fieldGreaterThan.value}`,
      );
    }
    return {
      kind: "field_greater_than",
      field: input.fieldGreaterThan.field,
      value: input.fieldGreaterThan.value,
    };
  }
  if ("fieldLessThan" in input) {
    if (!Number.isInteger(input.fieldLessThan.value)) {
      throw new Error(
        `whenContext.fieldLessThan.value must be an integer (Cedar Long), got ${input.fieldLessThan.value}`,
      );
    }
    return {
      kind: "field_less_than",
      field: input.fieldLessThan.field,
      value: input.fieldLessThan.value,
    };
  }
  throw new Error(
    `Invalid whenContext shape: expected fieldEquals/fieldNotEquals/fieldGreaterThan/fieldLessThan, got ${JSON.stringify(input)}`,
  );
}

export interface ApplyDeclarativeResult {
  /** Cedar source compiled from the submitted spec. Kept for audit/debug. */
  compiledCedar: string;
  /** ISO 8601 timestamp the server wrote the policy. */
  appliedAt: string;
  /** Server-assigned policy identifier — equal to `agent_id` today. */
  policyId: string;
}

export class PolicyBuilder {
  private readonly rules: DeclarativeRule[] = [];
  private readonly rolesMap: Record<string, DeclarativeRoleDefinition> = {};
  private userRoleFieldValue: string | undefined;

  constructor(
    private readonly http: AdminHttpClient,
    private readonly agentId: string,
  ) {
    if (!agentId) {
      throw new Error("PolicyBuilder requires a non-empty agentId");
    }
  }

  /** Add a `permit` HTTP rule. */
  permitHttp(r: HttpRuleInput): this {
    this.rules.push(this.httpRule(true, r));
    return this;
  }

  /** Add a `forbid` HTTP rule. */
  forbidHttp(r: HttpRuleInput): this {
    this.rules.push(this.httpRule(false, r));
    return this;
  }

  /** Add a `permit` MCP tool rule. */
  permitMcp(r: McpRuleInput): this {
    this.rules.push(this.mcpRule(true, r));
    return this;
  }

  /** Add a `forbid` MCP tool rule. */
  forbidMcp(r: McpRuleInput): this {
    this.rules.push(this.mcpRule(false, r));
    return this;
  }

  /**
   * Stage a `permit` god-mode rule (Task 1.4.6 — G30): matches any action
   * and any resource. Pair with a `whenUser` guard unless you truly want
   * unconditional permit.
   */
  permitAny(r: AllActionsRuleInput = {}): this {
    this.rules.push(this.allActionsRule(true, r));
    return this;
  }

  /** Stage a `forbid` god-mode rule (Task 1.4.6 — G30). */
  forbidAny(r: AllActionsRuleInput = {}): this {
    this.rules.push(this.allActionsRule(false, r));
    return this;
  }

  /**
   * Declare an RBAC role (Task 1.4.6 — G31). The server expands the role
   * into concrete `DeclarativeRule`s with an injected `when_user` guard on
   * the caller's role attribute (see `userRoleField()`, default `"role"`).
   *
   * Calling `role(name, ...)` again with the same name replaces the
   * previous definition — consistent with how `Record<string, T>` behaves
   * and how the Rust `BTreeMap<String, _>` round-trips it.
   */
  role(name: string, def: RoleInput): this {
    if (!name || !name.trim()) {
      throw new Error("role name must be non-empty");
    }
    const entry: DeclarativeRoleDefinition = {};
    if (def.allow !== undefined) entry.allow = def.allow;
    if (def.deny !== undefined) entry.deny = def.deny;
    this.rolesMap[name] = entry;
    return this;
  }

  /**
   * Override the attribute key on `context.user.attributes` that holds the
   * role string. Defaults to `"role"` server-side when not set. Useful for
   * tenants whose SSO schema uses `group` or `job_title` instead.
   */
  userRoleField(field: string): this {
    if (!field || !field.trim()) {
      throw new Error("userRoleField must be non-empty");
    }
    this.userRoleFieldValue = field;
    return this;
  }

  /**
   * Return the wire-shape spec without sending. Useful for unit tests,
   * GitOps diffing, or saving the spec to disk before calling `apply()`.
   */
  build(): DeclarativePolicySpec {
    const spec: DeclarativePolicySpec = {
      agent_id: this.agentId,
      rules: [...this.rules],
    };
    if (Object.keys(this.rolesMap).length > 0) {
      // Deep clone so later builder mutations don't leak into prior
      // `build()` results.
      spec.roles = JSON.parse(JSON.stringify(this.rolesMap));
    }
    if (this.userRoleFieldValue !== undefined) {
      spec.user_role_field = this.userRoleFieldValue;
    }
    return spec;
  }

  /** How many rules are currently staged. */
  get ruleCount(): number {
    return this.rules.length;
  }

  /** How many roles are currently declared. */
  get roleCount(): number {
    return Object.keys(this.rolesMap).length;
  }

  /**
   * Discard all staged rules **and** role definitions. The builder is
   * reusable afterwards with a fresh slate.
   */
  reset(): this {
    this.rules.length = 0;
    for (const k of Object.keys(this.rolesMap)) delete this.rolesMap[k];
    this.userRoleFieldValue = undefined;
    return this;
  }

  /**
   * Compile and apply the spec server-side. Emits
   * `POST /policies/declarative/:agent_id`; the server runs DSL compile +
   * Cedar parse + disk write + reload. Raises `AgentumError` (400) on
   * compile/parse failure.
   */
  async apply(): Promise<ApplyDeclarativeResult> {
    const spec = this.build();
    const res = await this.http.post<{
      compiled_cedar: string;
      applied_at: string;
      policy_id: string;
    }>(`policies/declarative/${this.agentId}`, spec);
    return {
      compiledCedar: res.compiled_cedar,
      appliedAt: res.applied_at,
      policyId: res.policy_id,
    };
  }

  private httpRule(permit: boolean, r: HttpRuleInput): DeclarativeRule {
    this.validateHitl(permit, r, "http");
    const rule: DeclarativeRule = {
      kind: "http",
      permit,
      method: r.method,
      host: r.host,
    };
    if (r.pathLike !== undefined) rule.path_like = r.pathLike;
    if (r.whenUser !== undefined) rule.when_user = normalizeWhenUser(r.whenUser);
    if (r.whenContext !== undefined) {
      rule.when_context = normalizeWhenContext(r.whenContext);
    }
    this.applyHitl(rule, r);
    return rule;
  }

  private mcpRule(permit: boolean, r: McpRuleInput): DeclarativeRule {
    this.validateHitl(permit, r, "mcp");
    const rule: DeclarativeRule = {
      kind: "mcp_tool",
      permit,
      tool: r.tool,
    };
    if (r.server !== undefined && r.server !== "") {
      rule.server = r.server;
    }
    if (r.whenUser !== undefined) rule.when_user = normalizeWhenUser(r.whenUser);
    if (r.whenContext !== undefined) {
      rule.when_context = normalizeWhenContext(r.whenContext);
    }
    this.applyHitl(rule, r);
    return rule;
  }

  private allActionsRule(
    permit: boolean,
    r: AllActionsRuleInput,
  ): DeclarativeRule {
    this.validateHitl(permit, r, "all_actions");
    const rule: DeclarativeRule = { kind: "all_actions", permit };
    if (r.whenUser !== undefined) rule.when_user = normalizeWhenUser(r.whenUser);
    if (r.whenContext !== undefined) {
      rule.when_context = normalizeWhenContext(r.whenContext);
    }
    this.applyHitl(rule, r);
    return rule;
  }

  /**
   * Reject invalid `requireApproval` combinations early — matches the DSL
   * server-side validation (permit + require_approval is meaningless;
   * approvalConfig without requireApproval drops the config silently).
   */
  private validateHitl(
    permit: boolean,
    r: {
      requireApproval?: boolean;
      approvalConfig?: ApprovalConfigInput;
    },
    kind: string,
  ): void {
    if (r.requireApproval && permit) {
      throw new Error(
        `${kind}: requireApproval is only valid on forbid rules — use forbidHttp/forbidMcp/forbidAny`,
      );
    }
    if (r.approvalConfig !== undefined && !r.requireApproval) {
      throw new Error(
        `${kind}: approvalConfig is set but requireApproval is false — set requireApproval: true or drop the config`,
      );
    }
    if (r.approvalConfig?.requiredApprovals !== undefined) {
      if (!Number.isInteger(r.approvalConfig.requiredApprovals) || r.approvalConfig.requiredApprovals <= 0) {
        throw new Error(
          `${kind}: approvalConfig.requiredApprovals must be a positive integer, got ${r.approvalConfig.requiredApprovals}`,
        );
      }
    }
    if (r.approvalConfig?.timeoutSeconds !== undefined) {
      if (!Number.isInteger(r.approvalConfig.timeoutSeconds) || r.approvalConfig.timeoutSeconds <= 0) {
        throw new Error(
          `${kind}: approvalConfig.timeoutSeconds must be a positive integer, got ${r.approvalConfig.timeoutSeconds}`,
        );
      }
    }
  }

  private applyHitl(
    rule: DeclarativeRule,
    r: { requireApproval?: boolean; approvalConfig?: ApprovalConfigInput },
  ): void {
    if (r.requireApproval) {
      rule.require_approval = true;
    }
    if (r.approvalConfig !== undefined) {
      const wire: import("../types.js").DeclarativeApprovalConfig = {};
      if (r.approvalConfig.requiredApprovals !== undefined) {
        wire.required_approvals = r.approvalConfig.requiredApprovals;
      }
      if (r.approvalConfig.timeoutSeconds !== undefined) {
        wire.timeout_seconds = r.approvalConfig.timeoutSeconds;
      }
      rule.approval_config = wire;
    }
  }
}
