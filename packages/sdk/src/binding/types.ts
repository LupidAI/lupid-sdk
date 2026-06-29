/**
 * Binding-mode types for the Spec 2 agent manifest (S2-E04).
 *
 * The agent manifest's `spec.runtime.binding_mode` field declares which
 * of the five archetype-specific placement patterns the agent uses. At
 * SDK init the dispatcher in `./dispatch.ts` reads this value, validates
 * the runtime can support it, and either proceeds (`orchestrator`,
 * `framework_hook`) or fails fast with `BindingModeNotYetSupportedError`
 * (the three MVP-3 modes).
 *
 * Spec source of truth: `.claude/plan/AGENT_MANIFEST_AND_REVISIONS.md`
 * §Archetype fit and `runtime.binding_mode`.
 *
 * MVP-1 active modes:  `orchestrator`, `framework_hook`.
 * MVP-3 deferred modes: `per_subagent`, `acl_edge`, `actor_per_instance`
 *                       (tracked under tickets S2-H01..S2-H09).
 */

/**
 * The five declared binding modes from
 * `AGENT_MANIFEST_AND_REVISIONS.md` §Archetype fit. The enum is closed —
 * any future mode requires (a) updating this union and (b) updating the
 * exhaustiveness `never` check in `dispatch.ts`.
 */
export type BindingMode =
  | "orchestrator"
  | "per_subagent"
  | "acl_edge"
  | "actor_per_instance"
  | "framework_hook";

/** All declared binding modes, in spec order. Used by tests + diagnostics. */
export const ALL_BINDING_MODES: readonly BindingMode[] = [
  "orchestrator",
  "per_subagent",
  "acl_edge",
  "actor_per_instance",
  "framework_hook",
];

/** Modes that actively run at MVP-1. Inferred from the dispatch table. */
export const ACTIVE_BINDING_MODES: readonly BindingMode[] = [
  "orchestrator",
  "framework_hook",
];

/** Modes that are accepted at parse but rejected at init (MVP-3 deferred). */
export const DEFERRED_BINDING_MODES: readonly BindingMode[] = [
  "per_subagent",
  "acl_edge",
  "actor_per_instance",
];

/**
 * The implementation tickets (S2-H01..S2-H09) that will activate the
 * three deferred modes. Surfaced on the error so a customer who
 * declares one of those modes gets an exact pointer to the tracking
 * work rather than a generic "not supported".
 */
export const MVP3_REFERENCE_TICKETS: readonly string[] = [
  "S2-H01",
  "S2-H02",
  "S2-H03",
  "S2-H04",
  "S2-H05",
  "S2-H06",
  "S2-H07",
  "S2-H08",
  "S2-H09",
];

/**
 * Thrown by `runPerModeScan` when the manifest declares one of the three
 * MVP-3 binding modes. The SDK refuses to start to avoid silently
 * shipping with the wrong enforcement plane wired.
 *
 * The error carries the declared mode, the milestone at which it
 * activates (`"MVP-3"`), and the list of tracking tickets so the
 * operator can subscribe to the work or pick a different archetype.
 */
export class BindingModeNotYetSupportedError extends Error {
  public readonly mode: BindingMode;
  public readonly supportedAt: string;
  public readonly referenceTickets: readonly string[];

  constructor(
    mode: BindingMode,
    opts: {
      supportedAt?: string;
      referenceTickets?: readonly string[];
      message?: string;
    } = {},
  ) {
    const supportedAt = opts.supportedAt ?? "MVP-3";
    const referenceTickets = opts.referenceTickets ?? MVP3_REFERENCE_TICKETS;
    const message =
      opts.message ??
      `Binding mode "${mode}" is not yet supported. ` +
        `It activates in ${supportedAt} via tickets ` +
        `${referenceTickets.join(", ")}. Until then the SDK refuses to ` +
        `start to avoid silently shipping with the wrong enforcement ` +
        `plane wired. If you do not need this archetype yet, set ` +
        `spec.runtime.binding_mode to "orchestrator" or "framework_hook" ` +
        `in your *.lupid.yaml manifest.`;
    super(message);
    this.name = "BindingModeNotYetSupportedError";
    this.mode = mode;
    this.supportedAt = supportedAt;
    this.referenceTickets = referenceTickets;
  }
}

/**
 * Thrown by `extractBindingMode` when `spec.runtime.binding_mode` is
 * present in the YAML but is not one of the five declared values. This
 * is a parse-time refusal — the manifest is malformed; the operator
 * needs to fix it before the SDK can proceed.
 */
export class InvalidBindingModeError extends Error {
  public readonly received: string;

  constructor(received: string) {
    super(
      `spec.runtime.binding_mode must be one of ` +
        `${ALL_BINDING_MODES.map((m) => `"${m}"`).join(" | ")}; ` +
        `got "${received}".`,
    );
    this.name = "InvalidBindingModeError";
    this.received = received;
  }
}
