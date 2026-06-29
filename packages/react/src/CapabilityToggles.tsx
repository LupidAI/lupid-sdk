"use client";

/**
 * `<CapabilityToggles>` — the one component exported by `@lupid/react` for
 * v1 of the Acme integration.
 *
 * Design constraints (per spec Z3 § "Scope discipline for v1"):
 * - One component. No router. No data layer dependency.
 * - Raw `useEffect` + `fetch` + 5s polling. Host apps that want TanStack
 *   Query / SWR can wrap this component themselves.
 * - SSR-safe (`"use client"` directive). Host apps on Next.js App Router
 *   import it from a Client Component boundary.
 * - No runtime deps beyond `react` (peer dep).
 *
 * Out of scope for v1: SSE subscription, bulk toggle, cascade-confirm
 * dialog, i18n, theming. The spec calls these out explicitly; see Z3
 * §"Explicitly out of scope".
 */

import type { ReactElement } from "react";
import { useEffect, useRef, useState } from "react";
import {
  deleteOverride,
  getDefaults,
  listCapabilities,
  toggleCapability,
} from "./api.js";
import { buildTree, type TreeNode } from "./tree.js";
import {
  LupidError,
  type CapabilityListResponse,
  type CapabilityTogglesScope,
  type LupidErrorCode,
  type ToggleResponse,
} from "./types.js";

export interface CapabilityTogglesProps {
  /**
   * The base URL of the host application's BFF that proxies to Lupid.
   * E.g. `"https://acme-admin.example.com/lupid-proxy"`. The component
   * appends `/api/v1/...` to this base.
   */
  apiBase: string;
  /** Lupid tenant id (UUID or slug). */
  tenant: string;
  /** Agent name within the tenant. */
  agent: string;
  /**
   * Either a `{ dimension, value }` scope identity, or the literal string
   * `"defaults"` to render the catalog-defaults read-only view (used as
   * the empty state before the operator picks a scope).
   */
  scope: CapabilityTogglesScope;
  /** Called after a successful PUT toggle commit. */
  onToggle?: (capabilityId: string, enabled: boolean, outcome: ToggleResponse) => void;
  /** Called on any fetch error (initial load, poll, or toggle PUT). */
  onError?: (error: LupidError) => void;
  /** Poll cadence in milliseconds. Default 5000 (per Q-B pin). */
  pollIntervalMs?: number;
  /**
   * Headers to forward to the BFF. The component does not authenticate;
   * the host BFF is expected to handle session→HMAC translation.
   */
  authHeaders?: Record<string, string>;
  /** Optional CSS class applied to the outermost wrapper. */
  className?: string;
}

/**
 * Friendly error copy keyed on the closed set of Lupid error codes. Copy
 * is hardcoded English for v1; i18n is out of scope.
 */
const ERROR_MESSAGES: Record<LupidErrorCode, string> = {
  scope_dimension_mismatch:
    "This scope doesn't match the agent's declared scoping dimension. Pick a different scope or update the agent manifest.",
  dimension_not_materialized:
    "No data has been observed for this scope dimension yet. Customers must produce traffic before per-scope overrides can be applied.",
  too_many_dimension_filters:
    "Too many dimension filters were applied. Reduce the number of filters and try again.",
  bulk_too_large:
    "The bulk toggle request exceeded the maximum number of entries allowed.",
  not_customer_visible:
    "This capability is system-managed and cannot be toggled by an operator.",
  no_scoping_dimension_declared:
    "The agent's manifest does not declare a scoping dimension; per-scope overrides are not available.",
  unknown_error:
    "Something went wrong contacting the Lupid API. Try again in a moment.",
};

/** Stable string for a scope, used to invalidate the polling effect. */
function scopeKey(scope: CapabilityTogglesScope): string {
  if (scope === "defaults") return "defaults";
  return `${scope.dimension}::${scope.value}`;
}

/**
 * Normalize any caught value into a `LupidError`. Network and parsing
 * failures already arrive as `LupidError` from `api.ts`; programmer
 * errors (a non-Error throw) are mapped to `unknown_error`.
 */
function asLupidError(err: unknown): LupidError {
  if (err instanceof LupidError) return err;
  if (err instanceof Error) {
    return new LupidError("unknown_error", err.message, 0);
  }
  return new LupidError("unknown_error", String(err), 0);
}

interface ErrorBannerProps {
  error: LupidError;
  className?: string | undefined;
}

function ErrorBanner({ error, className }: ErrorBannerProps): ReactElement {
  const friendly = ERROR_MESSAGES[error.code];
  return (
    <div
      role="alert"
      data-testid="capability-toggles-error"
      data-lupid-error-code={error.code}
      className={className ?? "lupid-capability-error"}
    >
      <strong>Couldn&apos;t load capabilities.</strong>
      <p>{friendly}</p>
    </div>
  );
}

interface CapabilityTreeNodeProps {
  node: TreeNode;
  depth: number;
  readonly: boolean;
  pending: ReadonlySet<string>;
  onToggle: (capabilityId: string, enabled: boolean) => void;
}

function CapabilityTreeNode({
  node,
  depth,
  readonly,
  pending,
  onToggle,
}: CapabilityTreeNodeProps): ReactElement {
  const checkboxDisabled = readonly || !node.customer_visible || pending.has(node.id);
  return (
    <div
      className="lupid-capability-node"
      data-testid={`capability-node-${node.id}`}
      data-depth={depth}
      data-risk={node.risk}
      style={{ paddingLeft: depth * 16 }}
    >
      <label className="lupid-capability-row">
        <input
          type="checkbox"
          checked={node.effective}
          disabled={checkboxDisabled}
          onChange={(e) => onToggle(node.id, e.target.checked)}
          aria-label={node.display ?? node.id}
          data-testid={`capability-toggle-${node.id}`}
        />
        <span className="lupid-capability-display">
          {node.display ?? node.id}
        </span>
        {node.override_value !== null && (
          <span
            className="lupid-capability-override-badge"
            data-testid={`capability-override-${node.id}`}
            title="Operator override is set for this scope"
          >
            override
          </span>
        )}
        {node.risk === "high" && (
          <span className="lupid-capability-risk-badge" aria-label="High risk">
            high
          </span>
        )}
      </label>
      {node.description !== null && node.description.length > 0 && (
        <p className="lupid-capability-description">{node.description}</p>
      )}
      {node.children.map((child) => (
        <CapabilityTreeNode
          key={child.id}
          node={child}
          depth={depth + 1}
          readonly={readonly}
          pending={pending}
          onToggle={onToggle}
        />
      ))}
    </div>
  );
}

/**
 * The Z3 component: renders the capability tree for a (tenant, agent,
 * scope) with optimistic toggle and 5s background polling.
 */
export function CapabilityToggles(props: CapabilityTogglesProps): ReactElement | null {
  const {
    apiBase,
    tenant,
    agent,
    scope,
    onToggle,
    onError,
    pollIntervalMs,
    authHeaders,
    className,
  } = props;

  const [data, setData] = useState<CapabilityListResponse | null>(null);
  const [error, setError] = useState<LupidError | null>(null);
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState<ReadonlySet<string>>(new Set());

  // Keep latest callback refs so the polling effect doesn't tear down +
  // re-arm on every parent render.
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;
  const onToggleRef = useRef(onToggle);
  onToggleRef.current = onToggle;

  const isDefaults = scope === "defaults";
  const sKey = scopeKey(scope);
  const effectivePollInterval = pollIntervalMs ?? 5000;

  // Polling effect — invalidated on (apiBase, tenant, agent, scope, pollInterval).
  useEffect(() => {
    let cancelled = false;

    const fetchData = async (): Promise<void> => {
      try {
        const resp = isDefaults
          ? await getDefaults(apiBase, tenant, agent, authHeaders)
          : await listCapabilities(
              apiBase,
              tenant,
              agent,
              scope as { dimension: string; value: string },
              authHeaders,
            );
        if (!cancelled) {
          setData(resp);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          const lupidErr = asLupidError(err);
          setError(lupidErr);
          setLoading(false);
          onErrorRef.current?.(lupidErr);
        }
      }
    };

    void fetchData();
    const handle = setInterval(() => {
      void fetchData();
    }, effectivePollInterval);
    return () => {
      cancelled = true;
      clearInterval(handle);
    };
    // `scope` is captured via `sKey`; `authHeaders` is intentionally
    // omitted (callers should memoize if they care about identity churn).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, tenant, agent, sKey, effectivePollInterval, isDefaults]);

  const handleToggle = async (capabilityId: string, enabled: boolean): Promise<void> => {
    if (isDefaults) return; // defaults view is read-only
    const concreteScope = scope as { dimension: string; value: string };
    const previousData = data;
    // Optimistic update — flip the row in-place.
    if (data !== null) {
      setData({
        ...data,
        capabilities: data.capabilities.map((c) =>
          c.id === capabilityId ? { ...c, effective: enabled, override_value: enabled } : c,
        ),
      });
    }
    setPending((prev) => {
      const next = new Set(prev);
      next.add(capabilityId);
      return next;
    });
    try {
      const outcome = await toggleCapability(
        apiBase,
        tenant,
        agent,
        concreteScope,
        capabilityId,
        enabled,
        authHeaders,
      );
      onToggleRef.current?.(capabilityId, enabled, outcome);
      // The next poll tick reconciles against the server. We don't
      // overwrite `data` here because the optimistic flip is already
      // visible, and the cascade preview (descendants_now_effective_off)
      // is surfaced through `onToggle` for the host app to render.
    } catch (err) {
      // Revert on failure.
      if (previousData !== null) {
        setData(previousData);
      }
      const lupidErr = asLupidError(err);
      setError(lupidErr);
      onErrorRef.current?.(lupidErr);
    } finally {
      setPending((prev) => {
        const next = new Set(prev);
        next.delete(capabilityId);
        return next;
      });
    }
  };

  const handleReset = async (capabilityId: string): Promise<void> => {
    if (isDefaults) return;
    const concreteScope = scope as { dimension: string; value: string };
    setPending((prev) => {
      const next = new Set(prev);
      next.add(capabilityId);
      return next;
    });
    try {
      await deleteOverride(apiBase, tenant, agent, concreteScope, capabilityId, authHeaders);
      // Next poll reconciles.
    } catch (err) {
      const lupidErr = asLupidError(err);
      setError(lupidErr);
      onErrorRef.current?.(lupidErr);
    } finally {
      setPending((prev) => {
        const next = new Set(prev);
        next.delete(capabilityId);
        return next;
      });
    }
  };

  if (loading) {
    return (
      <div className={className} data-testid="capability-toggles-loading">
        Loading capabilities…
      </div>
    );
  }
  if (error !== null && data === null) {
    return (
      <div className={className}>
        <ErrorBanner error={error} />
      </div>
    );
  }
  if (data === null) {
    return null;
  }

  const tree = buildTree(data.capabilities);

  return (
    <div className={className} data-testid="capability-toggles">
      {isDefaults && (
        <div
          className="lupid-capability-defaults-banner"
          role="note"
          data-testid="capability-toggles-defaults-banner"
        >
          Viewing catalog defaults. Pick a scope to make changes.
        </div>
      )}
      {error !== null && (
        // Non-fatal error (e.g. failed poll after a successful first load) —
        // show inline but keep rendering the last-known tree.
        <ErrorBanner error={error} />
      )}
      <div className="lupid-capability-tree">
        {tree.map((root) => (
          <CapabilityTreeNode
            key={root.id}
            node={root}
            depth={0}
            readonly={isDefaults}
            pending={pending}
            onToggle={(capId, enabled) => {
              void handleToggle(capId, enabled);
            }}
          />
        ))}
      </div>
      {!isDefaults && (
        <ResetOverridesPanel
          data={data}
          pending={pending}
          onReset={(capId) => {
            void handleReset(capId);
          }}
        />
      )}
    </div>
  );
}

interface ResetOverridesPanelProps {
  data: CapabilityListResponse;
  pending: ReadonlySet<string>;
  onReset: (capabilityId: string) => void;
}

/**
 * Sidebar of explicit overrides currently in effect for this scope, each
 * with a "reset" button that issues DELETE …/override. Renders nothing
 * when no overrides exist.
 */
function ResetOverridesPanel({
  data,
  pending,
  onReset,
}: ResetOverridesPanelProps): ReactElement | null {
  const overrides = data.capabilities.filter((c) => c.override_value !== null);
  if (overrides.length === 0) return null;
  return (
    <aside
      className="lupid-capability-overrides"
      data-testid="capability-overrides-panel"
    >
      <h4>Per-scope overrides</h4>
      <ul>
        {overrides.map((c) => (
          <li key={c.id} data-testid={`capability-override-item-${c.id}`}>
            <span>{c.display ?? c.id}</span>
            <button
              type="button"
              disabled={pending.has(c.id)}
              onClick={() => onReset(c.id)}
              data-testid={`capability-reset-${c.id}`}
            >
              Reset
            </button>
          </li>
        ))}
      </ul>
    </aside>
  );
}
