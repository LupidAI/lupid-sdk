# `@lupid/react`

Drop-in React component for embedding Lupid capability governance UI in
your operator-facing admin surface. Built for host applications (e.g.
Acme.ai Nexus) that proxy Lupid through their own BFF.

This package exports exactly one component for v1:
[`<CapabilityToggles>`](./src/CapabilityToggles.tsx).

## Install

```bash
npm install @lupid/react
```

`react >= 18` is a peer dependency. The package has no other runtime
dependencies — everything else (build tooling, testing) is a devDep.

The component opts into the Next.js App Router Client Component boundary
via a `"use client"` banner, so it is safe to import from a Server
Component file. Internally it uses `useState` / `useEffect` / `fetch`.

## Quick start

```tsx
import { CapabilityToggles } from "@lupid/react";

export function NexusAdminCapabilities({ accountId }: { accountId: string }) {
  return (
    <CapabilityToggles
      apiBase="https://acme-admin.example.com/lupid-proxy"
      tenant="Acme"
      agent="nexus-copilot"
      scope={{ dimension: "account_id", value: accountId }}
      onToggle={(capId, enabled, outcome) => {
        console.warn(
          `[lupid] toggle ${capId} -> ${enabled}; cascades:`,
          outcome.side_effects,
        );
      }}
      onError={(err) => {
        // Show in your own toast/notification system.
        console.warn(`[lupid] error: ${err.code}`, err.message);
      }}
      pollIntervalMs={5000}
      authHeaders={{ "X-Acme-Session": getSession() }}
      className="my-toggle-grid"
    />
  );
}
```

To render the catalog defaults view (the empty state — before the
operator picks a scope), pass `scope="defaults"`:

```tsx
<CapabilityToggles
  apiBase="https://acme-admin.example.com/lupid-proxy"
  tenant="Acme"
  agent="nexus-copilot"
  scope="defaults"
/>
```

In defaults mode, all toggles render as disabled and a banner explains
that the operator must pick a scope before edits.

## Props

| Prop             | Type                                      | Default | Notes |
| ---------------- | ----------------------------------------- | ------- | ----- |
| `apiBase`        | `string`                                  | —       | Required. Base URL of your BFF; the component appends `/api/v1/...`. |
| `tenant`         | `string`                                  | —       | Lupid tenant id (UUID or slug). |
| `agent`          | `string`                                  | —       | Agent name within the tenant. |
| `scope`          | `{ dimension; value } \| "defaults"`      | —       | The scope to render. Use `"defaults"` for the empty state. |
| `onToggle`       | `(id, enabled, outcome) => void`          | —       | Optional. Fires after a successful PUT. `outcome.side_effects` carries the cascade preview. |
| `onError`        | `(error) => void`                         | —       | Optional. Fires for any error (initial load, poll, or toggle PUT). |
| `pollIntervalMs` | `number`                                  | `5000`  | Background poll cadence. |
| `authHeaders`    | `Record<string, string>`                  | —       | Forwarded as request headers. The component does not authenticate; your BFF should. |
| `className`      | `string`                                  | —       | Applied to the outermost wrapper. |

## Styling hooks

The component ships with semantic class names + `data-testid` attributes.
There is no bundled stylesheet — bring your own CSS. The following
attributes are stable:

- Outermost: `className="<your value>" data-testid="capability-toggles"`
- Defaults banner: `data-testid="capability-toggles-defaults-banner"`
- Error banner: `data-testid="capability-toggles-error"
  data-lupid-error-code="<code>"`
- Each tree node: `data-testid="capability-node-<id>" data-depth="<n>"
  data-risk="low|medium|high"`
- Each toggle input: `data-testid="capability-toggle-<id>"`
- Override badge: `data-testid="capability-override-<id>"`
- Override reset button: `data-testid="capability-reset-<id>"`
- Overrides side panel: `data-testid="capability-overrides-panel"`

CSS class names used by the component (all under your control):

```
.lupid-capability-error
.lupid-capability-defaults-banner
.lupid-capability-tree
.lupid-capability-node
.lupid-capability-row
.lupid-capability-display
.lupid-capability-description
.lupid-capability-override-badge
.lupid-capability-risk-badge
.lupid-capability-overrides
```

## Error handling

All non-2xx responses surface as a typed `LupidError`. The component
maps each code to a friendly English message, but the raw error is also
delivered to `onError` so you can integrate with your own surface.

| Code                            | When |
| ------------------------------- | ---- |
| `scope_dimension_mismatch`      | The scope dimension doesn't match the agent manifest. |
| `dimension_not_materialized`    | No data observed yet for this dimension. |
| `too_many_dimension_filters`    | The filter API was called with more dimensions than the agent declares. |
| `bulk_too_large`                | Bulk PUT exceeded the per-request cap (100). |
| `not_customer_visible`          | Toggle attempted on a system-hidden capability. |
| `no_scoping_dimension_declared` | The agent manifest has no scoping dimension. |
| `unknown_error`                 | Anything else (network failure, unknown HTTP code). |

## Limitations (v1)

- **5s polling, no SSE.** The component polls the list endpoint every
  `pollIntervalMs` for live state. SSE wiring is a follow-up.
- **No bulk toggle UI.** Single-toggle PUT only.
- **No cascade-confirm dialog.** The `side_effects` cascade preview is
  delivered to `onToggle` for the host app to surface.
- **No i18n.** English copy only.
- **No theming knobs beyond class names.**

## License

Apache-2.0
