# Changelog

All notable changes to `@lupid/react` will be documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] — Unreleased

### Added

- Initial release of `@lupid/react` for the Acme.ai pilot integration
  (spec Z3).
- `<CapabilityToggles>` component — renders the per-scope capability
  registry as a tree with optimistic toggles + 5s background polling.
- Tree reconstruction from a flat `parent_id` list
  (`buildTree(flat)` → `TreeNode[]`).
- Typed `LupidError` mapping for the documented backend error codes:
  `scope_dimension_mismatch`, `dimension_not_materialized`,
  `too_many_dimension_filters`, `bulk_too_large`, `not_customer_visible`,
  `no_scoping_dimension_declared`, `unknown_error`.
- `"defaults"` scope mode renders the catalog defaults view (read-only).
- Friendly English error banner copy per known code.
- `data-testid` attributes on all interactive elements for downstream
  Playwright tests.

### Out of scope (tracked for follow-ups)

- SSE subscription for sub-second policy updates.
- TanStack Query / SWR-flavored variant.
- Bulk-toggle UI + cascade-confirmation dialog.
- Capability history view.
- i18n.
