# Changelog

All notable changes to `@lupid/sdk` are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed
- **Breaking (audit replay-prevention default ON):** SDK now always sends `x-agentum-nonce` (UUIDv4 via `crypto.randomUUID()`) + `x-agentum-timestamp` (Unix milliseconds) on `/audit/ingest` and `/audit/ingest/batch`. The central backend default for `tenant_settings.audit_ingest_require_freshness` flips to `true` in the paired Q4 backend release. Operators with custom audit consumers must either upgrade them to send these headers OR set `audit_ingest_require_freshness=false` per-tenant. New helper at `src/audit/freshness.ts`; both POST sites (`AgentumClient.ingestAuditEvent` + the batched flusher) and the `CedarToolCallClient` direct POST share it. (Q4)
- **Behavior change:** `AGENTUM_PDP_URL` no longer defaults to `http://127.0.0.1:7080`. Set it explicitly to enable local-PDP routing. Existing deployments relying on the implicit default must set the env var explicitly. The `init()` log line now reports `pdp=<url-or-disabled>` so Mode-B operators get positive confirmation that PDP is active. See [ADR-0017](../../docs/decisions/ADR-0017-pdp-default-opt-in.md).

## [0.1.0] — 2026-05-XX
### Added
- Initial public release of `@lupid/sdk`.
- `init()` autopatch for OpenAI, Anthropic, LangChain, Vercel AI SDK, MCP stdio.
- Cedar policy evaluation via `CedarToolCallClient`.
- Fetch + Node-http interceptors with fail-CLOSED defaults.
- Edge-runtime safety via lazy `node:*` imports (Vercel Edge / Cloudflare Workers compatible).
