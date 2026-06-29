# @lupid/sdk

## What is Agentum?

In-process governance for AI agents. The SDK patches your LLM/MCP clients (OpenAI, Anthropic, LangChain, Vercel AI SDK, MCP stdio) to enforce Cedar policies, capture audit trails, and gate tool calls before they execute. v1's enforcement plane is the SDK; the Rust backend provides policy storage, audit ingest, and HITL approvals.

## Install

```sh
npm install @lupid/sdk
```

All peer dependencies are **optional** (declared in `peerDependenciesMeta`) — install whichever you use:

- `openai` (≥ 4.0.0)
- `@anthropic-ai/sdk` (≥ 0.27.0)
- `@langchain/core` (≥ 0.2.0)
- `ai` (≥ 3.0.0) — Vercel AI SDK
- `fastify` (≥ 4.0.0) — only if using the Fastify integration
- `@nestjs/common` (≥ 9.0.0) — only if using the NestJS integration

No Cohere or Gemini SDK peer dep is declared today; those providers are governed via the fetch interceptor only.

## Quick start

```ts
import { init } from "@lupid/sdk";

await init({
  apiKey:    process.env.AGENTUM_API_KEY!,
  baseUrl:   process.env.AGENTUM_BASE_URL!,    // e.g. https://api.agentum.ai
  agentName: "my-agent",
});

// From this point, OpenAI / Anthropic / LangChain / Vercel-AI / MCP-stdio
// calls in this process are governed by Agentum policies.
```

`init()` derives the tenant from the API key server-side; do not pass a `tenantId`.

### Provisioning `AGENTUM_API_KEY` (recommended)

Operators / dashboards / CI should mint an **agent-scoped** key in a single call by setting `mint_scoped_key: true` on agent registration. The response embeds `api_key.plaintext_key` (bound to the new agent's UUID, role hard-clamped to `Operator`, auto-revoked on `kill_agent` / `quarantine_agent`). Plaintext is exposed exactly once — capture it and inject it into the SDK process as `AGENTUM_API_KEY`. See the repo-root README "Onboarding an SDK with an agent-scoped key" section and [`ADR-0012`](../../docs/decisions/ADR-0012-agent-scoped-api-keys-default.md) for the full operator-side flow. The SDK itself never mints; it only consumes the key.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AGENTUM_BASE_URL` | yes | — | Gateway URL, e.g. `http://localhost:7071`. |
| `AGENTUM_API_KEY` | yes | — | Agent-scoped key provisioned by your operator via `POST /api/v1/agents` with `mint_scoped_key: true` (see above). |
| `AGENTUM_AGENT_NAME` | yes | — | Stable identifier for this agent. |
| `AGENTUM_AGENT_FRAMEWORK` | no | `agentum-sdk` | Reported framework label. |
| `AGENTUM_DECLARED_TOOLS` | no | — | CSV of tool names declared at register. |
| `AGENTUM_DEFAULT_SESSION_ID` | no | auto-generated | Pin a default session_id (test/CI). |
| `AGENTUM_DEFAULT_USER_ID` | no | — | Pin a default user_id for context enrichment. |
| `LUPID_MANIFEST_PATH` | no | — | Absolute or cwd-relative path to a tenant-schema YAML manifest. When set, `init()` loads + locally validates it before contacting the API. See [Tenant identity schema](#tenant-identity-schema) below. |
| `AGENTUM_PDP_URL` | no | `""` (disabled) | Opt-in local-PDP routing per [ADR-0017](../../docs/decisions/ADR-0017-pdp-default-opt-in.md). Unset or empty → all tool-call decisions go straight to central (Mode A). Set to a TCP URL (`http://127.0.0.1:7080`) to route through a loopback PDP sidecar, or a UDS URL (`unix:///run/agentum/pdp.sock`) for peer-credential auth. See [Deployment modes](#deployment-modes) below. |
| `AGENTUM_PDP_SERVICE_TOKEN` | conditional | — | Required when `AGENTUM_PDP_URL` is a TCP URL — bearer token the SDK sends to the PDP. Ignored on the `unix://` path (peer-credential auth via L08). Missing token on a TCP URL surfaces an `init()` warning; PDP requests then 401 fail-closed. |

Programmatic callers can pass any of these as options to `init({...})`. The manifest path can also be passed as `init({ manifest: "./agent.lupid.yaml" })` — flag wins over env, env wins over discovery.

## Deployment modes

Per [ADR-0017](../../docs/decisions/ADR-0017-pdp-default-opt-in.md), the SDK runs in one of two modes — the presence of `AGENTUM_PDP_URL` is the single toggle.

- **Mode A — central-only (zero-config default).** No PDP env vars set. Every `evaluateToolCall` posts directly to `POST /api/v1/sdk/evaluate-tool-call` on the gateway named by `AGENTUM_BASE_URL`. The `init()` log line reports `pdp=disabled`. This is the right choice when you have not deployed a PDP sidecar; nothing probes loopback and no spurious service-token warning fires.
- **Mode B — local PDP (opt-in).** Operator deploys a [PDP sidecar](../../docs/decisions/ADR-0009-cedar-policy-store-postgres.md) and sets `AGENTUM_PDP_URL` (TCP) plus `AGENTUM_PDP_SERVICE_TOKEN`, **or** `AGENTUM_PDP_URL=unix:///run/agentum/pdp.sock` (UDS, peer-credential auth). The SDK probes `${pdpUrl}/v1/health` once per discovery window and routes decisions through the PDP on success, falling through to central on transport failure (see L01). The `init()` log line reports `pdp=<url>`.

Operators on existing deployments who were relying on the previous implicit `http://127.0.0.1:7080` default must set the env var explicitly — see CHANGELOG.

## Tenant identity schema

At `init()`, the SDK reconciles a **local manifest** (YAML) against the **live schema** stored in the Lupid control plane. The active schema is then consumed by per-request dimension resolution and PII masking.

### Discovery

When `opts.manifest` is unset, the SDK looks for a manifest in this order:

1. `LUPID_MANIFEST_PATH` environment variable (absolute or cwd-relative).
2. A single `*.lupid.yaml` file in the current working directory. Multiple matches throw — pass `--manifest` or set the env var to disambiguate.
3. `./lupid/agent.yaml`.

Edge runtimes (Vercel Edge / Cloudflare Workers) don't have a filesystem; discovery gracefully returns `null` and the SDK proceeds with the live schema only.

### Version negotiation

After discovery, `init()` fetches `GET /api/v1/tenants/{tenantId}/schema` and reconciles:

| Local | Live | Outcome |
|---|---|---|
| absent | absent | `init()` throws `InitError` (no schema at all) |
| absent | present | Uses live; logs "no local manifest; using live" |
| present | absent (404) | Uses local with a warning; first `lupid schema push` reconciles |
| equal versions | equal versions | Uses local |
| local > live | local > live | Uses live; warns "manifest ahead of deployed — run `lupid schema push`" |
| local < live | local < live | Throws `InitError` — refuse to start; run `lupid schema pull` or upgrade the SDK |

The local manifest is validated client-side against the same rule set as the server (rules 1-6, 9, 10 from `IDENTITY_SCHEMA_PRIMITIVE.md`). Rules 7 and 8 are install-time two-schema diffs and run server-side only.

### `getActiveSchema()`

Other SDK surfaces (dimension resolver, PII masking, enrichment) read the active schema via the free function `getActiveSchema()` exported from `@lupid/sdk`. Throws `InitError` if called before `init()`.

### Disabling the manifest

Skip both discovery and the live fetch by setting `AGENTUM_BASE_URL` to a server with no schema installed for your tenant — the SDK boots with an empty-dimensions placeholder. **Not recommended** for production: dimension resolution and PII masking become no-ops.

## Supported runtimes

- Node ≥ 18 (per `engines.node`).
- Vercel Edge / Cloudflare Workers / browser environments work via the same `import` / `require` entries — the package does **not** declare `browser` or `workerd` export conditions today. Edge-safety is achieved via lazy `node:*` imports inside the source rather than separate runtime entries.
- Node-http interception is Node-only; edge/browser runtimes get fetch-only interception.
- ESM + CJS dual-published.

## Audit ingest

Every audit POST (`/api/v1/audit/ingest` and `/api/v1/audit/ingest/batch`) carries two replay-prevention headers, generated client-side:

| Header | Value | Notes |
|---|---|---|
| `x-agentum-nonce` | `crypto.randomUUID()` per request | Single-use within the server's replay window (UUIDv4). |
| `x-agentum-timestamp` | `Date.now().toString()` | Unix milliseconds at request-build time. |

The central API enforces both as of Q4 — `tenant_settings.audit_ingest_require_freshness` now defaults to `TRUE` for net-new tenants. Operators on existing deployments inherit the default on upgrade; per-tenant opt-out (`audit_ingest_require_freshness = FALSE`) remains for backward compatibility with custom audit shippers that cannot send the headers. Clock skew beyond the server's freshness window (default ±5 minutes) causes rejection — keep SDK hosts roughly time-synced.

The helper used by both POST sites lives at `src/audit/freshness.ts` and is import-free (`crypto.randomUUID()` is global in Node ≥ 14.17, Cloudflare Workers, Vercel Edge, Deno, and the browser).

## Known limitations

- Cohere/Gemini streaming response-side enforcement is pre-flight-only today (G-016).
- OpenAI Responses API streaming response-side enforcement is pending (G-017).
- MCP-over-HTTP enforcement is pending (G-018).
- Pre-init detection of LLM clients is advisory (warning only) — call `init()` before importing OpenAI/Anthropic clients (G-029).
- The endpoint/MITM enforcement plane is out-of-scope for v1 — for hard prevention against a malicious or compromised app, the SDK alone is detection-rich but in-process. See roadmap.
- **Edge runtimes (Vercel Edge / Cloudflare Workers): per-request context isolation requires Node.js.** `withAgentumContext` is a no-op on runtimes that do not provide `node:async_hooks` — session IDs and dimension values from the context wrapper are silently discarded. All concurrent requests in the same isolate share the process-level defaults set at `init()`. For correct per-request attribution set `export const runtime = "nodejs"` in your Next.js route handlers, or use the Express/NestJS adapters on a Node server. The SDK emits a one-time `console.warn` on the first `withAgentumContext` call in a no-ALS environment.

## Links

- Homepage: https://github.com/lupidai/lupid-sdk
- Issue tracker: https://github.com/lupidai/lupid-sdk/issues
- Changelog: [./CHANGELOG.md](./CHANGELOG.md)
