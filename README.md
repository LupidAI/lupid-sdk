# Lupid SDK

In-process governance for AI agents — the developer-facing SDK for the **Agentum engine**.

`@lupid/sdk` drops into your agent host and transparently patches the LLM and MCP clients it already uses (OpenAI, Anthropic, the Vercel AI SDK, LangChain, raw `fetch`/`node:http`, MCP stdio) to add **identity, policy enforcement, PII masking, and audit** — without rewriting your agent.

> **Open-core.** This SDK is the open-source *autopatch plane* of the Agentum engine. It evaluates policy against an Agentum gateway / PDP endpoint (self-hostable, or Lupid Cloud). The SDK is Apache-2.0; the central control plane (multi-tenant policy authoring, dashboard, audit warehouse, HITL workflow) is a separate product.

## Packages

| Package | npm | What it is |
| --- | --- | --- |
| [`@lupid/sdk`](packages/sdk) | `@lupid/sdk` | The TypeScript/JavaScript SDK — autopatch + framework adapters + PII masking. |
| [`@lupid/react`](packages/react) | `@lupid/react` | React components for embedding capability-governance UI in host apps. |

## Quickstart

```bash
npm install @lupid/sdk
```

```ts
import { init } from "@lupid/sdk";

// Patches the LLM/MCP clients in this process. Point it at your
// Agentum gateway or local PDP via AGENTUM_BASE_URL.
await init({
  baseUrl: process.env.AGENTUM_BASE_URL, // e.g. http://localhost:7071
  apiKey: process.env.AGENTUM_API_KEY,
  agentId: process.env.AGENTUM_AGENT_ID,
});

// From here, your existing OpenAI/Anthropic/MCP calls are governed.
```

Framework adapters are available as subpath imports — e.g.
`@lupid/sdk/frameworks/langchain`, `/frameworks/vercel-ai`, `/frameworks/openai`,
`/frameworks/express`, `/frameworks/nextjs`, `/frameworks/fastify`,
`/frameworks/nestjs`. See [`packages/sdk/README.md`](packages/sdk/README.md) for
the full API, environment variables, and per-framework usage.

## What this is — and isn't

- **Is:** a self-contained, edge-safe SDK that intercepts LLM/MCP traffic in-process and enforces policy decisions returned by an Agentum gateway/PDP. Fail-closed by default.
- **Isn't:** a policy *authoring* tool or control plane. The SDK needs an Agentum gateway/PDP endpoint (`AGENTUM_BASE_URL`) to evaluate against — run one yourself or use Lupid Cloud.

## Configuration

Common environment variables (see the package README for the full list):

| Var | Purpose |
| --- | --- |
| `AGENTUM_BASE_URL` | **Required.** Gateway / PDP URL to evaluate policy against. |
| `AGENTUM_API_KEY` | Agent API key. |
| `AGENTUM_AGENT_ID` | Agent identity. |
| `AGENTUM_EXTRA_LLM_HOSTS` | Comma/space-separated extra LLM hostnames to govern (supports `*.` and `.*.` wildcards), in addition to the built-in public providers. |

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). All commits must be signed off ([DCO](CONTRIBUTING.md#developer-certificate-of-origin)). Please read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

[Apache-2.0](LICENSE).
