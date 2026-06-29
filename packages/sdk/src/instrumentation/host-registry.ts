/**
 * LLM host registry + provider classifier.
 *
 * The fetch interceptor uses this as a cheap first-pass filter so non-LLM
 * traffic incurs only a URL parse + Set lookup. User code can extend the
 * registry via `init({ llmHosts })` or `addLlmHosts()`.
 *
 * Wildcards: a leading `*.` matches any subdomain of the suffix
 * (e.g. `*.openai.azure.com`). A middle `.*.` matches any single label
 * between fixed prefix + suffix (e.g. `bedrock-runtime.*.amazonaws.com`
 * matches `bedrock-runtime.us-east-1.amazonaws.com`).
 */

export type Provider =
  | "openai"
  | "anthropic"
  | "openai-compatible"
  | "bedrock"
  | "cohere"
  | "gemini"
  // MCP Streamable-HTTP (GR-19). NOT emitted by `classifyUrl` — MCP servers
  // live on arbitrary URLs, so there is no hostname to classify. The interceptors
  // detect MCP at the wire level via `isMcpWireCandidate` (mcp-http.ts) and
  // construct `{ provider: "mcp-http", shape: "mcp-jsonrpc" }` directly when
  // they hand a request to the MCP path.
  | "mcp-http"
  | null;

export type WireShape =
  | "openai-chat"
  | "openai-responses"
  | "anthropic-messages"
  | "bedrock-invoke"
  | "bedrock-converse"
  | "cohere-chat"
  | "gemini-generate"
  // MCP JSON-RPC over Streamable HTTP (GR-19). Paired with `provider:
  // "mcp-http"`; emitted by the wire-level MCP gate, not `classifyUrl`.
  | "mcp-jsonrpc"
  | null;

export interface HostMatch {
  provider: Provider;
  shape: WireShape;
}

const DEFAULT_LLM_HOSTS: readonly string[] = [
  "api.openai.com",
  "api.anthropic.com",
  "*.openai.azure.com",
  "api.together.xyz",
  "api.mistral.ai",
  "api.groq.com",
  "api.deepseek.com",
  "api.x.ai",
  "api.perplexity.ai",
  "openrouter.ai",
  "api.cohere.ai",
  "generativelanguage.googleapis.com",
  "api.fireworks.ai",
  "api.anyscale.com",
  "bedrock-runtime.*.amazonaws.com",
];

/**
 * Mutate the active runtime's `HostRegistry` (if `init()` ran with the
 * fetch interceptor installed). Returns `true` if the hosts were applied.
 * Defined here to avoid circular imports — the runtime singleton holds
 * the registry reference.
 */
let _activeRegistry: HostRegistry | null = null;
export function _setActiveHostRegistry(reg: HostRegistry | null): void {
  _activeRegistry = reg;
}
export function addLlmHosts(hosts: readonly string[]): boolean {
  if (!_activeRegistry) return false;
  _activeRegistry.addAll(hosts);
  return true;
}

/**
 * Parse extra LLM host patterns from a raw env-var string
 * (`AGENTUM_EXTRA_LLM_HOSTS`). Patterns are separated by commas and/or any
 * whitespace, trimmed, with empties dropped. Same pattern syntax as
 * `DEFAULT_LLM_HOSTS` (exact, leading `*.`, middle `.*.` wildcards).
 *
 * Edge-safe: pure string processing, no Node builtins.
 */
export function parseExtraLlmHosts(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[\s,]+/)
    .map((h) => h.trim())
    .filter((h) => h.length > 0);
}

export class HostRegistry {
  private readonly exact: Set<string> = new Set();
  private readonly suffixes: string[] = [];
  // Middle-wildcard patterns like `bedrock-runtime.*.amazonaws.com`, stored
  // as `{prefix, suffix}` where the wildcard `.*.` must match exactly one
  // dot-bounded label (no further dots inside the gap).
  private readonly midWildcards: Array<{ prefix: string; suffix: string }> = [];

  constructor(extra: readonly string[] = []) {
    for (const h of DEFAULT_LLM_HOSTS) this.add(h);
    for (const h of extra) this.add(h);
  }

  add(host: string): void {
    const normalized = host.toLowerCase().trim();
    if (!normalized) return;
    if (normalized.startsWith("*.")) {
      this.suffixes.push(normalized.slice(1));
      return;
    }
    const star = normalized.indexOf(".*.");
    if (star > 0 && normalized.indexOf(".*.", star + 1) === -1) {
      this.midWildcards.push({
        prefix: normalized.slice(0, star + 1), // include trailing dot
        suffix: normalized.slice(star + 2),    // include leading dot
      });
      return;
    }
    this.exact.add(normalized);
  }

  addAll(hosts: readonly string[]): void {
    for (const h of hosts) this.add(h);
  }

  matches(host: string): boolean {
    const h = host.toLowerCase();
    if (this.exact.has(h)) return true;
    for (const sfx of this.suffixes) {
      if (h.endsWith(sfx)) return true;
    }
    for (const { prefix, suffix } of this.midWildcards) {
      if (!h.startsWith(prefix) || !h.endsWith(suffix)) continue;
      const middle = h.slice(prefix.length, h.length - suffix.length);
      // The wildcard label must be non-empty and contain no dots.
      if (middle.length > 0 && !middle.includes(".")) return true;
    }
    return false;
  }
}

/**
 * Classify a URL into provider + wire shape. Body inspection is cheap and
 * happens later — this is path-only.
 *
 * Returns `{provider:null, shape:null}` if not classifiable; the caller
 * should still treat host-registry-matched URLs as observable, but only
 * provider-classifiable ones can be enforced.
 */
export function classifyUrl(url: string): HostMatch {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { provider: null, shape: null };
  }
  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname;

  if (host === "api.openai.com" || host.endsWith(".openai.azure.com")) {
    if (path.includes("/responses")) {
      return { provider: "openai", shape: "openai-responses" };
    }
    if (path.includes("/chat/completions")) {
      return { provider: "openai", shape: "openai-chat" };
    }
    return { provider: "openai", shape: null };
  }
  if (host === "api.anthropic.com") {
    if (path.includes("/messages")) {
      return { provider: "anthropic", shape: "anthropic-messages" };
    }
    return { provider: "anthropic", shape: null };
  }

  // OpenAI-compatible — same chat-completions path shape, different host.
  const openAICompatHosts = new Set([
    "api.together.xyz",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.x.ai",
    "api.perplexity.ai",
    "openrouter.ai",
    "api.fireworks.ai",
    "api.anyscale.com",
  ]);
  if (openAICompatHosts.has(host)) {
    if (path.includes("/chat/completions")) {
      return { provider: "openai-compatible", shape: "openai-chat" };
    }
    return { provider: "openai-compatible", shape: null };
  }

  // Cohere — POST https://api.cohere.ai/v1/chat (or /v2/chat). The official
  // Cohere SDK (cohere-ai >=7) uses `fetch` against this exact path; only
  // explicit /v1 or /v2 chat is classified to avoid catching unrelated
  // routes (embeddings, rerank) that don't share the chat envelope.
  if (host === "api.cohere.ai" && /\/v[12]\/chat\b/.test(path)) {
    return { provider: "cohere", shape: "cohere-chat" };
  }

  // AWS Bedrock — region-suffixed host `bedrock-runtime.<region>.amazonaws.com`.
  // Two API shapes are recognised at the URL level only (body inspection is a
  // follow-up):
  //   /model/<modelId>/invoke[-with-response-stream]  → bedrock-invoke
  //   /model/<modelId>/converse[-stream]              → bedrock-converse
  // The modelId can be URL-encoded (`%3A` etc.); the `[^/]+` segment handles this.
  if (host.startsWith("bedrock-runtime.") && host.endsWith(".amazonaws.com")) {
    if (/^\/model\/[^/]+\/invoke(-with-response-stream)?$/.test(path)) {
      return { provider: "bedrock", shape: "bedrock-invoke" };
    }
    if (/^\/model\/[^/]+\/converse(-stream)?$/.test(path)) {
      return { provider: "bedrock", shape: "bedrock-converse" };
    }
    return { provider: "bedrock", shape: null };
  }

  // Gemini — POST https://generativelanguage.googleapis.com/v1{,beta}/models/<model>:generateContent
  // or :streamGenerateContent. Both URL shapes resolve to the same wire
  // shape `gemini-generate`; the streaming variant is parsed by
  // `GeminiSSEParser` in `wire-parsers.ts`. The stream path was previously
  // left unclassified because no SDK-side parser existed; that parser now
  // ships and enforces tool-call denies on streaming Gemini traffic.
  if (
    host === "generativelanguage.googleapis.com" &&
    (/:streamGenerateContent\b/.test(path) || /:generateContent\b/.test(path))
  ) {
    return { provider: "gemini", shape: "gemini-generate" };
  }

  return { provider: null, shape: null };
}

/**
 * Read-only snapshot of the built-in host list. Exported for tests so they
 * can assert the two-list invariant (every default host has a classifyUrl
 * branch). Not intended for runtime mutation — use `addLlmHosts()` for that.
 */
export const _DEFAULT_LLM_HOSTS_FOR_TESTS: readonly string[] = DEFAULT_LLM_HOSTS;
