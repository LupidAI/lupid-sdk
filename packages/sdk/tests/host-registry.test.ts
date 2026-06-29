/**
 * Unit tests for the LLM host registry + URL classifier.
 *
 * Covers the A1 regression: every host listed in `DEFAULT_LLM_HOSTS` must
 * have a matching `classifyUrl` branch — otherwise the fetch interceptor
 * silently observes-but-doesn't-enforce that provider (the original
 * Cohere / Gemini gap).
 */

import {
  classifyUrl,
  HostRegistry,
  parseExtraLlmHosts,
  _DEFAULT_LLM_HOSTS_FOR_TESTS,
} from "../src/instrumentation/host-registry";

// ── helpers ────────────────────────────────────────────────────────────────

/**
 * Map a `DEFAULT_LLM_HOSTS` entry to its canonical chat-shaped probe URL.
 * Every default host is supposed to have a classifiable LLM chat path; the
 * point of this map is so the two-list invariant test below knows the
 * "real" URL shape each provider uses, not just the hostname.
 *
 * If you add a host to `DEFAULT_LLM_HOSTS`, add the probe URL here AND a
 * branch in `classifyUrl` — the invariant test will fail until you do.
 */
function canonicalProbeUrl(host: string): string {
  // Wildcards: pick a representative subdomain.
  if (host === "*.openai.azure.com") {
    return "https://my-resource.openai.azure.com/openai/deployments/m/chat/completions?api-version=2024-02-15";
  }
  // OpenAI
  if (host === "api.openai.com") {
    return "https://api.openai.com/v1/chat/completions";
  }
  // Anthropic
  if (host === "api.anthropic.com") {
    return "https://api.anthropic.com/v1/messages";
  }
  // OpenAI-compatible
  if (
    host === "api.together.xyz" ||
    host === "api.mistral.ai" ||
    host === "api.groq.com" ||
    host === "api.deepseek.com" ||
    host === "api.x.ai" ||
    host === "api.perplexity.ai" ||
    host === "openrouter.ai" ||
    host === "api.fireworks.ai" ||
    host === "api.anyscale.com"
  ) {
    return `https://${host}/v1/chat/completions`;
  }
  // Cohere
  if (host === "api.cohere.ai") {
    return "https://api.cohere.ai/v1/chat";
  }
  // Gemini
  if (host === "generativelanguage.googleapis.com") {
    return "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent";
  }
  // AWS Bedrock — region-suffixed; pick us-east-1 as the canonical probe.
  if (host === "bedrock-runtime.*.amazonaws.com") {
    return "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet-20240229-v1%3A0/invoke";
  }
  throw new Error(`canonicalProbeUrl: no probe registered for host '${host}' — add one alongside the new DEFAULT_LLM_HOSTS entry`);
}

// ── tests ──────────────────────────────────────────────────────────────────

describe("host-registry / classifyUrl", () => {
  it("every DEFAULT_LLM_HOSTS entry has a classifyUrl branch (two-list invariant)", () => {
    for (const host of _DEFAULT_LLM_HOSTS_FOR_TESTS) {
      const probe = canonicalProbeUrl(host);
      const match = classifyUrl(probe);
      expect(match.shape).not.toBeNull();
      expect(match.provider).not.toBeNull();
    }
  });

  it("OpenAI chat.completions classifies as openai/openai-chat", () => {
    expect(classifyUrl("https://api.openai.com/v1/chat/completions")).toEqual({
      provider: "openai",
      shape: "openai-chat",
    });
  });

  it("OpenAI Responses classifies as openai/openai-responses", () => {
    expect(classifyUrl("https://api.openai.com/v1/responses")).toEqual({
      provider: "openai",
      shape: "openai-responses",
    });
  });

  it("Anthropic /v1/messages classifies as anthropic/anthropic-messages", () => {
    expect(classifyUrl("https://api.anthropic.com/v1/messages")).toEqual({
      provider: "anthropic",
      shape: "anthropic-messages",
    });
  });

  it("Cohere /v1/chat classifies as cohere/cohere-chat", () => {
    expect(classifyUrl("https://api.cohere.ai/v1/chat")).toEqual({
      provider: "cohere",
      shape: "cohere-chat",
    });
  });

  it("Cohere /v2/chat classifies as cohere/cohere-chat", () => {
    expect(classifyUrl("https://api.cohere.ai/v2/chat")).toEqual({
      provider: "cohere",
      shape: "cohere-chat",
    });
  });

  it("Cohere non-chat paths (embed, rerank) do not classify as cohere-chat", () => {
    expect(classifyUrl("https://api.cohere.ai/v1/embed")).toEqual({
      provider: null,
      shape: null,
    });
    expect(classifyUrl("https://api.cohere.ai/v1/rerank")).toEqual({
      provider: null,
      shape: null,
    });
  });

  it("Gemini :generateContent classifies as gemini/gemini-generate", () => {
    expect(
      classifyUrl(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
      ),
    ).toEqual({ provider: "gemini", shape: "gemini-generate" });
  });

  it("Gemini :streamGenerateContent classifies as gemini/gemini-generate (A13)", () => {
    // A13 added the streaming SSE parser (`GeminiSSEParser`) in
    // wire-parsers.ts, so the stream variant routes through the same
    // enforcement path as :generateContent. Before A13 this was
    // deliberately unclassified.
    expect(
      classifyUrl(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:streamGenerateContent",
      ),
    ).toEqual({ provider: "gemini", shape: "gemini-generate" });
  });

  it("Gemini :streamGenerateContent with ?alt=sse query also classifies", () => {
    // The Vercel AI SDK and the official @google/generative-ai SDK both
    // use `?alt=sse` to request SSE framing on the stream endpoint;
    // classification must tolerate the query string.
    expect(
      classifyUrl(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse",
      ),
    ).toEqual({ provider: "gemini", shape: "gemini-generate" });
  });

  // ── AWS Bedrock (PRE-S2-12) ─────────────────────────────────────────────
  it("Bedrock InvokeModel classifies as bedrock/bedrock-invoke", () => {
    const url =
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-sonnet-20240229-v1%3A0/invoke";
    expect(classifyUrl(url)).toEqual({
      provider: "bedrock",
      shape: "bedrock-invoke",
    });
  });

  it("Bedrock Converse classifies as bedrock/bedrock-converse", () => {
    const url =
      "https://bedrock-runtime.eu-west-1.amazonaws.com/model/amazon.nova-pro-v1%3A0/converse";
    expect(classifyUrl(url)).toEqual({
      provider: "bedrock",
      shape: "bedrock-converse",
    });
  });

  it("Bedrock ConverseStream classifies as bedrock/bedrock-converse", () => {
    const url =
      "https://bedrock-runtime.us-west-2.amazonaws.com/model/amazon.titan-text-express-v1/converse-stream";
    expect(classifyUrl(url)).toEqual({
      provider: "bedrock",
      shape: "bedrock-converse",
    });
  });

  it("Bedrock unknown path classifies as bedrock/null (provider known, shape unknown)", () => {
    const url = "https://bedrock-runtime.us-east-1.amazonaws.com/foundation-models";
    expect(classifyUrl(url)).toEqual({
      provider: "bedrock",
      shape: null,
    });
  });

  it("HostRegistry mid-wildcard matches Bedrock region hosts but not arbitrary AWS hosts", () => {
    const reg = new HostRegistry();
    expect(reg.matches("bedrock-runtime.us-east-1.amazonaws.com")).toBe(true);
    expect(reg.matches("bedrock-runtime.eu-west-1.amazonaws.com")).toBe(true);
    // Empty wildcard segment must not match.
    expect(reg.matches("bedrock-runtime..amazonaws.com")).toBe(false);
    // Multi-label segment (extra dots) must not match — wildcard is single label.
    expect(reg.matches("bedrock-runtime.us-east-1.foo.amazonaws.com")).toBe(false);
    // Unrelated AWS service must not match.
    expect(reg.matches("s3.us-east-1.amazonaws.com")).toBe(false);
  });

  it("Unknown hosts return {provider:null, shape:null}", () => {
    expect(classifyUrl("https://example.com/foo")).toEqual({
      provider: null,
      shape: null,
    });
  });

  it("Malformed URLs return {provider:null, shape:null}", () => {
    expect(classifyUrl("not-a-url")).toEqual({ provider: null, shape: null });
  });

  it("HostRegistry matches both default and custom hosts", () => {
    const reg = new HostRegistry(["my.private.llm"]);
    expect(reg.matches("api.cohere.ai")).toBe(true);
    expect(reg.matches("generativelanguage.googleapis.com")).toBe(true);
    expect(reg.matches("my.private.llm")).toBe(true);
    expect(reg.matches("example.com")).toBe(false);
  });

  // ── vendor-neutral OSS-prep: no hardcoded customer hosts ────────────────
  it("former vendor-specific hosts are no longer special-cased by classifyUrl", () => {
    expect(
      classifyUrl("https://grid.ai.vendor-example.com/v1/chat/completions"),
    ).toEqual({ provider: null, shape: null });
    expect(
      classifyUrl("https://app.ai.vendor-example.com/v1/chat/completions"),
    ).toEqual({ provider: null, shape: null });
  });

  it("public OpenAI-compatible hosts still classify (regression guard)", () => {
    expect(
      classifyUrl("https://api.deepseek.com/v1/chat/completions"),
    ).toEqual({ provider: "openai-compatible", shape: "openai-chat" });
    expect(classifyUrl("https://api.groq.com/v1/chat/completions")).toEqual({
      provider: "openai-compatible",
      shape: "openai-chat",
    });
  });

  it("a HostRegistry built with an extra host matches it (env-var path)", () => {
    expect(
      new HostRegistry(["custom.example.com"]).matches("custom.example.com"),
    ).toBe(true);
  });
});

describe("parseExtraLlmHosts", () => {
  it("splits on commas and whitespace, trims, drops empties", () => {
    expect(parseExtraLlmHosts("a.com, b.com  c.com")).toEqual([
      "a.com",
      "b.com",
      "c.com",
    ]);
  });

  it("returns [] for undefined / empty / whitespace-only input", () => {
    expect(parseExtraLlmHosts(undefined)).toEqual([]);
    expect(parseExtraLlmHosts("")).toEqual([]);
    expect(parseExtraLlmHosts("   ")).toEqual([]);
    expect(parseExtraLlmHosts(" , ,\t\n ")).toEqual([]);
  });

  it("preserves wildcard patterns verbatim", () => {
    expect(parseExtraLlmHosts("*.example.com, llm.*.internal")).toEqual([
      "*.example.com",
      "llm.*.internal",
    ]);
  });
});
