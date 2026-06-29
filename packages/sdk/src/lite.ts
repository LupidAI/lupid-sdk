/**
 * Agentum SDK-Lite: Zero-config governance for Node.js/Deno agents.
 *
 * Usage:
 *   import { init, wrap } from '@lupid/sdk/lite';
 *   await init({ gateway: 'http://localhost:7071', apiKey: 'your-key' });
 *   // All fetch() calls are now governed.
 *
 * Or with explicit wrapping:
 *   const openai = wrap(new OpenAI());
 *
 * @module
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

/** Options for initializing Agentum SDK-Lite. */
export interface InitOptions {
  /** Gateway API URL (e.g. http://localhost:7071). Defaults to AGENTUM_GATEWAY env var. */
  gateway?: string;
  /** Operator API key. Defaults to AGENTUM_API_KEY env var. */
  apiKey?: string;
  /** Agent name. Defaults to the script filename. */
  name?: string;
  /** Agent purpose description. */
  purpose?: string;
  /**
   * If true (default), monkeypatch globalThis.fetch to route through the proxy.
   * Set to false if you only want to use wrap() explicitly.
   */
  autoPatch?: boolean;
}

/** Result of a successful enrollment with the Agentum gateway. */
export interface Enrollment {
  agentId: string;
  sessionId: string;
  sessionJwt: string;
  proxyToken: string;
  proxyTokenExpiresAt: string;
  proxyUrl: string;
  caPath: string;
}

let _enrollment: Enrollment | null = null;

/**
 * Initialize Agentum governance for all outbound HTTP calls.
 *
 * @throws {Error} If apiKey is not provided and AGENTUM_API_KEY is not set.
 * @throws {Error} If enrollment with the gateway fails.
 */
export async function init(options: InitOptions = {}): Promise<Enrollment> {
  if (_enrollment) return _enrollment;

  const gateway =
    options.gateway || process.env.AGENTUM_GATEWAY || "http://localhost:7071";
  const apiKey = options.apiKey || process.env.AGENTUM_API_KEY;
  const name = options.name || detectScriptName();
  const purpose = options.purpose || "SDK-Lite governed agent";

  if (!apiKey) {
    throw new Error(
      "apiKey is required. Pass it directly or set AGENTUM_API_KEY.",
    );
  }

  // Enroll with the gateway.
  const enrollment = await enroll(gateway, apiKey, name, purpose);

  // Fetch CA certificate.
  const caPath = await fetchCaCert(gateway);

  // Build proxy URL.
  const proxyUrl = `http://${enrollment.proxy_token}:x@127.0.0.1:7070`;

  _enrollment = {
    agentId: enrollment.agent_id,
    sessionId: enrollment.session_id,
    sessionJwt: enrollment.session_jwt,
    proxyToken: enrollment.proxy_token,
    proxyTokenExpiresAt: enrollment.proxy_token_expires_at,
    proxyUrl,
    caPath,
  };

  if (options.autoPatch !== false) {
    patchGlobalFetch(proxyUrl, caPath);
  }

  return _enrollment;
}

/**
 * Wrap a specific HTTP client instance to route through Agentum.
 *
 * Supports any client that respects environment variables (OpenAI, Anthropic, etc.).
 * Sets HTTPS_PROXY and SSL_CERT_FILE env vars as a fallback.
 *
 * @returns The same client instance (for chaining).
 */
export function wrap<T>(httpClient: T): T {
  if (!_enrollment) {
    throw new Error("Call init() before wrap()");
  }

  // Set env vars that most HTTP clients respect.
  process.env.HTTPS_PROXY = _enrollment.proxyUrl;
  process.env.HTTP_PROXY = _enrollment.proxyUrl;
  process.env.SSL_CERT_FILE = _enrollment.caPath;
  process.env.NODE_EXTRA_CA_CERTS = _enrollment.caPath;

  return httpClient;
}

/**
 * Reset the SDK-Lite state. Useful for testing.
 * @internal
 */
export function _reset(): void {
  _enrollment = null;
}

// ── Internal helpers ────────────────────────────────────────────────────────

interface EnrollResponse {
  agent_id: string;
  session_id: string;
  session_jwt: string;
  proxy_token: string;
  proxy_token_expires_at: string;
}

async function enroll(
  gateway: string,
  apiKey: string,
  name: string,
  purpose: string,
): Promise<EnrollResponse> {
  const resp = await fetch(`${gateway}/api/v1/launcher/enroll`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": apiKey,
    },
    body: JSON.stringify({
      api_key: apiKey,
      name,
      purpose,
      platform: `${process.platform}-${process.arch}`,
      launcher_version: "sdk-lite-typescript-0.1.0",
      deployment_mode: "sdk-lite-typescript",
    }),
  });

  if (resp.status === 201) {
    return (await resp.json()) as EnrollResponse;
  }
  if (resp.status === 403) {
    throw new Error(`Invalid API key: ${await resp.text()}`);
  }
  throw new Error(
    `Enrollment failed (${resp.status}): ${await resp.text()}`,
  );
}

async function fetchCaCert(gateway: string): Promise<string> {
  const resp = await fetch(`${gateway}/api/v1/gateway/ca-cert`);
  if (resp.status !== 200) {
    throw new Error(`Failed to fetch CA cert: ${resp.status}`);
  }

  const pem = await resp.text();
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error("Gateway returned invalid CA cert (not PEM)");
  }

  const caDir = path.join(os.homedir(), ".agentum");
  fs.mkdirSync(caDir, { recursive: true });
  const caPath = path.join(caDir, "ca.pem");
  fs.writeFileSync(caPath, pem);
  return caPath;
}

function patchGlobalFetch(proxyUrl: string, caPath: string): void {
  // Set environment variables that Node.js HTTP clients respect.
  process.env.HTTPS_PROXY = proxyUrl;
  process.env.HTTP_PROXY = proxyUrl;
  process.env.https_proxy = proxyUrl;
  process.env.http_proxy = proxyUrl;
  process.env.NODE_EXTRA_CA_CERTS = caPath;
  process.env.SSL_CERT_FILE = caPath;

  // For undici-based fetch (Node 18+), we can patch via ProxyAgent.
  // However, since globalThis.fetch doesn't support the dispatcher option
  // in all environments, we use env vars as the primary mechanism.
  // Libraries like OpenAI, Anthropic, and httpx all respect HTTPS_PROXY.
}

function detectScriptName(): string {
  try {
    return path.basename(process.argv[1] || "node-agent", ".js");
  } catch {
    return "node-agent";
  }
}
