/**
 * Y02 — init() integration test for the manifest `pii:` block.
 *
 * Verifies that `init()`:
 *   1. accepts a manifest with a valid `pii:` block, populates the
 *      module-local active block, and boots cleanly
 *   2. backward-compat — accepts a manifest with NO `pii:` block at all
 *      and leaves the active block empty (no throw)
 *   3. fail-CLOSED — rejects a manifest with an invalid `pii:` block
 *      (bad JSONPath / unknown mode) before any patch installs
 *
 * Mirrors the harness in `tests/binding/init-binding-mode.test.ts`: a
 * temp dir holds the manifest YAML; `init()` is invoked with an
 * injected `fetchImpl` that short-circuits `/sdk/register` + the
 * per-agent schema route.
 */

import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";

import { init, _resetForTests } from "../../src/init";
import {
  getActivePiiBlock,
  PiiManifestValidationError,
} from "../../src/pii";

function silentLogger(): {
  log: jest.Mock;
  warn: jest.Mock;
  error: jest.Mock;
} {
  return { log: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: {
      get: (h: string) =>
        h.toLowerCase() === "content-type" ? "application/json" : null,
    },
  } as unknown as Response;
}

function makeFetch(): jest.Mock {
  return jest.fn().mockImplementation(async (input: unknown, opts: unknown) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const method =
      ((opts as { method?: string } | undefined)?.method ?? "GET").toUpperCase();
    if (url.endsWith("/api/v1/sdk/register") && method === "POST") {
      return jsonResponse(200, {
        agent_id: "agent-uuid-1",
        tenant_id: "tenant-uuid-1",
        created: true,
      });
    }
    if (
      url.includes("/api/v1/agents/") &&
      url.endsWith("/schema") &&
      method === "GET"
    ) {
      return jsonResponse(200, {
        tenant_id: "tenant-uuid-1",
        version: 1,
        definition: { version: 1, dimensions: [] },
      });
    }
    return jsonResponse(404, { error: "not found" });
  });
}

const ENV_BASE: Record<string, string> = {
  AGENTUM_BASE_URL: "http://gateway:7071",
  AGENTUM_API_KEY: "ak_test",
  AGENTUM_AGENT_NAME: "pii-it",
  // The valid-block test declares `mode: hash`, which requires the
  // hash secret env var. 32 zero bytes is non-production but
  // length-valid for the test.
  LUPID_PII_HASH_SECRET: Buffer.alloc(32, 0).toString("base64"),
};

async function writeManifest(dir: string, content: string): Promise<string> {
  const p = path.join(dir, "agent.lupid.yaml");
  await fs.writeFile(p, content, "utf8");
  return p;
}

describe("init() + manifest pii block (Y02)", () => {
  let tmpdir: string;

  beforeEach(async () => {
    await _resetForTests();
    tmpdir = await fs.mkdtemp(path.join(os.tmpdir(), "agentum-pii-"));
  });

  afterEach(async () => {
    await _resetForTests();
    await fs.rm(tmpdir, { recursive: true, force: true });
  });

  it("accepts a valid pii block and publishes it to the active state", async () => {
    const manifest = await writeManifest(
      tmpdir,
      [
        "version: 1",
        "dimensions: []",
        "pii:",
        "  field_rules:",
        "    - tool: \"*\"",
        "      path: \"$.args.email\"",
        "      mode: hash",
        "    - tool: send_message",
        "      path: \"$.body.text\"",
        "      mode: mask",
        "  text_scanners:",
        "    - enabled: true",
        "      patterns:",
        "        - pii.email",
        "",
      ].join("\n"),
    );

    const fetchImpl = makeFetch();
    await init({
      env: ENV_BASE,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
      disableAutoPatch: true,
    });

    const block = getActivePiiBlock();
    expect(block.field_rules).toHaveLength(2);
    expect(block.field_rules?.[0]).toEqual({
      tool: "*",
      path: "$.args.email",
      mode: "hash",
    });
    expect(block.text_scanners).toHaveLength(1);
    expect(block.text_scanners?.[0]?.enabled).toBe(true);
    expect(block.text_scanners?.[0]?.patterns).toEqual(["pii.email"]);
  });

  it("backward-compat: manifest with no pii block boots cleanly, active block is empty", async () => {
    // No `pii:` key at all → init must not throw, and the active block
    // is `{}` (legacy manifests pre-Y02 continue to work).
    const manifest = await writeManifest(
      tmpdir,
      "version: 1\ndimensions: []\n",
    );

    const fetchImpl = makeFetch();
    // No PII secrets env vars set — would throw only if a `pii: hash`
    // mode were declared. Without one, init must boot.
    const { LUPID_PII_HASH_SECRET: _omit, ...envNoSecret } = ENV_BASE;
    void _omit;

    await init({
      env: envNoSecret,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
      disableAutoPatch: true,
    });

    expect(getActivePiiBlock()).toEqual({});
  });

  it("fail-CLOSED: invalid JSONPath in pii block rejects init synchronously", async () => {
    const manifest = await writeManifest(
      tmpdir,
      [
        "version: 1",
        "dimensions: []",
        "pii:",
        "  field_rules:",
        "    - tool: \"*\"",
        // Missing `$.` prefix — Y02 syntactic gate rejects.
        "      path: \"args.email\"",
        "      mode: drop",
        "",
      ].join("\n"),
    );

    const fetchImpl = makeFetch();
    await expect(
      init({
        env: ENV_BASE,
        manifest,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        logger: silentLogger(),
        disableAutoPatch: true,
      }),
    ).rejects.toBeInstanceOf(PiiManifestValidationError);
  });

  it("fail-CLOSED: unknown mode in pii block rejects init synchronously", async () => {
    const manifest = await writeManifest(
      tmpdir,
      [
        "version: 1",
        "dimensions: []",
        "pii:",
        "  field_rules:",
        "    - tool: t",
        "      path: \"$.x\"",
        "      mode: obliterate",
        "",
      ].join("\n"),
    );

    const fetchImpl = makeFetch();
    await expect(
      init({
        env: ENV_BASE,
        manifest,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        logger: silentLogger(),
        disableAutoPatch: true,
      }),
    ).rejects.toBeInstanceOf(PiiManifestValidationError);
  });

  it("fail-CLOSED: field-rule mode: hash without LUPID_PII_HASH_SECRET aborts init", async () => {
    const manifest = await writeManifest(
      tmpdir,
      [
        "version: 1",
        "dimensions: []",
        "pii:",
        "  field_rules:",
        "    - tool: \"*\"",
        "      path: \"$.args.email\"",
        "      mode: hash",
        "",
      ].join("\n"),
    );

    const fetchImpl = makeFetch();
    const { LUPID_PII_HASH_SECRET: _omit, ...envNoSecret } = ENV_BASE;
    void _omit;
    await expect(
      init({
        env: envNoSecret,
        manifest,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        logger: silentLogger(),
        disableAutoPatch: true,
      }),
    ).rejects.toThrow(/LUPID_PII_HASH_SECRET/);
  });
});
