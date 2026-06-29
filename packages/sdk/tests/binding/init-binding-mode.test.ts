/**
 * S2-E04 — init() integration test for the per-mode init scan.
 *
 * Verifies:
 *   1. orchestrator               → init succeeds, runtime carries bindingMode
 *   2. framework_hook             → init succeeds, runtime carries bindingMode
 *   3. per_subagent               → throws BindingModeNotYetSupportedError
 *   4. acl_edge                   → throws BindingModeNotYetSupportedError
 *   5. actor_per_instance         → throws BindingModeNotYetSupportedError
 *   6. NO binding_mode declared   → defaults to orchestrator + warn
 *   7. error fields (mode, supportedAt, referenceTickets) are populated
 *   8. fail-fast contract — no network call when a deferred mode is declared
 *
 * The fail-fast property is what makes the dispatcher load-bearing:
 * a customer who declares `per_subagent` should NOT burn a
 * `/sdk/register` round-trip, NOT install the OpenAI patch, NOT
 * touch the PII secrets loader. We assert the registered `fetchImpl`
 * is never called.
 */

import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";

import { init, _resetForTests } from "../../src/init";
import {
  BindingModeNotYetSupportedError,
  type BindingMode,
} from "../../src/binding";

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

/** Same fetch double the S1-12 init-integration test uses. */
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
  AGENTUM_AGENT_NAME: "binding-it",
};

/**
 * Build a YAML manifest that carries:
 *   - `spec.runtime.binding_mode` (the new S2-E04 field), and
 *   - a minimal-but-valid `TenantSchema` body (for the S1-12 pipeline,
 *     which still runs after the binding-scan when the mode is active).
 *
 * For deferred modes we omit the tenant-schema body since the scan
 * throws before `parseAndValidate` is reached.
 */
function yamlWithMode(mode: BindingMode | null, includeSchema = true): string {
  const head =
    mode === null ? "" : `spec:\n  runtime:\n    binding_mode: ${mode}\n`;
  const tenantSchema = includeSchema
    ? "version: 1\ndimensions: []\n"
    : "";
  return `${head}${tenantSchema}`;
}

async function writeManifest(dir: string, content: string): Promise<string> {
  const p = path.join(dir, "agent.lupid.yaml");
  await fs.writeFile(p, content, "utf8");
  return p;
}

describe("init() + per-mode binding scan (S2-E04)", () => {
  let tmpdir: string;

  beforeEach(async () => {
    await _resetForTests();
    tmpdir = await fs.mkdtemp(path.join(os.tmpdir(), "agentum-binding-"));
  });

  afterEach(async () => {
    await _resetForTests();
    await fs.rm(tmpdir, { recursive: true, force: true });
  });

  it("orchestrator → init succeeds; runtime.bindingMode = orchestrator", async () => {
    const manifest = await writeManifest(tmpdir, yamlWithMode("orchestrator"));
    const fetchImpl = makeFetch();
    const rt = await init({
      env: ENV_BASE,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
      disableAutoPatch: true,
    });
    expect(rt.bindingMode).toBe("orchestrator");
  });

  it("framework_hook → init succeeds; runtime.bindingMode = framework_hook", async () => {
    const manifest = await writeManifest(tmpdir, yamlWithMode("framework_hook"));
    const fetchImpl = makeFetch();
    const rt = await init({
      env: ENV_BASE,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
      disableAutoPatch: true,
    });
    expect(rt.bindingMode).toBe("framework_hook");
  });

  it.each(["per_subagent", "acl_edge", "actor_per_instance"] as const)(
    "%s → throws BindingModeNotYetSupportedError",
    async (mode) => {
      const manifest = await writeManifest(
        tmpdir,
        yamlWithMode(mode, /* includeSchema */ false),
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
      ).rejects.toBeInstanceOf(BindingModeNotYetSupportedError);
    },
  );

  it("deferred mode → fail-fast: no network call is made", async () => {
    const manifest = await writeManifest(
      tmpdir,
      yamlWithMode("per_subagent", /* includeSchema */ false),
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
    ).rejects.toBeInstanceOf(BindingModeNotYetSupportedError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it.each(["per_subagent", "acl_edge", "actor_per_instance"] as const)(
    "%s error carries mode + supportedAt + referenceTickets",
    async (mode) => {
      const manifest = await writeManifest(
        tmpdir,
        yamlWithMode(mode, /* includeSchema */ false),
      );
      const fetchImpl = makeFetch();
      try {
        await init({
          env: ENV_BASE,
          manifest,
          fetchImpl: fetchImpl as unknown as typeof fetch,
          logger: silentLogger(),
          disableAutoPatch: true,
        });
        fail("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(BindingModeNotYetSupportedError);
        const e = err as BindingModeNotYetSupportedError;
        expect(e.mode).toBe(mode);
        expect(e.supportedAt).toBe("MVP-3");
        expect(e.referenceTickets).toContain("S2-H01");
        expect(e.referenceTickets).toContain("S2-H09");
      }
    },
  );

  it("manifest without binding_mode → defaults to orchestrator + warn", async () => {
    const manifest = await writeManifest(tmpdir, yamlWithMode(null));
    const fetchImpl = makeFetch();
    const logger = silentLogger();
    const rt = await init({
      env: ENV_BASE,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger,
      disableAutoPatch: true,
    });
    expect(rt.bindingMode).toBe("orchestrator");
    const warnings = logger.warn.mock.calls.map((c) => String(c[0]));
    expect(
      warnings.some((w) => /binding_mode/.test(w) && /orchestrator/.test(w)),
    ).toBe(true);
  });

  it("no manifest at all → defaults to orchestrator + warn", async () => {
    // Point manifest at a non-existent path; loader returns null on
    // miss (after consulting the 4-step ladder). The fail-fast check
    // for the explicit-path case actually surfaces the read failure;
    // for the *truly absent* path we rely on the env+cwd ladder
    // resolving to null. Use a clean env to avoid LUPID_MANIFEST_PATH
    // bleed-through.
    const isolatedEnv = { ...ENV_BASE };
    const fetchImpl = makeFetch();
    const logger = silentLogger();
    // Switch cwd to a known-empty dir so discoverManifest returns null.
    const origCwd = process.cwd();
    process.chdir(tmpdir);
    try {
      const rt = await init({
        env: isolatedEnv,
        fetchImpl: fetchImpl as unknown as typeof fetch,
        logger,
        disableAutoPatch: true,
      });
      expect(rt.bindingMode).toBe("orchestrator");
      const warnings = logger.warn.mock.calls.map((c) => String(c[0]));
      expect(
        warnings.some((w) => /binding_mode/.test(w) && /orchestrator/.test(w)),
      ).toBe(true);
    } finally {
      process.chdir(origCwd);
    }
  });

  it("init log line includes bindingMode=...", async () => {
    const manifest = await writeManifest(tmpdir, yamlWithMode("orchestrator"));
    const fetchImpl = makeFetch();
    const logger = silentLogger();
    await init({
      env: ENV_BASE,
      manifest,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      logger,
      disableAutoPatch: true,
    });
    const logs = logger.log.mock.calls.map((c) => String(c[0]));
    expect(logs.some((l) => /bindingMode=orchestrator/.test(l))).toBe(true);
  });
});
