/**
 * S1-12 — manifest discovery tests.
 *
 * Covers the 4-step search order and edge-runtime graceful degradation.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

import { discoverManifest, loadAndParse } from "../../src/manifest/loader";
import { ManifestError } from "../../src/manifest/errors";

async function mkTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "agentum-manifest-test-"));
  return dir;
}

describe("discoverManifest", () => {
  let origCwd: () => string;
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkTempDir();
    origCwd = process.cwd;
    process.cwd = () => tmp;
  });

  afterEach(async () => {
    process.cwd = origCwd;
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("returns opts.manifest resolved absolute when set", async () => {
    const p = path.join(tmp, "explicit.lupid.yaml");
    await fs.writeFile(p, "version: 1\n");
    const got = await discoverManifest({ manifest: p, env: {} });
    expect(got).toBe(path.resolve(p));
  });

  it("honors LUPID_MANIFEST_PATH env when opts.manifest is unset", async () => {
    const p = path.join(tmp, "via-env.lupid.yaml");
    await fs.writeFile(p, "version: 1\n");
    const got = await discoverManifest({
      env: { LUPID_MANIFEST_PATH: p },
    });
    expect(got).toBe(path.resolve(p));
  });

  it("matches a unique ./*.lupid.yaml in cwd", async () => {
    const p = path.join(tmp, "nexus.lupid.yaml");
    await fs.writeFile(p, "version: 1\n");
    const got = await discoverManifest({ env: {} });
    expect(got).toBe(p);
  });

  it("throws ManifestError when multiple *.lupid.yaml exist", async () => {
    await fs.writeFile(path.join(tmp, "a.lupid.yaml"), "version: 1\n");
    await fs.writeFile(path.join(tmp, "b.lupid.yaml"), "version: 1\n");
    await expect(discoverManifest({ env: {} })).rejects.toBeInstanceOf(
      ManifestError,
    );
  });

  it("falls back to ./lupid/agent.yaml when no *.lupid.yaml present", async () => {
    await fs.mkdir(path.join(tmp, "lupid"));
    const fallback = path.join(tmp, "lupid", "agent.yaml");
    await fs.writeFile(fallback, "version: 1\n");
    const got = await discoverManifest({ env: {} });
    expect(got).toBe(fallback);
  });

  it("returns null when no manifest exists in cwd", async () => {
    const got = await discoverManifest({ env: {} });
    expect(got).toBeNull();
  });

  it("returns null when process.cwd is unavailable (edge runtime stub)", async () => {
    // Simulate an edge runtime: temporarily unset process.cwd.
    const saved = process.cwd;
    // @ts-expect-error — we are deliberately unsetting for the stub.
    process.cwd = undefined;
    try {
      const got = await discoverManifest({ env: {} });
      expect(got).toBeNull();
    } finally {
      process.cwd = saved;
    }
  });
});

describe("loadAndParse", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await mkTempDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("parses a valid YAML manifest into a POJO", async () => {
    const p = path.join(tmp, "ok.lupid.yaml");
    await fs.writeFile(p, "version: 1\ndimensions: []\n");
    const v = await loadAndParse(p);
    expect(v).toEqual({ version: 1, dimensions: [] });
  });

  it("surfaces a ManifestError for missing files", async () => {
    await expect(
      loadAndParse(path.join(tmp, "missing.yaml")),
    ).rejects.toBeInstanceOf(ManifestError);
  });

  it("surfaces a ManifestError for malformed YAML", async () => {
    const p = path.join(tmp, "bad.lupid.yaml");
    // YAML alias `*nope` against an undeclared anchor — a hard parse error.
    await fs.writeFile(p, ":\n*nope\n");
    await expect(loadAndParse(p)).rejects.toBeInstanceOf(ManifestError);
  });
});
