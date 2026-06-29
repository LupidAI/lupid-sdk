/**
 * Manifest discovery + file load.
 *
 * Discovery order:
 *   1. `opts.manifest` — explicit path passed to `init()`
 *   2. `LUPID_MANIFEST_PATH` env var
 *   3. unique `./*.lupid.yaml` in cwd (multiple → `ManifestError`)
 *   4. `./lupid/agent.yaml` fallback
 *
 * All `node:*` imports AND the `yaml` parse import are lazy so this module
 * loads cleanly on edge runtimes (Vercel Edge, Cloudflare Workers). The
 * canonical lazy-import pattern is `sdk/typescript/src/anonymous-id.ts:101-103`.
 *
 * The loader does NOT validate the manifest — that is `validator.ts`'s job.
 * It returns the parsed-but-untyped value so callers can pipe it into
 * `parseAndValidate`.
 */

import { ManifestError } from "./errors.js";

/** Minimal slice of `InitOptions` consumed by `discoverManifest`. */
export interface ManifestDiscoveryOptions {
  manifest?: string;
  /** Test-injection: env clone. Falls back to `process.env`. */
  env?: Record<string, string | undefined>;
}

/**
 * Resolve a manifest file path or return `null` if discovery decides the
 * SDK should boot without a local manifest (e.g. edge runtime, no fallback
 * present).
 *
 * Throws `ManifestError` only when the user's intent is ambiguous —
 * specifically multiple `*.lupid.yaml` files in cwd, which is a likely
 * misconfiguration we refuse to guess at.
 */
export async function discoverManifest(
  opts: ManifestDiscoveryOptions,
): Promise<string | null> {
  const env = opts.env ?? (typeof process !== "undefined" ? process.env : undefined);

  // Step 1 — explicit path.
  if (opts.manifest) {
    try {
      const path = await import("node:path");
      return path.resolve(opts.manifest);
    } catch {
      // Edge runtime — return the path as-is; downstream `loadAndParse`
      // will surface the real failure when it tries to read the file.
      return opts.manifest;
    }
  }

  // Step 2 — env var.
  const envPath = env?.["LUPID_MANIFEST_PATH"];
  if (envPath) {
    try {
      const path = await import("node:path");
      return path.resolve(envPath);
    } catch {
      return envPath;
    }
  }

  // Steps 3 + 4 — walk cwd. Edge runtimes lack `process.cwd` / `node:fs`;
  // any failure here is treated as "no local manifest, proceed with live
  // schema only".
  try {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    if (typeof process === "undefined" || typeof process.cwd !== "function") {
      return null;
    }
    const cwd = process.cwd();
    const entries = await fs.readdir(cwd);
    const lupidYamls = entries.filter((f) => f.endsWith(".lupid.yaml"));

    if (lupidYamls.length > 1) {
      throw new ManifestError(
        `multiple *.lupid.yaml files in ${cwd}; pass opts.manifest or set LUPID_MANIFEST_PATH ` +
          `to disambiguate (found: ${lupidYamls.join(", ")})`,
      );
    }
    if (lupidYamls.length === 1) {
      // Guarded by length===1 above; the indexed access cannot be undefined
      // but `noUncheckedIndexedAccess` doesn't narrow array length.
      const match = lupidYamls[0];
      if (match !== undefined) {
        return path.join(cwd, match);
      }
    }

    // Step 4 — `lupid/agent.yaml` fallback.
    const fallback = path.join(cwd, "lupid", "agent.yaml");
    try {
      await fs.access(fallback);
      return fallback;
    } catch {
      return null;
    }
  } catch (e) {
    // Multiple-`.lupid.yaml` is the only unrecoverable case; rethrow it.
    if (e instanceof ManifestError) throw e;
    // Anything else (edge runtime, sandboxed fs) → no local manifest.
    return null;
  }
}

/**
 * Read and YAML-parse a manifest file.
 *
 * Returns the raw parsed value as `unknown` — callers should pipe through
 * `parseAndValidate` to get a typed `TenantSchema`.
 *
 * Lazy imports both `node:fs/promises` and `yaml` so this module is safe
 * to evaluate on edge runtimes that do not provide either. On those
 * runtimes the loader path is only reachable when `opts.manifest` is set,
 * which is itself a "you asked for it" override.
 */
export async function loadAndParse(filePath: string): Promise<unknown> {
  let fs: typeof import("node:fs/promises");
  try {
    fs = await import("node:fs/promises");
  } catch (e) {
    throw new ManifestError(
      `cannot read manifest at ${filePath}: node:fs/promises is unavailable in this runtime`,
      { cause: (e as Error).message },
    );
  }

  let text: string;
  try {
    text = await fs.readFile(filePath, "utf8");
  } catch (e) {
    throw new ManifestError(
      `failed to read manifest at ${filePath}: ${(e as Error).message}`,
    );
  }

  let yaml: typeof import("yaml");
  try {
    yaml = await import("yaml");
  } catch (e) {
    throw new ManifestError(
      `cannot parse manifest at ${filePath}: the "yaml" package failed to load`,
      { cause: (e as Error).message },
    );
  }

  try {
    return yaml.parse(text);
  } catch (e) {
    throw new ManifestError(
      `manifest at ${filePath} is not valid YAML: ${(e as Error).message}`,
    );
  }
}
