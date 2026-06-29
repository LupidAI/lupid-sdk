/**
 * Anonymous client-ID resolution for the SDK's `startSession` POST.
 *
 * Tier 1: app-provided via `ConnectOptions.anonymousClientId` (or the per-call
 *         override passed straight through) — handled in `startSession`.
 * Tier 2: browser auto-gen — `localStorage`, one ID per browser, shared across
 *         agents in this origin.
 * Tier 3: CLI auto-gen — `~/.config/agentum/anon_id`, one ID per machine user.
 *
 * Server SDK (Node service): does NOT auto-generate. The application must pass
 * the value per-request from its own session/cookie context — otherwise every
 * request collapses to a single `agent_users` row.
 *
 * Note: the SDK generates a raw UUID. The U01a backend prefixes with `anon:`
 * on receipt; do NOT prefix here or anonymous user counts fragment forever.
 */

const LS_KEY = "agentum_anon_id";

interface MinimalLocalStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

interface MinimalWindow {
  localStorage: MinimalLocalStorage;
}

function getBrowserWindow(): MinimalWindow | undefined {
  const g = globalThis as unknown as { window?: MinimalWindow };
  if (typeof g.window === "undefined") return undefined;
  if (typeof g.window.localStorage === "undefined") return undefined;
  return g.window;
}

function isCli(): boolean {
  // Heuristic: Node + TTY stdout + non-production NODE_ENV.
  // We deliberately do NOT auto-generate in a Node process that looks like a
  // server (e.g. NODE_ENV=production with no TTY) — that's the misuse pattern
  // (every request would pin to the same anonymous ID).
  return (
    typeof process !== "undefined" &&
    !!process.stdout &&
    !!process.stdout.isTTY &&
    process.env["NODE_ENV"] !== "production"
  );
}

function webRandomUUID(): string {
  // Web Crypto on browsers and Node 18+ exposes `globalThis.crypto.randomUUID`.
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  // Fallback: synthesise a v4-shaped UUID from Math.random. Acceptable for
  // analytics-grade identifiers (not for crypto material).
  const hex = (n: number) => n.toString(16).padStart(2, "0");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  // RFC 4122 variant / version bits.
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const b = Array.from(bytes, hex).join("");
  return `${b.slice(0, 8)}-${b.slice(8, 12)}-${b.slice(12, 16)}-${b.slice(16, 20)}-${b.slice(20)}`;
}

/**
 * Resolve an anonymous client ID using the tiered ladder above.
 *
 * Returns `undefined` in server SDK contexts (Node, no TTY) so the backend
 * can fall back to its per-IP UUIDv5 derivation. Never throws — anonymous-ID
 * resolution is best-effort; any unexpected failure resolves to `undefined`
 * so `startSession` keeps working (fail-CLOSED in the sense that we never
 * fabricate a value that would corrupt the agent_users registry).
 */
export async function resolveAnonymousClientId(
  override?: string,
): Promise<string | undefined> {
  if (override) return override;

  try {
    const win = getBrowserWindow();
    if (win) {
      try {
        let id = win.localStorage.getItem(LS_KEY);
        if (!id) {
          id = webRandomUUID();
          win.localStorage.setItem(LS_KEY, id);
        }
        return id;
      } catch {
        // Safari private mode throws on setItem; fall back to a per-session
        // in-memory ID. Lost on reload but valid for the current session.
        return webRandomUUID();
      }
    }

    if (isCli()) {
      // Dynamic import so bundlers for browser / edge runtimes don't try to
      // resolve node:* at module-load. `await import()` is the documented
      // pattern in .claude/rules/typescript.md; bare require() breaks in ESM
      // (this SDK ships dual CJS/ESM via tsup).
      try {
        const fs = await import("node:fs");
        const path = await import("node:path");
        const os = await import("node:os");

        const dir = path.join(os.homedir(), ".config", "agentum");
        const file = path.join(dir, "anon_id");
        if (fs.existsSync(file)) {
          return fs.readFileSync(file, "utf8").trim();
        }
        fs.mkdirSync(dir, { recursive: true });
        const id = webRandomUUID();
        fs.writeFileSync(file, id, { mode: 0o600 });
        return id;
      } catch {
        return undefined;
      }
    }
  } catch {
    // Any unexpected failure (e.g. odd globals on an edge runtime) falls back
    // to undefined — the backend handles missing values gracefully.
    return undefined;
  }

  // Server SDK (Node service): return undefined. Backend falls back to a
  // per-IP UUIDv5. See U01a `crates/agentum-api/src/routes/sessions.rs`.
  return undefined;
}
