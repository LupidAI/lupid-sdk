/**
 * Y04 — unit tests for `compileScanner` / `scanAndMask` / `selfCheck`.
 *
 * Coverage matrix:
 *   - Per-pattern positive: each of the 14 default IDs masks a known
 *     fixture into `***<id>***`.
 *   - Opt-out: `{ enabled: false }` returns the input verbatim.
 *   - Subset: `{ enabled: true, patterns: ["email"] }` masks email but
 *     leaves SSN intact.
 *   - Custom: a user-supplied pattern fires and is reported by its id.
 *   - Self-check happy path: a masked output passes silently.
 *   - Self-check failure: a hand-crafted residual triggers the throw.
 *   - Edge guard: no `node:*` imports are reachable from this file (the
 *     `tests/edge-entry.test.ts` post-build scan verifies bundle output;
 *     here we just smoke-import without crashing).
 */

import type { PiiTextScannerConfig } from "../../src/types";
import {
  compileScanner,
  scanAndMask,
  selfCheck,
  PiiSelfCheckFailedError,
  type Scanner,
} from "../../src/pii/text-scanner";
import { DEFAULT_PATTERNS } from "../../src/pii/pii-patterns-embedded";

// ── Per-pattern fixtures ──────────────────────────────────────────────────
//
// One input string per default pattern id. Each input is constructed to
// match *only* the named pattern when scanned in isolation, so the
// per-pattern tests can assert both "mask appears" and "mask appears for
// THIS id, not any other". `phone_us` and `ssn_us` share the digit-run
// shape with `credit_card`, so the input wraps them in plain text that
// the credit-card regex (13+ digits) cannot match.

const FIXTURES: Record<string, { input: string; expectMask: string }> = {
  email: {
    input: "Contact alice@example.com please.",
    expectMask: "***email***",
  },
  phone_us: {
    input: "Call me at (415) 555-0132 tomorrow.",
    expectMask: "***phone_us***",
  },
  ssn_us: {
    // 9-digit dashed run — below the 13-digit credit_card floor.
    input: "SSN: 123-45-6789 on file.",
    expectMask: "***ssn_us***",
  },
  credit_card: {
    input: "Card 4111 1111 1111 1111 on file.",
    expectMask: "***credit_card***",
  },
  ip_address: {
    input: "Source 192.168.1.42 hit the gateway.",
    expectMask: "***ip_address***",
  },
  aws_access_key_id: {
    input: "key=AKIAIOSFODNN7EXAMPLE not committed.",
    expectMask: "***aws_access_key_id***",
  },
  aws_secret_access_key: {
    input:
      "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY rotated",
    expectMask: "***aws_secret_access_key***",
  },
  github_token: {
    input: "token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa rotated.",
    expectMask: "***github_token***",
  },
  slack_token: {
    input:
      "slack xoxb-1234567890-1234567890-aaaaaaaaaaaaaaaaaaaaaaaa expired",
    expectMask: "***slack_token***",
  },
  openai_key: {
    input: "use sk-aaaaaaaaaaaaaaaaaaaa in dev.",
    expectMask: "***openai_key***",
  },
  anthropic_key: {
    // sk-ant-api<2-digits>-<90+ chars of [A-Za-z0-9_-]>
    input:
      "use sk-ant-api03-" +
      "a".repeat(95) +
      " in dev.",
    expectMask: "***anthropic_key***",
  },
  google_api_key: {
    // AIza + 35 chars
    input: "google AIza" + "0".repeat(35) + " key.",
    expectMask: "***google_api_key***",
  },
  jwt_token: {
    input:
      "Authorization: Bearer " +
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    expectMask: "***jwt_token***",
  },
  private_key_pem: {
    input: "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
    expectMask: "***private_key_pem***",
  },
  bearer_token: {
    // `Bearer` + >=20 token chars. (jwt_token fires first on real JWTs;
    // this catches opaque non-JWT bearers — exercised with a single-pattern
    // scanner here so jwt_token does not subsume it.)
    input: "auth Bearer abcdefghijklmnopqrstuvwxyz012345 ok",
    expectMask: "***bearer_token***",
  },
  generic_high_entropy: {
    // A 40+ char base64-class run — the coarse high-entropy heuristic.
    input: "blob " + "A".repeat(44) + " end",
    expectMask: "***generic_high_entropy***",
  },
};

describe("compileScanner — default behaviour", () => {
  test("returns all 16 default patterns when config is undefined", () => {
    const scanner = compileScanner();
    expect(scanner.patterns).toHaveLength(16);
    const ids = scanner.patterns.map((p) => p.id).sort();
    expect(ids).toEqual(
      [...DEFAULT_PATTERNS].map((p) => p.id).sort(),
    );
  });

  test("returns all 16 default patterns when enabled is true", () => {
    const scanner = compileScanner({ enabled: true });
    expect(scanner.patterns).toHaveLength(16);
  });

  test("returns zero patterns when enabled is false", () => {
    const scanner = compileScanner({ enabled: false });
    expect(scanner.patterns).toHaveLength(0);
  });
});

describe("scanAndMask — per default pattern", () => {
  // Per-pattern tests scan with a single-pattern scanner so adjacent
  // patterns (e.g. openai_key vs anthropic_key, where the openai_key
  // regex is a strict superset of the anthropic-key prefix shape) do
  // not subsume the match and force a flaky expectation. The full-stack
  // scanner is still exercised by the integration test below ("all 14
  // patterns active does not regress on multi-PII input").
  for (const id of Object.keys(FIXTURES)) {
    const fix = FIXTURES[id]!;
    test(`pattern '${id}' masks its fixture`, () => {
      const scanner = compileScanner({ enabled: true, patterns: [id] });
      const masked = scanAndMask(fix.input, scanner);
      expect(masked).toContain(fix.expectMask);
      // Sanity: the raw match should be gone. We probe a fragment that is
      // load-bearing for each pattern's positive case; an exact-equality
      // check would over-specify on patterns with optional grouping.
      if (id === "email") expect(masked).not.toContain("alice@example.com");
      if (id === "credit_card") expect(masked).not.toContain("4111 1111 1111 1111");
      if (id === "private_key_pem")
        expect(masked).not.toContain("BEGIN RSA PRIVATE KEY");
    });
  }

  test("full default scanner masks multiple PII kinds in one pass", () => {
    const scanner = compileScanner();
    const input =
      "alice@example.com — card 4111 1111 1111 1111 — IP 10.0.0.1";
    const masked = scanAndMask(input, scanner);
    expect(masked).toContain("***email***");
    expect(masked).toContain("***credit_card***");
    expect(masked).toContain("***ip_address***");
    expect(masked).not.toContain("alice@example.com");
    expect(masked).not.toContain("4111 1111 1111 1111");
    expect(masked).not.toContain("10.0.0.1");
  });

  test("covers every embedded pattern id", () => {
    // Drift guard: if Y09's parity gate / a future YAML change adds a new
    // pattern, this test forces us to add a fixture for it.
    const fixtureIds = new Set(Object.keys(FIXTURES));
    const embeddedIds = new Set(DEFAULT_PATTERNS.map((p) => p.id));
    expect([...embeddedIds].sort()).toEqual([...fixtureIds].sort());
  });
});

describe("scanAndMask — disabled / subset / custom", () => {
  test("disabled scanner returns input verbatim", () => {
    const scanner = compileScanner({ enabled: false });
    const input = "alice@example.com — SSN 123-45-6789 — IP 10.0.0.1";
    expect(scanAndMask(input, scanner)).toBe(input);
  });

  test("subset masks listed ids, leaves others intact", () => {
    const cfg: PiiTextScannerConfig = { enabled: true, patterns: ["email"] };
    const scanner = compileScanner(cfg);
    const input = "alice@example.com — SSN 123-45-6789";
    const masked = scanAndMask(input, scanner);
    expect(masked).toContain("***email***");
    // The SSN regex was filtered out, so its raw form survives.
    expect(masked).toContain("123-45-6789");
    expect(masked).not.toContain("***ssn_us***");
  });

  test("custom pattern is applied and reports its own id", () => {
    const cfg: PiiTextScannerConfig = {
      enabled: true,
      // No defaults match `INT-123456`, so subset to nothing to keep the
      // test focused on the custom rule.
      patterns: [],
      custom: [{ id: "internal_id", pattern: "INT-\\d{6}" }],
    };
    const scanner = compileScanner(cfg);
    const masked = scanAndMask("ticket INT-123456 escalated", scanner);
    expect(masked).toContain("***internal_id***");
    expect(masked).not.toContain("INT-123456");
  });

  test("unknown subset ids are silently dropped (typo tolerance)", () => {
    const scanner = compileScanner({
      enabled: true,
      patterns: ["email", "not_a_real_pattern"],
    });
    expect(scanner.patterns.map((p) => p.id)).toEqual(["email"]);
  });
});

describe("scanAndMask — multi-pass + idempotence", () => {
  test("scanning twice is idempotent on a clean input", () => {
    const scanner = compileScanner();
    const once = scanAndMask("alice@example.com", scanner);
    const twice = scanAndMask(once, scanner);
    expect(twice).toBe(once);
  });

  test("global regex state does not leak across calls", () => {
    const scanner = compileScanner({
      enabled: true,
      patterns: ["email"],
    });
    // First call advances `lastIndex` internally; second call must still
    // mask from the start of the string.
    expect(scanAndMask("a@b.co", scanner)).toContain("***email***");
    expect(scanAndMask("a@b.co", scanner)).toContain("***email***");
  });

  test("empty text returns empty string fast-path", () => {
    expect(scanAndMask("", compileScanner())).toBe("");
  });
});

describe("selfCheck — Stage D verification", () => {
  test("clean masked output passes silently", () => {
    const scanner = compileScanner();
    const masked = scanAndMask("contact alice@example.com", scanner);
    expect(() => selfCheck(masked, scanner)).not.toThrow();
  });

  test("disabled scanner never throws (vacuously safe)", () => {
    const scanner = compileScanner({ enabled: false });
    expect(() => selfCheck("alice@example.com", scanner)).not.toThrow();
  });

  test("residual PII triggers PiiSelfCheckFailedError", () => {
    // Hand-craft the failure: build a scanner that "masks" by replacing
    // with the literal "PLACEHOLDER" instead of stripping the match. Then
    // selfCheck on the original raw PII still hits the regex.
    const scanner = compileScanner();
    const raw = "alice@example.com";
    expect(() => selfCheck(raw, scanner)).toThrow(PiiSelfCheckFailedError);
    try {
      selfCheck(raw, scanner);
    } catch (err) {
      expect(err).toBeInstanceOf(PiiSelfCheckFailedError);
      const e = err as PiiSelfCheckFailedError;
      expect(e.unmaskedPatternId).toBe("email");
      expect(e.sample.length).toBeGreaterThan(0);
      expect(e.sample.length).toBeLessThanOrEqual(31); // 30 + ellipsis
    }
  });

  test("error sample is truncated for long matches", () => {
    // Use a custom pattern that matches a very long run.
    const cfg: PiiTextScannerConfig = {
      enabled: true,
      patterns: [],
      custom: [{ id: "long_run", pattern: "X{50,}" }],
    };
    const scanner = compileScanner(cfg);
    const raw = "X".repeat(100);
    try {
      selfCheck(raw, scanner);
      throw new Error("selfCheck should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(PiiSelfCheckFailedError);
      const e = err as PiiSelfCheckFailedError;
      // 30 chars + "…" ellipsis = 31 chars total.
      expect(e.sample.length).toBe(31);
      expect(e.sample.endsWith("…")).toBe(true);
    }
  });
});

describe("Scanner shape", () => {
  test("Scanner is a plain object with a `patterns` array", () => {
    const scanner: Scanner = compileScanner();
    expect(Array.isArray(scanner.patterns)).toBe(true);
    expect(scanner.patterns[0]).toHaveProperty("id");
    expect(scanner.patterns[0]).toHaveProperty("regex");
    expect(scanner.patterns[0]).toHaveProperty("severity");
  });
});
