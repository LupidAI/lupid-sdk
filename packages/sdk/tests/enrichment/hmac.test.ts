/**
 * S1-14 — HMAC signing fixture test.
 *
 * Deterministic vector (per orchestrator-provided fixture):
 *   payload = '{"end_user_id":"u_42"}'
 *   secret  = 'sekret'
 *   sha256  = 9346cbd6affe14db80b5bc67fdbb983045001cc341a9d3f261c9f00396ac6f3a
 *
 * Computed once with:
 *   node -e "console.log(require('crypto').createHmac('sha256','sekret').update('{\"end_user_id\":\"u_42\"}').digest('hex'))"
 */

import { sign } from "../../src/enrichment/hmac";

const PAYLOAD = '{"end_user_id":"u_42"}';
const SECRET = "sekret";
const EXPECTED = "9346cbd6affe14db80b5bc67fdbb983045001cc341a9d3f261c9f00396ac6f3a";

describe("enrichment/hmac", () => {
  test("produces the deterministic SHA-256 hex for the fixture vector", async () => {
    const sig = await sign(PAYLOAD, SECRET, "test_ref");
    expect(sig).toBe(EXPECTED);
  });

  test("different payload yields a different signature", async () => {
    const sig = await sign('{"end_user_id":"u_43"}', SECRET, "test_ref");
    expect(sig).not.toBe(EXPECTED);
    expect(sig).toHaveLength(64);
  });

  test("different secret yields a different signature", async () => {
    const sig = await sign(PAYLOAD, "other-secret", "test_ref");
    expect(sig).not.toBe(EXPECTED);
    expect(sig).toHaveLength(64);
  });
});
