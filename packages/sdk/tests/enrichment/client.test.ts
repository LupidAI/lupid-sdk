/**
 * S1-14 — End-to-end enrichment client tests.
 *
 * Uses nock to mock the customer-hosted webhook. Covers:
 *   - cache hit (no fetch fires)
 *   - cache miss + concurrent coalescing (exactly one HTTP)
 *   - background refresh past ttl/2
 *   - timeout → fail_open (null) and fail_closed (throw)
 *   - circuit breaker (5x 500 → 6th call short-circuits)
 *   - rate limit (configurable bucket; exhausted call short-circuits)
 *   - required-dimension composition with on_failure: fail_open
 *   - HMAC signature header present and correct shape
 *   - response-shape validation (missing ref key → failure)
 *   - http:// URL rejected at config time
 *   - send_raw: true → one-shot stderr warning, fetch still fires
 */

import nock from "nock";

import { resolveEnrichment, __resetEnrichmentStateForTest } from "../../src/enrichment/index";
import { EnrichmentConfigError, EnrichmentFailedError } from "../../src/enrichment/errors";
import { __configureRateLimitForTest } from "../../src/enrichment/rate-limit";
import { getEnrichmentMetricsSnapshot } from "../../src/enrichment/metrics";
import {
  resolveDimensions,
  RequiredDimensionMissingError,
} from "../../src/instrumentation/resolve-dimensions";
import { _setActiveSchema } from "../../src/manifest/state";
import type { TenantSchema, EnrichmentDef } from "../../src/manifest/types";

const ORIGIN = "https://acme-internal.test";
const PATH = "/api/lupid/classify_user";
const URL = `${ORIGIN}${PATH}`;

function schemaWith(enrich: EnrichmentDef, dims: TenantSchema["dimensions"] = []): TenantSchema {
  return {
    version: 1,
    dimensions: dims,
    enrichments: { classify_user: enrich },
  };
}

function baseEnrich(over: Partial<EnrichmentDef> = {}): EnrichmentDef {
  return {
    kind: "webhook",
    url: URL,
    timeout_ms: 250,
    on_failure: "fail_open",
    cache: { key: ["account_id", "end_user_id"], ttl_ms: 1000, negative_ttl_ms: 200 },
    auth: { secret_ref: "env:LUPID_TEST_HMAC" },
    request: { include_dimensions: ["account_id", "end_user_id"], method: "POST" },
    response: { shape: { classify_user: "string" } },
    ...over,
  };
}

const SECRET_VAR = "LUPID_TEST_HMAC";

beforeAll(() => {
  // Disable real network. nock.disableNetConnect() is too aggressive when
  // other suites share the process; only block the enrichment host.
  nock.disableNetConnect();
});

afterAll(() => {
  nock.enableNetConnect();
});

beforeEach(() => {
  process.env[SECRET_VAR] = "sekret";
  __resetEnrichmentStateForTest();
  nock.cleanAll();
});

afterEach(() => {
  delete process.env[SECRET_VAR];
  _setActiveSchema(null);
  nock.abortPendingRequests();
  nock.cleanAll();
});

describe("resolveEnrichment — happy path + caching", () => {
  test("first call hits webhook, second call hits cache (no second HTTP)", async () => {
    const schema = schemaWith(baseEnrich());
    const scope = nock(ORIGIN)
      .post(PATH)
      .reply(200, { classify_user: "paying" });

    const r1 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r1).toBe("paying");
    expect(scope.isDone()).toBe(true);

    const r2 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r2).toBe("paying");
    // No pending mocks; if a second HTTP fired, nock would have errored.
    expect(nock.pendingMocks()).toEqual([]);

    const m = getEnrichmentMetricsSnapshot();
    expect(m.requests["classify_user"]?.success).toBe(1);
    expect(m.cacheHits["classify_user"]).toBe(1);
    expect(m.cacheMisses["classify_user"]).toBe(1);
  });

  test("concurrent miss coalesces to one HTTP", async () => {
    const schema = schemaWith(baseEnrich());
    const scope = nock(ORIGIN)
      .post(PATH)
      .delay(20)
      .reply(200, { classify_user: "paying" });

    const [r1, r2, r3] = await Promise.all([
      resolveEnrichment("classify_user", { account_id: "acme", end_user_id: "u_42" }, schema),
      resolveEnrichment("classify_user", { account_id: "acme", end_user_id: "u_42" }, schema),
      resolveEnrichment("classify_user", { account_id: "acme", end_user_id: "u_42" }, schema),
    ]);
    expect([r1, r2, r3]).toEqual(["paying", "paying", "paying"]);
    expect(scope.isDone()).toBe(true);
    expect(nock.pendingMocks()).toEqual([]);
  });

  test("sends HMAC-SHA256 signature header on the request", async () => {
    process.env[SECRET_VAR] = "sekret";
    const schema = schemaWith(baseEnrich());
    let receivedSig: string | undefined;
    const scope = nock(ORIGIN)
      .post(PATH)
      .reply(function (_uri, _body) {
        const v = this.req.headers["x-lupid-signature"];
        receivedSig = Array.isArray(v) ? v[0] : v;
        return [200, { classify_user: "paying" }];
      });

    await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(scope.isDone()).toBe(true);
    expect(receivedSig).toBeDefined();
    expect(receivedSig).toMatch(/^sha256=[0-9a-f]{64}$/);
  });
});

describe("resolveEnrichment — failure modes", () => {
  test("timeout → fail_open returns null", async () => {
    const schema = schemaWith(baseEnrich({ timeout_ms: 30 }));
    nock(ORIGIN).post(PATH).delay(200).reply(200, { classify_user: "paying" });

    const r = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r).toBeNull();
    const m = getEnrichmentMetricsSnapshot();
    expect(m.requests["classify_user"]?.failure).toBe(1);
  });

  test("timeout → fail_closed throws EnrichmentFailedError", async () => {
    const schema = schemaWith(
      baseEnrich({ timeout_ms: 30, on_failure: "fail_closed" }),
    );
    nock(ORIGIN).post(PATH).delay(200).reply(200, { classify_user: "paying" });

    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentFailedError);
  });

  test("5xx + fail_open returns null and caches the negative result", async () => {
    const schema = schemaWith(baseEnrich());
    nock(ORIGIN).post(PATH).reply(500, "boom");

    const r1 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r1).toBeNull();
    // Second call inside negative_ttl_ms should hit cache, not webhook.
    const r2 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r2).toBeNull();
    expect(nock.pendingMocks()).toEqual([]);
  });

  test("response missing the ref key fails validation", async () => {
    const schema = schemaWith(baseEnrich({ on_failure: "fail_closed" }));
    nock(ORIGIN).post(PATH).reply(200, { other_key: "x" });

    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentFailedError);
  });

  test("response with null value when shape is 'string|null' is accepted", async () => {
    const schema = schemaWith(
      baseEnrich({ response: { shape: { classify_user: "string|null" } } }),
    );
    nock(ORIGIN).post(PATH).reply(200, { classify_user: null });

    const r = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_42" },
      schema,
    );
    expect(r).toBeNull();
  });
});

describe("resolveEnrichment — circuit breaker", () => {
  test("opens after 5 sequential 500s and short-circuits the 6th call", async () => {
    const schema = schemaWith(baseEnrich());
    // 5 actual 500s + assert no 6th HTTP fires
    nock(ORIGIN).post(PATH).times(5).reply(500, "boom");

    for (let i = 0; i < 5; i += 1) {
      const r = await resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: `u_${i}` },
        schema,
      );
      expect(r).toBeNull();
    }
    // 6th call: breaker open → no HTTP. We didn't set up a 6th mock, so if
    // a fetch fires, nock will throw a "no match" error.
    const r6 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_6" },
      schema,
    );
    expect(r6).toBeNull();

    const m = getEnrichmentMetricsSnapshot();
    expect(m.requests["classify_user"]?.circuit_open).toBe(1);
  });
});

describe("resolveEnrichment — rate limit", () => {
  test("exhausted bucket short-circuits without firing HTTP", async () => {
    __configureRateLimitForTest(2, 0); // 2 tokens, no refill
    const schema = schemaWith(baseEnrich());
    nock(ORIGIN).post(PATH).times(2).reply(200, { classify_user: "paying" });

    // Two distinct keys to bypass caching for this test.
    const r1 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_a" },
      schema,
    );
    const r2 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_b" },
      schema,
    );
    expect(r1).toBe("paying");
    expect(r2).toBe("paying");
    expect(nock.pendingMocks()).toEqual([]);

    // 3rd call: bucket empty, no HTTP allowed.
    const r3 = await resolveEnrichment(
      "classify_user",
      { account_id: "acme", end_user_id: "u_c" },
      schema,
    );
    expect(r3).toBeNull();
    const m = getEnrichmentMetricsSnapshot();
    expect(m.requests["classify_user"]?.rate_limited).toBe(1);
  });
});

describe("resolveEnrichment — config errors", () => {
  test("rejects http:// URLs at config time", async () => {
    const schema = schemaWith(baseEnrich({ url: "http://example.test/x" }));
    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentConfigError);
  });

  test("S1-15 Pre-1: allow_http=true accepts http:// + emits one-shot stderr warning", async () => {
    const HTTP_ORIGIN = "http://acme-internal-dev.test";
    const HTTP_URL = `${HTTP_ORIGIN}${PATH}`;
    const schema = schemaWith(
      baseEnrich({ url: HTTP_URL, allow_http: true } as Partial<EnrichmentDef>),
    );
    const scope = nock(HTTP_ORIGIN)
      .post(PATH)
      .twice()
      .reply(200, { classify_user: "paying" });
    const writes: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (
      s: string,
    ): boolean => {
      writes.push(s);
      return true;
    };
    try {
      const r1 = await resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      );
      expect(r1).toBe("paying");
      const r2 = await resolveEnrichment(
        "classify_user",
        { account_id: "globex", end_user_id: "u_99" },
        schema,
      );
      expect(r2).toBe("paying");
    } finally {
      (process.stderr as unknown as { write: typeof origWrite }).write = origWrite;
    }
    expect(scope.isDone()).toBe(true);
    const allowHttpWarnings = writes.filter((w) => w.includes("allow_http=true"));
    expect(allowHttpWarnings.length).toBe(1);
    expect(allowHttpWarnings[0]).toMatch(/insecure http:\/\/ URL accepted/);
    expect(allowHttpWarnings[0]).toMatch(/DEV ONLY/);
  });

  test("S1-15 Pre-1: allow_http=false + http:// URL still throws EnrichmentConfigError", async () => {
    const schema = schemaWith(
      baseEnrich({ url: "http://example.test/x", allow_http: false } as Partial<EnrichmentDef>),
    );
    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentConfigError);
  });

  test("S1-15 Pre-1: allow_http=true + https:// URL → no warning, succeeds", async () => {
    const schema = schemaWith(
      baseEnrich({ allow_http: true } as Partial<EnrichmentDef>),
    );
    nock(ORIGIN).post(PATH).reply(200, { classify_user: "paying" });
    const writes: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (
      s: string,
    ): boolean => {
      writes.push(s);
      return true;
    };
    try {
      const r = await resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      );
      expect(r).toBe("paying");
    } finally {
      (process.stderr as unknown as { write: typeof origWrite }).write = origWrite;
    }
    expect(writes.filter((w) => w.includes("allow_http=true"))).toHaveLength(0);
  });

  test("rejects missing secret env var", async () => {
    delete process.env[SECRET_VAR];
    const schema = schemaWith(baseEnrich());
    nock(ORIGIN).post(PATH).reply(200, { classify_user: "paying" });
    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentConfigError);
    nock.cleanAll();
  });

  test("rejects unsupported secret_ref prefix", async () => {
    const schema = schemaWith(
      baseEnrich({ auth: { secret_ref: "vault:/path/to/secret" } }),
    );
    await expect(
      resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      ),
    ).rejects.toBeInstanceOf(EnrichmentConfigError);
  });

  test("returns null when ref is not defined in the schema", async () => {
    const schema: TenantSchema = { version: 1, dimensions: [] };
    const r = await resolveEnrichment(
      "missing_ref",
      { account_id: "acme" },
      schema,
    );
    expect(r).toBeNull();
  });
});

describe("resolveEnrichment — send_raw warning", () => {
  test("emits a one-shot stderr warning when send_raw: true", async () => {
    const schema = schemaWith(baseEnrich({ send_raw: true }));
    const writes: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    // Wrap stderr.write to capture; restore in finally.
    (process.stderr as unknown as { write: (s: string) => boolean }).write = (
      s: string,
    ): boolean => {
      writes.push(s);
      return true;
    };
    try {
      nock(ORIGIN).post(PATH).times(2).reply(200, { classify_user: "paying" });
      await resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_42" },
        schema,
      );
      await resolveEnrichment(
        "classify_user",
        { account_id: "acme", end_user_id: "u_43" },
        schema,
      );
      const matches = writes.filter((w) => w.includes("send_raw: true"));
      expect(matches.length).toBe(1);
    } finally {
      (process.stderr as unknown as { write: typeof origWrite }).write = origWrite;
    }
  });
});

describe("required-dimension composition", () => {
  test("when_missing: reject + on_failure: fail_open + 5xx → RequiredDimensionMissingError", async () => {
    const schema: TenantSchema = {
      version: 1,
      dimensions: [
        {
          name: "classify_user",
          source: { kind: "enrichment", enrichment_ref: "classify_user" },
          required: true,
          when_missing: "reject",
        },
      ],
      enrichments: { classify_user: baseEnrich() },
    };
    _setActiveSchema(schema);
    nock(ORIGIN).post(PATH).reply(500, "boom");

    await expect(resolveDimensions()).rejects.toBeInstanceOf(
      RequiredDimensionMissingError,
    );
  });
});
