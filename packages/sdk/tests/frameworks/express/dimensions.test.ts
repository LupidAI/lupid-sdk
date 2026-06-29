/**
 * S1-13 — Express dimension adapter unit tests.
 *
 * Invoke the middleware directly with a synthetic `req`/`next` pair (the SDK
 * doesn't depend on `express`, and the adapter uses structural types). Assert
 * that `request_header`-source dimensions land in `resolveDimensions()`'s
 * output for a request made inside the `next()` callback.
 */

import { agentumExpressAdapter } from "../../../src/frameworks/express/dimensions";
import { resolveDimensions } from "../../../src/instrumentation/resolve-dimensions";
import { _setActiveSchema } from "../../../src/manifest/index";
import type { TenantSchema, Dimension } from "../../../src/manifest/types";

function schema(dimensions: Dimension[]): TenantSchema {
  return { version: 1, dimensions };
}

afterEach(() => {
  _setActiveSchema(null);
});

describe("agentumExpressAdapter", () => {
  test("primes ALS with request_header dimensions", async () => {
    _setActiveSchema(
      schema([
        {
          name: "account_id",
          source: { kind: "request_header", header: "x-acme-account-id" },
        },
      ]),
    );
    const mw = agentumExpressAdapter();
    const req = { headers: { "x-acme-account-id": "acme" } };
    let inside: Record<string, string | null> | undefined;
    await new Promise<void>((resolve, reject) => {
      mw(req, {}, (err?: unknown) => {
        if (err) {
          reject(err as Error);
          return;
        }
        // `next()` runs inside the `withAgentumContext` callback — the ALS
        // store is live here, so resolveDimensions sees the primed header.
        resolveDimensions()
          .then((got) => {
            inside = got;
            resolve();
          })
          .catch(reject);
      });
    });
    expect(inside).toEqual({ account_id: "acme" });
  });

  test("declaring header with mixed case still matches lowercase req.headers", async () => {
    _setActiveSchema(
      schema([
        {
          name: "account_id",
          source: { kind: "request_header", header: "X-Acme-Account-Id" },
        },
      ]),
    );
    const mw = agentumExpressAdapter();
    const req = { headers: { "x-acme-account-id": "acme" } };
    let inside: Record<string, string | null> | undefined;
    await new Promise<void>((resolve, reject) => {
      mw(req, {}, () => {
        resolveDimensions()
          .then((got) => {
            inside = got;
            resolve();
          })
          .catch(reject);
      });
    });
    expect(inside).toEqual({ account_id: "acme" });
  });

  test("skips context-source dimensions (no priming)", async () => {
    _setActiveSchema(
      schema([
        { name: "bot_id", source: { kind: "context", path: "bot_id" } },
        {
          name: "account_id",
          source: { kind: "request_header", header: "x-acme-account-id" },
        },
      ]),
    );
    const mw = agentumExpressAdapter();
    const req = { headers: { "x-acme-account-id": "acme", "x-bot-id": "ignored" } };
    let inside: Record<string, string | null> | undefined;
    await new Promise<void>((resolve, reject) => {
      mw(req, {}, () => {
        resolveDimensions()
          .then((got) => {
            inside = got;
            resolve();
          })
          .catch(reject);
      });
    });
    expect(inside).toEqual({ bot_id: null, account_id: "acme" });
  });

  test("array-valued header takes first element", async () => {
    _setActiveSchema(
      schema([
        {
          name: "account_id",
          source: { kind: "request_header", header: "x-account" },
        },
      ]),
    );
    const mw = agentumExpressAdapter();
    const req = { headers: { "x-account": ["acme", "beta"] } };
    let inside: Record<string, string | null> | undefined;
    await new Promise<void>((resolve, reject) => {
      mw(req, {}, () => {
        resolveDimensions()
          .then((got) => {
            inside = got;
            resolve();
          })
          .catch(reject);
      });
    });
    expect(inside).toEqual({ account_id: "acme" });
  });

  test("pre-init pass-through: no schema → next() invoked without throwing", async () => {
    _setActiveSchema(null);
    const mw = agentumExpressAdapter();
    const req = { headers: { "x-acme-account-id": "acme" } };
    const next = jest.fn();
    mw(req, {}, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test("missing header yields no dimension binding", async () => {
    _setActiveSchema(
      schema([
        {
          name: "account_id",
          source: { kind: "request_header", header: "x-acme-account-id" },
        },
      ]),
    );
    const mw = agentumExpressAdapter();
    const req = { headers: {} };
    let inside: Record<string, string | null> | undefined;
    await new Promise<void>((resolve, reject) => {
      mw(req, {}, () => {
        resolveDimensions()
          .then((got) => {
            inside = got;
            resolve();
          })
          .catch(reject);
      });
    });
    expect(inside).toEqual({ account_id: null });
  });
});
