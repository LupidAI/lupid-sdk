/**
 * P03: Fail-CLOSED default for the layer-1 / layer-1.5 interceptors.
 *
 * Both `installFetchInterceptor` and `installNodeHttpInterceptor` must
 * default to `failMode: "deny"` when the option is omitted. Historically
 * they defaulted to `"allow"` (fail-OPEN), with only `init.ts` paving over
 * the gap by passing an explicit `"deny"`. This file pins the new default
 * by constructing the interceptor options WITHOUT a `failMode` key and
 * exercising the evaluator-error path.
 *
 * Reference shape: `tests/fetch-interceptor.test.ts` named test
 * "failMode=allow on evaluator error passes through; failMode=deny
 * short-circuits" exercises both branches with explicit `failMode`. This
 * file is the omitted-option counterpart.
 */

import * as http from "node:http";
import { AddressInfo } from "node:net";

import {
  installFetchInterceptor,
  type FetchInterceptorOptions,
} from "../src/instrumentation/fetch-interceptor";
import {
  installNodeHttpInterceptor,
  type NodeHttpInterceptorOptions,
} from "../src/instrumentation/node-http-interceptor";
import { HostRegistry } from "../src/instrumentation/host-registry";
import {
  CedarToolCallClient,
  type ToolCallEvaluation,
} from "../src/evaluation/cedar-client";

function silentLogger(): Pick<Console, "log" | "warn" | "error"> {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

function throwingEvaluator(): CedarToolCallClient {
  return {
    evaluateToolCall: jest.fn(async () => {
      throw new Error("boom");
    }),
    invalidateAll: jest.fn(),
  } as unknown as CedarToolCallClient;
}

// ── fetch-interceptor ──────────────────────────────────────────────────────

function jsonResponse(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...headers },
  });
}

interface MockUpstream {
  fetchImpl: jest.Mock;
}

function mockUpstream(handler: () => Response | Promise<Response>): MockUpstream {
  const fetchImpl = jest.fn(async () => handler());
  return { fetchImpl: fetchImpl as unknown as jest.Mock };
}

afterEach(() => {
  delete (globalThis as { fetch?: unknown }).fetch;
});

describe("P03 fail-CLOSED default — fetch-interceptor", () => {
  it("defaults to fail-CLOSED on evaluator error when failMode is omitted", async () => {
    const errEv = throwingEvaluator();
    // Response carries a tool_call so the post-flight evaluator path runs
    // and the fake evaluator throws — the interceptor's fail-mode branch
    // is what we're pinning here.
    const respBody = {
      id: "x",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            tool_calls: [
              {
                id: "c",
                type: "function",
                function: { name: "f", arguments: "{}" },
              },
            ],
          },
          finish_reason: "tool_calls",
        },
      ],
    };
    const up = mockUpstream(() => jsonResponse(respBody));

    // Construct opts WITHOUT failMode — this is the production-default test.
    const opts: FetchInterceptorOptions = {
      runtime: {
        baseUrl: "http://agentum.test:7071",
        apiKey: "ak_test",
        evaluator: errEv,
      },
      agentId: "a-1",
      hosts: new HostRegistry(),
      capturePrompts: false,
      fetchImpl: up.fetchImpl as unknown as typeof fetch,
      logger: silentLogger(),
    };
    const uninstall = installFetchInterceptor(opts);
    try {
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        body: JSON.stringify({ model: "gpt-4", messages: [] }),
      });
      const j = (await r.json()) as {
        choices: Array<{ message: Record<string, unknown>; finish_reason: string }>;
      };
      // Fail-CLOSED: tool_calls dropped, finish_reason normalised to "stop".
      expect(j.choices[0]!.message["tool_calls"]).toBeUndefined();
      expect(j.choices[0]!.finish_reason).toBe("stop");
    } finally {
      uninstall();
    }
  });
});

// ── node-http-interceptor ──────────────────────────────────────────────────

interface StubServer {
  port: number;
  close: () => Promise<void>;
}

async function startStub(
  handler: (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void,
): Promise<StubServer> {
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      handler(req, Buffer.concat(chunks).toString("utf8"), res);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

const localhostLookup = (
  _hostname: string,
  options: unknown,
  callback: ((err: Error | null, address: string, family: number) => void) &
    ((err: Error | null, addresses: Array<{ address: string; family: number }>) => void),
): void => {
  const all =
    typeof options === "object" &&
    options !== null &&
    (options as { all?: boolean }).all === true;
  if (all) {
    (callback as (
      err: Error | null,
      addresses: Array<{ address: string; family: number }>,
    ) => void)(null, [{ address: "127.0.0.1", family: 4 }]);
  } else {
    (callback as (err: Error | null, address: string, family: number) => void)(
      null,
      "127.0.0.1",
      4,
    );
  }
};

interface CollectedResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function collect(req: http.ClientRequest): Promise<CollectedResponse> {
  return new Promise((resolve, reject) => {
    req.on("response", (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) =>
        chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)),
      );
      res.on("end", () =>
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        }),
      );
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

describe("P03 fail-CLOSED default — node-http-interceptor", () => {
  it("defaults to fail-CLOSED on evaluator error when failMode is omitted", async () => {
    // Upstream stub returns an OpenAI-shaped response with a tool_call so
    // the post-flight evaluator runs.
    const stub = await startStub((_req, _body, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          id: "x",
          choices: [
            {
              index: 0,
              message: {
                role: "assistant",
                content: null,
                tool_calls: [
                  {
                    id: "c",
                    type: "function",
                    function: { name: "f", arguments: "{}" },
                  },
                ],
              },
              finish_reason: "tool_calls",
            },
          ],
        }),
      );
    });
    const hosts = new HostRegistry();
    hosts.add("api.openai.com");
    const errEv = throwingEvaluator();

    // Construct opts WITHOUT failMode — this is the production-default test.
    const opts: NodeHttpInterceptorOptions = {
      runtime: {
        baseUrl: "http://agentum.test:7071",
        apiKey: "ak_test",
        evaluator: errEv,
      },
      agentId: "a-1",
      hosts,
      capturePrompts: false,
      logger: silentLogger(),
    };
    const uninstall = await installNodeHttpInterceptor(opts);
    try {
      const req = http.request({
        hostname: "api.openai.com",
        port: stub.port,
        path: "/v1/chat/completions",
        method: "POST",
        headers: { "content-type": "application/json", host: "api.openai.com" },
        lookup: localhostLookup,
      });
      req.end(JSON.stringify({ model: "gpt-4", messages: [] }));
      const resp = await collect(req);
      const json = JSON.parse(resp.body) as {
        choices: Array<{ message: Record<string, unknown>; finish_reason: string }>;
      };
      // Fail-CLOSED: tool_calls dropped, finish_reason normalised to "stop".
      expect(json.choices[0]!.message["tool_calls"]).toBeUndefined();
      expect(json.choices[0]!.finish_reason).toBe("stop");
    } finally {
      uninstall();
      await stub.close();
    }
  });
});
