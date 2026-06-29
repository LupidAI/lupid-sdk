/**
 * Unix-domain-socket (UDS) `fetch` shim for the local PDP.
 *
 * The TCP baseline talks to the PDP over loopback (`http://127.0.0.1:7080`).
 * This shim lets operators move that to a UDS at `unix:///run/agentum/pdp.sock`,
 * where the PDP enforces peer-credential auth (uid match) instead of the
 * env-var-harvestable service token. The SDK side is a routing change only:
 * when `AGENTUM_PDP_URL` starts with `unix://`, `init.ts` lazy-loads this
 * module and injects the returned function as `CedarToolCallClient.fetchImpl`.
 *
 * Edge-runtime safety. `cedar-client.ts` MUST NOT import `node:*`, so this
 * shim is the only place we touch `node:http`. The literal `import("node:http")`
 * call is preserved by esbuild/tsup as a runtime require (see
 * `instrumentation/node-http-interceptor.ts:122-126` for the canonical idiom),
 * so it does NOT appear in the static module graph of `dist/index.mjs`.
 * Bundlers tree-shake this whole file out for non-`unix://` deployments
 * because `init.ts` gates the dynamic `import("./uds-fetch")` behind a
 * runtime `pdpUrlRaw.startsWith("unix://")` check.
 *
 * URL convention. `cedar-client.ts` builds absolute URLs against `this.pdpUrl`:
 *   `${pdpUrl}/v1/health`, `${pdpUrl}/v1/authorize`
 * When `pdpUrl === "unix:///run/agentum/pdp.sock"`, the resulting URL is
 * `unix:///run/agentum/pdp.sock/v1/authorize`. We strip the known
 * `unix://${socketPath}` prefix to recover the HTTP path. This is a prefix
 * match — `new URL("unix://...")` silently misinterprets the first path
 * component as the URL authority, so we do not use it.
 */

import type { IncomingMessage, ClientRequest } from "node:http";

interface NodeHttpModule {
  request: (
    options: {
      socketPath: string;
      path: string;
      method: string;
      headers?: Record<string, string | string[]>;
    },
    callback: (res: IncomingMessage) => void,
  ) => ClientRequest;
}

/**
 * Build a `fetch`-shaped function that targets the local PDP over a Unix
 * domain socket. Fails closed (throws) if invoked in a non-Node runtime —
 * the caller (init.ts) must only reach this code path on Node, but we
 * defend in depth.
 *
 * @param socketPath absolute filesystem path to the UDS socket (e.g.
 *   `/run/agentum/pdp.sock`). Must match the `socketPath` portion of the
 *   `unix://` URL the SDK was configured with — the shim asserts that
 *   every request URL starts with `unix://${socketPath}`.
 */
export async function makeUdsFetch(socketPath: string): Promise<typeof fetch> {
  if (typeof process === "undefined" || !process.versions?.node) {
    throw new Error(
      "AGENTUM_PDP_URL=unix:// requires a Node runtime; edge runtimes are not supported. " +
      "Configure http://127.0.0.1:7080 with a service token instead.",
    );
  }
  // Lazy dynamic import — bundlers preserve literal `import("node:*")` calls
  // as runtime requires, mirroring `node-http-interceptor.ts:122-126`.
  const httpNs = await import("node:http");
  const nodeHttp = ((httpNs as unknown as { default?: NodeHttpModule }).default
    ?? httpNs) as unknown as NodeHttpModule;

  const urlPrefix = `unix://${socketPath}`;

  return ((url: string | URL, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof url === "string" ? url : url.toString();
    if (!urlStr.startsWith(urlPrefix)) {
      return Promise.reject(
        new Error(
          `UDS fetch received unexpected URL: ${urlStr} (expected prefix: ${urlPrefix})`,
        ),
      );
    }
    const pathAndQuery = urlStr.slice(urlPrefix.length) || "/";
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = normaliseRequestHeaders(init?.headers);

    return new Promise<Response>((resolve, reject) => {
      let req: ClientRequest;
      try {
        req = nodeHttp.request(
          { socketPath, path: pathAndQuery, method, headers },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () => {
              const body = Buffer.concat(chunks);
              resolve(
                new Response(body, {
                  status: res.statusCode ?? 502,
                  // node:http.IncomingHttpHeaders is NOT a DOM Headers
                  // object — under the SDK's `lib: ["ES2020","ES2023"]`
                  // (no DOM) typing it as such would compile with
                  // skipLibCheck but break runtime `.get()`/`.has()`
                  // callers. Build a real Headers from the entries.
                  headers: new Headers(
                    Object.entries(res.headers).flatMap(([k, v]) =>
                      Array.isArray(v)
                        ? v.map((x) => [k, x] as [string, string])
                        : v != null
                          ? [[k, String(v)] as [string, string]]
                          : [],
                    ),
                  ),
                }),
              );
            });
            res.on("error", reject);
          },
        );
      } catch (err) {
        reject(err as Error);
        return;
      }
      req.on("error", reject);
      // AbortSignal support — mirrors the rest of the SDK's fetch usage.
      const signal = init?.signal;
      if (signal) {
        if (signal.aborted) {
          req.destroy(new DOMException("Aborted", "AbortError"));
          return;
        }
        signal.addEventListener("abort", () => {
          req.destroy(new DOMException("Aborted", "AbortError"));
        });
      }
      const body = init?.body;
      if (body !== undefined && body !== null) {
        req.write(serialiseRequestBody(body));
      }
      req.end();
    });
  }) as typeof fetch;
}

/**
 * Coerce a `HeadersInit` (the DOM fetch flavour) into the `node:http`
 * `{ [key: string]: string | string[] }` shape. Handles all three
 * legal HeadersInit forms — `Headers`, array of pairs, plain record.
 */
function normaliseRequestHeaders(
  headers: RequestInit["headers"] | undefined,
): Record<string, string | string[]> {
  if (!headers) return {};
  const out: Record<string, string | string[]> = {};
  if (typeof (headers as Headers).forEach === "function" &&
      typeof (headers as Headers).get === "function") {
    (headers as Headers).forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  if (Array.isArray(headers)) {
    for (const pair of headers) {
      if (Array.isArray(pair) && pair.length === 2) {
        const [k, v] = pair as [string, string];
        const existing = out[k];
        if (existing === undefined) {
          out[k] = v;
        } else if (Array.isArray(existing)) {
          existing.push(v);
        } else {
          out[k] = [existing, v];
        }
      }
    }
    return out;
  }
  for (const [k, v] of Object.entries(headers as Record<string, string>)) {
    out[k] = v;
  }
  return out;
}

/**
 * Reduce the DOM `BodyInit` union (typed as `RequestInit["body"]` since the
 * SDK's tsconfig has no DOM lib and `BodyInit` is unresolved) down to the
 * `string | Buffer | Uint8Array` shapes `node:http.ClientRequest.write`
 * accepts. The PDP SDK paths only send JSON strings today, so the exotic
 * Blob/FormData/ReadableStream cases are accepted-but-stringified rather
 * than streamed.
 */
function serialiseRequestBody(
  body: NonNullable<RequestInit["body"]>,
): string | Buffer | Uint8Array {
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return body;
  if (Buffer.isBuffer(body as unknown as Buffer)) return body as unknown as Buffer;
  // Fall back: stringify whatever it is. JSON.stringify on Blob/FormData/etc
  // yields `"{}"`, which is wrong but at least non-crashing — and the PDP
  // SDK paths in cedar-client.ts always pass a JSON string body, so this
  // branch is unreachable in practice.
  return String(body);
}
