import type { IncomingHttpHeaders } from "node:http";
import { Buffer } from "node:buffer";
import { UltraTonHttpError, UltraTonNetworkError, UltraTonParseError } from "../errors.ts";
import type { UltraTonRedirect, UltraTonResponse, UltraTonStreamResponse } from "../types/request-response.ts";

/** The `redirects` of every response that followed none: frozen, so one array serves them all. */
export const NO_REDIRECTS: readonly UltraTonRedirect[] = Object.freeze([]);

export const secureReviver = (key: string, value: any) => {
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    return undefined; // Strip dangerous keys
  }
  return value;
};

/**
 * The exact body length a response promises with `content-length`, or `undefined` when none applies: HEAD, 1xx, 204
 * and 304 responses carry no body whatever the header says, and an absent or malformed header promises nothing.
 * Both engines compare it with the bytes received, so a response cut short never resolves as a success.
 */
export function declaredBodyLength(method: string | undefined, statusCode: number, headers: IncomingHttpHeaders): number | undefined {
  if (method === "HEAD" || statusCode < 200 || statusCode === 204 || statusCode === 304) return undefined;
  const raw = headers["content-length"];
  if (typeof raw !== "string" || !/^\d+$/.test(raw)) return undefined;
  const length = Number(raw);
  return Number.isSafeInteger(length) ? length : undefined;
}

/** The error both engines give a response that ended before (or beyond) the body it promised. */
export const incompleteResponse = (cause?: unknown) =>
  new UltraTonNetworkError("UltraTon: Connection failed (ECONNRESET).", { code: "ECONNRESET", cause });

/**
 * Builds the response both engines hand to the caller. The body stays a raw Buffer: JSON is parsed only when
 * `json()` is called, so a huge or malformed payload cannot fail (or block) the request itself.
 * HTTP/2 pseudo-headers (':status', ...) are protocol framing, not response headers, so they are dropped.
 */
export function createResponse<T = unknown>(
  statusCode: number,
  rawHeaders: IncomingHttpHeaders,
  data: Buffer,
  url = "",
  redirects: readonly UltraTonRedirect[] = NO_REDIRECTS,
): UltraTonResponse<T> {
  // `__proto__` is defined, not assigned: on a plain object `headers['__proto__'] = v` would set the prototype (or be
  // ignored) instead of keeping a header the server named `__proto__` (node:http2 hands it over as an ordinary key) as
  // data. Every other key is assigned: only `__proto__` has a setter on a plain object, and defineProperty per header
  // was a measurable share of every response.
  const headers: IncomingHttpHeaders = {};
  for (const key of Object.keys(rawHeaders)) {
    if (key.startsWith(":")) continue;
    if (key === "__proto__") Object.defineProperty(headers, key, { value: rawHeaders[key], enumerable: true, writable: true, configurable: true });
    else headers[key] = rawHeaders[key];
  }

  // A leading byte order mark is not content, as fetch reads it; `data` keeps the raw bytes.
  const text = (): string => {
    const decoded = data.toString("utf-8");
    return decoded.charCodeAt(0) === 0xfeff ? decoded.slice(1) : decoded;
  };
  const response: UltraTonResponse<T> = {
    statusCode,
    ok: statusCode >= 200 && statusCode < 300,
    headers,
    url,
    redirected: redirects.length > 0,
    redirects,
    data,
    json<R = T>(): R {
      const payload = text();
      if (payload === "") return {} as R;
      try {
        return JSON.parse(payload, secureReviver) as R;
      } catch (cause: unknown) {
        throw new UltraTonParseError("UltraTon: Failed to parse JSON response payload.", { cause });
      }
    },
    text,
    assertOk(): UltraTonResponse<T> {
      if (response.ok) return response;
      throw new UltraTonHttpError(statusCode, response);
    },
  };
  return response;
}

/** The stream counterpart of createResponse: same status and header rules, the body left to the caller. */
export function createStreamResponse(
  statusCode: number,
  rawHeaders: IncomingHttpHeaders,
  body: ReadableStream<Uint8Array>,
  url: string,
  redirects: readonly UltraTonRedirect[],
): UltraTonStreamResponse {
  const { headers } = createResponse(statusCode, rawHeaders, Buffer.alloc(0));
  const response: UltraTonStreamResponse = {
    statusCode,
    ok: statusCode >= 200 && statusCode < 300,
    headers,
    url,
    redirected: redirects.length > 0,
    redirects,
    body,
    assertOk(): UltraTonStreamResponse {
      if (response.ok) return response;
      // Nobody will read a body the caller refused: cancel it so the connection is not held (its failure is irrelevant).
      void body.cancel().catch(() => {});
      throw new UltraTonHttpError(statusCode, response);
    },
  };
  return response;
}
