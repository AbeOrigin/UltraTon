import type { IncomingHttpHeaders } from "node:http";
import { Buffer } from "node:buffer";
import { UltraTonNetworkError, UltraTonParseError } from "../errors.ts";
import type { UltraTonResponse, UltraTonStreamResponse } from "../types/request-response.ts";

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
): UltraTonResponse<T> {
  // Defined, not assigned: on a plain object `headers['__proto__'] = v` would set the prototype (or be ignored) instead
  // of keeping a header the server named `__proto__` (node:http2 hands it over as an ordinary key) as data.
  const headers: IncomingHttpHeaders = {};
  for (const key of Object.keys(rawHeaders)) {
    if (key.startsWith(":")) continue;
    Object.defineProperty(headers, key, { value: rawHeaders[key], enumerable: true, writable: true, configurable: true });
  }

  return {
    statusCode,
    ok: statusCode >= 200 && statusCode < 300,
    headers,
    data,
    json<R = T>(): R {
      if (data.length === 0) return {} as R;
      try {
        return JSON.parse(data.toString("utf-8"), secureReviver) as R;
      } catch (cause: unknown) {
        throw new UltraTonParseError("UltraTon: Failed to parse JSON response payload.", { cause });
      }
    },
    text(): string {
      return data.toString("utf-8");
    },
  };
}

/** The stream counterpart of createResponse: same status and header rules, the body left to the caller. */
export function createStreamResponse(
  statusCode: number,
  rawHeaders: IncomingHttpHeaders,
  body: ReadableStream<Uint8Array>,
  url: string,
): UltraTonStreamResponse {
  const { headers } = createResponse(statusCode, rawHeaders, Buffer.alloc(0));
  return { statusCode, ok: statusCode >= 200 && statusCode < 300, headers, url, body };
}
