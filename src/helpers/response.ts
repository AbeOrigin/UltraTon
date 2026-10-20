import type { IncomingHttpHeaders } from "node:http";
import { Buffer } from "node:buffer";
import { UltraTonParseError } from "../errors.ts";
import type { UltraTonResponse } from "../types/request-response.ts";

export const secureReviver = (key: string, value: any) => {
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    return undefined; // Strip dangerous keys
  }
  return value;
};

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
  const headers: IncomingHttpHeaders = {};
  for (const key of Object.keys(rawHeaders)) {
    if (!key.startsWith(":")) headers[key] = rawHeaders[key];
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
