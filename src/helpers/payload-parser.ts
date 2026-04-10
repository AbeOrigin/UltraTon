import { Buffer } from "node:buffer";
import { UltraTonParseError } from "../exceptions/parse.error.ts";

export const MAX_SYNC_PARSE_BYTES = 5242880; // 5MB

export const secureReviver = (key: string, value: any) => {
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    return undefined; // Strip dangerous keys
  }
  return value;
};

/**
 * Parses a raw buffer payload based on content type
 * @param rawData - The raw buffer data to parse
 * @param contentType - The content type header value
 * @returns Parsed object if JSON, otherwise the raw Buffer
 */
export function parseSecurePayload<T = unknown>(
  rawData: Buffer,
  contentType?: string | string[],
): T | Buffer {
  let typeStr = "";
  if (Array.isArray(contentType)) {
    typeStr = contentType[0]?.toLowerCase() || "";
  } else {
    typeStr = contentType?.toLowerCase() || "";
  }

  if (!typeStr.includes("application/json")) {
    return rawData;
  }

  if (rawData.length === 0) {
    return {} as T;
  }

  if (rawData.length > MAX_SYNC_PARSE_BYTES) {
    return rawData;
  }

  try {
    return JSON.parse(rawData.toString("utf-8"), secureReviver) as T;
  } catch (e: unknown) {
    throw new UltraTonParseError(
      `UltraTon: Failed to parse JSON response payload.`,
    );
  }
}
