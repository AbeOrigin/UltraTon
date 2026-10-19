import { Buffer } from "node:buffer";
import { constants } from "node:http2";
import type {
  ClientHttp2Session,
  ClientHttp2Stream,
  IncomingHttpHeaders,
  OutgoingHttpHeaders,
} from "node:http2";
import type { UltraTonResponse } from "./types/request-response.ts";
import { Http2SessionManager } from "./classes/http-session-mannager.ts";
import type {
  SecureUltraTonRequestOptions,
  UltraTonOptionsHttp2,
  UltraTonRequestOptionsHttp2,
} from "./types/request-options.types.ts";
import {
  SecureHttpError,
  UltraTonMemoryError,
  UltraTonNetworkTimeoutError,
  UltraTonParseError,
  UltraTonRedirectError,
} from "./errors.ts";
import { HTTP_CODES_REDIRECTS } from "./constants.ts";
import { parseSecurePayload, secureReviver } from "./helpers/payload-parser.ts";
import { buildSafeRequestOptions } from "./helpers/request-options.ts";
import { parseSafeUrl } from "./helpers/url-parser.ts";

const globalPool = new Http2SessionManager();

export class UltraTonHTTP2 {
  readonly #sessionManager: Http2SessionManager;
  readonly #globalOptions: UltraTonOptionsHttp2;

  /**
   * @param options - Public configuration options.
   * @param _sessionManager - Internal DI seam for unit testing. Allows injecting
   *   a pre-wired Http2SessionManager (with a mock connectFn) so tests never
   *   touch the network. Do NOT use in production code.
   */
  constructor(
    options: UltraTonOptionsHttp2 = {},
    _sessionManager?: Http2SessionManager,
  ) {
    this.#globalOptions = options;
    if (_sessionManager) {
      this.#sessionManager = _sessionManager;
      return;
    }
    if (options.isolatePool) {
      this.#sessionManager = new Http2SessionManager(options.tlsSettings);
      return;
    }
    this.#sessionManager = globalPool;
  }

  public async get<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "GET" });
  }

  public async post<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "POST" });
  }

  public async put<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "PUT" });
  }

  public async patch<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "PATCH" });
  }

  public async delete<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "DELETE" });
  }

  public async head<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "HEAD" });
  }

  public async options<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, { ...options, method: "OPTIONS" });
  }

  private async _request<T = unknown>(
    targetUrl: string,
    options: UltraTonRequestOptionsHttp2 = {},
  ): Promise<UltraTonResponse<T>> {
    // One clock for the whole redirect chain: timeoutMs is a budget shared by every hop.
    const startTime = Date.now();
    let currentUrl = targetUrl;
    let currentOptions = { ...options };
    let redirectCount = 0;
    // Validate before touching the network: invalid input must fail without connecting.
    let reqOpts = this.#buildRequestOptions(currentOptions);

    while (true) {
      const parsedUrl = parseSafeUrl(currentUrl);
      const origin = parsedUrl.origin;
      const path = parsedUrl.pathname + parsedUrl.search;

      const session = await this.#sessionManager.getSession(
        origin,
        undefined,
        reqOpts.permitReservedIps,
      );

      // reqOpts.headers is already lowercased and CRLF/pseudo-header checked.
      const safeHeaders: Record<string, string | string[] | undefined> = {
        ...reqOpts.headers,
      };

      if (currentOptions.body) {
        safeHeaders["content-length"] = Buffer.byteLength(
          currentOptions.body,
        ).toString();
      }

      const method = (reqOpts.method || "GET").toUpperCase();

      const pseudoHeaders: OutgoingHttpHeaders = {
        ":method": method,
        ":path": path,
        ":authority": parsedUrl.host,
        ...safeHeaders,
      };

      // Measured after getSession so the time spent connecting is charged to the budget too.
      // A spent budget must throw here: a non-positive value would disable the stream timer.
      let remainingMs = reqOpts.timeoutMs;
      if (reqOpts.timeoutMs > 0) {
        remainingMs = reqOpts.timeoutMs - (Date.now() - startTime);
        if (remainingMs <= 0) {
          throw new UltraTonNetworkTimeoutError(
            `UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`,
          );
        }
      }

      const response = await this.#executeStream<T>(
        session,
        pseudoHeaders,
        currentOptions.body,
        remainingMs,
        reqOpts.timeoutMs,
        reqOpts.maxBodySize,
      );

      const statusCode = response.statusCode;
      const location = response.headers.location;

      if (
        statusCode &&
        HTTP_CODES_REDIRECTS.has(statusCode) &&
        location &&
        typeof location === "string"
      ) {
        if (reqOpts.maxRedirects > 0) {
          if (redirectCount >= reqOpts.maxRedirects) {
            throw new UltraTonRedirectError(
              `UltraTon: Max redirects (${reqOpts.maxRedirects}) exceeded.`,
            );
          }

          redirectCount++;

          const nextUrl = parseSafeUrl(location, currentUrl);
          // sanitizeHeaders already lowercased every key
          const nextHeaders = { ...reqOpts.headers } as Record<
            string,
            string | string[] | undefined
          >;

          if (parsedUrl.origin !== nextUrl.origin) {
            delete nextHeaders["authorization"];
            delete nextHeaders["cookie"];
            delete nextHeaders["proxy-authorization"];
          }

          let nextMethod = method;
          let nextBody = currentOptions.body;

          if (
            statusCode === 303 ||
            ((statusCode === 301 || statusCode === 302) &&
              nextMethod !== "GET" &&
              nextMethod !== "HEAD")
          ) {
            nextMethod = "GET";
            nextBody = undefined;
            delete nextHeaders["content-length"];
            delete nextHeaders["content-type"];
            delete nextHeaders["transfer-encoding"];
          }

          currentUrl = nextUrl.href;
          currentOptions = {
            ...currentOptions,
            method: nextMethod,
            headers: nextHeaders,
            body: nextBody,
          };
          reqOpts = this.#buildRequestOptions(currentOptions);

          continue;
        }
      }

      return response;
    }
  }

  /**
   * Runs the per-request options through the same firewall as the HTTP/1 client.
   * A per-request value wins over the client-wide one; an unset one (undefined)
   * falls back to the client-wide value.
   */
  #buildRequestOptions(
    options: UltraTonRequestOptionsHttp2,
  ): SecureUltraTonRequestOptions {
    const g = this.#globalOptions;
    return buildSafeRequestOptions({
      ...options,
      maxRedirects: options.maxRedirects ?? g.maxRedirects,
      timeoutMs: options.timeoutMs ?? g.timeoutMs,
      maxBodySize: options.maxBodySize ?? g.maxBodySize,
      permitReservedIps: options.permitReservedIps ?? g.permitReservedIps,
    });
  }

  #executeStream<T = unknown>(
    session: ClientHttp2Session,
    pseudoHeaders: OutgoingHttpHeaders,
    body: Buffer | string | undefined,
    remainingMs: number,
    timeoutMs: number,
    maxBodySize: number,
  ): Promise<UltraTonResponse<T>> {
    return new Promise((resolve, reject) => {
      let settled = false;
      let statusCode: number | undefined;
      let responseHeaders: IncomingHttpHeaders = {};
      const chunks: Buffer[] = [];

      let stream: ClientHttp2Stream;

      try {
        stream = session.request(pseudoHeaders);
      } catch (err: unknown) {
        return reject(
          new SecureHttpError(
            `UltraTon: Failed to initialize HTTP/2 stream: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
      }

      // remainingMs is what is left of the shared budget; timeoutMs is the configured total, for the message.
      const streamTimer =
        remainingMs > 0
          ? setTimeout(() => {
            if (settled) return;
            settled = true;
            stream.close(constants.NGHTTP2_CANCEL);
            reject(
              new UltraTonNetworkTimeoutError(
                `UltraTon: Absolute execution time of ${timeoutMs}ms exceeded.`,
              ),
            );
          }, remainingMs)
          : undefined;

      stream.on("response", (headers) => {
        if (settled) return;
        statusCode = Number(headers[":status"]);
        responseHeaders = headers;

        if (pseudoHeaders[":method"] === "HEAD") {
          settled = true;
          clearTimeout(streamTimer);
          stream.close();

          return resolve({
            statusCode,
            headers: responseHeaders,
            body: Buffer.alloc(0),
            json: (): T => ({}) as T,
          });
        }
      });

      let totalBytes = 0;
      stream.on("data", (chunk: Buffer) => {
        if (settled) return;
        totalBytes += chunk.length;
        if (totalBytes > maxBodySize) {
          settled = true;
          clearTimeout(streamTimer);
          stream.close(constants.NGHTTP2_CANCEL);
          reject(
            new UltraTonMemoryError(
              `UltraTon: HTTP/2 response body exceeded the maximum allowed size of ${maxBodySize} bytes.`,
            ),
          );
          return;
        }
        chunks.push(chunk);
      });

      stream.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(streamTimer);

        const data = Buffer.concat(chunks);
        let parsedBody: T | Buffer;
        try {
          parsedBody = parseSecurePayload<T>(
            data,
            responseHeaders["content-type"],
          );
        } catch (err: unknown) {
          // This is an event listener, not the executor: a throw here would be an uncaught exception.
          return reject(err);
        }

        resolve({
          statusCode,
          headers: responseHeaders,
          body: parsedBody,
          json: (): T => {
            try {
              // If body is already parsed (not a Buffer), return it as-is
              if (!(parsedBody instanceof Buffer)) {
                return parsedBody as T;
              }
              // If body is a Buffer, parse it
              if (data.length === 0) return {} as T;
              return JSON.parse(data.toString("utf-8"), secureReviver) as T;
            } catch (e: unknown) {
              throw new UltraTonParseError(
                `UltraTon: Failed to parse JSON response payload.`,
              );
            }
          },
        });
      });

      stream.on("error", (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(streamTimer);
        reject(new SecureHttpError(`UltraTon stream error: ${err.message}`));
      });

      if (body) {
        stream.write(body);
      }

      stream.end();
    });
  }
}
