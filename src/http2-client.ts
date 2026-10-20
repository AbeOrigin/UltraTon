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
  InternalRequestOptions,
  ResolvedRequestOptions,
  SecureUltraTonRequestOptions,
  UltraTonOptionsHttp2,
  UltraTonRequestOptionsHttp2,
} from "./types/request-options.types.ts";
import {
  SecureHttpError,
  UltraTonMemoryError,
  UltraTonNetworkError,
  UltraTonNetworkTimeoutError,
  UltraTonRedirectError,
  toNetworkError,
} from "./errors.ts";
import { HTTP_CODES_REDIRECTS } from "./constants.ts";
import { createResponse } from "./helpers/response.ts";
import {
  basicAuthorization,
  buildSafeRequestOptions,
  resolveRequestBody,
  withMethod,
} from "./helpers/request-options.ts";
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
    return this._request<T>(url, withMethod("GET", options));
  }

  public async post<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("POST", options));
  }

  public async put<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("PUT", options));
  }

  public async patch<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("PATCH", options));
  }

  public async delete<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("DELETE", options));
  }

  public async head<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("HEAD", options));
  }

  public async options<T = unknown>(
    url: string,
    options?: UltraTonRequestOptionsHttp2,
  ): Promise<UltraTonResponse<T>> {
    return this._request<T>(url, withMethod("OPTIONS", options));
  }

  private async _request<T = unknown>(
    targetUrl: string,
    options: InternalRequestOptions,
  ): Promise<UltraTonResponse<T>> {
    // One clock for the whole redirect chain: timeoutMs is a budget shared by every hop.
    const startTime = Date.now();
    let currentUrl = targetUrl;
    // Validate before touching the network: invalid input must fail without connecting. The caller's own options are
    // checked (unknown keys, json/body, body type) and `json` is serialized before any client-wide default is merged in.
    let currentOptions: ResolvedRequestOptions = resolveRequestBody(options);
    let redirectCount = 0;
    let reqOpts = this.#buildRequestOptions(currentOptions);

    // `auth` has no HTTP/2 equivalent of node:http's option, so it becomes a Basic authorization header like there (an
    // explicit authorization header wins). Moving it into the headers is what lets a cross-origin redirect strip it.
    if (reqOpts.auth) {
      const headers = { ...reqOpts.headers };
      headers["authorization"] ??= basicAuthorization(reqOpts.auth);
      currentOptions = { ...currentOptions, headers, auth: undefined };
      reqOpts = this.#buildRequestOptions(currentOptions);
    }

    while (true) {
      const parsedUrl = parseSafeUrl(currentUrl);
      const origin = parsedUrl.origin;
      const path = parsedUrl.pathname + parsedUrl.search;

      // DNS and the pool wait run under the same budget as the stream: a nameserver that never answers must not
      // outlive timeoutMs. The budget left here is what bounds session acquisition; it is measured again below.
      const session = await this.#acquireSession(
        origin,
        reqOpts,
        this.#remainingBudget(reqOpts.timeoutMs, startTime),
      );

      // reqOpts.headers is already lowercased and CRLF/pseudo-header checked.
      const safeHeaders: Record<string, string | string[] | undefined> = {
        ...reqOpts.headers,
      };

      // Always present with a body, and the real byte length wins over anything the caller put in the header.
      // HTTP/2 does its own framing: a caller transfer-encoding is a connection-specific header node rejects.
      if (currentOptions.body !== undefined) {
        safeHeaders["content-length"] = String(currentOptions.body.length);
        delete safeHeaders["transfer-encoding"];
      }

      const method = (reqOpts.method || "GET").toUpperCase();

      const pseudoHeaders: OutgoingHttpHeaders = {
        ":method": method,
        ":path": path,
        ":authority": parsedUrl.host,
        ...safeHeaders,
      };

      // Measured again after getSession, so DNS resolution and pool wait are already charged to the budget.
      // The TCP/TLS connect runs inside the stream and is bounded by the same remaining budget.
      const remainingMs = this.#remainingBudget(reqOpts.timeoutMs, startTime);

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

          // A response fetched over TLS must never steer the request onto plaintext (e.g. the http loopback escape hatch).
          if (parsedUrl.protocol === "https:" && nextUrl.protocol === "http:") {
            throw new SecureHttpError(
              "UltraTon: Redirect from https to http is not allowed.",
            );
          }

          // sanitizeHeaders already lowercased every key
          const nextHeaders = { ...reqOpts.headers } as Record<
            string,
            string | string[] | undefined
          >;

          if (parsedUrl.origin !== nextUrl.origin) {
            delete nextHeaders["authorization"];
            delete nextHeaders["cookie"];
            delete nextHeaders["proxy-authorization"];
            delete nextHeaders["host"];
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
   * What is left of the budget `timeoutMs` shared by every hop and step of a request, or `timeoutMs` itself
   * when it is not positive (0 means no timeout). A spent budget must throw here: a non-positive value
   * would silently disable the timer it is passed to.
   */
  #remainingBudget(timeoutMs: number, startTime: number): number {
    if (timeoutMs <= 0) return timeoutMs;
    const remainingMs = timeoutMs - (Date.now() - startTime);
    if (remainingMs <= 0) {
      throw new UltraTonNetworkTimeoutError(
        `UltraTon: Absolute execution time of ${timeoutMs}ms exceeded.`,
      );
    }
    return remainingMs;
  }

  /**
   * Gets a session, giving up with the same error as the stream timer once `remainingMs` is spent.
   * The timer lives only as long as this call and is cleared on every path.
   */
  async #acquireSession(
    origin: string,
    reqOpts: SecureUltraTonRequestOptions,
    remainingMs: number,
  ): Promise<ClientHttp2Session> {
    if (remainingMs <= 0) {
      return this.#sessionManager.getSession(
        origin,
        undefined,
        reqOpts.permitReservedIps,
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort(
        new UltraTonNetworkTimeoutError(
          `UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`,
        ),
      );
    }, remainingMs);
    try {
      return await this.#sessionManager.getSession(
        origin,
        undefined,
        reqOpts.permitReservedIps,
        controller.signal,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Runs the per-request options through the same firewall as the HTTP/1 client.
   * A per-request value wins over the client-wide one; an unset one (undefined)
   * falls back to the client-wide value.
   */
  #buildRequestOptions(
    options: ResolvedRequestOptions,
  ): SecureUltraTonRequestOptions {
    const g = this.#globalOptions;
    const safe = buildSafeRequestOptions({
      ...options,
      maxRedirects: options.maxRedirects ?? g.maxRedirects,
      timeoutMs: options.timeoutMs ?? g.timeoutMs,
      maxBodySize: options.maxBodySize ?? g.maxBodySize,
      permitReservedIps: options.permitReservedIps ?? g.permitReservedIps,
    });
    // RFC 9113 8.3.1: a host header must not differ from :authority, which comes from the URL.
    if (safe.headers && Object.hasOwn(safe.headers, "host")) {
      throw new TypeError(
        "UltraTon: The 'host' header cannot be set on HTTP/2 requests; it is derived from the URL.",
      );
    }
    return safe;
  }

  #executeStream<T = unknown>(
    session: ClientHttp2Session,
    pseudoHeaders: OutgoingHttpHeaders,
    body: Buffer | undefined,
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
        // node ends the stream by itself for GET, HEAD and DELETE: keep it open when there is a body to write.
        stream = session.request(
          pseudoHeaders,
          body && body.length > 0 ? { endStream: false } : undefined,
        );
      } catch (err: unknown) {
        return reject(toNetworkError(err));
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

          return resolve(createResponse<T>(statusCode, responseHeaders, Buffer.alloc(0)));
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

      // A response that ended without a status, or on a stream that was reset or aborted, is a lost response, not a
      // successful one: resolving it would hand the caller a statusless or truncated body.
      const lostResponse = (cause?: unknown) =>
        new UltraTonNetworkError("UltraTon: Connection failed (ECONNRESET).", {
          code: "ECONNRESET",
          cause,
        });

      stream.on("end", () => {
        if (settled) return;
        settled = true;
        clearTimeout(streamTimer);

        if (
          stream.aborted ||
          (stream.rstCode !== undefined && stream.rstCode !== constants.NGHTTP2_NO_ERROR) ||
          statusCode === undefined ||
          Number.isNaN(statusCode)
        ) {
          return reject(lostResponse());
        }

        resolve(createResponse<T>(statusCode, responseHeaders, Buffer.concat(chunks)));
      });

      stream.on("error", (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(streamTimer);
        // A session that dies (e.g. ECONNREFUSED while connecting) cancels its streams with a generic
        // ERR_HTTP2_STREAM_CANCEL whose cause is the real error: report that one.
        const { code, cause } = err as NodeJS.ErrnoException;
        // Node's socket/TLS messages embed the resolved IP and port: map them to a code-only error.
        reject(toNetworkError(code === "ERR_HTTP2_STREAM_CANCEL" && cause ? cause : err));
      });

      // Closed before a clean end and without an error event (e.g. the socket was destroyed): the response is lost.
      stream.on("close", () => {
        if (settled) return;
        settled = true;
        clearTimeout(streamTimer);
        reject(lostResponse());
      });

      if (body && body.length > 0) {
        stream.write(body);
      }

      stream.end();
    });
  }
}
