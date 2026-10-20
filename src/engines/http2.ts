import { Buffer } from "node:buffer";
import { constants } from "node:http2";
import type {
  ClientHttp2Session,
  ClientHttp2Stream,
  IncomingHttpHeaders,
  OutgoingHttpHeaders,
} from "node:http2";
import type { UltraTonResponse } from "../types/request-response.ts";
import { heldStreams, holdSession } from "./http2-session-manager.ts";
import type { Http2SessionManager } from "./http2-session-manager.ts";
import type {
  ResolvedRequestOptions,
  SecureUltraTonRequestOptions,
} from "../types/request-options.types.ts";
import {
  SecureHttpError,
  UltraTonMemoryError,
  UltraTonNetworkTimeoutError,
  UltraTonRedirectError,
  toNetworkError,
} from "../errors.ts";
import { HTTP_CODES_REDIRECTS } from "../constants.ts";
import {
  createResponse,
  declaredBodyLength,
  incompleteResponse,
} from "../helpers/response.ts";
import {
  basicAuthorization,
  buildSafeRequestOptions,
} from "../helpers/request-options.ts";
import { parseSafeUrl } from "../helpers/url-parser.ts";

/** Request bodies go out in pieces of this size so that the idle timer can tell progress from a stall. */
const BODY_CHUNK_BYTES = 64 * 1024;

const clientClosed = () => new SecureHttpError("UltraTon: Client is closed.");

/** Connection-specific request headers, meaningless (and refused by node) on HTTP/2. `te` is handled apart. */
const HOP_BY_HOP_HEADERS = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/** The HTTP/2 engine behind `UltraTonClient({ http2: true })`. Not public: the client validates and merges the options. */
export class Http2Engine {
  readonly #sessionManager: Http2SessionManager;
  #closed = false;

  /**
   * @param sessionManager - The client's own session pool (built with its `tls`), or the one injected by tests
   *   through `kSessionManager`. Never shared between clients.
   */
  constructor(sessionManager: Http2SessionManager) {
    this.#sessionManager = sessionManager;
  }

  /** Closes every pooled session (in-flight streams on them fail) and refuses any later request. */
  public close(): void {
    this.#closed = true;
    this.#sessionManager.closeAll();
  }

  /** A failure caused by close() reports the closed client, not the reset or cancel it caused. */
  #orClosed(err: unknown): unknown {
    return this.#closed ? clientClosed() : err;
  }

  /**
   * @param options - Already validated, serialized (`json`) and merged with the client defaults by `UltraTonClient`.
   */
  public async request<T = unknown>(
    targetUrl: string,
    options: ResolvedRequestOptions,
  ): Promise<UltraTonResponse<T>> {
    // One clock for the whole redirect chain: timeoutMs is a budget shared by every hop.
    const startTime = Date.now();
    let currentUrl = targetUrl;
    // Validate before touching the network: invalid input must fail without connecting.
    let currentOptions: ResolvedRequestOptions = options;
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
      if (this.#closed) throw clientClosed();
      // Before anything is resolved or opened; throws the signal's reason (an AbortError when it had none).
      reqOpts.signal?.throwIfAborted();
      const parsedUrl = parseSafeUrl(currentUrl);
      const origin = parsedUrl.origin;
      const path = parsedUrl.pathname + parsedUrl.search;

      // DNS and the pool wait run under the same budget as the stream: a nameserver that never answers must not
      // outlive timeoutMs. The budget left here is what bounds session acquisition; it is measured again below.
      let session: ClientHttp2Session;
      try {
        session = await this.#acquireSession(
          origin,
          reqOpts,
          this.#remainingBudget(reqOpts.timeoutMs, startTime),
        );
      } catch (err: unknown) {
        throw this.#orClosed(err);
      }
      // close() ran while DNS or the connect was pending: the session just pooled would outlive it.
      if (this.#closed) {
        this.#sessionManager.closeAll();
        throw clientClosed();
      }

      // reqOpts.headers is already lowercased and CRLF/pseudo-header checked.
      const safeHeaders: Record<string, string | string[] | undefined> = {
        ...reqOpts.headers,
      };

      // HTTP/2 has no connection-specific headers (RFC 9113 8.2.2) and node refuses to send them, which would fail
      // the request with a misleading network error: drop them, on every request. `te` may only be `trailers`.
      for (const name of HOP_BY_HOP_HEADERS) delete safeHeaders[name];
      if (safeHeaders["te"] !== "trailers") delete safeHeaders["te"];

      // Always present with a body, and the real byte length wins over anything the caller put in the header.
      // Without a body a caller content-length would promise bytes that never come: drop it.
      if (currentOptions.body !== undefined) {
        safeHeaders["content-length"] = String(currentOptions.body.length);
      } else {
        delete safeHeaders["content-length"];
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
        reqOpts.socketTimeoutMs,
        reqOpts.signal,
        reqOpts.maxRedirects > 0,
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
              { code: "ERR_ULTRATON_DOWNGRADE" },
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
    const callerSignal = reqOpts.signal;
    if (remainingMs <= 0) {
      return this.#sessionManager.getSession(
        origin,
        undefined,
        reqOpts.permitReservedIps,
        callerSignal,
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
        // Whichever fires first: the budget or the caller. The rejection carries that signal's own reason.
        callerSignal
          ? AbortSignal.any([controller.signal, callerSignal])
          : controller.signal,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /** Runs the request options through the same firewall as the HTTP/1 engine, plus the HTTP/2-only `host` rule. */
  #buildRequestOptions(
    options: ResolvedRequestOptions,
  ): SecureUltraTonRequestOptions {
    const safe = buildSafeRequestOptions(options);
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
    socketTimeoutMs: number,
    signal: AbortSignal | undefined,
    followRedirects: boolean,
  ): Promise<UltraTonResponse<T>> {
    return new Promise((resolve, reject) => {
      // The caller may have aborted while the session was being acquired: do not open a stream for nobody.
      if (signal?.aborted) return reject(signal.reason);

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
        return reject(this.#orClosed(toNetworkError(err)));
      }

      // Holds the session (and so the process) for as long as the stream lives; 'close' always fires, so it always lets go.
      const release = holdSession(session);
      stream.once("close", release);

      // Gives the stream up (abort or timeout). A stream still waiting for the session to connect cannot close until
      // it does, which could be the OS connect timeout away: release the hold now so the process may exit, and drop
      // the session itself when nothing else uses it (it leaves the pool through its own 'close' handler).
      const abandon = () => {
        stream.close(constants.NGHTTP2_CANCEL);
        release();
        if (stream.pending && heldStreams(session) === 0 && !session.destroyed) session.destroy();
      };

      // remainingMs is what is left of the shared budget; timeoutMs is the configured total, for the message.
      const streamTimer =
        remainingMs > 0
          ? setTimeout(() => {
            if (settled) return;
            settled = true;
            cleanup();
            abandon();
            reject(
              new UltraTonNetworkTimeoutError(
                `UltraTon: Absolute execution time of ${timeoutMs}ms exceeded.`,
              ),
            );
          }, remainingMs)
          : undefined;

      // socketTimeoutMs: no bytes received for that long closes the stream (0 disables it). Reset by every chunk.
      let idleTimer: NodeJS.Timeout | undefined;
      const armIdleTimer = () => {
        if (socketTimeoutMs <= 0) return;
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanup();
          abandon();
          reject(
            new UltraTonNetworkTimeoutError(
              `UltraTon: Socket completely idle for ${socketTimeoutMs}ms.`,
            ),
          );
        }, socketTimeoutMs);
      };

      const onAbort = () => {
        if (settled) return;
        settled = true;
        cleanup();
        abandon();
        reject(signal!.reason);
      };

      // Stops every timer and listener this stream armed; runs on every path that settles the promise.
      const cleanup = () => {
        clearTimeout(streamTimer);
        clearTimeout(idleTimer);
        signal?.removeEventListener("abort", onAbort);
      };

      signal?.addEventListener("abort", onAbort, { once: true });
      armIdleTimer();

      stream.on("response", (headers) => {
        if (settled) return;
        armIdleTimer();
        statusCode = Number(headers[":status"]);
        responseHeaders = headers;

        // A redirect that will be followed: its body is never read (a large one must not hit maxBodySize, nor be
        // buffered for nothing). End the stream at once, cleanly if the server sent no body, else cancelled.
        const location = headers.location;
        if (followRedirects && HTTP_CODES_REDIRECTS.has(statusCode) && typeof location === "string" && location) {
          settled = true;
          cleanup();
          if (!stream.closed && !stream.destroyed) {
            stream.close(stream.endAfterHeaders ? constants.NGHTTP2_NO_ERROR : constants.NGHTTP2_CANCEL);
          }
          return resolve(createResponse<T>(statusCode, responseHeaders, Buffer.alloc(0)));
        }

        if (pseudoHeaders[":method"] === "HEAD") {
          settled = true;
          cleanup();
          stream.close();

          return resolve(createResponse<T>(statusCode, responseHeaders, Buffer.alloc(0)));
        }
      });

      let totalBytes = 0;
      stream.on("data", (chunk: Buffer) => {
        if (settled) return;
        armIdleTimer();
        totalBytes += chunk.length;
        if (totalBytes > maxBodySize) {
          settled = true;
          cleanup();
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

      // A response that ended without a status, on a stream that was reset or aborted, or with fewer or more bytes than
      // its content-length, is a lost response, not a successful one: resolving it would hand the caller a statusless
      // or truncated body.
      const lostResponse = incompleteResponse;
      const declared = () =>
        statusCode === undefined || Number.isNaN(statusCode)
          ? undefined
          : declaredBodyLength(String(pseudoHeaders[":method"]), statusCode, responseHeaders);

      stream.on("end", () => {
        if (settled) return;
        settled = true;
        cleanup();

        // The server finished its response while the request body is still being written (writeFrom stops once
        // settled): the stream is half-open and would never close, holding the session (and the process) for good.
        // A complete response ends it cleanly; a failed one cancels.
        const stopUpload = (code: number) => {
          if (!stream.writableEnded && !stream.closed && !stream.destroyed) stream.close(code);
        };
        const fail = (err: unknown) => {
          stopUpload(constants.NGHTTP2_CANCEL);
          reject(err);
        };

        // close() ends a stream whose body is still arriving with a clean NO_ERROR: that is not a complete response.
        if (this.#closed) return fail(clientClosed());

        const expected = declared();
        if (expected !== undefined && totalBytes !== expected) {
          return fail(lostResponse());
        }

        if (
          stream.aborted ||
          (stream.rstCode !== undefined && stream.rstCode !== constants.NGHTTP2_NO_ERROR) ||
          statusCode === undefined ||
          Number.isNaN(statusCode)
        ) {
          return fail(this.#orClosed(lostResponse()));
        }

        stopUpload(constants.NGHTTP2_NO_ERROR);
        resolve(createResponse<T>(statusCode, responseHeaders, Buffer.concat(chunks)));
      });

      stream.on("error", (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        // A session that dies (e.g. ECONNREFUSED while connecting) cancels its streams with a generic
        // ERR_HTTP2_STREAM_CANCEL whose cause is the real error: report that one.
        const { code, cause } = err as NodeJS.ErrnoException;
        // A body cut short of its content-length (nghttp2 resets such a stream itself) is the same incomplete response
        // HTTP/1 reports; the original error stays reachable as `cause`.
        const expected = declared();
        if (expected !== undefined && totalBytes < expected) {
          return reject(this.#orClosed(lostResponse(err)));
        }
        // Node's socket/TLS messages embed the resolved IP and port: map them to a code-only error.
        reject(this.#orClosed(toNetworkError(code === "ERR_HTTP2_STREAM_CANCEL" && cause ? cause : err)));
      });

      // Closed before a clean end and without an error event (e.g. the socket was destroyed): the response is lost.
      stream.on("close", () => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(this.#orClosed(lostResponse()));
      });

      // Written one chunk at a time, each acknowledged write counting as activity: a large upload that is slower than
      // socketTimeoutMs but keeps moving is not idle. Node acknowledges a write once the data got through flow control
      // (queued writes are acknowledged all at once at the end, which would hide the progress), so the next chunk waits
      // for it. A stalled upload (the server stopped reading) stops acknowledging and times out.
      const writeFrom = (offset: number): void => {
        if (body === undefined || offset >= body.length) {
          stream.end();
          return;
        }
        stream.write(body.subarray(offset, offset + BODY_CHUNK_BYTES), (err) => {
          if (settled || err) return;
          armIdleTimer();
          writeFrom(offset + BODY_CHUNK_BYTES);
        });
      };
      writeFrom(0);
    });
  }
}
