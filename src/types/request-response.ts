import type { IncomingHttpHeaders } from 'node:http';
import type { UltraTonTimings } from '../helpers/diagnostics.ts';

/** A complete response, whatever its status code. `T` is the default type of `json()`. */
export interface UltraTonResponse<T = unknown> {
    /**
     * The HTTP status code of the response (e.g., 200, 404, 500). Always a number: a connection that fails
     * before a response arrives rejects instead of resolving. Non-2xx responses resolve.
     */
    readonly statusCode: number;
    /** True for status codes 200-299. */
    readonly ok: boolean;
    /**
     * The raw HTTP headers returned by the server, as Node's IncomingHttpHeaders.
     * HTTP/2 pseudo-headers (keys starting with ':') are not included.
     */
    readonly headers: IncomingHttpHeaders;
    /** The final URL, after any redirect that was followed. */
    readonly url: string;
    /** True when at least one redirect was followed to get here. */
    readonly redirected: boolean;
    /** The raw response payload. Never parsed automatically; empty for HEAD and bodiless responses. */
    readonly data: Buffer;
    /**
     * Where the time of this call went, phase by phase on the hop that got the response, and `totalMs` until the body
     * was read (every redirect and retry included). Only with the `timings` option; `undefined` otherwise.
     */
    readonly timings?: UltraTonTimings;

    /**
     * Parses `data` as JSON on every call, independent of the content-type. Keys named `__proto__`, `constructor`
     * and `prototype` are stripped at every depth. An empty body gives `{}`.
     * @throws UltraTonParseError (with the original SyntaxError as `cause`) if the payload is not valid JSON.
     */
    json<R = T>(): R;

    /** Decodes `data` as UTF-8. A leading byte order mark is skipped, as `fetch` does; `data` keeps it. */
    text(): string;
    /**
     * The response itself when `ok`; otherwise throws `UltraTonHttpError` (`ERR_ULTRATON_HTTP_STATUS`, with
     * `statusCode` and the response), so `(await client.get(url)).assertOk().json()` reads like a fetch that throws.
     * A redirect that was not followed is not `ok` either.
     */
    assertOk(): UltraTonResponse<T>;
}

/** A response whose body is read as a stream: what `client.stream()` resolves with once the headers arrive. */
export interface UltraTonStreamResponse {
    /** The HTTP status code. Non-2xx responses resolve too. */
    readonly statusCode: number;
    /** True for status codes 200-299. */
    readonly ok: boolean;
    /** The response headers as received (no HTTP/2 pseudo-headers). */
    readonly headers: IncomingHttpHeaders;
    /** The final URL, after any redirect that was followed. */
    readonly url: string;
    /** True when at least one redirect was followed to get here. */
    readonly redirected: boolean;
    /**
     * The body, decoded when `decompress` is on. Read it to the end or `cancel()` it: until then it holds its
     * connection (and keeps the process alive). It fails, rather than ending, when the body is cut short, too large,
     * corrupt, idle past `socketTimeoutMs` while being read, aborted, or when the client is closed.
     */
    readonly body: ReadableStream<Uint8Array>;
    /**
     * As on {@link UltraTonResponse.timings}, with `totalMs` until the headers arrived (the body is read later, by you).
     * Only with the `timings` option.
     */
    readonly timings?: UltraTonTimings;
    /**
     * The response itself when `ok`; otherwise cancels `body` (so the connection is not held by a body nobody reads)
     * and throws `UltraTonHttpError` (`ERR_ULTRATON_HTTP_STATUS`). A redirect that was not followed is not `ok` either.
     */
    assertOk(): UltraTonStreamResponse;
}

/** One address a host resolved to, as the client's policy judges it. See {@link UltraTonExplanation}. */
export interface UltraTonExplainedAddress {
    /** The IP address, as the resolver returned it (or the literal in the URL). */
    readonly address: string;
    /** 4 or 6. */
    readonly family: 4 | 6;
    /** Whether a request may connect to it under the client's (or the call's) `permitReservedIps`. */
    readonly allowed: boolean;
}

/**
 * What a request to a URL would do before connecting: the result of `UltraTonClient.explain()`. For the operator who
 * configures the policy: it names resolved addresses, so never return it to whoever supplied the URL.
 */
export interface UltraTonExplanation {
    /** The URL as the request would send it (`baseUrl` applied, normalized). Absent when the URL itself is rejected. */
    readonly href?: string;
    /** `'allowed'`: a request would connect. `'blocked'`: it would reject before connecting, with `code` and `reason`. */
    readonly verdict: 'allowed' | 'blocked';
    /** The `code` of the error the request would reject with: an UltraTon code, or a resolver's such as `ENOTFOUND`. */
    readonly code?: string;
    /** The message the request would reject with, or a note on what was not checked here. */
    readonly reason?: string;
    /** The addresses the host resolves to (an IP literal is listed as itself), each with the policy's judgement; empty when nothing was resolved. */
    readonly addresses: readonly UltraTonExplainedAddress[];
}
