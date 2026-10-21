import type { IncomingHttpHeaders } from 'node:http';

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
     * Parses `data` as JSON on every call, independent of the content-type. Keys named `__proto__`, `constructor`
     * and `prototype` are stripped at every depth. An empty body gives `{}`.
     * @throws UltraTonParseError (with the original SyntaxError as `cause`) if the payload is not valid JSON.
     */
    json<R = T>(): R;

    /** Decodes `data` as UTF-8. */
    text(): string;
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
}
