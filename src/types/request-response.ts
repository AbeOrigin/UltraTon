import type { IncomingHttpHeaders } from 'node:http';

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
