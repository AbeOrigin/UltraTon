import type { ReservedIpPolicy } from "../security/dns-pinner.ts";

export type { ReservedIpPolicy };

/** A value of the `query` option: sent as its string form. */
export type QueryValue = string | number | boolean;

/**
 * The options of one request, the same for every method and both engines. A closed list: anything else throws a
 * `TypeError` (with a hint for the common mistakes), it is never ignored.
 */
export interface UltraTonRequestOptions {
    /**
     * Key-value pairs for HTTP headers, as a plain object (a `Headers` or `Map` instance throws a `TypeError`).
     * Pseudo-headers (keys starting with ':') are rejected, and so is 'host' on HTTP/2 (it is derived from the URL).
     */
    readonly headers?: Record<string, string | string[] | undefined>;

    /**
     * Query parameters appended to the URL, after any query it already has (which is kept as is). Values are encoded
     * like URLSearchParams (spaces as '+'), an array repeats its key and `undefined` is skipped. `null`, nested objects
     * and non-finite numbers throw a `TypeError`. They only ever land in the query: they cannot change the path.
     */
    readonly query?: Readonly<Record<string, QueryValue | readonly QueryValue[] | undefined>> | URLSearchParams;

    /**
     * A JSON payload. It is serialized with `JSON.stringify` and sent with `content-type: application/json`
     * unless a `content-type` header is already set, by the request or by the client's default `headers`.
     * Cannot be combined with `form` or `body`.
     */
    readonly json?: unknown;

    /**
     * Form fields, sent urlencoded (`application/x-www-form-urlencoded;charset=UTF-8`) with the same rules as `query`:
     * an array repeats its key, `undefined` is skipped, and `null` or nested objects throw a `TypeError`. The request's
     * own `content-type` header is kept; a client default one is replaced. Cannot be combined with `json` or `body`.
     */
    readonly form?: Readonly<Record<string, QueryValue | readonly QueryValue[] | undefined>> | URLSearchParams;

    /**
     * The payload as bytes, always sent with a `content-length` (never chunked). A `URLSearchParams` is sent urlencoded,
     * a `FormData` as `multipart/form-data` with its boundary, and a `Blob` (or `File`) with its `type`, if it has one, as content-type.
     * Those content-types replace a client default one; the request's own `content-type` header is kept, except with a
     * `FormData`, where it throws a `TypeError` (the boundary must match the body). Everything is read into memory
     * before sending, a large `File` included. Cannot be combined with `json` or `form`.
     */
    readonly body?: string | Buffer | Uint8Array | Blob | FormData | URLSearchParams;

    /**
     * Credentials as `user:password`, sent as a Basic `authorization` header. Dropped when a redirect changes origin.
     */
    readonly auth?: string;

    /**
     * Aborts the request when the signal fires, in any phase (before connecting, while connecting or resolving DNS,
     * waiting for the response, or mid-body). The request rejects with `signal.reason`, which is a DOMException
     * `AbortError` when `abort()` was called without a reason. A signal that is already aborted rejects without connecting.
     * Anything that is not an `AbortSignal` throws a `TypeError`.
     */
    readonly signal?: AbortSignal;

    /**
     * Decode gzip, deflate and br response bodies, and ask for them with an
     * `accept-encoding` header unless the request sets its own. `maxBodySize` then bounds the decoded bytes too, so a
     * decompression bomb stops at the limit. `false` sends no `accept-encoding` and leaves `data` as received. Default true.
     */
    readonly decompress?: boolean;

    /**
     * The maximum size of the response body in bytes: an integer from 0 to 2147483647 (anything else throws a
     * `TypeError`). Default is 2MB.
     */
    readonly maxBodySize?: number;

    /**
     * The maximum time the connection may stay idle, in milliseconds: no bytes received for that long rejects with
     * `UltraTonNetworkTimeoutError`. On HTTP/1 it is the socket's idle time; on HTTP/2 it is per stream.
     * `0` disables it. An integer from 0 to 2147483647 (anything else throws a `TypeError`). Default is 10000ms.
     */
    readonly socketTimeoutMs?: number;

    /**
     * The maximum time to wait for the request to complete in milliseconds, DNS and every redirect hop included.
     * `0` disables it. An integer from 0 to 2147483647 (anything else throws a `TypeError`). Default is 30000ms.
     */
    readonly timeoutMs?: number;

    /**
     * The maximum number of redirects to follow: an integer from 0 to 20 (anything else throws a `TypeError`).
     * Default is 0 (redirects are returned, not followed).
     */
    readonly maxRedirects?: number;

    /**
     * Allows resolution of internal/reserved IPs (like localhost or private network space).
     * `true` allows all of them: set it ONLY if you are building an internal API client.
     * An array allows just what it names: IPs (`'10.0.0.5'`), CIDRs (`'10.0.0.0/8'`) and exact,
     * case-insensitive hostnames (`'api.internal'`, no wildcards). IPv4 and IPv6 entries never cover each other:
     * an IPv6 entry (even `'::/0'`) does not cover a native IPv4 address, and an IPv6 address that embeds an IPv4
     * (IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`) is judged
     * only by that embedded IPv4 against your IPv4 entries (`'10.0.0.0/8'` allows `::ffff:10.0.0.1`). So list IPv4
     * CIDRs for IPv4 targets: an IPv6 entry written in one of those forms (`'::ffff:0:0/96'`) is inert.
     * A hostname entry allows that host to resolve to any reserved IP, so prefer IP/CIDR entries when you know the addresses.
     * `false` and `[]` allow none. Default is false (Strict SSRF mitigation).
     */
    readonly permitReservedIps?: ReservedIpPolicy;

    /**
     * Retries, off by default. A number is the most retries (an integer from 0 to 10) with the default rules; an
     * object sets the rules (see {@link UltraTonRetryOptions}). On a request it merges over the client's `retry` field
     * by field, and `retry: 0` turns retries off for that request. Never used by `client.fetch()`.
     */
    readonly retry?: number | UltraTonRetryOptions;
}

/** The HTTP methods `client.stream()` accepts. */
export type UltraTonStreamMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/**
 * When and how a request is retried. Each attempt is a full request: DNS is resolved and validated again for a new
 * connection, and every SSRF check runs again. `timeoutMs` is the budget of every attempt and wait together.
 * Retried: `UltraTonNetworkError` with code `ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `EAI_AGAIN` or `EPIPE`, the idle
 * timeout (`ERR_ULTRATON_SOCKET_TIMEOUT`) and the statuses in `statusCodes`. Never retried: policy errors
 * (`ERR_ULTRATON_RESERVED_IP`, `ERR_ULTRATON_PLAIN_HTTP`, `ERR_ULTRATON_DOWNGRADE`, ...), `TypeError`,
 * `UltraTonMemoryError`, `UltraTonRedirectError`, the absolute timeout (`ERR_ULTRATON_TIMEOUT`) and an abort.
 * On HTTP/2, a stream the server never processed (a REFUSED_STREAM reset, or above the last stream a GOAWAY
 * processed) fails with code `NGHTTP2_REFUSED_STREAM` and is retried; any other reset is not.
 * When the retries run out on a status, the last response is returned.
 */
export interface UltraTonRetryOptions {
    /** The most retries, an integer from 0 to 10. Default 2 once `retry` is an object (inherited from the client's). */
    readonly limit?: number;
    /** The methods that may be retried. Default GET, PUT, DELETE, HEAD and OPTIONS: never POST or PATCH unless listed. */
    readonly methods?: readonly UltraTonStreamMethod[];
    /** The statuses that are retried, integers from 400 to 599. Replaces the default 408, 429, 502, 503 and 504. */
    readonly statusCodes?: readonly number[];
    /**
     * The longest wait between attempts in ms, an integer from 0 to 2147483647. Default 30000. Backoff is exponential
     * with full jitter (base 300ms) up to it. A `Retry-After` (seconds or an HTTP date) is waited exactly; when it asks
     * for more than this or than what is left of `timeoutMs`, the request is not retried and that response is returned.
     */
    readonly maxDelayMs?: number;
    /**
     * Called before each wait, to log or observe. Throwing from it ends the request with that error. It cannot change
     * the retry; abort through `signal` for that.
     */
    readonly onRetry?: (info: UltraTonRetryInfo) => void;
}

/** What `onRetry` receives: the retry about to happen (1 for the first), the wait before it, and what caused it. */
export interface UltraTonRetryInfo {
    readonly attempt: number;
    readonly delayMs: number;
    /** The status of the response being retried. */
    readonly statusCode?: number;
    /** The network error being retried (an `UltraTonNetworkError`). */
    readonly error?: unknown;
}

/** The options of `client.stream()`: the request options plus the method, and a `maxBodySize` that may go past 2 GiB. */
export interface UltraTonStreamOptions extends Omit<UltraTonRequestOptions, 'maxBodySize'> {
    /** The HTTP method. Default 'GET'. */
    readonly method?: UltraTonStreamMethod;
    /**
     * The maximum size of the body in bytes, counted as it is read (decoded bytes included): an integer from 0 to
     * Number.MAX_SAFE_INTEGER. There is no "unlimited": a large download sets a large, explicit limit. Default as for
     * the other methods (the client's `maxBodySize`, else 2MB).
     */
    readonly maxBodySize?: number;
}

/** What the client methods hand to the engines: the caller's options plus the HTTP method they set. Not public. */
export interface InternalRequestOptions extends UltraTonRequestOptions {
    readonly method?: string;
}

/** Request options once `json`, `form` or `body` has been encoded: the body, if any, is the exact bytes that go on the wire. */
export type ResolvedRequestOptions = Omit<InternalRequestOptions, 'json' | 'form' | 'body'> & { readonly body?: Buffer };

/**
 * Internal system type assigned after security fallbacks have been applied.
 * Enforces that critical execution constraints are mathematically guaranteed.
 */
export interface SecureUltraTonRequestOptions extends InternalRequestOptions {
    readonly decompress: boolean;
    readonly maxBodySize: number;
    readonly socketTimeoutMs: number;
    readonly timeoutMs: number;
    readonly maxRedirects: number;
    readonly permitReservedIps: ReservedIpPolicy;
}

/** A PEM certificate, key or CA: a string or Buffer, or a list of them. */
export type TlsMaterial = string | Buffer | Array<string | Buffer>;

/** The `tls` constructor option once validated: only these keys ever reach `node:https` / `node:http2`. Not public. */
export interface TlsOptions {
    readonly ca?: TlsMaterial;
    readonly cert?: TlsMaterial;
    readonly key?: TlsMaterial;
}

/**
 * The options of `new UltraTonClient(options)`. A closed list, validated like the per-request options: an unknown key or
 * a value of the wrong type throws a `TypeError`. `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`,
 * `maxRedirects` and `permitReservedIps` are defaults: a request that sets the same option wins, key by key (headers
 * case-insensitively), and an option a request leaves `undefined` takes the client's value.
 */
export interface UltraTonClientOptions {
    /**
     * An `https:` URL (or `http://localhost`) every request path is resolved against. With it set, request URLs must be
     * relative (`'users/7'` or `'/users/7'`, both under the base path): absolute and protocol-relative URLs throw, and so
     * does any path that resolves outside the base (`'../admin'`, `'%2e%2e/admin'`). A query string or fragment is not
     * allowed in the base. Redirects are not bound to it; they follow `maxRedirects` (default 0).
     */
    readonly baseUrl?: string;

    /** Headers sent with every request, as a plain object. A request header with the same name (any case) replaces it. */
    readonly headers?: Record<string, string | string[] | undefined>;

    /** Default `timeoutMs` for every request. See {@link UltraTonRequestOptions.timeoutMs}. */
    readonly timeoutMs?: number;

    /** Default `socketTimeoutMs` for every request. See {@link UltraTonRequestOptions.socketTimeoutMs}. */
    readonly socketTimeoutMs?: number;

    /** Default `decompress` for every request. See {@link UltraTonRequestOptions.decompress}. */
    readonly decompress?: boolean;

    /** Default `maxBodySize` for every request. See {@link UltraTonRequestOptions.maxBodySize}. */
    readonly maxBodySize?: number;

    /** Default `maxRedirects` for every request. See {@link UltraTonRequestOptions.maxRedirects}. */
    readonly maxRedirects?: number;

    /**
     * Default `permitReservedIps` for every request. See {@link UltraTonRequestOptions.permitReservedIps}. A list is
     * copied when the client is built, so changing your array afterwards does not change the client's policy.
     */
    readonly permitReservedIps?: ReservedIpPolicy;

    /**
     * Default `retry` for every request. See {@link UltraTonRequestOptions.retry}. A request's own `retry` merges over
     * it field by field; the lists are copied when the client is built.
     */
    readonly retry?: number | UltraTonRetryOptions;

    /** Use HTTP/2 (TLS with ALPN `h2`, or h2c over plain http to a loopback name). Default false: HTTP/1.1. */
    readonly http2?: boolean;

    /**
     * Extra trust and client certificates: `ca` (PEM CAs to trust, e.g. a private CA, in place of the system list),
     * `cert` and `key` (a client certificate for mutual TLS). Nothing else is accepted: certificate verification can not
     * be turned off (`rejectUnauthorized`), and SNI and hostname checks are not configurable.
     */
    readonly tls?: {
        readonly ca?: TlsMaterial;
        readonly cert?: TlsMaterial;
        readonly key?: TlsMaterial;
    };

    /** The `user-agent` header sent by default. Default `ultraton/<version>`. Cannot be combined with a `user-agent` in `headers`. */
    readonly userAgent?: string;

    /**
     * An outbound proxy for `https:` targets, as a URL (`'http://egress.corp:3128'`) or {@link UltraTonProxyOptions}.
     * Each request is tunnelled with CONNECT to the IP UltraTon resolved and validated, so the proxy cannot resolve the
     * name to anything else; TLS then runs to the target through the tunnel and checks its certificate against the
     * hostname. Plain `http:` targets (loopback only) never use it. Never read from `HTTP_PROXY`/`HTTPS_PROXY`.
     */
    readonly proxy?: string | UltraTonProxyOptions;
}

/** The `proxy` client option in full. */
export interface UltraTonProxyOptions {
    /** `http:` or `https:` (TLS to the proxy itself), origin only: no credentials, path, query or fragment. */
    readonly url: string;
    /** Credentials as `user:password`, sent as Basic `proxy-authorization` on the CONNECT only, never to a target. */
    readonly auth?: string;
    /** PEM CAs that an `https:` proxy's certificate is checked against, in place of the system list. Never trusted for targets. */
    readonly ca?: TlsMaterial;
    /**
     * Who resolves the target's name. `'local'` (default): UltraTon resolves and validates it and sends the IP in the
     * CONNECT. `'proxy'`: the name is sent and the proxy resolves it, for proxies that filter by name (Squid ACLs,
     * Smokescreen); DNS pinning is then up to the proxy, and only IP literals are still judged by UltraTon.
     */
    readonly resolve?: 'local' | 'proxy';
}
