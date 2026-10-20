import type { ReservedIpPolicy } from "../security/dns-pinner.ts";

export type { ReservedIpPolicy };

/**
 * The options of one request, the same for every method and both engines. A closed list: anything else throws a
 * `TypeError` (with a hint for the common mistakes), it is never ignored.
 */
export interface UltraTonRequestOptions {
    /**
     * Key-value pairs for HTTP headers.
     * Pseudo-headers (keys starting with ':') are rejected, and so is 'host' on HTTP/2 (it is derived from the URL).
     */
    readonly headers?: Record<string, string | string[] | undefined>;

    /**
     * A JSON payload. It is serialized with `JSON.stringify` and sent with `content-type: application/json`
     * unless a `content-type` header is already set. Cannot be combined with `body`.
     */
    readonly json?: unknown;

    /**
     * A raw payload. It is always sent with a `content-length` in bytes (never chunked). Cannot be combined with `json`.
     */
    readonly body?: string | Buffer | Uint8Array;

    /**
     * Credentials as `user:password`, sent as a Basic `authorization` header. Dropped when a redirect changes origin.
     */
    readonly auth?: string;

    /**
     * Aborts the request when the signal fires.
     */
    readonly signal?: AbortSignal;

    /**
     * The maximum size of the response body in bytes.
     * Default is 2MB.
     */
    readonly maxBodySize?: number;

    /**
     * The maximum time to wait for the socket to connect in milliseconds.
     * Default is 10000ms.
     */
    readonly socketTimeoutMs?: number;

    /**
     * The maximum time to wait for the request to complete in milliseconds.
     * Default is 30000ms.
     */
    readonly timeoutMs?: number;

    /**
     * The maximum number of redirects to follow.
     * Default is 0.
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
}

/** What the client methods hand to the engines: the caller's options plus the HTTP method they set. Not public. */
export interface InternalRequestOptions extends UltraTonRequestOptions {
    readonly method?: string;
}

/** Request options once `json` has been serialized: the body, if any, is the exact bytes that go on the wire. */
export type ResolvedRequestOptions = Omit<InternalRequestOptions, 'json' | 'body'> & { readonly body?: Buffer };

/**
 * Internal system type assigned after security fallbacks have been applied.
 * Enforces that critical execution constraints are mathematically guaranteed.
 */
export interface SecureUltraTonRequestOptions extends InternalRequestOptions {
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

    /** Headers sent with every request. A request header with the same name (any case) replaces it. */
    readonly headers?: Record<string, string | string[] | undefined>;

    /** Default `timeoutMs` for every request. See {@link UltraTonRequestOptions.timeoutMs}. */
    readonly timeoutMs?: number;

    /** Default `socketTimeoutMs` for every request. See {@link UltraTonRequestOptions.socketTimeoutMs}. */
    readonly socketTimeoutMs?: number;

    /** Default `maxBodySize` for every request. See {@link UltraTonRequestOptions.maxBodySize}. */
    readonly maxBodySize?: number;

    /** Default `maxRedirects` for every request. See {@link UltraTonRequestOptions.maxRedirects}. */
    readonly maxRedirects?: number;

    /**
     * Default `permitReservedIps` for every request. See {@link UltraTonRequestOptions.permitReservedIps}. A list is
     * copied when the client is built, so changing your array afterwards does not change the client's policy.
     */
    readonly permitReservedIps?: ReservedIpPolicy;

    /** Use HTTP/2 (TLS with ALPN `h2`, or h2c on the `http://localhost` escape hatch). Default false: HTTP/1.1. */
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
}
