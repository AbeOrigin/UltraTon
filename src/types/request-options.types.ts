import { SecureClientSessionOptions } from "node:http2";
import { RequestOptions } from "node:https";
import type { ReservedIpPolicy } from "../security/dns-pinner.ts";

export type { ReservedIpPolicy };

type NativeHttpsOptions = Pick<RequestOptions, 'method' | 'headers' | 'auth' | 'signal'>

export interface UltraTonRequestOptions extends NativeHttpsOptions {
    /** 
     * The HTTP Method (e.g., 'GET', 'POST', 'PUT', 'DELETE'). 
     * Default should be 'GET' if not provided.
     */
    readonly method?: string;

    /** 
     * Key-value pairs for HTTP headers. 
     */
    readonly headers?: Record<string, string | string[] | undefined>;

    /** 
     * The payload to send for POST/PUT/PATCH requests.
     * We accept a Buffer or a string.
     */
    readonly body?: Buffer | string;

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
     * case-insensitive hostnames (`'api.internal'`, no wildcards). A hostname entry allows that host to
     * resolve to any reserved IP, so prefer IP/CIDR entries when you know the addresses.
     * `false` and `[]` allow none. Default is false (Strict SSRF mitigation).
     */
    readonly permitReservedIps?: ReservedIpPolicy;
}

/**
 * Internal system type assigned after security fallbacks have been applied.
 * Enforces that critical execution constraints are mathematically guaranteed.
 */
export interface SecureUltraTonRequestOptions extends UltraTonRequestOptions {
    readonly maxBodySize: number;
    readonly socketTimeoutMs: number;
    readonly timeoutMs: number;
    readonly maxRedirects: number;
    readonly permitReservedIps: ReservedIpPolicy;
}

// HTTP2 Options

/**
 * Deliberately a closed list: it does NOT extend node:https `RequestOptions`,
 * which would advertise ~40 options (agent, auth, rejectUnauthorized, ...) that
 * the HTTP/2 client ignores. Anything not listed here is dropped by the firewall.
 */
export interface UltraTonRequestOptionsHttp2 {
    readonly method?: string;
    readonly body?: Buffer | string;
    /** Pseudo-headers (keys starting with ':') and 'host' (derived from the URL) are rejected. */
    readonly headers?: Record<string, string | string[] | undefined>;
    readonly maxRedirects?: number;
    readonly timeoutMs?: number;
    readonly maxBodySize?: number;
    /** Same SSRF opt-out (boolean or allowlist) as the HTTP/1 client. Default is false. */
    readonly permitReservedIps?: ReservedIpPolicy;
}



export interface UltraTonOptionsHttp2 {
    /**
     * If true, the session will be isolated to the current request.
     * Default is false.
     */
    isolatePool?: boolean;

    /**
     * TLS Settings for the session.
     */
    tlsSettings?: SecureClientSessionOptions;

    /**
     * The maximum number of redirects to follow.
     * Default is 0.
     */
    maxRedirects?: number;

    /**
     * The absolute time budget for the whole request in milliseconds, shared by every
     * redirect hop (it is not reset per hop). DNS resolution and pool wait are charged
     * before each hop starts; the TCP/TLS connect and the stream itself are bounded by
     * what remains of the budget.
     * Default is 30000ms.
     */
    timeoutMs?: number;

    /**
     * The maximum size of any response body in bytes.
     * Default is 2MB (2,097,152 bytes).
     */
    maxBodySize?: number;

    /**
     * Allows resolution of internal/reserved IPs (like localhost or private network space).
     * `true` allows all of them: set it ONLY if you are building an internal API client.
     * An array allows just what it names: IPs, CIDRs and exact, case-insensitive hostnames (no wildcards).
     * `false` and `[]` allow none. Default is false (Strict SSRF mitigation).
     */
    permitReservedIps?: ReservedIpPolicy;
}
