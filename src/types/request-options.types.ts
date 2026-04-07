import { SecureClientSessionOptions } from "node:http2";
import { RequestOptions } from "node:https";

type NativeHttpsOptions = Pick<RequestOptions, 'method' | 'headers' | 'timeout' | 'auth' | 'signal'>

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
     * Set to true ONLY if you are building an internal API client. 
     * Default is false (Strict SSRF mitigation).
     */
    readonly permitReservedIps?: boolean;
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
    readonly permitReservedIps: boolean;
}

// HTTP2 Options

export interface UltraTonRequestOptionsHttp2 extends RequestOptions {
    readonly method?: string;
    readonly body?: Buffer | string;
    readonly headers?: Record<string, string | string[] | undefined>;
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
}
