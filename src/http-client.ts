import type * as http from 'node:http';
import type * as https from 'node:https';
import { SecureHttpError } from './errors.ts';
import { VERSION } from './constants.ts';
import { Http1Engine } from './engines/http1.ts';
import { Http2Engine } from './engines/http2.ts';
import { Http2SessionManager } from './engines/http2-session-manager.ts';
import { mergeClientDefaults, resolveClientOptions, resolveRequestBody, withMethod } from './helpers/request-options.ts';
import type { ClientDefaults } from './helpers/request-options.ts';
import { kSessionManager, kTransport } from './internal.ts';
import type { UltraTonClientOptions, UltraTonRequestOptions } from './types/request-options.types.ts';
import type { UltraTonResponse } from './types/request-response.ts';

/** The constructor options plus the internal test seams, which are symbols and never part of the public types. */
interface InternalClientOptions extends UltraTonClientOptions {
    readonly [kTransport]?: typeof https.request | typeof http.request;
    readonly [kSessionManager]?: Http2SessionManager;
}

const MUST_BE_RELATIVE = 'UltraTon: With baseUrl set, request paths must be relative.';
const ESCAPES_BASE = 'UltraTon: Request path escapes baseUrl.';

/**
 * Resolves a request path against the client's `baseUrl` so that it can never land outside it.
 * The input is judged as the WHATWG parser will read it (leading/trailing C0 controls and spaces ignored, tabs and
 * newlines removed anywhere), and the final check is on the resolved href, not on the input: percent-encoded dots
 * (`%2e%2e`) and backslashes are dot segments and slashes to the parser, whatever the input looks like.
 * @throws {TypeError} If the path is absolute or protocol-relative, or resolves outside the base path.
 */
function resolveAgainstBase(path: unknown, base: URL): string {
    if (typeof path !== 'string') {
        throw new TypeError(`UltraTon: Expected the request URL to be a string, received ${path === null ? 'null' : typeof path}.`);
    }
    const parsed = path.replace(/^[\u0000- ]+|[\u0000- ]+$/g, '').replace(/[\t\n\r]/g, '');
    // A scheme makes it absolute (https:, javascript:, ...); two leading slashes in any mix with backslashes make it
    // protocol-relative, since special schemes read '\' as '/'.
    if (URL.canParse(parsed) || /^[\\/]{2}/.test(parsed)) throw new TypeError(MUST_BE_RELATIVE);
    // One leading slash means "from the base", not "from the origin root".
    const resolved = new URL(parsed.replace(/^[\\/]/, ''), base);
    // base.href ends with '/', so this also rules out another host, port or scheme and sibling paths ('/v1-admin').
    if (!resolved.href.startsWith(base.href)) throw new TypeError(ESCAPES_BASE);
    return resolved.href;
}

/**
 * The UltraTon client. Configure it once; every request is validated, merged with the client's defaults and sent over
 * HTTP/1.1 or, with `http2: true`, HTTP/2. Each client owns its connection pools: two clients never share a socket or a
 * session, so a permissive `permitReservedIps` or a custom `tls` never reaches another client. Call `close()` when done.
 */
export class UltraTonClient {
    readonly #engine: Http1Engine | Http2Engine;
    readonly #defaults: ClientDefaults;
    readonly #baseUrl?: URL;
    #closed = false;

    /**
     * @param options - Defaults for every request plus `baseUrl`, `http2`, `tls` and `userAgent`. Validated now: an
     *   unknown key, a value of the wrong type or a `tls` key other than `ca`/`cert`/`key` throws a `TypeError`.
     */
    constructor(options?: UltraTonClientOptions) {
        const resolved = resolveClientOptions(options, `ultraton/${VERSION}`);
        this.#defaults = resolved.defaults;
        this.#baseUrl = resolved.baseUrl;

        // The seams are read only once the options validated as an object.
        const internal = (options ?? {}) as InternalClientOptions;
        this.#engine = resolved.http2
            ? new Http2Engine(internal[kSessionManager] ?? new Http2SessionManager(resolved.tls))
            : new Http1Engine(resolved.tls, internal[kTransport]);
    }

    public async get<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('GET', url, options);
    }

    public async post<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('POST', url, options);
    }

    public async put<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PUT', url, options);
    }

    public async patch<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PATCH', url, options);
    }

    public async delete<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('DELETE', url, options);
    }

    public async head<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('HEAD', url, options);
    }

    public async options<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('OPTIONS', url, options);
    }

    /**
     * Destroys every pooled socket and session of this client; requests still in flight on them fail. Any later
     * request rejects with `SecureHttpError('UltraTon: Client is closed.')`. Calling it again does nothing.
     */
    public async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        this.#engine.close();
    }

    async #request<T>(method: string, url: string, options: unknown): Promise<UltraTonResponse<T>> {
        if (this.#closed) throw new SecureHttpError('UltraTon: Client is closed.');
        const target = this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url;
        // The caller's own options are validated (unknown keys, json/body, body type) and `json` serialized before any
        // client default is merged in.
        const own = resolveRequestBody(withMethod(method, options));
        return this.#engine.request<T>(target, mergeClientDefaults(own, this.#defaults));
    }
}
