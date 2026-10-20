import type * as http from 'node:http';
import type * as https from 'node:https';
import { SecureHttpError } from './errors.ts';
import { VERSION } from './constants.ts';
import { Http1Engine } from './engines/http1.ts';
import { Http2Engine } from './engines/http2.ts';
import { Http2SessionManager } from './engines/http2-session-manager.ts';
import { mergeClientDefaults, resolveClientOptions, resolveRequestBody, retryOption, splitStreamOptions, withAcceptEncoding, withBodyContentType, withJsonContentType, withMethod, withQuery } from './helpers/request-options.ts';
import type { ClientDefaults } from './helpers/request-options.ts';
import { kSessionManager, kTransport } from './internal.ts';
import { fetchWith } from './helpers/fetch.ts';
import { resolveRetry, withRetry } from './helpers/retry.ts';
import type { UltraTonClientOptions, UltraTonRequestOptions, UltraTonStreamOptions } from './types/request-options.types.ts';
import type { UltraTonResponse, UltraTonStreamResponse } from './types/request-response.ts';

/** The constructor options plus the internal test seams, which are symbols and never part of the public types. */
interface InternalClientOptions extends UltraTonClientOptions {
    readonly [kTransport]?: typeof https.request | typeof http.request;
    readonly [kSessionManager]?: Http2SessionManager;
}

const MUST_BE_RELATIVE = 'UltraTon: With baseUrl set, request paths must be relative.';
const ESCAPES_BASE = 'UltraTon: Request path escapes baseUrl.';
const MALFORMED_ENCODING = 'UltraTon: Request path has malformed percent-encoding.';

/** How many times the part below the base is percent-decoded before a still-changing path is refused. */
const MAX_DECODE_PASSES = 5;
/** Path separators for the servers this check anticipates: '/', '\', DIVISION SLASH and REVERSE SOLIDUS OPERATOR. */
const SEPARATORS = /[/\\\u2215\u29F5]/;
/** A segment made only of dots plus spaces and control characters, which lenient servers trim (Windows/IIS). */
const DOTS_AND_JUNK = /^[.\u0000-\u0020\u007F-\u009F]*$/;
// Fatal: a run of bytes that is not UTF-8 throws instead of becoming U+FFFD.
const utf8 = new TextDecoder('utf-8', { fatal: true });

/**
 * Decodes every `%XX` run and leaves anything else as is (a bare '%' not followed by two hex digits stays literal, so
 * '100%' is fine), the way lenient servers decode a second time. A run that is not UTF-8, such as the double-encoded
 * overlong dots of '%25c0%25ae', is something a lenient server may read as anything, so it throws ESCAPES_BASE.
 */
function lenientDecode(text: string): string {
    return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, run => {
        try {
            return utf8.decode(Buffer.from(run.replace(/%/g, ''), 'hex'));
        } catch {
            throw new TypeError(ESCAPES_BASE);
        }
    });
}

/**
 * Judges the part of a resolved path below the base the way the most lenient servers read it, and throws if any of
 * them could see a step out of the base. That means: percent-decoded until it stops changing (at most
 * MAX_DECODE_PASSES, else refused), NFKC-normalized (fullwidth dots and slashes, the two-dot leader), split on every
 * separator in SEPARATORS, each segment cut at ';' (Tomcat/Spring params) and at a decoded '?' or '#'. A segment that
 * is then '.' or '..', or only dots plus trailing spaces/controls ('.. ', '..%00'), escapes. So does a run of 3 or
 * more dots followed by a separator ('.../'); the same run as the last segment is an ordinary file name.
 * An encoded slash inside an ordinary segment (GitLab's 'group%2Fproject') stays allowed.
 */
function assertNoDecodedTraversal(below: string): void {
    let decoded: string;
    try {
        decoded = decodeURIComponent(below).normalize('NFKC');
    } catch {
        throw new TypeError(MALFORMED_ENCODING);
    }
    for (let passes = 1; ; passes++) {
        const next = lenientDecode(decoded).normalize('NFKC');
        if (next === decoded) break;
        if (passes === MAX_DECODE_PASSES) throw new TypeError(ESCAPES_BASE);
        decoded = next;
    }

    const segments = decoded.split(SEPARATORS);
    segments.forEach((segment, index) => {
        const name = segment.split(/[;?#]/, 1)[0];
        if (!name.includes('.') || !DOTS_AND_JUNK.test(name)) return;
        const fileNameOfDots = /^\.{3,}$/.test(name) && index === segments.length - 1;
        if (!fileNameOfDots) throw new TypeError(ESCAPES_BASE);
    });
}

/**
 * Resolves a request path against the client's `baseUrl` so that it can never land outside it.
 * The input is judged as the WHATWG parser will read it (leading/trailing C0 controls and spaces ignored, tabs and
 * newlines removed anywhere), and the final check is on the resolved href, not on the input: percent-encoded dots
 * (`%2e%2e`) and backslashes are dot segments and slashes to the parser, whatever the input looks like.
 * @throws {TypeError} If the path is absolute or protocol-relative, resolves outside the base path, could be read as a
 *   step out of it by a lenient server (see assertNoDecodedTraversal), or has malformed percent-encoding.
 */
function resolveAgainstBase(path: unknown, base: URL): string {
    if (typeof path !== 'string') {
        throw new TypeError(`UltraTon: Expected the request URL to be a string, received ${path === null ? 'null' : typeof path}.`);
    }
    // Index scan, not /[\u0000- ]+$/: that regex retries from every position and goes quadratic on long control runs.
    let start = 0;
    let end = path.length;
    while (start < end && path.charCodeAt(start) <= 0x20) start++;
    while (end > start && path.charCodeAt(end - 1) <= 0x20) end--;
    const parsed = path.slice(start, end).replace(/[\t\n\r]/g, '');
    // A scheme makes it absolute (https:, javascript:, ...); two leading slashes in any mix with backslashes make it
    // protocol-relative, since special schemes read '\' as '/'.
    if (URL.canParse(parsed) || /^[\\/]{2}/.test(parsed)) throw new TypeError(MUST_BE_RELATIVE);
    // One leading slash means "from the base", not "from the origin root".
    const resolved = new URL(parsed.replace(/^[\\/]/, ''), base);
    // base.href ends with '/', so this also rules out another host, port or scheme and sibling paths ('/v1-admin').
    if (!resolved.href.startsWith(base.href)) throw new TypeError(ESCAPES_BASE);
    // The URL is inside the base, but servers do not all read it the same way: some decode %2F/%5C (even twice) before
    // resolving dot segments, IIS reads '\' as '/' and trims trailing dots and spaces, Tomcat/Spring drop ';params'.
    assertNoDecodedTraversal(resolved.pathname.slice(base.pathname.length));
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
     * A `fetch()` that goes through this client: same arguments and a standard `Response`, with every UltraTon check
     * (SSRF, redirects up to the client's `maxRedirects`, limits, decoding) and `json()` stripping `__proto__` keys.
     * Bound to the client, so it can be handed to any library that accepts a fetch implementation.
     * Network and policy failures reject as `TypeError('fetch failed')` with the UltraTon error as `cause`; an abort
     * with the signal's reason. Request bodies are buffered (a ReadableStream body throws).
     */
    public readonly fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> =>
        fetchWith((url, options) => this.stream(url, options), input, init);

    /**
     * @param options - Defaults for every request plus `baseUrl`, `http2`, `tls` and `userAgent`. Validated now: an
     *   unknown key, a value of the wrong type or a `tls` key other than `ca`/`cert`/`key` throws a `TypeError`.
     */
    constructor(options?: UltraTonClientOptions) {
        const resolved = resolveClientOptions(options, `ultraton/${VERSION}`);
        this.#defaults = resolved.defaults;
        this.#baseUrl = resolved.baseUrl;

        // The seams are read only once the options validated as an object, and only as own properties.
        const internal = (options ?? {}) as InternalClientOptions;
        const own = <K extends typeof kTransport | typeof kSessionManager>(key: K) =>
            Object.hasOwn(internal, key) ? internal[key] : undefined;
        this.#engine = resolved.http2
            ? new Http2Engine(own(kSessionManager) ?? new Http2SessionManager(resolved.tls))
            : new Http1Engine(resolved.tls, own(kTransport));
    }

    /**
     * Sends a GET request. Every method works the same way; only the HTTP method differs.
     * @param url - An absolute `https:` URL (plain `http:` only to loopback), or a relative path when `baseUrl` is set.
     * @param options - Per-request options; they override the client's defaults. See {@link UltraTonRequestOptions}.
     * @returns The response, for any status code: check `ok` or `statusCode`. Not-followed redirects resolve too.
     * @throws {TypeError} Before connecting, on an unknown or mistyped option, or with `baseUrl` a path that is absolute,
     *   malformed or escapes it. A malformed, non-http(s) or credential-bearing absolute URL is a `SecureHttpError`.
     * @throws {SecureHttpError} On a policy rejection (`code` `ERR_ULTRATON_*`), or a subclass: network failure,
     *   timeout, `maxBodySize` or `maxRedirects` exceeded. An abort rejects with `signal.reason`.
     */
    public async get<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('GET', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends a POST request. Send the payload as `{ json }`, `{ form }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async post<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('POST', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends a PUT request. Send the payload as `{ json }`, `{ form }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async put<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PUT', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends a PATCH request. Send the payload as `{ json }`, `{ form }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async patch<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PATCH', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends a DELETE request. See {@link UltraTonClient.get}. */
    public async delete<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('DELETE', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends a HEAD request. Cannot have a body; `data` is empty. See {@link UltraTonClient.get}. */
    public async head<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('HEAD', url, options) as Promise<UltraTonResponse<T>>;
    }

    /** Sends an OPTIONS request. See {@link UltraTonClient.get}. */
    public async options<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('OPTIONS', url, options) as Promise<UltraTonResponse<T>>;
    }

    /**
     * Sends a request and resolves as soon as the response headers arrive, with the body as a `ReadableStream`. Every
     * check of the other methods applies (SSRF, redirects, credentials, `timeoutMs` until the headers), and the body
     * keeps its limits as it is read: `maxBodySize` (here up to Number.MAX_SAFE_INTEGER), content-length, decoding,
     * `socketTimeoutMs` while waiting on the server, abort and `close()`. Read the body to the end or cancel it.
     * @param options - The request options plus `method` (default 'GET').
     * @throws {TypeError} As the other methods, and for a method outside GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS.
     */
    public async stream(url: string, options?: UltraTonStreamOptions): Promise<UltraTonStreamResponse> {
        const { method, maxBodySize, rest } = splitStreamOptions(options);
        return this.#request(method, url, rest, { maxBodySize }) as Promise<UltraTonStreamResponse>;
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

    async #request<T>(method: string, url: string, options: unknown, stream?: { maxBodySize?: number }): Promise<UltraTonResponse<T> | UltraTonStreamResponse> {
        if (this.#closed) throw new SecureHttpError('UltraTon: Client is closed.');
        const resolved = this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url;
        // The caller's own options are validated (unknown keys, json/form/body, body type) and the body encoded before any
        // client default is merged in. The content-type comes last: a client default one is kept for json, replaced by
        // the one a form, FormData, URLSearchParams or typed Blob implies.
        // `query` is applied here, after baseUrl's path check, and `retry` wraps the engine call: neither reaches the engines.
        // withMethod returns a null-prototype object: both are deleted from it, never destructured into a plain one.
        const requested = withMethod(method, options);
        const target = withQuery(resolved, requested.query);
        const retry = resolveRetry(this.#defaults.retry, retryOption(requested.retry), method);
        Reflect.deleteProperty(requested, 'query');
        Reflect.deleteProperty(requested, 'retry');
        const body = await resolveRequestBody(requested);
        const merged = withAcceptEncoding(mergeClientDefaults(body.options, this.#defaults));
        const resolvedOptions = requested.json === undefined ? withBodyContentType(merged, body.contentType) : withJsonContentType(merged);
        const send = (timeoutMs?: number): Promise<UltraTonResponse<T> | UltraTonStreamResponse> => {
            const attempt = timeoutMs === undefined ? resolvedOptions : { ...resolvedOptions, timeoutMs };
            return stream ? this.#engine.request(target, attempt, stream) : this.#engine.request<T>(target, attempt);
        };
        return retry ? withRetry(send, retry, resolvedOptions.timeoutMs, resolvedOptions.signal) : send();
    }
}
