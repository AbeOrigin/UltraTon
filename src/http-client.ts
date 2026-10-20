import type * as http from 'node:http';
import type * as https from 'node:https';
import { SecureHttpError } from './errors.ts';
import { VERSION } from './constants.ts';
import { Http1Engine } from './engines/http1.ts';
import { Http2Engine } from './engines/http2.ts';
import { Http2SessionManager } from './engines/http2-session-manager.ts';
import { mergeClientDefaults, resolveClientOptions, resolveRequestBody, withAcceptEncoding, withJsonContentType, withMethod, withQuery } from './helpers/request-options.ts';
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
        return this.#request<T>('GET', url, options);
    }

    /** Sends a POST request. Send the payload as `{ json }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async post<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('POST', url, options);
    }

    /** Sends a PUT request. Send the payload as `{ json }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async put<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PUT', url, options);
    }

    /** Sends a PATCH request. Send the payload as `{ json }` or `{ body }`. See {@link UltraTonClient.get}. */
    public async patch<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('PATCH', url, options);
    }

    /** Sends a DELETE request. See {@link UltraTonClient.get}. */
    public async delete<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('DELETE', url, options);
    }

    /** Sends a HEAD request. Cannot have a body; `data` is empty. See {@link UltraTonClient.get}. */
    public async head<T = unknown>(url: string, options?: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        return this.#request<T>('HEAD', url, options);
    }

    /** Sends an OPTIONS request. See {@link UltraTonClient.get}. */
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
        const resolved = this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url;
        // The caller's own options are validated (unknown keys, json/body, body type) and `json` serialized before any
        // client default is merged in. The json content-type comes last, so a client default content-type is kept.
        // `query` is applied here, after baseUrl's path check, and never reaches the engines.
        // withMethod returns a null-prototype object: `query` is deleted from it, never destructured into a plain one.
        const requested = withMethod(method, options);
        const target = withQuery(resolved, requested.query);
        Reflect.deleteProperty(requested, 'query');
        const merged = withAcceptEncoding(mergeClientDefaults(resolveRequestBody(requested), this.#defaults));
        return this.#engine.request<T>(target, requested.json === undefined ? merged : withJsonContentType(merged));
    }
}
