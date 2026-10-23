import type * as http from 'node:http';
import type * as https from 'node:https';
import { isIP } from 'node:net';
import { SecureHttpError, clientClosed } from './errors.ts';
import { VERSION } from './constants.ts';
import { Http1Engine } from './engines/http1.ts';
import { Http2Engine } from './engines/http2.ts';
import { Http2SessionManager } from './engines/http2-session-manager.ts';
import { buildSafeRequestOptions, mergeClientDefaults, mergeClientOptions, resolveClientOptions, resolveRequestBody, retryOption, splitPaginateOptions, splitStreamOptions, withAcceptEncoding, withBodyContentType, withJsonContentType, withMethod, withQuery } from './helpers/request-options.ts';
import { judgeAddresses, type ReservedIpPolicy } from './security/dns-pinner.ts';
import { parseSafeUrl } from './helpers/url-parser.ts';
import type { ClientDefaults } from './helpers/request-options.ts';
import { kSessionManager, kSharedEngine, kTransport } from './internal.ts';
import { fetchWith } from './helpers/fetch.ts';
import { discardBody, StreamedBody } from './helpers/request-body.ts';
import { resolveRetry, withRetry } from './helpers/retry.ts';
import { observeRequest } from './helpers/diagnostics.ts';
import { nextLink } from './helpers/link-header.ts';
import type { UltraTonClientOptions, UltraTonPaginateOptions, UltraTonRequestOptions, UltraTonStreamOptions } from './types/request-options.types.ts';
import type { UltraTonExplanation, UltraTonResponse, UltraTonStreamResponse } from './types/request-response.ts';

/** The constructor options plus the internal test seams, which are symbols and never part of the public types. */
/** A copy of `value` with its arrays and plain objects copied down to `depth` levels; anything else (a Buffer, a function) as is. */
function snapshot(value: unknown, depth: number): unknown {
    if (depth === 0 || typeof value !== 'object' || value === null) return value;
    if (Array.isArray(value)) return value.map(item => snapshot(item, depth - 1));
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return value;
    const copy: Record<string, unknown> = {};
    for (const key of Object.keys(value)) copy[key] = snapshot((value as Record<string, unknown>)[key], depth - 1);
    return copy;
}

/** An engine and the number of clients using it: the last one to close closes the engine. */
interface SharedEngine {
    readonly engine: Http1Engine | Http2Engine;
    refs: number;
}

interface InternalClientOptions extends UltraTonClientOptions {
    readonly [kSharedEngine]?: SharedEngine;
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
 * session, so a permissive `permitReservedIps` or a custom `tls` never reaches another client. The one exception is a
 * variant made with `extend()`, which shares the pools of the client it came from; inside them, sockets are still kept
 * apart per `permitReservedIps` policy, and a variant with its own `tls`, `proxy` or `http2` gets pools of its own.
 * Call `close()` when done.
 */
export class UltraTonClient {
    readonly #engine: Http1Engine | Http2Engine;
    /** The engine and who else uses it (a variant from `extend()`, or the client it came from). */
    readonly #shared: SharedEngine;
    /** The constructor options, string keys only (the seams are never inherited): what `extend()` builds on. */
    readonly #options: UltraTonClientOptions;
    readonly #defaults: ClientDefaults;
    readonly #baseUrl?: URL;
    /** With `proxy.resolve: 'proxy'` (or a `socks5h:` URL) names are resolved by the proxy, so explain() has no addresses to judge. */
    readonly #proxyResolvesNames: boolean;
    #closed = false;

    /**
     * A `fetch()` that goes through this client: same arguments and a standard `Response`, with every UltraTon check
     * (SSRF, redirects up to the client's `maxRedirects`, limits, decoding) and `json()` stripping `__proto__` keys.
     * Bound to the client, so it can be handed to any library that accepts a fetch implementation.
     * Network and policy failures reject as `TypeError('fetch failed')` with the UltraTon error as `cause`; an abort
     * with the signal's reason. A `ReadableStream` or async iterable body is streamed, as `body` is for the other methods.
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
        this.#proxyResolvesNames = resolved.proxy?.resolve === 'proxy';
        // Validated as a plain object above. Object.keys leaves the symbol-keyed seams out, and the copy goes two
        // levels down so that a caller mutating their arrays or objects later (the permitReservedIps list, headers,
        // tls material) changes neither this client nor a variant made from it: the policy a variant gets is the one
        // this client was built with.
        this.#options = snapshot(options ?? {}, 2) as UltraTonClientOptions;

        // The seams are read only once the options validated as an object, and only as own properties.
        const internal = (options ?? {}) as InternalClientOptions;
        const own = <K extends typeof kTransport | typeof kSessionManager | typeof kSharedEngine>(key: K) =>
            Object.hasOwn(internal, key) ? internal[key] : undefined;
        const shared = own(kSharedEngine);
        if (shared) {
            shared.refs++;
            this.#shared = shared;
        } else {
            // An injected session manager (test seam) brings its own TLS and proxy settings; `proxy` applies to the default one.
            const engine = resolved.http2
                ? new Http2Engine(own(kSessionManager) ?? new Http2SessionManager(resolved.tls, undefined, undefined, resolved.proxy))
                : new Http1Engine(resolved.tls, own(kTransport), resolved.proxy);
            this.#shared = { engine, refs: 1 };
        }
        this.#engine = this.#shared.engine;
    }

    /**
     * A new client with this client's options and `options` on top: what `options` sets wins, headers merge
     * case-insensitively (`options` wins), `retry` merges field by field when both are objects, and a `userAgent` or
     * `user-agent` header here replaces whichever this client had. The variant shares this client's connection pools
     * unless `options` sets `http2`, `tls` or `proxy`; pools are kept apart per `permitReservedIps` policy either way,
     * so a variant never takes a socket judged under another policy. Closing either client leaves the other working;
     * the pools close with the last one.
     * @throws {SecureHttpError} If this client is closed.
     * @throws {TypeError} As the constructor: an unknown or invalid option.
     */
    public extend(options?: UltraTonClientOptions): UltraTonClient {
        if (this.#closed) throw clientClosed();
        const merged = mergeClientOptions(this.#options, options ?? {});
        const extra = options as Record<string, unknown> | undefined;
        const ownEngine = ['http2', 'tls', 'proxy'].some(key => extra !== undefined && Object.hasOwn(extra, key) && extra[key] !== undefined);
        return new UltraTonClient(ownEngine ? merged : { ...merged, [kSharedEngine]: this.#shared } as UltraTonClientOptions);
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
     * Walks a paginated collection with GET requests, yielding each page as a complete response once it arrives: every
     * page is a full `get()`, with all its checks. The next page is the `rel="next"` link of the `Link` header (RFC 8288)
     * (resolved against the page's final `url`) or what `next(page)` returns (an absolute URL, or a path read as `get()`
     * reads one: under `baseUrl`, from the base; otherwise from the page's `url`). The walk stays on the first page's origin
     * and, with `baseUrl`, inside it: a next page outside rejects, and so does a page a redirect served from outside it
     * (that server would otherwise pick the next request, with your credentials, on your origin). A non-2xx page is
     * yielded and ends the walk. `query` applies to the first page only (a next link carries its own); every other
     * option to every page.
     * @param url - As for `get()`.
     * @param options - The `get()` options without a body, plus `next` and `maxPages`. See {@link UltraTonPaginateOptions}.
     * @throws {TypeError} Now, for an invalid `next`, `maxPages` or a body; later, as `get()` does.
     * @throws {SecureHttpError} With `code` `ERR_ULTRATON_PAGE_OUT_OF_SCOPE` for a next page, or a page it would be read
     *   from, on another origin or outside `baseUrl`; `ERR_ULTRATON_MAX_PAGES` when a next page is left after
     *   `maxPages`; and anything `get()` throws.
     */
    public paginate<T = unknown>(url: string, options?: UltraTonPaginateOptions<T>): AsyncGenerator<UltraTonResponse<T>, void, undefined> {
        // Validated here rather than on the first iteration, so a stream body is released even if nothing iterates.
        return this.#paginate<T>(url, splitPaginateOptions(options));
    }

    async *#paginate<T>(url: string, split: ReturnType<typeof splitPaginateOptions>): AsyncGenerator<UltraTonResponse<T>, void, undefined> {
        const next = (split.next ?? ((page: UltraTonResponse<T>) => nextLink(page.headers.link))) as NonNullable<UltraTonPaginateOptions<T>['next']>;
        let page = await this.get<T>(url, split.rest as UltraTonRequestOptions);
        // Taken once the first request succeeded, so a bad URL fails exactly as get() fails it.
        const origin = new URL(this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url).origin;
        const base = this.#baseUrl;
        const inScope = (target: URL) => target.origin === origin && (!base || target.href.startsWith(base.href));
        const outOfScope = () => new SecureHttpError('UltraTon: The next page is outside the origin or baseUrl of the first one.', { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
        const later = { ...(split.rest as object), query: undefined };
        for (let count = 1; ; count++) {
            yield page;
            if (!page.ok) return;
            const ref = next(page);
            if (ref === undefined || ref === null) return;
            if (typeof ref !== 'string' && !(ref instanceof URL)) {
                throw new TypeError(`UltraTon: Expected 'next' to return a string, a URL, null or undefined, received ${typeof ref}.`);
            }
            // A redirect may have served this page from elsewhere: then it does not get to choose a request on this origin.
            const from = new URL(page.url);
            if (!inScope(from)) throw outOfScope();
            // ponytail: a link back to the same page loops until maxPages; detect it if a real API does that.
            if (count === split.maxPages) {
                throw new SecureHttpError(`UltraTon: More pages than maxPages (${split.maxPages}).`, { code: 'ERR_ULTRATON_MAX_PAGES' });
            }
            let target: URL;
            if (base && split.next && typeof ref === 'string' && !URL.canParse(ref)) {
                // A path from the caller's own next() under baseUrl reads as a get() path ('/items' is from the base);
                // a Link header keeps RFC 8288's resolution against the page.
                target = new URL(resolveAgainstBase(ref, base));
            } else {
                if (!URL.canParse(ref, from)) throw new SecureHttpError('UltraTon: Invalid next page URL.');
                target = new URL(ref, from);
            }
            if (!inScope(target)) throw outOfScope();
            // Under baseUrl the part below it goes through get() as a path, so the traversal checks of a path apply too.
            // './' keeps it relative and resolving to exactly `target` ('//x', 'users:search', '?q' included).
            page = await this.get<T>(base ? `./${target.href.slice(base.href.length)}` : target.href, later);
        }
    }

    /**
     * Says what a request to `url` would do before connecting, without connecting: the URL as it would be sent
     * (`baseUrl` applied, normalized), the addresses its host resolves to and how the policy judges each one, and the
     * verdict with the `code` and message the request would reject with. The same functions decide here and in a
     * request, so the two cannot disagree. It covers the first hop only (not redirects), and with `resolve: 'proxy'`
     * nothing is resolved here. For the operator configuring `permitReservedIps` or `baseUrl`: the result names resolved
     * addresses, so never return it to whoever supplied the URL.
     * @param url - As for `get()`: an absolute URL, or a path when `baseUrl` is set.
     * @param options - `permitReservedIps` for this call; the client's default otherwise.
     */
    public async explain(url: string, options?: { readonly permitReservedIps?: ReservedIpPolicy }): Promise<UltraTonExplanation> {
        const blocked = (err: unknown, href?: string): UltraTonExplanation => ({
            href,
            verdict: 'blocked',
            code: typeof (err as { code?: unknown })?.code === 'string' ? (err as { code: string }).code : undefined,
            reason: err instanceof Error ? err.message : String(err),
            addresses: [],
        });
        let target: URL;
        let policy: ReservedIpPolicy;
        try {
            target = parseSafeUrl(this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url);
            policy = buildSafeRequestOptions({ permitReservedIps: options?.permitReservedIps ?? this.#defaults.permitReservedIps }).permitReservedIps;
        } catch (err) {
            return blocked(err);
        }
        // Node never resolves an IP literal, and a hostname in brackets is an IPv6 literal.
        const bareHost = target.hostname.replace(/^\[|\]$/g, '');
        if (this.#proxyResolvesNames && isIP(bareHost) === 0) {
            return { href: target.href, verdict: 'allowed', reason: 'The proxy resolves the name; UltraTon judges no address here.', addresses: [] };
        }
        try {
            const judged = await judgeAddresses(bareHost, policy, target.protocol === 'http:');
            const refused = judged.find(a => a.error?.code === 'ERR_ULTRATON_PLAIN_HTTP') ?? judged.find(a => !a.allowed);
            return {
                href: target.href,
                verdict: refused ? 'blocked' : 'allowed',
                ...(refused ? { code: refused.error?.code, reason: refused.error?.message } : {}),
                addresses: judged.map(({ address, family, allowed }) => ({ address, family, allowed })),
            };
        } catch (err) {
            return blocked(err, target.href);
        }
    }

    /**
     * Closes this client: any later request rejects with `SecureHttpError('UltraTon: Client is closed.')`. Its pooled
     * sockets and sessions are destroyed with it (requests still in flight on them fail), unless a client made with
     * `extend()` still shares them: then they close with the last of those clients. Calling it again does nothing.
     */
    public async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        if (--this.#shared.refs === 0) this.#engine.close();
    }

    /** Closes the client, as `close()` does: lets `await using client = new UltraTonClient()` close it when the block ends. */
    async [Symbol.asyncDispose](): Promise<void> {
        await this.close();
    }

    async #request<T>(method: string, url: string, options: unknown, stream?: { maxBodySize?: number }): Promise<UltraTonResponse<T> | UltraTonStreamResponse> {
        try {
            return await this.#send<T>(method, url, options, stream);
        } catch (err: unknown) {
            // A stream body the request never got to read (bad input, a policy rejection, an abort, a closed client)
            // is released, as one cut short mid-upload is: a file stream must not keep its descriptor open. Only an own
            // property counts, as for every option.
            const own = typeof options === 'object' && options !== null && Object.hasOwn(options, 'body');
            discardBody(own ? (options as { body?: unknown }).body : undefined);
            throw err;
        }
    }

    async #send<T>(method: string, url: string, options: unknown, stream?: { maxBodySize?: number }): Promise<UltraTonResponse<T> | UltraTonStreamResponse> {
        if (this.#closed) throw clientClosed();
        const resolved = this.#baseUrl ? resolveAgainstBase(url, this.#baseUrl) : url;
        // The caller's own options are validated (unknown keys, json/form/body, body type) and the body encoded before any
        // client default is merged in. The content-type comes last: a client default one is kept for json, replaced by
        // the one a form, FormData, URLSearchParams or typed Blob implies.
        // `query` is applied here, after baseUrl's path check, and `retry` wraps the engine call: neither reaches the engines.
        // withMethod returns a null-prototype object: both are deleted from it, never destructured into a plain one.
        const requested = withMethod(method, options);
        const target = withQuery(resolved, requested.query);
        const retryPolicy = resolveRetry(this.#defaults.retry, retryOption(requested.retry), method);
        Reflect.deleteProperty(requested, 'query');
        Reflect.deleteProperty(requested, 'retry');
        const pending = resolveRequestBody(requested);
        const body = pending instanceof Promise ? await pending : pending;
        // A stream can only be read once: a request with one is sent once, whatever the retry option says.
        const retry = body.options.body instanceof StreamedBody ? undefined : retryPolicy;
        const merged = withAcceptEncoding(mergeClientDefaults(body.options, this.#defaults));
        const resolvedOptions = requested.json === undefined ? withBodyContentType(merged, body.contentType) : withJsonContentType(merged);
        const send = (timeoutMs?: number): Promise<UltraTonResponse<T> | UltraTonStreamResponse> => {
            const attempt = timeoutMs === undefined ? resolvedOptions : { ...resolvedOptions, timeoutMs };
            return stream ? this.#engine.request(target, attempt, stream) : this.#engine.request<T>(target, attempt);
        };
        // diagnostics_channel: started once the options are valid, so a TypeError for bad input publishes nothing.
        const observer = observeRequest(method, target);
        if (!observer) return retry ? withRetry(send, retry, resolvedOptions.timeoutMs, resolvedOptions.signal) : send();
        const observed = retry && {
            ...retry,
            // The caller's hook first: when it throws there is no retry, so no retry event either.
            onRetry: (info: Parameters<NonNullable<typeof retry.onRetry>>[0]) => { retry.onRetry?.(info); observer.retry(info); },
        };
        return observer.track(observed ? withRetry(send, observed, resolvedOptions.timeoutMs, resolvedOptions.signal) : send());
    }
}
