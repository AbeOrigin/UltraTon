import { HTTP_CODES_REDIRECTS } from '../constants.ts';
import { UltraTonRedirectError } from '../errors.ts';
import { secureReviver } from './response.ts';
import type { UltraTonStreamMethod, UltraTonStreamOptions } from '../types/request-options.types.ts';
import type { UltraTonStreamResponse } from '../types/request-response.ts';

/** The RequestInit fields UltraTon acts on. */
const SUPPORTED = new Set(['method', 'headers', 'body', 'signal', 'redirect']);
/**
 * Fields that only mean something in a browser (or, for duplex, to a streaming upload, which is refused on its own):
 * accepted and ignored, so code written for fetch runs unchanged. Anything else (dispatcher, agent, a node-fetch
 * timeout...) throws: ignoring it would let the caller believe it changed the connection.
 */
const IGNORED = new Set(['mode', 'credentials', 'cache', 'referrer', 'referrerPolicy', 'integrity', 'keepalive', 'priority', 'window', 'duplex']);
/** Statuses whose Response must have a null body (Fetch standard; 1xx never reach a Response). */
const NULL_BODY_STATUS = new Set([204, 205, 304]);

/**
 * A Response whose json() strips `__proto__`, `constructor` and `prototype` keys at every depth, like UltraTon's own,
 * with the `url` and `redirected` only the platform's fetch can otherwise set. clone() keeps all three.
 */
class UltraTonFetchResponse extends Response {
    constructor(body: ReadableStream<Uint8Array> | null, init: ResponseInit, url: string, redirected: boolean) {
        super(body, init);
        // Read-only getters on Response: shadowed on the instance.
        Object.defineProperty(this, 'url', { value: url, enumerable: true });
        Object.defineProperty(this, 'redirected', { value: redirected, enumerable: true });
    }

    override async json(): Promise<any> {
        return JSON.parse(await this.text(), secureReviver);
    }

    override clone(): UltraTonFetchResponse {
        const copy = super.clone();
        return new UltraTonFetchResponse(copy.body, { status: this.status, statusText: this.statusText, headers: this.headers }, this.url, this.redirected);
    }
}

/** Gives a body up without letting its own error (the connection may have dropped) replace the one being reported. */
const discard = (body: ReadableStream<Uint8Array>) => body.cancel().catch(() => {});

const failed = (cause: unknown) => new TypeError('fetch failed', { cause });

const isStreamingBody = (body: unknown) =>
    body instanceof ReadableStream ||
    (typeof body === 'object' && body !== null && Symbol.asyncIterator in body &&
        !(body instanceof Blob) && !(body instanceof FormData) && !(body instanceof URLSearchParams));

/**
 * fetch() on top of `stream()`: the init is normalized through the platform's own Request (headers, and body types with
 * the content-type they imply), sent with every UltraTon check, and answered with a standard Response streaming the
 * body. Errors follow undici: a failure that is not a TypeError rejects as `TypeError('fetch failed')` with the
 * UltraTon error as `cause`; an abort rejects with the signal's reason.
 */
export async function fetchWith(
    stream: (url: string, options: UltraTonStreamOptions) => Promise<UltraTonStreamResponse>,
    input: string | URL | Request,
    init: RequestInit = {},
): Promise<Response> {
    if (typeof init !== 'object' || init === null) throw new TypeError("UltraTon: The fetch init must be an object.");
    for (const key of Object.keys(init)) {
        if (SUPPORTED.has(key) || IGNORED.has(key)) continue;
        throw new TypeError(`UltraTon: Unsupported fetch option '${key}'. Configure the connection on the UltraTonClient instead.`);
    }
    if (isStreamingBody(init.body)) {
        throw new TypeError('UltraTon: Streaming request bodies are not supported; pass a string, Buffer, Blob, FormData or URLSearchParams.');
    }

    const base = input instanceof Request ? input : undefined;
    const url = base ? base.url : input instanceof URL ? input.href : String(input);
    // An explicit `signal: null` means no signal, as in fetch: only `undefined` falls back to the Request's.
    const signal = init.signal !== undefined ? init.signal ?? undefined : base?.signal;
    // Upper-cased like the other client methods (the platform would keep 'patch' as is, and warn about it).
    const method = String(init.method ?? base?.method ?? 'GET').toUpperCase();

    // The platform's Request does the WHATWG work: header normalization, and every body type with its content-type
    // (a FormData's multipart boundary included), and the redirect mode is validated. A GET or HEAD with a body throws
    // here, as fetch does.
    const normalized = new Request('http://ultraton.invalid/', {
        method,
        redirect: init.redirect ?? base?.redirect,
        headers: init.headers ?? base?.headers,
        body: init.body !== undefined ? init.body : base?.body ? await base.arrayBuffer() : undefined,
    });
    const headers: Record<string, string> = {};
    normalized.headers.forEach((value, name) => { headers[name] = value; });
    const body = normalized.body ? Buffer.from(await normalized.arrayBuffer()) : undefined;
    const redirect = normalized.redirect;

    let res: UltraTonStreamResponse;
    try {
        res = await stream(url, {
            method: method as UltraTonStreamMethod,
            headers,
            body,
            signal: signal ?? undefined,
            // 'follow' keeps the client's maxRedirects; 'manual' and 'error' see the 3xx itself.
            ...(redirect === 'follow' ? {} : { maxRedirects: 0 }),
        });
    } catch (err: unknown) {
        if (err instanceof TypeError || (signal?.aborted && err === signal.reason)) throw err;
        throw failed(err);
    }

    if (redirect === 'error' && HTTP_CODES_REDIRECTS.has(res.statusCode) && res.headers.location) {
        await discard(res.body);
        throw failed(new UltraTonRedirectError('UltraTon: Redirect not allowed (redirect: "error").'));
    }

    const nullBody = NULL_BODY_STATUS.has(res.statusCode) || method === 'HEAD';
    try {
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(res.headers)) {
            if (value === undefined) continue;
            for (const item of Array.isArray(value) ? value : [value]) responseHeaders.append(name, item);
        }
        if (nullBody) await discard(res.body);
        return new UltraTonFetchResponse(nullBody ? null : res.body, { status: res.statusCode, headers: responseHeaders }, res.url, res.redirected);
    } catch (err: unknown) {
        // A header value or a status (below 200, above 599) a Response cannot represent.
        await discard(res.body);
        throw failed(err);
    }
}
