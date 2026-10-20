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
/** Statuses whose Response must have a null body (Fetch standard). */
const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304]);

/** A Response whose json() strips `__proto__`, `constructor` and `prototype` keys at every depth, like UltraTon's own. */
class UltraTonFetchResponse extends Response {
    override async json(): Promise<any> {
        return JSON.parse(await this.text(), secureReviver);
    }
}

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
    const signal = init.signal ?? base?.signal ?? undefined;
    const redirect = init.redirect ?? base?.redirect ?? 'follow';
    // Upper-cased like the other client methods (the platform would keep 'patch' as is, and warn about it).
    const method = String(init.method ?? base?.method ?? 'GET').toUpperCase();

    // The platform's Request does the WHATWG work: header normalization, and every body type with its content-type
    // (a FormData's multipart boundary included). A GET or HEAD with a body throws here, as fetch does.
    const normalized = new Request('http://ultraton.invalid/', {
        method,
        headers: init.headers ?? base?.headers,
        body: init.body !== undefined ? init.body : base?.body ? await base.arrayBuffer() : undefined,
    });
    const headers: Record<string, string> = {};
    normalized.headers.forEach((value, name) => { headers[name] = value; });
    const body = normalized.body ? Buffer.from(await normalized.arrayBuffer()) : undefined;

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
        await res.body.cancel();
        throw failed(new UltraTonRedirectError('UltraTon: Redirect not allowed (redirect: "error").'));
    }

    const responseHeaders = new Headers();
    for (const [name, value] of Object.entries(res.headers)) {
        if (value === undefined) continue;
        for (const item of Array.isArray(value) ? value : [value]) responseHeaders.append(name, item);
    }
    const nullBody = NULL_BODY_STATUS.has(res.statusCode) || method === 'HEAD';
    if (nullBody) await res.body.cancel();

    let response: Response;
    try {
        response = new UltraTonFetchResponse(nullBody ? null : res.body, { status: res.statusCode, headers: responseHeaders });
    } catch (err: unknown) {
        // A status Response cannot represent (below 200 or above 599).
        await res.body.cancel();
        throw failed(err);
    }
    // Read-only getters on Response that only the platform's fetch fills in.
    Object.defineProperty(response, 'url', { value: res.url, enumerable: true });
    Object.defineProperty(response, 'redirected', { value: res.redirected, enumerable: true });
    return response;
}
