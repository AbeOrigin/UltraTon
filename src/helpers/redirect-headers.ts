import type { RedirectHeaders, ResolvedRequestOptions, SecureUltraTonRequestOptions } from '../types/request-options.types.ts';
import { SecureHttpError, UltraTonRedirectError } from '../errors.ts';
import { parseSafeUrl } from './url-parser.ts';

/** Always dropped on a hop to another origin: credentials for the origin that got them, and `host`, which names it. */
const CREDENTIALS = ['authorization', 'cookie', 'proxy-authorization', 'host'];
/** All that follows a request to another origin with `redirectHeaders: 'safe'`: content negotiation and the body's framing. */
const SAFE_ACROSS_ORIGINS = new Set(['accept', 'accept-encoding', 'accept-language', 'user-agent', 'content-type', 'content-length']);

/**
 * The headers of the next hop of a redirect, from the current ones (keys already lowercased by sanitizeHeaders). On the
 * same origin everything follows. On another origin the credential headers never do, and with `'safe'` neither does
 * anything outside SAFE_ACROSS_ORIGINS: an `x-api-key` or any other custom header is a credential as far as the caller
 * knows, and a server that redirects could send it anywhere. `'all'` lets the rest follow, as fetch, got and axios do.
 */
function headersForNextHop(
    headers: Readonly<Record<string, string | string[] | undefined>> | undefined,
    crossOrigin: boolean,
    mode: RedirectHeaders,
): Record<string, string | string[] | undefined> {
    const next: Record<string, string | string[] | undefined> = { ...headers };
    if (!crossOrigin) return next;
    for (const name of CREDENTIALS) delete next[name];
    if (mode === 'safe') {
        for (const name of Object.keys(next)) if (!SAFE_ACROSS_ORIGINS.has(name)) delete next[name];
    }
    return next;
}

/**
 * The request of the next hop, for a redirect both engines have already decided to follow (redirects on, and not a
 * 307/308 with a streamed body, which cannot be sent twice). The same rules on both: no more than `maxRedirects` hops;
 * the Location is parsed and validated like any URL; a response fetched over TLS never steers the request onto
 * plaintext (the http loopback escape hatch included); credentials, and with `'safe'` every custom header, stay on
 * their origin; a 303, or a 301/302 on anything but GET or HEAD, becomes a GET without body or body framing.
 * @throws {UltraTonRedirectError} past `maxRedirects`.
 * @throws {SecureHttpError} `ERR_ULTRATON_DOWNGRADE` on https→http, or whatever parseSafeUrl rejects the Location with.
 */
export function followRedirect(
    statusCode: number,
    location: string,
    from: URL,
    options: ResolvedRequestOptions,
    reqOpts: SecureUltraTonRequestOptions,
    redirectCount: number,
): { url: string; options: ResolvedRequestOptions } {
    if (redirectCount >= reqOpts.maxRedirects) {
        throw new UltraTonRedirectError(`UltraTon: Max redirects (${reqOpts.maxRedirects}) exceeded.`);
    }
    const next = parseSafeUrl(location, from.href);
    if (from.protocol === 'https:' && next.protocol === 'http:') {
        throw new SecureHttpError('UltraTon: Redirect from https to http is not allowed.', { code: 'ERR_ULTRATON_DOWNGRADE' });
    }
    const crossOrigin = from.origin !== next.origin;
    const headers = headersForNextHop(reqOpts.headers, crossOrigin, reqOpts.redirectHeaders);
    let method = (reqOpts.method || 'GET').toUpperCase();
    let body = options.body;
    if (statusCode === 303 || ((statusCode === 301 || statusCode === 302) && method !== 'GET' && method !== 'HEAD')) {
        method = 'GET';
        body = undefined;
        delete headers['content-length'];
        delete headers['content-type'];
        delete headers['transfer-encoding'];
    }
    return { url: next.href, options: { ...options, method, headers, body, auth: crossOrigin ? undefined : options.auth } };
}
