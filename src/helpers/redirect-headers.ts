import type { RedirectHeaders } from '../types/request-options.types.ts';

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
export function headersForNextHop(
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
