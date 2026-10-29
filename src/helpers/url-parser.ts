import { isIP } from "node:net";
import { SecureHttpError } from "../errors.ts";

/**
 * Loopback names: `localhost`, any `*.localhost` (RFC 6761) with non-empty labels, IPv4 literals in 127.0.0.0/8 and
 * `[::1]`. The WHATWG parser has already lowercased the host and normalized IP literals (`127.1` is `127.0.0.1`,
 * `[0:0::1]` is `[::1]`). A name is only a name: the engines also require every address it resolves to be loopback.
 */
export const isLoopbackHost = (hostname: string): boolean =>
    hostname === 'localhost' ||
    /^(?:[^.]+\.)+localhost$/.test(hostname) ||
    hostname === '[::1]' ||
    (isIP(hostname) === 4 && hostname.startsWith('127.'));

/**
 * Safely parses a URL, avoids logging malformed strings,
 * blocks inline credential usage per RFC 3986 §3.2.1, and enforces HTTPS (plain HTTP only for loopback names).
 * 
 * @param url The URL string to parse (or relative path if base is provided)
 * @param base The base URL (used during redirects)
 * @param allowPlainHttp The client's `allowPlainHttp`: plain http to any host. The address policy still applies.
 */
export function parseSafeUrl(url: string, base?: string, allowPlainHttp = false): URL {
    let urlObj: URL;
    
    try {
        urlObj = base ? new URL(url, base) : new URL(url);
    } catch (e: unknown) {
        if (base) {
            throw new SecureHttpError("UltraTon: Invalid redirect location provided.");
        }
        throw new SecureHttpError("UltraTon: Invalid URL provided.");
    }

    if (urlObj.username || urlObj.password) {
        throw new SecureHttpError(`UltraTon: Credentials in URL authority are strictly prohibited. Use the 'auth' option instead.`);
    }

    if (urlObj.protocol !== 'https:') {
        if (urlObj.protocol === 'http:' && (allowPlainHttp || isLoopbackHost(urlObj.hostname))) {
            // [Loopback Escape Hatch] Accept plain HTTP only for loopback names, for local development and testing.
            // This only skips the https requirement. A `*.localhost` name is resolved like any other, so both engines
            // also reject the hop unless every address it resolves to is loopback (127.0.0.0/8, ::1, ::ffff:127.0.0.0/104),
            // and every address is still judged by the reserved-IP policy: the caller must also set `permitReservedIps`
            // to allow them (true, or an allowlist such as ['127.0.0.0/8', '::1'] or ['localhost']). Redirects from
            // https to http stay rejected. A client with `allowPlainHttp` lifts the loopback rule, never the policy.
        } else if (urlObj.protocol === 'http:') {
            throw new SecureHttpError('UltraTon: Plain http is only allowed for loopback hosts; use https.', { code: 'ERR_ULTRATON_PLAIN_HTTP' });
        } else {
            throw new SecureHttpError(`UltraTon: Unsupported protocol "${urlObj.protocol}"`);
        }
    }

    return urlObj;
}
