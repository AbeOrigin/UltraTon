import { isIP } from "node:net";
import { SecureHttpError } from "../errors.ts";

/**
 * Loopback names: `localhost`, any `*.localhost` (RFC 6761), IPv4 literals in 127.0.0.0/8 and `[::1]`. The WHATWG
 * parser has already lowercased the host and normalized IP literals (`127.1` is `127.0.0.1`, `[0:0::1]` is `[::1]`).
 */
const isLoopbackHost = (hostname: string): boolean =>
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '[::1]' ||
    (isIP(hostname) === 4 && hostname.startsWith('127.'));

/**
 * Safely parses a URL, avoids logging malformed strings,
 * blocks inline credential usage per RFC 3986 §3.2.1, and enforces HTTPS (plain HTTP only for loopback names).
 * 
 * @param url The URL string to parse (or relative path if base is provided)
 * @param base The base URL (used during redirects)
 */
export function parseSafeUrl(url: string, base?: string): URL {
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
        if (urlObj.protocol === 'http:' && isLoopbackHost(urlObj.hostname)) {
            // [Loopback Escape Hatch] Accept plain HTTP only for loopback names, for local development and testing.
            // This only skips the https requirement: every address is still judged, so these hosts are rejected unless
            // the caller also sets `permitReservedIps` to allow every address the name reaches (true, or an allowlist
            // such as ['127.0.0.0/8', '::1'] or ['localhost']). A `*.localhost` name is resolved like any other: one that
            // resolves outside loopback is judged by the same policy, and redirects from https to http stay rejected.
        } else {
            throw new SecureHttpError(`UltraTon: Unsupported protocol "${urlObj.protocol}"`);
        }
    }

    return urlObj;
}
