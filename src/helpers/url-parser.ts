import { SecureHttpError } from "../exceptions/secure-http.error.ts";

/**
 * Safely parses a URL, avoids logging malformed strings,
 * blocks inline credential usage per RFC 3986 §3.2.1, and enforces HTTPS.
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

    const isLocalhost = urlObj.hostname === 'localhost' || urlObj.hostname === '127.0.0.1';

    if (urlObj.protocol !== 'https:') {
        if (urlObj.protocol === 'http:' && isLocalhost) {
            // [Localhost Escape Hatch] Accept plain HTTP only for local development testing
        } else {
            throw new SecureHttpError(`UltraTon: Unsupported protocol "${urlObj.protocol}"`);
        }
    }

    return urlObj;
}
