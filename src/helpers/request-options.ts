import { isIP } from "node:net";
import type { InternalRequestOptions, ResolvedRequestOptions, SecureUltraTonRequestOptions, ReservedIpPolicy } from "../types/request-options.types.ts";
import { MAX_REDIRECTS_CEILING } from "../constants.ts";
const INT32_MAX = 2147483647;

/**
 * @throws {TypeError} Synchronously throws if the value is defined but breaches the expected type.
 * @returns {boolean} `true` if the value exists and is valid. `false` if `undefined`.
 */
function validateType(propName: string, value: unknown, expectedType: 'string' | 'number' | 'object' | 'boolean'): boolean {
    if (value === undefined) return false;

    const isValid = expectedType === 'object' ? typeof value === 'object' && value !== null && !Array.isArray(value)
        : expectedType === 'number' ? typeof value === 'number' && !Number.isNaN(value)
        : typeof value === expectedType;

    if (!isValid) {
        throw new TypeError(`UltraTon: Expected '${propName}' to be a ${expectedType}, received ${typeof value}`);
    }

    return true;
}

/** Non-negative integer up to `max`; a wrong type throws, an out-of-range value falls back. */
function intOption(propName: string, value: unknown, fallback: number, max = INT32_MAX): number {
    return validateType(propName, value, 'number') && Number.isInteger(value) && (value as number) >= 0 && (value as number) <= max
        ? value as number
        : fallback;
}

/** An IP, a CIDR (`ip/prefix`, prefix 0-32 for v4 and 0-128 for v6) or a hostname with no leading or trailing dot. */
function isReservedIpEntry(entry: unknown): entry is string {
    if (typeof entry !== 'string') return false;
    if (isIP(entry) !== 0) return true;

    const slash = entry.indexOf('/');
    if (slash !== -1) {
        const family = isIP(entry.slice(0, slash));
        const prefix = entry.slice(slash + 1);
        return family !== 0 && /^\d{1,3}$/.test(prefix) && Number(prefix) <= (family === 4 ? 32 : 128);
    }

    return /^[a-z0-9.-]+$/i.test(entry) && !entry.startsWith('.') && !entry.endsWith('.');
}

/**
 * `permitReservedIps` is a boolean or an allowlist of IPs, CIDRs and hostnames. The list is copied and frozen after
 * validation, so the caller cannot widen the policy by mutating their array afterwards.
 * @throws {TypeError} For any other type, or for a list entry that is none of an IP, a CIDR or a hostname.
 */
function reservedIpPolicy(value: unknown): ReservedIpPolicy {
    if (!Array.isArray(value)) {
        return validateType('permitReservedIps', value, 'boolean') && value === true;
    }

    for (const entry of value) {
        if (!isReservedIpEntry(entry)) {
            throw new TypeError(`UltraTon: Invalid permitReservedIps entry '${String(entry)}': expected an IP, CIDR or hostname.`);
        }
    }
    return Object.freeze([...value] as string[]);
}

/**
 * Parses and strictly sanitizes headers.
 * 
 * @param rawHeaders - User input headers.
 * @throws {TypeError} Synchronously throws if CRLF injection or an HTTP/2 pseudo-header key is detected.
 */
function sanitizeHeaders(rawHeaders: Record<string, unknown>): Record<string, string | string[]> {
    const sanitized: Record<string, string | string[]> = {};
    const crlfRegex = /[\r\n\0]/;

    for (const key in rawHeaders) {
        if (!Object.prototype.hasOwnProperty.call(rawHeaders, key)) continue;

        // Prototype pollution prevention
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;

        const lowerKey = key.toLowerCase();
        if (crlfRegex.test(lowerKey)) {
            throw new TypeError(`UltraTon: Header key '${key}' contains invalid CRLF characters.`);
        }
        // HTTP/2 pseudo-headers (:authority, :path, ...) belong to the client; a caller must not be able to set them.
        if (lowerKey.startsWith(':')) {
            throw new TypeError(`UltraTon: Header key '${key}' is an HTTP/2 pseudo-header and cannot be set.`);
        }

        const value = rawHeaders[key];
        let normalizedValue = value;

        if ((typeof value === 'number' && !Number.isNaN(value)) || typeof value === 'boolean') {
            normalizedValue = String(value);
        }

        if (typeof normalizedValue === 'string') {
            if (crlfRegex.test(normalizedValue)) {
                throw new TypeError(`UltraTon: Header value for '${key}' contains invalid CRLF characters.`);
            }
            sanitized[lowerKey] = normalizedValue;
        } else if (Array.isArray(normalizedValue)) {
            const sanitizedVal: string[] = [];
            for (let item of normalizedValue) {
                if ((typeof item === 'number' && !Number.isNaN(item)) || typeof item === 'boolean') {
                    item = String(item);
                }
                if (typeof item === 'string') {
                    if (crlfRegex.test(item)) {
                        throw new TypeError(`UltraTon: Header array value for '${key}' contains invalid CRLF characters.`);
                    }
                    sanitizedVal.push(item);
                }
            }
            sanitized[lowerKey] = sanitizedVal;
        }
    }

    return sanitized;
}

/** The per-request options a caller may pass. `method` is not one of them: the client method being called sets it. */
const REQUEST_OPTION_KEYS = ['headers', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'maxRedirects', 'permitReservedIps', 'signal', 'auth', 'json', 'body'];
/** What buildSafeRequestOptions accepts: the options above plus the `method` the client methods set internally. */
const ACCEPTED_KEYS = new Set([...REQUEST_OPTION_KEYS, 'method']);

const QUERY_HINT = " Put the query string in the URL.";
const TLS_HINT = " TLS is configured with the 'tls' option of the client constructor.";
const BASE_URL_HINT = " 'baseUrl' is an option of the client constructor, not of a request.";
// A Map, not an object: an option named 'constructor' or '__proto__' must not find a hint through the prototype chain.
const OPTION_HINTS = new Map<string, string>([
    ['timeout', " Use 'timeoutMs' (milliseconds)."],
    ['baseURL', BASE_URL_HINT],
    ['prefixUrl', BASE_URL_HINT],
    ['data', " Use 'json' for a JSON payload or 'body' for a string or Buffer."],
    ['params', QUERY_HINT],
    ['query', QUERY_HINT],
    ['searchParams', QUERY_HINT],
    ['agent', TLS_HINT],
    ['ca', TLS_HINT],
    ['rejectUnauthorized', " Disabling certificate verification is not supported; to trust a private CA use the 'tls' option of the client constructor."],
]);

/** @throws {TypeError} For any own key outside the allowlist, whatever its value (`undefined` included). */
function assertKnownOptions(options: object): void {
    for (const key of Object.keys(options)) {
        if (ACCEPTED_KEYS.has(key)) continue;
        const hint = OPTION_HINTS.get(key) ?? ` Valid options: ${REQUEST_OPTION_KEYS.join(', ')}.`;
        throw new TypeError(`UltraTon: Unknown option '${key}'.${hint}`);
    }
}

/** @throws {TypeError} If both `json` and `body` are set, or `body` is not a string, Buffer or Uint8Array. */
function assertBodyOptions(options: { json?: unknown; body?: unknown }): void {
    if (options.json !== undefined && options.body !== undefined) {
        throw new TypeError("UltraTon: Use either 'json' or 'body', not both.");
    }
    if (options.body !== undefined && typeof options.body !== 'string' && !(options.body instanceof Uint8Array)) {
        throw new TypeError(`UltraTon: Expected 'body' to be a string, Buffer or Uint8Array, received ${options.body === null ? 'null' : typeof options.body}. Use 'json' to send an object.`);
    }
}

/**
 * Builds the options of one request from what a client method (`get`, `post`, ...) received: the caller's options object
 * plus the method. A caller-supplied `method` throws instead of being silently overridden, and so does an `options` that
 * is not an object (typically the old `post(url, body)` call shape).
 */
export function withMethod(method: string, options: unknown): InternalRequestOptions {
    if (options === undefined) return { method };
    if (typeof options !== 'object' || options === null || Array.isArray(options)) {
        throw new TypeError("UltraTon: 'options' must be an object. Send a request body with { json } or { body }.");
    }
    if (Object.hasOwn(options, 'method')) {
        throw new TypeError("UltraTon: Unknown option 'method'. The HTTP method is set by the client method you call (get, post, put, patch, delete, head, options).");
    }
    return { ...options, method };
}

/**
 * Validates the caller's body options and resolves them into the bytes that go on the wire: `json` is serialized (and
 * sets `content-type: application/json` unless the caller already set one), a string/Uint8Array `body` becomes a Buffer.
 * Run it on the user-supplied options, before any internal enrichment.
 * @throws {TypeError} On an unknown option, `json` together with `body`, a `body` of the wrong type or a `json` that cannot be serialized.
 */
export function resolveRequestBody(options: InternalRequestOptions): ResolvedRequestOptions {
    assertKnownOptions(options);
    assertBodyOptions(options);
    if ((options.json !== undefined || options.body !== undefined) && (options.method === 'GET' || options.method === 'HEAD')) {
        throw new TypeError('UltraTon: GET and HEAD requests cannot have a body.');
    }

    const { json, body, ...rest } = options;
    if (json === undefined) {
        if (body === undefined) return rest;
        return { ...rest, body: Buffer.isBuffer(body) ? body : Buffer.from(body as string | Uint8Array) };
    }

    let serialized: string | undefined;
    try {
        serialized = JSON.stringify(json);
    } catch (err: unknown) {
        throw new TypeError(`UltraTon: 'json' could not be serialized: ${err instanceof Error ? err.message : 'unknown error'}.`, { cause: err });
    }
    if (serialized === undefined) {
        throw new TypeError("UltraTon: 'json' could not be serialized: functions and symbols have no JSON representation.");
    }

    // headers is only checked for shape by buildSafeRequestOptions later; here, anything that is not a plain object is left alone.
    const headers: unknown = rest.headers;
    let withType: unknown = headers;
    if (headers === undefined) {
        withType = { 'content-type': 'application/json' };
    } else if (typeof headers === 'object' && headers !== null && !Array.isArray(headers)) {
        const map = headers as Record<string, unknown>;
        const hasContentType = Object.keys(map).some(key => key.toLowerCase() === 'content-type' && map[key] !== undefined);
        if (!hasContentType) withType = { ...map, 'content-type': 'application/json' };
    }

    return { ...rest, headers: withType as ResolvedRequestOptions['headers'], body: Buffer.from(serialized) };
}

/** `auth` as the value of a Basic `authorization` header, the same encoding `node:http` applies to its own `auth` option. */
export function basicAuthorization(auth: string): string {
    return `Basic ${Buffer.from(auth).toString('base64')}`;
}

/**
 * Acts as an absolute firewall between the user's input and the native Node.js HTTP stack.
 * Extracts ONLY explicitly approved properties and throws on any other key. Drops all potential socket injections
 * and enforces strict runtime primitive types to prevent C++ thread exhaustion or V8 crashes.
 * Throws TypeError synchronously on malformed security primitives to fail loud.
 */
export function buildSafeRequestOptions(options: InternalRequestOptions): SecureUltraTonRequestOptions {
    assertKnownOptions(options);
    assertBodyOptions(options);

    const safeOptions: Record<string, unknown> = {};

    if (validateType('method', options.method, 'string')) safeOptions.method = options.method;
    if (validateType('auth', options.auth, 'string')) safeOptions.auth = options.auth;
    if (validateType('signal', options.signal, 'object')) safeOptions.signal = options.signal;
    if (validateType('headers', options.headers, 'object')) {
        safeOptions.headers = sanitizeHeaders(options.headers as Record<string, unknown>);
    }

    safeOptions.maxBodySize = intOption('maxBodySize', options.maxBodySize, 2 * 1024 * 1024); // Strict 2MB fallback
    safeOptions.socketTimeoutMs = intOption('socketTimeoutMs', options.socketTimeoutMs, 10_000); // Strict 10s fallback
    safeOptions.timeoutMs = intOption('timeoutMs', options.timeoutMs, 30_000); // Strict 30s fallback
    safeOptions.maxRedirects = Math.min(intOption('maxRedirects', options.maxRedirects, 0, Infinity), MAX_REDIRECTS_CEILING);
    // Strict fallback: block SSRF
    safeOptions.permitReservedIps = reservedIpPolicy(options.permitReservedIps);

    return safeOptions as unknown as SecureUltraTonRequestOptions;
}