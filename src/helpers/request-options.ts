import { isIP } from "node:net";
import type { InternalRequestOptions, ResolvedRequestOptions, SecureUltraTonRequestOptions, ReservedIpPolicy, TlsMaterial, TlsOptions } from "../types/request-options.types.ts";
import { MAX_REDIRECTS_CEILING } from "../constants.ts";
import { parseSafeUrl } from "./url-parser.ts";
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

/** The options of `new UltraTonClient(options)`. */
const CLIENT_OPTION_KEYS = ['baseUrl', 'headers', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'maxRedirects', 'permitReservedIps', 'http2', 'tls', 'userAgent'];
const CLIENT_KEYS = new Set(CLIENT_OPTION_KEYS);
const TLS_OPTION_KEYS = ['ca', 'cert', 'key'] as const;

const QUERY_HINT = " Put the query string in the URL.";
const TLS_HINT = " TLS is configured with the 'tls' option of the client constructor.";
const BASE_URL_HINT = " 'baseUrl' is an option of the client constructor, not of a request.";
const TIMEOUT_HINT = " Use 'timeoutMs' (milliseconds).";
const NO_VERIFY_OFF = " Disabling certificate verification is not supported; to trust a private CA use";
// Maps, not objects: an option named 'constructor' or '__proto__' must not find a hint through the prototype chain.
const OPTION_HINTS = new Map<string, string>([
    ['timeout', TIMEOUT_HINT],
    ['baseURL', BASE_URL_HINT],
    ['prefixUrl', BASE_URL_HINT],
    ['baseUrl', BASE_URL_HINT],
    ['data', " Use 'json' for a JSON payload or 'body' for a string or Buffer."],
    ['params', QUERY_HINT],
    ['query', QUERY_HINT],
    ['searchParams', QUERY_HINT],
    ['agent', TLS_HINT],
    ['ca', TLS_HINT],
    ['tls', TLS_HINT],
    ['rejectUnauthorized', `${NO_VERIFY_OFF} the 'tls' option of the client constructor.`],
    ['http2', " 'http2' is an option of the client constructor, not of a request."],
    ['userAgent', " Set a 'user-agent' header, or 'userAgent' in the client constructor."],
]);
const perRequestOnly = (key: string) => ` '${key}' is a per-request option, not a client option.`;
const CLIENT_OPTION_HINTS = new Map<string, string>([
    ['timeout', TIMEOUT_HINT],
    ['baseURL', " Use 'baseUrl'."],
    ['prefixUrl', " Use 'baseUrl'."],
    ['rejectUnauthorized', `${NO_VERIFY_OFF} tls: { ca }.`],
    ['ca', " Pass it as tls: { ca }."],
    ['cert', " Pass it as tls: { cert }."],
    ['key', " Pass it as tls: { key }."],
    ['agent', " Every client has its own connection pool; TLS is configured with the 'tls' option."],
    ['isolatePool', " Every client has its own connection pool."],
    ['tlsSettings', " Use 'tls' ({ ca, cert, key })."],
    ['signal', perRequestOnly('signal')],
    ['auth', perRequestOnly('auth')],
    ['json', perRequestOnly('json')],
    ['body', perRequestOnly('body')],
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

/** The request options a client supplies when a request leaves them `undefined`. Headers are already sanitized (lowercase keys). */
export interface ClientDefaults {
    readonly headers: Readonly<Record<string, string | string[]>>;
    readonly timeoutMs?: number;
    readonly socketTimeoutMs?: number;
    readonly maxBodySize?: number;
    readonly maxRedirects?: number;
    readonly permitReservedIps?: ReservedIpPolicy;
}

/** `new UltraTonClient(options)` once validated. */
export interface ResolvedClientOptions {
    /** Normalized: no query or fragment, and the path ends with '/'. */
    readonly baseUrl?: URL;
    readonly http2: boolean;
    readonly tls: TlsOptions;
    readonly defaults: ClientDefaults;
}

function tlsMaterial(propName: string, value: unknown): TlsMaterial | undefined {
    if (value === undefined) return undefined;
    const isPem = (v: unknown) => typeof v === 'string' || Buffer.isBuffer(v);
    if (isPem(value)) return value as string | Buffer;
    if (Array.isArray(value) && value.every(isPem)) return [...value] as Array<string | Buffer>;
    throw new TypeError(`UltraTon: Expected '${propName}' to be a string, Buffer or an array of them, received ${value === null ? 'null' : typeof value}.`);
}

/**
 * Only `ca`, `cert` and `key` can ever reach the TLS layer: anything else (`rejectUnauthorized`, `servername`,
 * `checkServerIdentity`, ...) could weaken certificate verification, so it throws.
 */
function tlsOptions(value: unknown): TlsOptions {
    if (!validateType('tls', value, 'object')) return {};
    const raw = value as Record<string, unknown>;
    for (const key of Object.keys(raw)) {
        if ((TLS_OPTION_KEYS as readonly string[]).includes(key)) continue;
        const hint = key === 'rejectUnauthorized' ? `${NO_VERIFY_OFF} tls: { ca }.` : ` Valid tls options: ${TLS_OPTION_KEYS.join(', ')}.`;
        throw new TypeError(`UltraTon: Unknown tls option '${key}'.${hint}`);
    }
    const tls: { ca?: TlsMaterial; cert?: TlsMaterial; key?: TlsMaterial } = {};
    for (const key of TLS_OPTION_KEYS) {
        const material = tlsMaterial(`tls.${key}`, raw[key]);
        if (material !== undefined) tls[key] = material;
    }
    return tls;
}

/**
 * Validates `new UltraTonClient(options)` with the same rules as a request: unknown keys throw (with hints), and so do
 * values of the wrong type. The defaults go through the request firewall once here, so a bad header or allowlist fails
 * at construction, and an allowlist is copied and frozen so the caller cannot widen it later.
 * Symbol keys (the internal test seams) are not options: `Object.keys` skips them and the client reads them itself.
 * @param defaultUserAgent - Sent as `user-agent` unless `userAgent` or a `user-agent` header is given.
 * @throws {TypeError} On an unknown key, a value of the wrong type, CRLF in a header, or a `tls` key other than ca/cert/key.
 * @throws {SecureHttpError} When `baseUrl` fails `parseSafeUrl` (protocol, credentials, malformed).
 */
export function resolveClientOptions(options: unknown, defaultUserAgent: string): ResolvedClientOptions {
    if (options === undefined) options = {};
    if (typeof options !== 'object' || options === null || Array.isArray(options)) {
        throw new TypeError('UltraTon: Client options must be an object.');
    }
    const raw = options as Record<string, unknown>;
    for (const key of Object.keys(raw)) {
        if (CLIENT_KEYS.has(key)) continue;
        const hint = CLIENT_OPTION_HINTS.get(key) ?? ` Valid options: ${CLIENT_OPTION_KEYS.join(', ')}.`;
        throw new TypeError(`UltraTon: Unknown option '${key}'.${hint}`);
    }

    const safe = buildSafeRequestOptions({
        headers: raw.headers as InternalRequestOptions['headers'],
        timeoutMs: raw.timeoutMs as number | undefined,
        socketTimeoutMs: raw.socketTimeoutMs as number | undefined,
        maxBodySize: raw.maxBodySize as number | undefined,
        maxRedirects: raw.maxRedirects as number | undefined,
        permitReservedIps: raw.permitReservedIps as ReservedIpPolicy | undefined,
    });

    // sanitizeHeaders never keeps an undefined value.
    const headers = { ...safe.headers } as Record<string, string | string[]>;
    validateType('userAgent', raw.userAgent, 'string');
    if (Object.hasOwn(headers, 'user-agent')) {
        if (raw.userAgent !== undefined) {
            throw new TypeError("UltraTon: Set the user agent with either 'userAgent' or a 'user-agent' header, not both.");
        }
    } else {
        Object.assign(headers, sanitizeHeaders({ 'user-agent': raw.userAgent ?? defaultUserAgent }));
    }

    const http2 = validateType('http2', raw.http2, 'boolean') && raw.http2 === true;
    const tls = tlsOptions(raw.tls);

    let baseUrl: URL | undefined;
    if (validateType('baseUrl', raw.baseUrl, 'string')) {
        baseUrl = parseSafeUrl(raw.baseUrl as string);
        if (baseUrl.search !== '' || baseUrl.hash !== '') {
            throw new TypeError("UltraTon: 'baseUrl' cannot contain a query string or fragment.");
        }
        // An empty '?' or '#' parses to '' but stays in href: clear both so href is exactly origin + path.
        baseUrl.search = '';
        baseUrl.hash = '';
        // With the trailing slash, href is a prefix only of URLs inside the base path ('/v1/' never matches '/v1-admin').
        if (!baseUrl.pathname.endsWith('/')) baseUrl.pathname += '/';
    }

    return {
        baseUrl,
        http2,
        tls,
        defaults: {
            headers,
            // Type-checked above. Kept as given, so an out-of-range value falls back exactly as it would on a request.
            timeoutMs: raw.timeoutMs as number | undefined,
            socketTimeoutMs: raw.socketTimeoutMs as number | undefined,
            maxBodySize: raw.maxBodySize as number | undefined,
            maxRedirects: raw.maxRedirects as number | undefined,
            permitReservedIps: raw.permitReservedIps === undefined ? undefined : safe.permitReservedIps,
        },
    };
}

/**
 * Fills in what a request left `undefined` from the client defaults, key by key. Headers merge case-insensitively and
 * the request wins; a request header set to `undefined` keeps the default, like any other option. Run it after
 * `resolveRequestBody`, so the caller's own options are what gets checked for unknown keys and `json`/`body`.
 */
export function mergeClientDefaults(options: ResolvedRequestOptions, defaults: ClientDefaults): ResolvedRequestOptions {
    return {
        ...options,
        headers: mergeHeaders(defaults.headers, options.headers),
        timeoutMs: options.timeoutMs ?? defaults.timeoutMs,
        socketTimeoutMs: options.socketTimeoutMs ?? defaults.socketTimeoutMs,
        maxBodySize: options.maxBodySize ?? defaults.maxBodySize,
        maxRedirects: options.maxRedirects ?? defaults.maxRedirects,
        permitReservedIps: options.permitReservedIps ?? defaults.permitReservedIps,
    };
}

function mergeHeaders(defaults: ClientDefaults['headers'], own: unknown): ResolvedRequestOptions['headers'] {
    if (own === undefined) return { ...defaults };
    // Not a plain object: leave it for buildSafeRequestOptions to reject with the usual message.
    if (typeof own !== 'object' || own === null || Array.isArray(own)) return own as ResolvedRequestOptions['headers'];
    const map = own as Record<string, unknown>;
    // No prototype: a '__proto__' key from the caller stays a plain key (which sanitizeHeaders then drops).
    const merged: Record<string, unknown> = Object.assign(Object.create(null), defaults);
    for (const key of Object.keys(map)) {
        if (map[key] === undefined) continue;
        // Default keys are lowercase; the request's own key keeps its case so error messages name it as written.
        delete merged[key.toLowerCase()];
        merged[key] = map[key];
    }
    return merged as ResolvedRequestOptions['headers'];
}
