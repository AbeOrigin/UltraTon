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

/**
 * A non-negative integer up to `max` (INT32_MAX by default, the most a timer accepts), or `fallback` when `undefined`.
 * @throws {TypeError} For a wrong type, and for a negative, fractional or too large number, naming the allowed range:
 *   an out-of-range value is a mistake to report, never something to replace silently with the default.
 */
function intOption(propName: string, value: unknown, fallback: number, max = INT32_MAX): number {
    if (!validateType(propName, value, 'number')) return fallback;
    const n = value as number;
    if (!Number.isInteger(n) || n < 0 || n > max) {
        throw new TypeError(`UltraTon: Expected '${propName}' to be an integer from 0 to ${max}, received ${n}.`);
    }
    return n;
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
 * Only a plain object is read as headers: a `Headers` or `Map` keeps its entries out of reach of `Object.keys`, so it
 * would otherwise be sent as no headers at all (an `authorization` silently dropped).
 * @throws {TypeError} For any object whose prototype is neither `Object.prototype` nor `null`.
 */
function assertPlainHeaders(headers: unknown): void {
    if (isPlainObject(headers)) return;
    const ctor: unknown = (Object.getPrototypeOf(headers) as { constructor?: unknown } | null)?.constructor;
    const name = typeof ctor === 'function' && ctor.name ? ctor.name : 'non-plain';
    throw new TypeError(`UltraTon: Expected 'headers' to be a plain object, received a ${name} instance; pass a plain object, e.g. Object.fromEntries(headers).`);
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
const REQUEST_OPTION_KEYS = ['headers', 'query', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'maxRedirects', 'permitReservedIps', 'signal', 'auth', 'json', 'body'];
/** What buildSafeRequestOptions accepts: the options above plus the `method` the client methods set internally. */
const ACCEPTED_KEYS = new Set([...REQUEST_OPTION_KEYS, 'method']);

/** The options of `new UltraTonClient(options)`. */
const CLIENT_OPTION_KEYS = ['baseUrl', 'headers', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'maxRedirects', 'permitReservedIps', 'http2', 'tls', 'userAgent'];
const CLIENT_KEYS = new Set(CLIENT_OPTION_KEYS);
const TLS_OPTION_KEYS = ['ca', 'cert', 'key'] as const;

const QUERY_HINT = " Use 'query'.";
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
    ['query', perRequestOnly('query')],
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

/** An object whose prototype is `Object.prototype` or `null`: not an array, a class instance, a Map or a Headers. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null) return false;
    const proto: unknown = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}

/**
 * A copy of the object's own enumerable properties on a null-prototype object. Every options object is read through
 * one: a property inherited from a polluted `Object.prototype` (`baseUrl`, `tls`, `permitReservedIps`, `auth`, ...)
 * must never be taken for an option.
 * @throws {TypeError} If the object is not plain (its prototype is neither `Object.prototype` nor `null`): a class
 *   instance or `Object.create(proto)` keeps options in getters or on its prototype, which would otherwise be dropped
 *   silently (a `get http2() { return true }` giving an HTTP/1 client).
 */
function ownOptions<T extends object>(options: T): T {
    if (!isPlainObject(options)) {
        throw new TypeError('UltraTon: Options must be a plain object.');
    }
    const own = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(options)) own[key] = (options as Record<string, unknown>)[key];
    return own as T;
}

/**
 * Builds the options of one request from what a client method (`get`, `post`, ...) received: the caller's options object
 * plus the method. A caller-supplied `method` throws instead of being silently overridden, and so does an `options` that
 * is not an object (typically the old `post(url, body)` call shape).
 */
export function withMethod(method: string, options: unknown): InternalRequestOptions {
    if (options === undefined) return ownOptions({ method });
    if (typeof options !== 'object' || options === null || Array.isArray(options)) {
        throw new TypeError("UltraTon: 'options' must be an object. Send a request body with { json } or { body }.");
    }
    if (Object.hasOwn(options, 'method')) {
        throw new TypeError("UltraTon: Unknown option 'method'. The HTTP method is set by the client method you call (get, post, put, patch, delete, head, options).");
    }
    // Copied from the caller's object itself, so a non-plain one is refused before a spread could flatten it.
    return Object.assign(ownOptions(options), { method });
}

/**
 * Validates the caller's body options and resolves them into the bytes that go on the wire: `json` is serialized, a
 * string/Uint8Array `body` becomes a Buffer. Run it on the user-supplied options, before any internal enrichment; the
 * content-type of a `json` body is added after the client defaults are merged (see withJsonContentType).
 * @throws {TypeError} On an unknown option, `json` together with `body`, a `body` of the wrong type or a `json` that cannot be serialized.
 */
export function resolveRequestBody(options: InternalRequestOptions): ResolvedRequestOptions {
    options = ownOptions(options);
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

    return { ...rest, body: Buffer.from(serialized) };
}

/**
 * Adds `content-type: application/json` for a `json` body, unless the headers already carry a content-type. Run it on
 * the options merged with the client defaults, so a client default content-type (`application/vnd.api+json`) is kept
 * and a request's own one wins over both. Headers that are not a plain object are left for buildSafeRequestOptions to reject.
 */
export function withJsonContentType(options: ResolvedRequestOptions): ResolvedRequestOptions {
    const headers: unknown = options.headers;
    if (headers === undefined) return { ...options, headers: { 'content-type': 'application/json' } };
    if (!isPlainObject(headers)) return options;
    const map = headers as Record<string, unknown>;
    const hasContentType = Object.keys(map).some(key => key.toLowerCase() === 'content-type' && map[key] !== undefined);
    if (hasContentType) return options;
    return { ...options, headers: { ...map, 'content-type': 'application/json' } as ResolvedRequestOptions['headers'] };
}

const describeValue = (value: unknown): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'an array';
    if (typeof value === 'number') return String(value);
    if (typeof value === 'object') return `a ${(Object.getPrototypeOf(value) as { constructor?: { name?: string } } | null)?.constructor?.name ?? 'null-prototype object'}`;
    return typeof value;
};

function queryValue(key: string, value: unknown): string {
    if (typeof value === 'string') return value;
    if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return String(value);
    throw new TypeError(`UltraTon: Expected query parameter '${key}' to be a string, a finite number or a boolean, received ${describeValue(value)}.`);
}

/**
 * Appends the `query` option to a request URL. Values are encoded with URLSearchParams (spaces as '+'), an array repeats
 * its key, an `undefined` value is skipped. The URL's own query is kept byte for byte: the new pairs are appended to it,
 * never re-serialized with it. Encoded values can only ever land in the query, so they cannot change the path (baseUrl
 * is checked on the path before this runs) or add a fragment.
 * @throws {TypeError} If `query` is not a plain object or URLSearchParams, or a value is not a string, a finite number
 *   or a boolean (`null`, nested objects and arrays inside arrays included). A malformed URL is left for the engine to reject.
 */
export function withQuery(url: string, query: unknown): string {
    if (query === undefined) return url;
    let params: URLSearchParams;
    if (query instanceof URLSearchParams) {
        params = query;
    } else if (isPlainObject(query)) {
        params = new URLSearchParams();
        for (const key of Object.keys(query)) {
            const value = query[key];
            if (value === undefined) continue;
            for (const item of Array.isArray(value) ? value : [value]) params.append(key, queryValue(key, item));
        }
    } else {
        throw new TypeError(`UltraTon: Expected 'query' to be a plain object or URLSearchParams, received ${describeValue(query)}.`);
    }
    const extra = params.toString();
    if (extra === '' || !URL.canParse(url)) return url;
    const target = new URL(url);
    target.search = target.search.length > 1 ? `${target.search.slice(1)}&${extra}` : extra;
    return target.href;
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
    options = ownOptions(options);
    assertKnownOptions(options);
    assertBodyOptions(options);

    // No prototype either: an option it leaves out (auth, signal, headers) reads as undefined, never as an inherited value.
    const safeOptions: Record<string, unknown> = Object.create(null);

    if (validateType('method', options.method, 'string')) safeOptions.method = options.method;
    if (validateType('auth', options.auth, 'string')) safeOptions.auth = options.auth;
    if (options.signal !== undefined) {
        // Anything else would only fail later, deep in the engine, with an unrelated message (or never abort).
        if (!(options.signal instanceof AbortSignal)) {
            const received = options.signal === null ? 'null' : typeof options.signal;
            throw new TypeError(`UltraTon: Expected 'signal' to be an AbortSignal, received ${received}.`);
        }
        safeOptions.signal = options.signal;
    }
    if (validateType('headers', options.headers, 'object')) {
        assertPlainHeaders(options.headers);
        safeOptions.headers = sanitizeHeaders(options.headers as Record<string, unknown>);
    }

    // Defaults when unset: 2MB body, 10s idle, 30s total, no redirects. 0 disables the two timeouts.
    safeOptions.maxBodySize = intOption('maxBodySize', options.maxBodySize, 2 * 1024 * 1024);
    safeOptions.socketTimeoutMs = intOption('socketTimeoutMs', options.socketTimeoutMs, 10_000);
    safeOptions.timeoutMs = intOption('timeoutMs', options.timeoutMs, 30_000);
    safeOptions.maxRedirects = intOption('maxRedirects', options.maxRedirects, 0, MAX_REDIRECTS_CEILING);
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
    const raw = ownOptions(value as Record<string, unknown>);
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
    const raw = ownOptions(options as Record<string, unknown>);
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
            // Validated above (type and range). Kept as given, so `undefined` still means "use the request's own default".
            timeoutMs: raw.timeoutMs as number | undefined,
            socketTimeoutMs: raw.socketTimeoutMs as number | undefined,
            maxBodySize: raw.maxBodySize as number | undefined,
            maxRedirects: raw.maxRedirects as number | undefined,
            permitReservedIps: raw.permitReservedIps === undefined ? undefined : safe.permitReservedIps,
        },
    };
}

/**
 * Fills in what a request left `undefined` from the client defaults, key by key. Only `undefined` falls back: `null`
 * (or any other wrong type) stays and is rejected by the request firewall. Headers merge case-insensitively and the
 * request wins; a request header set to `undefined` keeps the default, like any other option. Run it after
 * `resolveRequestBody`, so the caller's own options are what gets checked for unknown keys and `json`/`body`.
 * Every option is an own property of the result (`undefined` when unset), so later copies with `{ ...spread }` never
 * fall through to `Object.prototype`.
 */
export function mergeClientDefaults(options: ResolvedRequestOptions, defaults: ClientDefaults): ResolvedRequestOptions {
    const own = ownOptions(options);
    const or = <V>(value: V | undefined, fallback: V | undefined) => (value === undefined ? fallback : value);
    return {
        method: own.method,
        headers: mergeHeaders(defaults.headers, own.headers),
        timeoutMs: or(own.timeoutMs, defaults.timeoutMs),
        socketTimeoutMs: or(own.socketTimeoutMs, defaults.socketTimeoutMs),
        maxBodySize: or(own.maxBodySize, defaults.maxBodySize),
        maxRedirects: or(own.maxRedirects, defaults.maxRedirects),
        permitReservedIps: or(own.permitReservedIps, defaults.permitReservedIps),
        signal: own.signal,
        auth: own.auth,
        body: own.body,
    };
}

function mergeHeaders(defaults: ClientDefaults['headers'], own: unknown): ResolvedRequestOptions['headers'] {
    if (own === undefined) return { ...defaults };
    // Not a plain object (a Headers or Map included, whose entries Object.keys cannot see): leave it for
    // buildSafeRequestOptions to reject with the usual message instead of merging it as if it were empty.
    if (!isPlainObject(own)) return own as ResolvedRequestOptions['headers'];
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
