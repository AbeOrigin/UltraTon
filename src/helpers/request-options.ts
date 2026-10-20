import { ACCEPT_ENCODING } from './body-reader.ts';
import { isIP } from "node:net";
import type { InternalRequestOptions, ResolvedRequestOptions, SecureUltraTonRequestOptions, ReservedIpPolicy, TlsMaterial, TlsOptions, UltraTonRetryInfo } from "../types/request-options.types.ts";
import { DEFAULT_TIMEOUT_MS, MAX_REDIRECTS_CEILING } from "../constants.ts";
import { parseSafeUrl } from "./url-parser.ts";
import type { ProxyConfig } from "../proxy/tunnel.ts";
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
const REQUEST_OPTION_KEYS = ['headers', 'query', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'decompress', 'maxRedirects', 'permitReservedIps', 'signal', 'auth', 'json', 'form', 'body', 'retry'];
/** What buildSafeRequestOptions accepts: the options above plus the `method` the client methods set internally. */
const ACCEPTED_KEYS = new Set([...REQUEST_OPTION_KEYS, 'method']);

/** The options of `new UltraTonClient(options)`. */
const CLIENT_OPTION_KEYS = ['baseUrl', 'headers', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'decompress', 'maxRedirects', 'permitReservedIps', 'retry', 'http2', 'tls', 'userAgent', 'proxy'];
const CLIENT_KEYS = new Set(CLIENT_OPTION_KEYS);
const TLS_OPTION_KEYS = ['ca', 'cert', 'key'] as const;

const QUERY_HINT = " Use 'query'.";
const TLS_HINT = " TLS is configured with the 'tls' option of the client constructor.";
const BASE_URL_HINT = " 'baseUrl' is an option of the client constructor, not of a request.";
const TIMEOUT_HINT = " Use 'timeoutMs' (milliseconds).";
const RETRY_OPTION_KEYS = ['limit', 'methods', 'statusCodes', 'maxDelayMs', 'onRetry'];
const RETRY_HINT = ` Use 'retry': a number of retries, or { ${RETRY_OPTION_KEYS.join(', ')} }.`;
const NO_VERIFY_OFF = " Disabling certificate verification is not supported; to trust a private CA use";
// Maps, not objects: an option named 'constructor' or '__proto__' must not find a hint through the prototype chain.
const OPTION_HINTS = new Map<string, string>([
    ['timeout', TIMEOUT_HINT],
    ['retries', RETRY_HINT],
    ['maxRetries', RETRY_HINT],
    ['baseURL', BASE_URL_HINT],
    ['prefixUrl', BASE_URL_HINT],
    ['baseUrl', BASE_URL_HINT],
    ['data', " Use 'json' for a JSON payload, 'form' for urlencoded fields or 'body' for a string, Buffer, Blob, FormData or URLSearchParams."],
    ['params', QUERY_HINT],
    ['searchParams', QUERY_HINT],
    ['agent', TLS_HINT],
    ['ca', TLS_HINT],
    ['tls', TLS_HINT],
    ['rejectUnauthorized', `${NO_VERIFY_OFF} the 'tls' option of the client constructor.`],
    ['http2', " 'http2' is an option of the client constructor, not of a request."],
    ['userAgent', " Set a 'user-agent' header, or 'userAgent' in the client constructor."],
    ['proxy', " 'proxy' is an option of the client constructor, not of a request."],
]);
const perRequestOnly = (key: string) => ` '${key}' is a per-request option, not a client option.`;
const CLIENT_OPTION_HINTS = new Map<string, string>([
    ['timeout', TIMEOUT_HINT],
    ['retries', RETRY_HINT],
    ['maxRetries', RETRY_HINT],
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
    ['form', perRequestOnly('form')],
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

const isBody = (body: unknown): boolean => typeof body === 'string' || body instanceof Uint8Array
    || body instanceof Blob || body instanceof FormData || body instanceof URLSearchParams;

/** @throws {TypeError} If more than one of `json`, `form` and `body` is set, or `body` is of a type it cannot be. */
function assertBodyOptions(options: { json?: unknown; form?: unknown; body?: unknown }): void {
    if ([options.json, options.form, options.body].filter(value => value !== undefined).length > 1) {
        throw new TypeError("UltraTon: Use only one of 'json', 'form' or 'body'.");
    }
    if (options.body !== undefined && !isBody(options.body)) {
        throw new TypeError(`UltraTon: Expected 'body' to be a string, Buffer, Uint8Array, Blob, FormData or URLSearchParams, received ${describeValue(options.body)}. Use 'json' to send an object.`);
    }
}

const hasContentType = (headers: unknown): boolean => isPlainObject(headers)
    && Object.keys(headers).some(key => key.toLowerCase() === 'content-type' && headers[key] !== undefined);

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
        throw new TypeError("UltraTon: 'options' must be an object. Send a request body with { json }, { form } or { body }.");
    }
    if (Object.hasOwn(options, 'method')) {
        throw new TypeError("UltraTon: Unknown option 'method'. The HTTP method is set by the client method you call (get, post, put, patch, delete, head, options).");
    }
    // Copied from the caller's object itself, so a non-plain one is refused before a spread could flatten it.
    return Object.assign(ownOptions(options), { method });
}

const FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded;charset=UTF-8';

/**
 * A request whose body is resolved to bytes. `contentType` is the one a form, URLSearchParams, FormData or typed Blob
 * implies, set by withBodyContentType; it is left out when the request sets its own (a `json` body has its own rule).
 */
export interface ResolvedBody {
    readonly options: ResolvedRequestOptions;
    readonly contentType?: string;
}

/**
 * Validates the caller's body options and resolves them into the bytes that go on the wire: `json` is serialized,
 * `form` urlencoded, a string/Uint8Array `body` becomes a Buffer and a Blob, FormData or URLSearchParams is encoded by
 * the platform's Response (a FormData's multipart boundary included), all of it buffered. Run it on the user-supplied
 * options, before any internal enrichment; the content-type is added after the client defaults are merged (see
 * withJsonContentType and withBodyContentType).
 * @throws {TypeError} On an unknown option, more than one of `json`/`form`/`body`, a body on GET or HEAD, a `body` or
 *   `form` of the wrong type, a `json` that cannot be serialized, or a FormData sent with a content-type of its own.
 */
export async function resolveRequestBody(options: InternalRequestOptions): Promise<ResolvedBody> {
    options = ownOptions(options);
    assertKnownOptions(options);
    assertBodyOptions(options);
    const { json, form, body, ...rest } = options;
    if (json === undefined && form === undefined && body === undefined) return { options: rest };
    if (options.method === 'GET' || options.method === 'HEAD') {
        throw new TypeError('UltraTon: GET and HEAD requests cannot have a body.');
    }

    if (form !== undefined) {
        const encoded = Buffer.from(searchParams('form', 'form field', form).toString());
        return { options: { ...rest, body: encoded }, contentType: hasContentType(rest.headers) ? undefined : FORM_CONTENT_TYPE };
    }
    if (typeof body === 'string' || body instanceof Uint8Array) {
        return { options: { ...rest, body: Buffer.isBuffer(body) ? body : Buffer.from(body) } };
    }
    if (body !== undefined) {
        if (body instanceof FormData && hasContentType(rest.headers)) {
            throw new TypeError("UltraTon: A FormData body sets its own content-type (with the multipart boundary); remove the 'content-type' header.");
        }
        // A Blob may be a whole file: an already aborted request must not read it into memory first.
        if (options.signal instanceof AbortSignal) options.signal.throwIfAborted();
        // ponytail: a subclass that overrides iteration or toString shapes its own bytes; it is the caller's body anyway.
        const encoded = new Response(body);
        const contentType = hasContentType(rest.headers) ? undefined : encoded.headers.get('content-type') ?? undefined;
        return { options: { ...rest, body: Buffer.from(await encoded.arrayBuffer()) }, contentType };
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

    return { options: { ...rest, body: Buffer.from(serialized) } };
}

const STREAM_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

/**
 * Takes `method` and `maxBodySize` out of the options of `client.stream()`, validated. The rest goes through the usual
 * request firewall; `maxBodySize` stays out of it because a stream may go past the 2 GiB a buffered body is held to.
 * @throws {TypeError} If the method is not one of STREAM_METHODS (uppercase) or maxBodySize is not a safe integer >= 0.
 */
export function splitStreamOptions(options: unknown): { method: string; maxBodySize?: number; rest: unknown } {
    // Not an object: left for withMethod to reject with its usual message.
    if (typeof options !== 'object' || options === null || Array.isArray(options)) return { method: 'GET', rest: options };
    const own = ownOptions(options as Record<string, unknown>);
    const { method = 'GET', maxBodySize, ...rest } = own;
    if (typeof method !== 'string' || !STREAM_METHODS.includes(method)) {
        throw new TypeError(`UltraTon: Expected 'method' to be one of ${STREAM_METHODS.join(', ')}, received ${describeValue(method)}.`);
    }
    if (maxBodySize !== undefined && !(Number.isSafeInteger(maxBodySize) && (maxBodySize as number) >= 0)) {
        throw new TypeError(`UltraTon: Expected 'maxBodySize' to be an integer from 0 to ${Number.MAX_SAFE_INTEGER}, received ${describeValue(maxBodySize)}.`);
    }
    return { method, maxBodySize: maxBodySize as number | undefined, rest };
}

/** A `retry` option once validated: only what the caller set, lists copied and frozen. Merged and defaulted by retry.ts. */
export interface RetryInput {
    readonly limit?: number;
    readonly methods?: readonly string[];
    readonly statusCodes?: readonly number[];
    readonly maxDelayMs?: number;
    readonly onRetry?: (info: UltraTonRetryInfo) => void;
}

/** The most retries a request can make: bounded, so a server answering 503 forever costs at most 11 requests. */
const MAX_RETRIES = 10;

function listOption<T>(name: string, value: unknown, valid: (entry: unknown) => boolean, expected: string): readonly T[] {
    if (!Array.isArray(value)) throw new TypeError(`UltraTon: Expected '${name}' to be ${expected}, received ${describeValue(value)}.`);
    for (const entry of value) {
        if (!valid(entry)) {
            const received = typeof entry === 'string' ? `'${entry}'` : describeValue(entry);
            throw new TypeError(`UltraTon: Expected '${name}' to be ${expected}, received ${received}.`);
        }
    }
    return Object.freeze([...value] as T[]);
}

/**
 * Validates `retry`, of a client or a request: a number of retries (0 to MAX_RETRIES), or a plain object with only the
 * fields of RETRY_OPTION_KEYS. Lists are copied and frozen, so the caller cannot change them afterwards.
 * @throws {TypeError} On any other type, an unknown field, or a field of the wrong type or range.
 */
export function retryOption(value: unknown): RetryInput | undefined {
    if (value === undefined) return undefined;
    if (typeof value === 'number') return Object.freeze({ limit: intOption('retry', value, 0, MAX_RETRIES) });
    if (!isPlainObject(value)) {
        throw new TypeError(`UltraTon: Expected 'retry' to be a number or a plain object, received ${describeValue(value)}.`);
    }
    const raw = ownOptions(value);
    for (const key of Object.keys(raw)) {
        if (!RETRY_OPTION_KEYS.includes(key)) {
            throw new TypeError(`UltraTon: Unknown retry option '${key}'. Valid retry options: ${RETRY_OPTION_KEYS.join(', ')}.`);
        }
    }
    const retry: { -readonly [K in keyof RetryInput]: RetryInput[K] } = {};
    if (raw.limit !== undefined) retry.limit = intOption('retry.limit', raw.limit, 0, MAX_RETRIES);
    if (raw.maxDelayMs !== undefined) retry.maxDelayMs = intOption('retry.maxDelayMs', raw.maxDelayMs, 0);
    if (raw.methods !== undefined) {
        retry.methods = listOption('retry.methods', raw.methods, m => typeof m === 'string' && STREAM_METHODS.includes(m), `an array of ${STREAM_METHODS.join(', ')}`);
    }
    if (raw.statusCodes !== undefined) {
        retry.statusCodes = listOption('retry.statusCodes', raw.statusCodes, c => Number.isInteger(c) && (c as number) >= 400 && (c as number) <= 599, 'an array of integers from 400 to 599');
    }
    if (raw.onRetry !== undefined) {
        if (typeof raw.onRetry !== 'function') throw new TypeError(`UltraTon: Expected 'retry.onRetry' to be a function, received ${describeValue(raw.onRetry)}.`);
        retry.onRetry = raw.onRetry as RetryInput['onRetry'];
    }
    return Object.freeze(retry);
}

/**
 * Adds the default `accept-encoding` (every coding the body reader can decode) unless `decompress` is `false` or the
 * headers already carry one. Run it on the options merged with the client defaults, like withJsonContentType.
 */
export function withAcceptEncoding(options: ResolvedRequestOptions): ResolvedRequestOptions {
    if (options.decompress === false) return options;
    const headers: unknown = options.headers;
    if (headers !== undefined && !isPlainObject(headers)) return options;
    const map = (headers ?? {}) as Record<string, unknown>;
    if (Object.keys(map).some(key => key.toLowerCase() === 'accept-encoding' && map[key] !== undefined)) return options;
    return { ...options, headers: { ...map, 'accept-encoding': ACCEPT_ENCODING } as ResolvedRequestOptions['headers'] };
}

/**
 * Adds `content-type: application/json` for a `json` body, unless the headers already carry a content-type. Run it on
 * the options merged with the client defaults, so a client default content-type (`application/vnd.api+json`) is kept
 * and a request's own one wins over both. Headers that are not a plain object are left for buildSafeRequestOptions to reject.
 */
export function withJsonContentType(options: ResolvedRequestOptions): ResolvedRequestOptions {
    const headers: unknown = options.headers;
    if (headers === undefined) return { ...options, headers: { 'content-type': 'application/json' } };
    if (!isPlainObject(headers) || hasContentType(headers)) return options;
    return { ...options, headers: { ...headers, 'content-type': 'application/json' } as ResolvedRequestOptions['headers'] };
}

/**
 * Sets the content-type a form, URLSearchParams, FormData or typed Blob implies (see ResolvedBody), over a client default
 * one: unlike `json`, a client-wide content-type cannot fit these bodies (a multipart needs its boundary). Run it on the
 * options merged with the client defaults; the request's own content-type, if any, already left `contentType` unset.
 * Client default keys are lowercase, so 'content-type' replaces one.
 */
export function withBodyContentType(options: ResolvedRequestOptions, contentType: string | undefined): ResolvedRequestOptions {
    const headers: unknown = options.headers;
    if (contentType === undefined || (headers !== undefined && !isPlainObject(headers))) return options;
    return { ...options, headers: { ...headers as object, 'content-type': contentType } as ResolvedRequestOptions['headers'] };
}

const describeValue = (value: unknown): string => {
    if (value === null) return 'null';
    if (Array.isArray(value)) return 'an array';
    if (typeof value === 'number') return String(value);
    if (typeof value === 'object') {
        const name = (Object.getPrototypeOf(value) as { constructor?: { name?: string } } | null)?.constructor?.name || 'null-prototype object';
        return `${/^[aeiou]/i.test(name) ? 'an' : 'a'} ${name}`;
    }
    return typeof value;
};

function pairValue(label: string, key: string, value: unknown): string {
    if (typeof value === 'string') return value;
    if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return String(value);
    throw new TypeError(`UltraTon: Expected ${label} '${key}' to be a string, a finite number or a boolean, received ${describeValue(value)}.`);
}

/**
 * The pairs of a `query` or `form` option. An array repeats its key, an `undefined` value is skipped and symbol keys are
 * ignored, like Object.keys ignores them. A URLSearchParams from another realm (vm, worker) is accepted through its
 * string form, re-parsed so a spoofed toStringTag can only ever yield ordinary encoded pairs.
 * @throws {TypeError} If the option is not a plain object or URLSearchParams, or a value is not a string, a finite
 *   number or a boolean (`null`, nested objects and arrays inside arrays included).
 */
function searchParams(option: 'query' | 'form', label: string, value: unknown): URLSearchParams {
    if (value instanceof URLSearchParams) return value;
    if (Object.prototype.toString.call(value) === '[object URLSearchParams]') return new URLSearchParams(String(value));
    if (!isPlainObject(value)) {
        throw new TypeError(`UltraTon: Expected '${option}' to be a plain object or URLSearchParams, received ${describeValue(value)}.`);
    }
    const params = new URLSearchParams();
    for (const key of Object.keys(value)) {
        const item = value[key];
        if (item === undefined) continue;
        for (const entry of Array.isArray(item) ? item : [item]) params.append(key, pairValue(label, key, entry));
    }
    return params;
}

/**
 * Appends the `query` option to a request URL, encoded with URLSearchParams (spaces as '+'; see searchParams). The URL's
 * own query is kept byte for byte: the new pairs are appended to it, never re-serialized with it. Encoded values can
 * only ever land in the query, so they cannot change the path (baseUrl is checked on the path before this runs) or add
 * a fragment.
 * @throws {TypeError} As searchParams. A malformed URL is left for the engine to reject.
 */
export function withQuery(url: string, query: unknown): string {
    if (query === undefined) return url;
    const extra = searchParams('query', 'query parameter', query).toString();
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
    safeOptions.decompress = validateType('decompress', options.decompress, 'boolean') ? options.decompress : true;
    safeOptions.maxBodySize = intOption('maxBodySize', options.maxBodySize, 2 * 1024 * 1024);
    safeOptions.socketTimeoutMs = intOption('socketTimeoutMs', options.socketTimeoutMs, 10_000);
    safeOptions.timeoutMs = intOption('timeoutMs', options.timeoutMs, DEFAULT_TIMEOUT_MS);
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
    readonly decompress?: boolean;
    readonly retry?: RetryInput;
}

/** `new UltraTonClient(options)` once validated. */
export interface ResolvedClientOptions {
    /** Normalized: no query or fragment, and the path ends with '/'. */
    readonly baseUrl?: URL;
    readonly http2: boolean;
    readonly tls: TlsOptions;
    readonly proxy?: ProxyConfig;
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

const PROXY_OPTION_KEYS = ['url', 'auth', 'ca', 'resolve'];

/**
 * `proxy` of the client: a URL string or { url, auth, ca, resolve }. The URL is operator configuration, so its host is
 * not held to `permitReservedIps` (a proxy is usually internal), but it must be a bare http(s) origin: credentials go
 * in `auth`, never in a URL that ends up in logs.
 * @throws {TypeError} On any other type, an unknown field, a URL that is not a bare http(s) origin, or a field of the wrong type.
 */
function proxyOption(value: unknown): ProxyConfig | undefined {
    if (value === undefined) return undefined;
    let raw: Record<string, unknown>;
    if (typeof value === 'string') {
        raw = { url: value };
    } else if (isPlainObject(value)) {
        raw = ownOptions(value);
        for (const key of Object.keys(raw)) {
            if (!PROXY_OPTION_KEYS.includes(key)) {
                throw new TypeError(`UltraTon: Unknown proxy option '${key}'. Valid proxy options: ${PROXY_OPTION_KEYS.join(', ')}.`);
            }
        }
        validateType('proxy.url', raw.url ?? null, 'string');
    } else {
        throw new TypeError(`UltraTon: Expected 'proxy' to be a URL string or a plain object, received ${describeValue(value)}.`);
    }

    const url = URL.canParse(raw.url as string) ? new URL(raw.url as string) : undefined;
    if (!url || !PROXY_SCHEMES.includes(url.protocol) || url.hostname === '') {
        throw new TypeError("UltraTon: Expected 'proxy' to be an http:, https:, socks5: or socks5h: URL, such as 'http://egress.corp:3128'.");
    }
    if (url.username !== '' || url.password !== '') {
        throw new TypeError("UltraTon: 'proxy' cannot contain credentials; pass them as proxy: { url, auth }.");
    }
    // A socks5: URL is not a special scheme, so its empty path stays '' where http's is '/'.
    if ((url.pathname !== '/' && url.pathname !== '') || url.search !== '' || url.hash !== '' || (raw.url as string).includes('?') || (raw.url as string).includes('#')) {
        throw new TypeError("UltraTon: 'proxy' must be an origin only (no path, query or fragment).");
    }
    if (raw.resolve !== undefined && raw.resolve !== 'local' && raw.resolve !== 'proxy') {
        const received = typeof raw.resolve === 'string' ? `'${raw.resolve}'` : describeValue(raw.resolve);
        throw new TypeError(`UltraTon: Expected 'proxy.resolve' to be 'local' or 'proxy', received ${received}.`);
    }
    const socks = url.protocol === 'socks5:' || url.protocol === 'socks5h:';
    // socks5h: is curl's spelling of "the proxy resolves the name", the same as resolve: 'proxy'.
    if (url.protocol === 'socks5h:' && raw.resolve === 'local') {
        throw new TypeError("UltraTon: A socks5h: proxy resolves names itself; use socks5: with resolve: 'local', or drop 'resolve'.");
    }
    validateType('proxy.auth', raw.auth, 'string');
    if (socks && raw.auth !== undefined) assertSocksAuth(raw.auth as string);
    if (socks && raw.ca !== undefined) {
        throw new TypeError("UltraTon: 'proxy.ca' only applies to an https: proxy; a SOCKS5 proxy has no TLS of its own.");
    }
    const ca = tlsMaterial('proxy.ca', raw.ca);
    return Object.freeze({
        url,
        kind: socks ? 'socks5' : 'connect',
        resolve: (url.protocol === 'socks5h:' ? 'proxy' : raw.resolve ?? 'local') as ProxyConfig['resolve'],
        ...(raw.auth !== undefined ? { auth: raw.auth as string } : {}),
        ...(ca !== undefined ? { ca } : {}),
    });
}

const PROXY_SCHEMES = ['http:', 'https:', 'socks5:', 'socks5h:'];

/**
 * SOCKS5 username/password authentication (RFC 1929) carries each part as 1 to 255 bytes after a length byte.
 * @throws {TypeError} When `auth` is not `user:password` with both parts in that range.
 */
function assertSocksAuth(auth: string): void {
    const colon = auth.indexOf(':');
    const user = colon === -1 ? auth : auth.slice(0, colon);
    const password = colon === -1 ? '' : auth.slice(colon + 1);
    for (const part of [user, password]) {
        const bytes = Buffer.byteLength(part);
        if (bytes < 1 || bytes > 255) {
            throw new TypeError("UltraTon: A SOCKS5 'proxy.auth' must be 'user:password', each part from 1 to 255 bytes.");
        }
    }
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
        decompress: raw.decompress as boolean | undefined,
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
    const proxy = proxyOption(raw.proxy);

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
        proxy,
        defaults: {
            headers,
            // Validated above (type and range). Kept as given, so `undefined` still means "use the request's own default".
            timeoutMs: raw.timeoutMs as number | undefined,
            socketTimeoutMs: raw.socketTimeoutMs as number | undefined,
            maxBodySize: raw.maxBodySize as number | undefined,
            maxRedirects: raw.maxRedirects as number | undefined,
            permitReservedIps: raw.permitReservedIps === undefined ? undefined : safe.permitReservedIps,
            decompress: raw.decompress as boolean | undefined,
            retry: retryOption(raw.retry),
        },
    };
}

/**
 * Fills in what a request left `undefined` from the client defaults, key by key. Only `undefined` falls back: `null`
 * (or any other wrong type) stays and is rejected by the request firewall. Headers merge case-insensitively and the
 * request wins; a request header set to `undefined` keeps the default, like any other option. Run it after
 * `resolveRequestBody`, so the caller's own options are what gets checked for unknown keys and `json`/`form`/`body`.
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
        decompress: or(own.decompress, defaults.decompress),
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
