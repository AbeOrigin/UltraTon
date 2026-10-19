import { isIP } from "node:net";
import type { UltraTonRequestOptions, SecureUltraTonRequestOptions, ReservedIpPolicy } from "../types/request-options.types.ts";
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

/**
 * Acts as an absolute firewall between the user's input and the native Node.js HTTP stack.
 * Extracts ONLY explicitly approved properties. Drops all potential socket injections
 * and enforces strict runtime primitive types to prevent C++ thread exhaustion or V8 crashes.
 * Throws TypeError synchronously on malformed security primitives to fail loud.
 */
export function buildSafeRequestOptions(options: UltraTonRequestOptions): SecureUltraTonRequestOptions {
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