import type { UltraTonRequestOptions, SecureUltraTonRequestOptions } from "../types/request-options.types.ts";
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

/**
 * Parses and strictly sanitizes headers.
 * 
 * @param rawHeaders - User input headers.
 * @throws {TypeError} Synchronously throws if CRLF injection is detected.
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
    safeOptions.permitReservedIps = validateType('permitReservedIps', options.permitReservedIps, 'boolean') && options.permitReservedIps;

    return safeOptions as unknown as SecureUltraTonRequestOptions;
}