import type { UltraTonRequestOptions, SecureUltraTonRequestOptions } from "../types/request-options.types.ts";

/**
 * Evaluates a runtime property against a strict primitive type boundary.
 * 
 * @param propName - The name of the property being evaluated (used for error contextualization).
 * @param value - The raw runtime value injected by the caller.
 * @param expectedType - The explicitly allowed primitive type.
 * @throws {TypeError} Synchronously throws if the value is defined but breaches the expected type.
 * @returns {boolean} `true` if the value exists and is valid. `false` if `undefined`.
 */
function validateType(propName: string, value: any, expectedType: 'string' | 'number' | 'object'): boolean {
    if (value === undefined) return false;

    let isValid = false;

    if (expectedType === 'string') {
        isValid = typeof value === 'string';
    } else if (expectedType === 'number') {
        isValid = typeof value === 'number' && !isNaN(value);
    } else if (expectedType === 'object') {
        isValid = typeof value === 'object' && value !== null && !Array.isArray(value);
    }

    if (!isValid) {
        throw new TypeError(`UltraTon: Expected '${propName}' to be a ${expectedType}, received ${typeof value}`);
    }

    return true;
}

/**
 * Parses and strictly sanitizes headers.
 * 
 * @param rawHeaders - User input headers.
 * @throws {TypeError} Synchronously throws if CRLF injection is detected.
 */
function sanitizeHeaders(rawHeaders: Record<string, any>): Record<string, string | string[]> {
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

        if (typeof value === 'string') {
            if (crlfRegex.test(value)) {
                throw new TypeError(`UltraTon: Header value for '${key}' contains invalid CRLF characters.`);
            }
            sanitized[lowerKey] = value;
        } else if (Array.isArray(value)) {
            const sanitizedVal: string[] = [];
            for (const item of value) {
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
    const safeOptions: any = {};

    if (validateType('method', options.method, 'string')) safeOptions.method = options.method;
    if (validateType('auth', options.auth, 'string')) safeOptions.auth = options.auth;
    if (validateType('signal', options.signal, 'object')) safeOptions.signal = options.signal;
    if (validateType('headers', options.headers, 'object')) {
        safeOptions.headers = sanitizeHeaders(options.headers as Record<string, any>);
    }

    if (validateType('timeout', options.timeout, 'number') && Number.isInteger(options.timeout) && options.timeout! >= 0 && options.timeout! <= 2147483647) {
        safeOptions.timeout = options.timeout;
    }

    if (validateType('maxBodySize', options.maxBodySize, 'number')) {
        safeOptions.maxBodySize = options.maxBodySize;
    } else {
        safeOptions.maxBodySize = 1024 * 1024 * 2; // Strict 2MB Fallback
    }

    if (validateType('socketTimeoutMs', options.socketTimeoutMs, 'number') && Number.isInteger(options.socketTimeoutMs) && options.socketTimeoutMs! >= 0 && options.socketTimeoutMs! <= 2147483647) {
        safeOptions.socketTimeoutMs = options.socketTimeoutMs;
    } else {
        safeOptions.socketTimeoutMs = 10 * 1000; // Strict 10s Fallback
    }

    if (validateType('timeoutMs', options.timeoutMs, 'number') && Number.isInteger(options.timeoutMs) && options.timeoutMs! >= 0 && options.timeoutMs! <= 2147483647) {
        safeOptions.timeoutMs = options.timeoutMs;
    } else {
        safeOptions.timeoutMs = 30 * 1000; // Strict 30s Fallback
    }

    if (validateType('maxRedirects', options.maxRedirects, 'number') && options.maxRedirects! >= 0 && Number.isInteger(options.maxRedirects)) {
        safeOptions.maxRedirects = options.maxRedirects;
    } else {
        safeOptions.maxRedirects = 0; // Strict 0 Fallback
    }

    return safeOptions as SecureUltraTonRequestOptions;
}