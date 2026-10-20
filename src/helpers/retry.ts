import type { IncomingHttpHeaders } from 'node:http';
import { UltraTonNetworkError, absoluteTimeout } from '../errors.ts';
import { DEFAULT_TIMEOUT_MS } from '../constants.ts';
import type { UltraTonRetryInfo } from '../types/request-options.types.ts';
import type { RetryInput } from './request-options.ts';

const DEFAULT_LIMIT = 2;
/** Idempotent methods only: a POST or PATCH that reached the server may have done its work already. */
const DEFAULT_METHODS: readonly string[] = ['GET', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
/** Statuses that say "try again". 500 is left out: it is usually deterministic, and retrying it only adds load. */
const DEFAULT_STATUS_CODES: readonly number[] = [408, 429, 502, 503, 504];
const DEFAULT_MAX_DELAY_MS = 30_000;
const BASE_DELAY_MS = 300;
const INT32_MAX = 2147483647;
/**
 * Transient network failures, the idle timeout, and an HTTP/2 stream the server never processed (REFUSED_STREAM or
 * above a GOAWAY's last stream). Anything else (policy, memory, redirects, decoding, other resets) is final.
 */
const RETRYABLE_CODES = new Set(['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'EPIPE', 'ERR_ULTRATON_SOCKET_TIMEOUT', 'NGHTTP2_REFUSED_STREAM']);

/** The retry rules of one request, defaults filled in. */
export interface Retry {
    readonly limit: number;
    readonly statusCodes: readonly number[];
    readonly maxDelayMs: number;
    readonly onRetry?: (info: UltraTonRetryInfo) => void;
}

/**
 * The client's `retry` with the request's merged over it field by field, or `undefined` when this request is not
 * retried at all (neither sets one, the limit is 0, or the method is not in `methods`).
 */
export function resolveRetry(client: RetryInput | undefined, request: RetryInput | undefined, method: string): Retry | undefined {
    if (client === undefined && request === undefined) return undefined;
    // No prototype: a field neither sets must read as undefined, never as a polluted Object.prototype.limit/methods.
    const merged: RetryInput = Object.assign(Object.create(null), client, request);
    const limit = merged.limit ?? DEFAULT_LIMIT;
    if (limit === 0 || !(merged.methods ?? DEFAULT_METHODS).includes(method)) return undefined;
    return {
        limit,
        statusCodes: merged.statusCodes ?? DEFAULT_STATUS_CODES,
        maxDelayMs: merged.maxDelayMs ?? DEFAULT_MAX_DELAY_MS,
        onRetry: merged.onRetry,
    };
}

/** What a response must expose to be judged; a stream response's body is cancelled before the next attempt. */
interface Attempted {
    readonly statusCode: number;
    readonly headers: IncomingHttpHeaders;
    readonly body?: unknown;
}

const isRetryable = (err: unknown): boolean =>
    err instanceof UltraTonNetworkError && typeof err.code === 'string' && RETRYABLE_CODES.has(err.code);

/**
 * `Retry-After` in ms: delta-seconds (digits only) or an IMF-fixdate (`Wed, 21 Oct 2015 07:28:00 GMT`), a date in the
 * past being 0. `undefined` for anything else, which falls back to backoff. Parsed without a regex: it is server input.
 */
function retryAfterMs(value: unknown): number | undefined {
    if (typeof value !== 'string') return undefined;
    const text = value.trim();
    if (text === '') return undefined;
    if ([...text].every(c => c >= '0' && c <= '9')) return Number(text) * 1000;
    if (!text.endsWith(' GMT')) return undefined;
    const date = Date.parse(text);
    return Number.isNaN(date) ? undefined : Math.max(0, date - Date.now());
}

/**
 * The wait before the next attempt, or `undefined` to give up: the server's `Retry-After` exactly, unless it asks for
 * more than `maxDelayMs` (retrying sooner than asked would most likely fail again); else full-jitter exponential backoff.
 */
function delayBefore(attempt: number, response: Attempted | undefined, retry: Retry): number | undefined {
    const asked = retryAfterMs(response?.headers['retry-after']);
    if (asked !== undefined) return asked <= retry.maxDelayMs ? asked : undefined;
    return Math.floor(Math.random() * Math.min(retry.maxDelayMs, BASE_DELAY_MS * 2 ** attempt));
}

/** Waits `ms`, or rejects with the signal's reason as soon as it aborts. */
function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
    signal?.throwIfAborted();
    // An explicit range guard on a duration that can come from the server (Retry-After): never a 0/overflowed timer.
    if (!(ms > 0 && ms <= INT32_MAX)) return Promise.resolve();
    return new Promise((resolve, reject) => {
        const onAbort = () => { clearTimeout(timer); reject(signal!.reason); };
        const timer = setTimeout(() => { signal?.removeEventListener('abort', onAbort); resolve(); }, ms);
        signal?.addEventListener('abort', onAbort, { once: true });
    });
}

async function discard(response: Attempted | undefined): Promise<void> {
    if (response?.body instanceof ReadableStream) await response.body.cancel().catch(() => undefined);
}

/**
 * Runs `send` until it gives a final answer: a response whose status is not retried, a failure that is not retried, or
 * the last allowed attempt. `timeoutMs` (the request's, as merged) is one budget for every attempt and wait: each later
 * attempt gets what is left of it, and a wait that would not fit in it is not taken. Every attempt is a full request
 * through the engine, so DNS is validated and pinned again for each new connection.
 * @param send - One attempt; `timeoutMs` overrides the request's when given.
 */
export async function withRetry<R extends Attempted>(
    send: (timeoutMs?: number) => Promise<R>,
    retry: Retry,
    timeoutMs: unknown,
    signal: unknown,
): Promise<R> {
    const abortSignal = signal instanceof AbortSignal ? signal : undefined;
    const configured = timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : timeoutMs;
    // A malformed timeoutMs is left for the engine to reject on the first attempt; 0 means no budget.
    const budget = Number.isInteger(configured) && (configured as number) > 0 ? configured as number : 0;
    const started = Date.now();
    const left = () => budget - (Date.now() - started);

    for (let attempt = 0; ; attempt++) {
        let response: R | undefined;
        let error: unknown;
        try {
            if (attempt === 0 || budget === 0) {
                response = await send();
            } else {
                if (left() <= 0) throw absoluteTimeout(budget);
                response = await send(left());
            }
        } catch (err) {
            // A later attempt ran on what was left of the budget: report the budget itself, as one request would.
            if (attempt > 0 && err instanceof UltraTonNetworkError && err.code === 'ERR_ULTRATON_TIMEOUT') throw absoluteTimeout(budget);
            if (attempt >= retry.limit || !isRetryable(err)) throw err;
            error = err;
        }
        if (response && (attempt >= retry.limit || !retry.statusCodes.includes(response.statusCode))) return response;

        const delayMs = delayBefore(attempt, response, retry);
        if (delayMs === undefined || (budget > 0 && delayMs >= left())) {
            if (response) return response;
            throw error;
        }
        try {
            retry.onRetry?.(response ? { attempt: attempt + 1, delayMs, statusCode: response.statusCode } : { attempt: attempt + 1, delayMs, error });
        } finally {
            await discard(response);
        }
        await sleep(delayMs, abortSignal);
    }
}
