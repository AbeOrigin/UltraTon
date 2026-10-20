import diagnosticsChannel from 'node:diagnostics_channel';
import { performance } from 'node:perf_hooks';
import type { UltraTonRetryInfo } from '../types/request-options.types.ts';

/** The request every event of one client call carries: the same frozen object from start to end. */
export interface UltraTonDiagnosticsRequest {
    readonly method: string;
    /** Scheme, host and port: never a resolved IP. */
    readonly origin: string;
    /**
     * The path without the query string and without `;params` (`;jsessionid=...`). Its segments are published as
     * they are: an API that puts a secret in the path (a bot token, a webhook URL) needs redacting in the subscriber.
     */
    readonly path: string;
}

/** An error as the events describe it: its name and its UltraTon or Node `code`, never its message chain or `cause`. */
export interface UltraTonDiagnosticsError {
    readonly name: string;
    readonly code: string | undefined;
}

const start = diagnosticsChannel.channel('ultraton:request:start');
const response = diagnosticsChannel.channel('ultraton:request:response');
const failure = diagnosticsChannel.channel('ultraton:request:error');
const retry = diagnosticsChannel.channel('ultraton:request:retry');

/** `ultraton:request:start`. */
export interface UltraTonRequestStartMessage { readonly request: UltraTonDiagnosticsRequest }
/** `ultraton:request:retry`, published once a retry is decided (after `onRetry` ran), before the wait. */
export interface UltraTonRequestRetryMessage {
    readonly request: UltraTonDiagnosticsRequest;
    readonly attempt: number;
    readonly delayMs: number;
    readonly statusCode?: number;
    readonly error?: UltraTonDiagnosticsError;
}
/** `ultraton:request:response`. For `stream()` it is published on the headers. */
export interface UltraTonRequestResponseMessage { readonly request: UltraTonDiagnosticsRequest; readonly statusCode: number; readonly durationMs: number }
/** `ultraton:request:error`. */
export interface UltraTonRequestErrorMessage { readonly request: UltraTonDiagnosticsRequest; readonly error: UltraTonDiagnosticsError; readonly durationMs: number }

/**
 * Only a string `name` and `code`. The error may be anything the caller made reject the request (an abort reason, a
 * value thrown from onRetry): a hostile getter must neither throw here, which would replace the request's own error,
 * nor put a non-string in the payload.
 */
const describeError = (err: unknown): UltraTonDiagnosticsError => {
    try {
        const name: unknown = err instanceof Error ? err.name : typeof err;
        const code: unknown = (err as { code?: unknown } | null)?.code;
        return { name: typeof name === 'string' ? name : 'Error', code: typeof code === 'string' ? code : undefined };
    } catch {
        return { name: 'Error', code: undefined };
    }
};

/** The events of one client call, once it has a request to report on. */
export interface RequestObserver {
    /** Publishes `ultraton:request:retry`: call it once the retry is decided, before the wait. */
    retry(info: UltraTonRetryInfo): void;
    /** Publishes `ultraton:request:response` or `ultraton:request:error` when `result` settles, and passes it on. */
    track<R extends { readonly statusCode: number }>(result: Promise<R>): Promise<R>;
}

/**
 * Starts the diagnostics of one client call (`get`, `stream()`, `fetch()`, ...) and publishes `ultraton:request:start`.
 * `undefined`, at no cost, when nobody listens to any UltraTon channel or the URL does not parse (the engine rejects it).
 * Payloads hold the method, origin and path (no query), status, durations, retry attempt and the error's name and
 * code: never headers, bodies, credentials, `error.cause` or resolved addresses, since APMs ship events off the host.
 */
export function observeRequest(method: string, url: string): RequestObserver | undefined {
    if (!(start.hasSubscribers || response.hasSubscribers || failure.hasSubscribers || retry.hasSubscribers)) return undefined;
    if (!URL.canParse(url)) return undefined;
    const parsed = new URL(url);
    // ;params dropped per segment (/a;jsessionid=x/b is /a/b): servers often carry session ids in them.
    const path = parsed.pathname.split('/').map(segment => segment.split(';', 1)[0]).join('/');
    const request: UltraTonDiagnosticsRequest = Object.freeze({ method, origin: parsed.origin, path });
    const startedAt = performance.now();
    const elapsed = () => performance.now() - startedAt;
    if (start.hasSubscribers) start.publish({ request });
    return {
        retry(info) {
            if (!retry.hasSubscribers) return;
            retry.publish({
                request,
                attempt: info.attempt,
                delayMs: info.delayMs,
                statusCode: info.statusCode,
                error: info.error === undefined ? undefined : describeError(info.error),
            });
        },
        track(result) {
            return result.then(res => {
                if (response.hasSubscribers) response.publish({ request, statusCode: res.statusCode, durationMs: elapsed() });
                return res;
            }, (err: unknown) => {
                if (failure.hasSubscribers) failure.publish({ request, error: describeError(err), durationMs: elapsed() });
                throw err;
            });
        },
    };
}
