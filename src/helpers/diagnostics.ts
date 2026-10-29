import diagnosticsChannel from 'node:diagnostics_channel';
import { performance } from 'node:perf_hooks';
import type { UltraTonRetryInfo } from '../types/request-options.types.ts';

/** The request every event of one client call carries: the same frozen object from start to end. */
export interface UltraTonDiagnosticsRequest {
    /** The HTTP method. */
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
    /** The error's `name`, such as `UltraTonNetworkError`. */
    readonly name: string;
    /** Its `code` (`ERR_ULTRATON_*` or Node's own), or `undefined` when it has none. */
    readonly code: string | undefined;
}

/** Where the time of a call went, in milliseconds. Phases a call did not go through are `undefined`. */
export interface UltraTonTimings {
    /** Waiting for a free slot under the client's `maxConcurrency`, before the first hop; `undefined` when the call did not wait. */
    readonly queuedMs?: number;
    /** Name resolution of the last hop, when a new connection was opened for it. */
    readonly dnsMs?: number;
    /** TCP connect of the last hop (on HTTP/2: TCP and TLS together, Node reports them as one). */
    readonly connectMs?: number;
    /** TLS handshake of the last hop, HTTP/1.1 only. */
    readonly tlsMs?: number;
    /** From the request of the last hop being sent to its first response byte (headers). */
    readonly firstByteMs?: number;
    /** The whole call: every hop, every retry, until the response (or the error). */
    readonly totalMs: number;
    /** Whether the last hop went over a pooled connection or session. */
    readonly reusedConnection: boolean;
}

/**
 * The moments an engine marks on a hop. `start`: the hop begins (on HTTP/2, the connection attempt does); `lookup`: the
 * name resolved (never for an IP literal); `connect`: the connection is up (TCP, or TCP and TLS for an HTTP/2 session,
 * or a proxy tunnel); `secure`: the TLS handshake of an HTTP/1.1 socket is done; `sent`: the request and its body were
 * written; `response`: its headers arrived.
 */
export type TimingsPhase = 'start' | 'lookup' | 'connect' | 'secure' | 'sent' | 'response';

/** The marks of one hop. A hop given up (a redirect, a failed attempt) keeps getting late marks, which nothing reads. */
export class HopTimings {
    readonly marks: Partial<Record<TimingsPhase, number>> = {};
    isReused = false;

    /** Records `phase` now, or at `at` (a `performance.now()` taken earlier). The first mark of a phase wins. */
    mark(phase: TimingsPhase, at: number = performance.now()): void {
        // A response that came before the upload finished: the time to it is measured from the connection instead.
        if (phase === 'sent' && this.marks.response !== undefined) return;
        this.marks[phase] ??= at;
    }

    /** The hop went over a pooled connection or session: it had no lookup nor connect of its own. */
    reused(): void {
        this.isReused = true;
    }
}

const tenth = (ms: number): number => Math.round(ms * 10) / 10;
const between = (from: number | undefined, to: number | undefined): number | undefined =>
    from === undefined || to === undefined ? undefined : tenth(Math.max(0, to - from));

/**
 * The timings of one client call, handed to the engine only while someone listens (see observeRequest) or the call asked
 * for them (`timings: true`). Each hop (every redirect, every retry) starts a new HopTimings: the response and the events
 * report the last one, and the whole call, from the moment this was created, as `totalMs`.
 */
export class TimingsCollector {
    readonly #startedAt = performance.now();
    #last = new HopTimings();
    #queuedMs?: number;

    /** Starts the record of a new hop, which replaces the previous one. */
    hop(): HopTimings {
        this.#last = new HopTimings();
        return this.#last;
    }

    /** The call waited `ms` in the `maxConcurrency` queue before its first hop. */
    queued(ms: number): void {
        this.#queuedMs = ms;
    }

    /** The timings of the last hop, with `totalMs` up to now. Only numbers and one boolean. */
    snapshot(): UltraTonTimings {
        const totalMs = performance.now() - this.#startedAt;
        const { marks, isReused } = this.#last;
        const connected = marks.secure ?? marks.connect;
        // Nothing goes out before the connection is up: an HTTP/2 stream opened on a connecting session waits for it.
        const ready = marks.sent ?? connected ?? marks.start;
        const sent = ready === undefined || connected === undefined ? ready : Math.max(ready, connected);
        const phases = {
            queuedMs: this.#queuedMs === undefined ? undefined : tenth(this.#queuedMs),
            dnsMs: between(marks.start, marks.lookup),
            connectMs: between(marks.lookup ?? marks.start, marks.connect),
            tlsMs: between(marks.connect, marks.secure),
            firstByteMs: between(sent, marks.response),
        };
        const timings: Record<string, number | boolean> = {};
        for (const [name, value] of Object.entries(phases)) if (value !== undefined) timings[name] = value;
        timings.totalMs = tenth(totalMs);
        timings.reusedConnection = isReused;
        return timings as unknown as UltraTonTimings;
    }
}

const start = diagnosticsChannel.channel('ultraton:request:start');
const response = diagnosticsChannel.channel('ultraton:request:response');
const failure = diagnosticsChannel.channel('ultraton:request:error');
const retry = diagnosticsChannel.channel('ultraton:request:retry');

/** `ultraton:request:start`. */
export interface UltraTonRequestStartMessage {
    /** The request this call makes. */
    readonly request: UltraTonDiagnosticsRequest;
}
/** `ultraton:request:retry`, published once a retry is decided (after `onRetry` ran), before the wait. */
export interface UltraTonRequestRetryMessage {
    /** The request being retried. */
    readonly request: UltraTonDiagnosticsRequest;
    /** The retry about to happen: 1 for the first. */
    readonly attempt: number;
    /** The wait before it, in milliseconds. */
    readonly delayMs: number;
    /** The status of the response being retried. */
    readonly statusCode?: number;
    /** The network error being retried. */
    readonly error?: UltraTonDiagnosticsError;
}
/** `ultraton:request:response`. For `stream()` it is published on the headers. */
export interface UltraTonRequestResponseMessage {
    /** The request that got this response. */
    readonly request: UltraTonDiagnosticsRequest;
    /** The status the call resolved with, after any retries. */
    readonly statusCode: number;
    /** Milliseconds from the start of the call, retries included: `timings.totalMs`. */
    readonly durationMs: number;
    /** Where that time went, phase by phase, on the hop that got the response. */
    readonly timings: UltraTonTimings;
}
/** `ultraton:request:error`. */
export interface UltraTonRequestErrorMessage {
    /** The request that failed. */
    readonly request: UltraTonDiagnosticsRequest;
    /** Why it failed. */
    readonly error: UltraTonDiagnosticsError;
    /** Milliseconds from the start of the call, retries included: `timings.totalMs`. */
    readonly durationMs: number;
    /** Where that time went, phase by phase, on the hop that failed (the phases it got through). */
    readonly timings: UltraTonTimings;
}

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
    /** What the engine measures each hop on; the events publish the last hop's. */
    readonly timings: TimingsCollector;
    /** Publishes `ultraton:request:retry`: call it once the retry is decided, before the wait. */
    retry(info: UltraTonRetryInfo): void;
    /** Publishes `ultraton:request:response` or `ultraton:request:error` when `result` settles, and passes it on. */
    track<R extends { readonly statusCode: number; readonly timings?: UltraTonTimings }>(result: Promise<R>): Promise<R>;
}

/**
 * Starts the diagnostics of one client call (`get`, `stream()`, `fetch()`, ...) and publishes `ultraton:request:start`.
 * `undefined`, at no cost, when nobody listens to any UltraTon channel or the URL does not parse (the engine rejects it).
 * `own` is the call's collector when it asked for timings, so the response and the events report the same ones.
 * Payloads hold the method, origin and path (no query), status, durations, retry attempt and the error's name and
 * code: never headers, bodies, credentials, `error.cause` or resolved addresses, since APMs ship events off the host.
 * The timings are numbers and one boolean; nothing creates or measures them when this returns `undefined`.
 */
export function observeRequest(method: string, url: string, own?: TimingsCollector): RequestObserver | undefined {
    if (!(start.hasSubscribers || response.hasSubscribers || failure.hasSubscribers || retry.hasSubscribers)) return undefined;
    if (!URL.canParse(url)) return undefined;
    const parsed = new URL(url);
    // ;params dropped per segment (/a;jsessionid=x/b is /a/b): servers often carry session ids in them.
    const path = parsed.pathname.split('/').map(segment => segment.split(';', 1)[0]).join('/');
    const collector = own ?? new TimingsCollector();
    const request: UltraTonDiagnosticsRequest = Object.freeze({ method, origin: parsed.origin, path });
    if (start.hasSubscribers) start.publish({ request });
    return {
        timings: collector,
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
                if (response.hasSubscribers) {
                    // The ones the response carries, when the call asked for them: one measurement, never two that differ.
                    const timings = res.timings ?? collector.snapshot();
                    response.publish({ request, statusCode: res.statusCode, durationMs: timings.totalMs, timings });
                }
                return res;
            }, (err: unknown) => {
                if (failure.hasSubscribers) {
                    const timings = collector.snapshot();
                    failure.publish({ request, error: describeError(err), durationMs: timings.totalMs, timings });
                }
                throw err;
            });
        },
    };
}
