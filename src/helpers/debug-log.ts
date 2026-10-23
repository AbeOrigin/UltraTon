/**
 * `NODE_DEBUG=ultraton`: one line on stderr per response, retry and error, built on the diagnostics_channel events of
 * diagnostics.ts (no second instrumentation path). When the section is off nothing subscribes, so observeRequest stays
 * free. The lines carry the method, the origin, the status or error code, the duration and its phases: never headers,
 * bodies, credentials, query strings or resolved addresses (the events have none of those). Paths can carry secrets
 * (`/bot<TOKEN>/...`), so they need their own switch, ULTRATON_DEBUG_PATHS=1: `NODE_DEBUG=*` is what someone debugging
 * something else types, and these lines leave the host with the logs.
 */
import { debuglog } from 'node:util';
import diagnosticsChannel from 'node:diagnostics_channel';
import type { UltraTonRequestErrorMessage, UltraTonRequestResponseMessage, UltraTonRequestRetryMessage, UltraTonTimings } from './diagnostics.ts';

type Message = UltraTonRequestResponseMessage | UltraTonRequestRetryMessage | UltraTonRequestErrorMessage;

/**
 * ` [dns 3 ms, connect 12 ms, tls 28 ms, ttfb 40 ms]` or ` [queued 120 ms, reused, ttfb 9 ms]`: the phases gone
 * through, if any.
 */
function formatTimings(timings: UltraTonTimings | undefined): string {
    if (!timings) return '';
    const phases = timings.queuedMs === undefined ? [] : [`queued ${Math.round(timings.queuedMs)} ms`];
    if (timings.reusedConnection) phases.push('reused');
    const named: Array<[string, number | undefined]> = [['dns', timings.dnsMs], ['connect', timings.connectMs], ['tls', timings.tlsMs], ['ttfb', timings.firstByteMs]];
    for (const [name, ms] of named) if (ms !== undefined) phases.push(`${name} ${Math.round(ms)} ms`);
    return phases.length > 0 ? ` [${phases.join(', ')}]` : '';
}

/** One debug line for a diagnostics event, without the `ULTRATON <pid>:` prefix debuglog adds. Exported for tests. */
export function formatDebugLine(kind: 'response' | 'retry' | 'error', message: Message, withPath: boolean): string {
    const { request } = message;
    const target = `${request.method} ${request.origin}${withPath ? request.path : ''}`;
    if (kind === 'response') {
        const { statusCode, durationMs, timings } = message as UltraTonRequestResponseMessage;
        return `${target} -> ${statusCode} (${Math.round(durationMs)} ms)${formatTimings(timings)}`;
    }
    if (kind === 'retry') {
        const { attempt, delayMs, statusCode, error } = message as UltraTonRequestRetryMessage;
        return `${target} retry ${attempt} in ${delayMs} ms (${statusCode ?? error?.code ?? error?.name})`;
    }
    const { error, durationMs, timings } = message as UltraTonRequestErrorMessage;
    return `${target} failed: ${error.name}${error.code ? ` ${error.code}` : ''} (${Math.round(durationMs)} ms)${formatTimings(timings)}`;
}

const log = debuglog('ultraton');
const withPath = process.env.ULTRATON_DEBUG_PATHS === '1';

if (log.enabled) {
    diagnosticsChannel.subscribe('ultraton:request:response', message => log('%s', formatDebugLine('response', message as Message, withPath)));
    diagnosticsChannel.subscribe('ultraton:request:retry', message => log('%s', formatDebugLine('retry', message as Message, withPath)));
    diagnosticsChannel.subscribe('ultraton:request:error', message => log('%s', formatDebugLine('error', message as Message, withPath)));
}
