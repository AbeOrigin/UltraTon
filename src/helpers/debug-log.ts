/**
 * `NODE_DEBUG=ultraton`: one line on stderr per response, retry and error, built on the diagnostics_channel events of
 * diagnostics.ts (no second instrumentation path). When the section is off nothing subscribes, so observeRequest stays
 * free. The lines carry the method, the origin, the status or error code and the duration: never headers, bodies,
 * credentials, query strings or resolved addresses (the events have none of those). Paths can carry secrets
 * (`/bot<TOKEN>/...`), so they need their own switch, ULTRATON_DEBUG_PATHS=1: `NODE_DEBUG=*` is what someone debugging
 * something else types, and these lines leave the host with the logs.
 */
import { debuglog } from 'node:util';
import diagnosticsChannel from 'node:diagnostics_channel';
import type { UltraTonRequestErrorMessage, UltraTonRequestResponseMessage, UltraTonRequestRetryMessage } from './diagnostics.ts';

type Message = UltraTonRequestResponseMessage | UltraTonRequestRetryMessage | UltraTonRequestErrorMessage;

/** One debug line for a diagnostics event, without the `ULTRATON <pid>:` prefix debuglog adds. Exported for tests. */
export function formatDebugLine(kind: 'response' | 'retry' | 'error', message: Message, withPath: boolean): string {
    const { request } = message;
    const target = `${request.method} ${request.origin}${withPath ? request.path : ''}`;
    if (kind === 'response') {
        const { statusCode, durationMs } = message as UltraTonRequestResponseMessage;
        return `${target} -> ${statusCode} (${Math.round(durationMs)} ms)`;
    }
    if (kind === 'retry') {
        const { attempt, delayMs, statusCode, error } = message as UltraTonRequestRetryMessage;
        return `${target} retry ${attempt} in ${delayMs} ms (${statusCode ?? error?.code ?? error?.name})`;
    }
    const { error, durationMs } = message as UltraTonRequestErrorMessage;
    return `${target} failed: ${error.name}${error.code ? ` ${error.code}` : ''} (${Math.round(durationMs)} ms)`;
}

const log = debuglog('ultraton');
const withPath = process.env.ULTRATON_DEBUG_PATHS === '1';

if (log.enabled) {
    diagnosticsChannel.subscribe('ultraton:request:response', message => log('%s', formatDebugLine('response', message as Message, withPath)));
    diagnosticsChannel.subscribe('ultraton:request:retry', message => log('%s', formatDebugLine('retry', message as Message, withPath)));
    diagnosticsChannel.subscribe('ultraton:request:error', message => log('%s', formatDebugLine('error', message as Message, withPath)));
}
