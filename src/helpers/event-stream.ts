import { eventStreamIdle, eventTooLarge } from '../errors.ts';
import type { UltraTonEvent, UltraTonEventStream, UltraTonStreamResponse } from '../types/request-response.ts';

const LF = 0x0a;
const CR = 0x0d;
const BOM = [0xef, 0xbb, 0xbf] as const;
const ASCII_DIGITS = /^[0-9]+$/;

/** The bounds of one event stream. Both are checked before anything is buffered past them. */
export interface EventStreamLimits {
    /** The most bytes one line may take, and the most bytes of `data` lines one event may gather before it ends. */
    readonly maxEventSize: number;
    /** The most milliseconds without a complete line (an event's or a comment's); 0 for no limit. */
    readonly idleMs: number;
}

/** One line's bytes, joined from the pieces it came in: only now, when it is complete. */
function joinLine(pieces: Uint8Array[], last: Uint8Array): Buffer {
    if (pieces.length === 0) return Buffer.from(last.buffer, last.byteOffset, last.byteLength);
    return Buffer.concat([...pieces, last]);
}

/**
 * Reads a Server-Sent Events body (WHATWG HTML, "Parsing an event stream") and yields its events as they are
 * dispatched. It works on bytes: CR and LF never occur inside a multi-byte UTF-8 character, so lines are split before
 * decoding, a line that arrives in many chunks is joined once (linear time, however small the chunks), and a line is
 * decoded only when complete (invalid UTF-8 becomes U+FFFD). A leading BOM is dropped; CR, LF and CRLF end a line,
 * a CRLF split across chunks included. An event the stream ends in the middle of is dropped, as the standard says.
 *
 * The reader is cancelled when the generator ends for any reason: the body ran out, a limit failed, or the caller
 * left the loop.
 * @throws {UltraTonMemoryError} `ERR_ULTRATON_EVENT_TOO_LARGE`: a line, or one event's data, went past `maxEventSize`.
 * @throws {UltraTonNetworkTimeoutError} `ERR_ULTRATON_SOCKET_TIMEOUT`: no complete line for `idleMs`.
 */
export async function* parseEventStream(reader: ReadableStreamDefaultReader<Uint8Array>, limits: EventStreamLimits): AsyncGenerator<UltraTonEvent, void, undefined> {
    const { maxEventSize, idleMs } = limits;
    // The incomplete line at the end of what came so far, as the pieces it arrived in.
    let partial: Uint8Array[] = [];
    let partialBytes = 0;
    // The event being built. Its `data` lines' bytes are what an event holds in memory, so they are what is bounded.
    let type = '';
    let data = '';
    let dataBytes = 0;
    // Kept across events, as the standard says.
    let lastEventId = '';
    let retry: number | undefined;
    // The byte before was the CR ending a line: an LF right after it ends no second line.
    let afterCR = false;
    // Bytes of a leading BOM matched so far; 3 or -1 once the start of the stream is behind.
    let bom = 0;
    let lastLineAt = performance.now();
    let finished = false;

    /** The next chunk, or a timeout once `idleMs` has passed since the last complete line. */
    const read = (): Promise<ReadableStreamReadResult<Uint8Array>> => {
        if (idleMs === 0) return reader.read();
        const left = idleMs - (performance.now() - lastLineAt);
        if (left <= 0) return Promise.reject(eventStreamIdle(idleMs));
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(eventStreamIdle(idleMs)), left);
            reader.read().then(
                result => { clearTimeout(timer); resolve(result); },
                (err: unknown) => { clearTimeout(timer); reject(err); },
            );
        });
    };

    let failure: unknown;
    try {
        for (;;) {
            const { done, value } = await read();
            if (done) {
                finished = true;
                return;
            }
            let chunk = value;
            if (bom >= 0 && bom < 3) {
                let i = 0;
                while (bom < 3 && i < chunk.length && chunk[i] === BOM[bom]) { bom++; i++; }
                if (bom === 3) {
                    chunk = chunk.subarray(i);
                } else if (i < chunk.length) {
                    // Not a BOM after all: the bytes matched so far are the start of the first line.
                    if (bom > 0) { partial.push(Uint8Array.from(BOM.slice(0, bom))); partialBytes += bom; }
                    chunk = chunk.subarray(i);
                    bom = -1;
                } else {
                    continue;
                }
            }
            let lineStart = 0;
            for (let i = 0; i < chunk.length; i++) {
                const byte = chunk[i];
                if (afterCR) {
                    afterCR = false;
                    if (byte === LF) { lineStart = i + 1; continue; }
                }
                if (byte !== LF && byte !== CR) continue;
                const line = joinLine(partial, chunk.subarray(lineStart, i));
                partial = [];
                partialBytes = 0;
                lineStart = i + 1;
                afterCR = byte === CR;
                lastLineAt = performance.now();

                if (line.length === 0) {
                    // A blank line dispatches the event, if it has data.
                    if (data !== '') {
                        const event: UltraTonEvent = Object.freeze(Object.assign(Object.create(null) as object, {
                            event: type === '' ? 'message' : type,
                            data: data.slice(0, -1),
                            id: lastEventId,
                            retry,
                        }));
                        type = '';
                        data = '';
                        dataBytes = 0;
                        yield event;
                    } else {
                        type = '';
                    }
                    continue;
                }
                if (line.length > maxEventSize) throw eventTooLarge(maxEventSize);
                const text = line.toString('utf8');
                // A comment (a keep-alive, usually): nothing to do but what was done, the idle clock reset.
                if (text.charCodeAt(0) === 0x3a) continue;
                const colon = text.indexOf(':');
                const field = colon === -1 ? text : text.slice(0, colon);
                let fieldValue = colon === -1 ? '' : text.slice(colon + 1);
                if (fieldValue.charCodeAt(0) === 0x20) fieldValue = fieldValue.slice(1);
                switch (field) {
                    case 'event':
                        type = fieldValue;
                        break;
                    case 'data':
                        dataBytes += line.length;
                        if (dataBytes > maxEventSize) throw eventTooLarge(maxEventSize);
                        data += `${fieldValue}\n`;
                        break;
                    case 'id':
                        if (!fieldValue.includes('\0')) lastEventId = fieldValue;
                        break;
                    case 'retry':
                        if (ASCII_DIGITS.test(fieldValue)) {
                            const ms = Number(fieldValue);
                            if (Number.isSafeInteger(ms)) retry = ms;
                        }
                        break;
                    default:
                        // Any other field is ignored, as the standard says.
                }
            }
            if (lineStart < chunk.length) {
                // A copy: a view would keep the whole chunk alive for the few bytes of the line it ends with.
                const rest = chunk.slice(lineStart);
                partial.push(rest);
                partialBytes += rest.length;
                if (partialBytes > maxEventSize) throw eventTooLarge(maxEventSize);
            }
        }
    } catch (err: unknown) {
        failure = err;
        throw err;
    } finally {
        // A limit failed or the caller left the loop: the body is not wanted any more, and its connection is released.
        if (!finished) await reader.cancel(failure).catch(() => {});
    }
}

/** Media type `text/event-stream`, in any case and with any parameters (`; charset=utf-8`). */
export function isEventStreamType(contentType: unknown): boolean {
    return typeof contentType === 'string' && contentType.split(';', 1)[0].trim().toLowerCase() === 'text/event-stream';
}

/**
 * The events of a response already checked to be an event stream. `cancel()` cancels the body first, so a loop
 * waiting on the server ends at once, then closes the generator.
 */
export function createEventStream(res: UltraTonStreamResponse, limits: EventStreamLimits): UltraTonEventStream {
    const reader = res.body.getReader();
    const events = parseEventStream(reader, limits);
    let cancelled: Promise<void> | undefined;
    return Object.freeze({
        statusCode: res.statusCode,
        headers: res.headers,
        url: res.url,
        redirects: res.redirects,
        [Symbol.asyncIterator]: () => events,
        cancel: () => (cancelled ??= (async () => {
            await reader.cancel().catch(() => {});
            await events.return(undefined);
        })()),
    });
}
