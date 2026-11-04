import { eventStreamIdle, eventTooLarge } from '../errors.ts';
import type { UltraTonEvent, UltraTonEventStream, UltraTonStreamResponse } from '../types/request-response.ts';

const LF = 0x0a;
const CR = 0x0d;
const BOM = [0xef, 0xbb, 0xbf] as const;
const ASCII_DIGITS = /^[0-9]+$/;

/** The bounds of one event stream. Both are checked before anything is buffered past them. */
export interface EventStreamLimits {
    /**
     * The most bytes one line may take, and the most bytes of `data` lines one event may gather before it ends. What is
     * held for them stays within about twice that (see LineBuffer).
     */
    readonly maxEventSize: number;
    /** The most milliseconds without a complete line (an event's or a comment's); 0 for no limit. */
    readonly idleMs: number;
}

/**
 * The incomplete line at the end of what came so far, in one buffer that doubles as it grows: appending is amortized
 * linear however small the pieces, and the memory held stays within about twice the line's bytes (one small object per
 * piece would cost a couple hundred bytes for each byte a server drips). Let go once the line is taken.
 */
export class LineBuffer {
    #buffer: Buffer = Buffer.alloc(0);
    #length = 0;

    /** The bytes of the line so far. */
    get length(): number {
        return this.#length;
    }

    /** The bytes allocated to hold them. */
    get capacity(): number {
        return this.#buffer.length;
    }

    append(bytes: Uint8Array): void {
        const needed = this.#length + bytes.length;
        if (needed > this.#buffer.length) {
            const grown = Buffer.allocUnsafe(Math.max(needed, this.#buffer.length * 2, 64));
            this.#buffer.copy(grown, 0, 0, this.#length);
            this.#buffer = grown;
        }
        this.#buffer.set(bytes, this.#length);
        this.#length = needed;
    }

    /** The whole line, ending with `last` (the bytes before its line end in the current chunk), and an empty buffer. */
    take(last: Uint8Array): Buffer {
        if (this.#length === 0) return Buffer.from(last.buffer, last.byteOffset, last.byteLength);
        const line = Buffer.allocUnsafe(this.#length + last.length);
        this.#buffer.copy(line, 0, 0, this.#length);
        line.set(last, this.#length);
        this.#buffer = Buffer.alloc(0);
        this.#length = 0;
        return line;
    }
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
    // The incomplete line at the end of what came so far.
    const partial = new LineBuffer();
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
                    if (bom > 0) partial.append(Uint8Array.from(BOM.slice(0, bom)));
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
                const line = partial.take(chunk.subarray(lineStart, i));
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
                        // The time the caller spent on the event is not the server's: the idle clock restarts when it
                        // asks for the next one. A yield only follows a complete line, so a drip cannot use this.
                        lastLineAt = performance.now();
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
                // Checked before it is copied in: a line past the limit is never held whole.
                if (partial.length + (chunk.length - lineStart) > maxEventSize) throw eventTooLarge(maxEventSize);
                partial.append(chunk.subarray(lineStart));
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
