import { Readable } from 'node:stream';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';
import { requestBodyLength, requestBodyTooLarge } from '../errors.ts';

/** Something a body chunk is written to: an `http.ClientRequest` or an HTTP/2 stream. */
interface BodySink {
    readonly destroyed: boolean;
    write(chunk: Uint8Array, callback: (err?: Error | null) => void): unknown;
    once(event: 'close', listener: () => void): unknown;
    off(event: 'close', listener: () => void): unknown;
}

/**
 * The sink went away before the body was sent: the request is over (answered, aborted, timed out, closed) and has its
 * own outcome. The engines ignore it; any other pump failure is the body's own (the stream, a limit, the length).
 */
class SinkClosedError extends Error {}
const ended = (cause?: unknown) => new SinkClosedError('UltraTon: The request ended before its body was sent.', { cause });

/** True for a pump failure that only means the request ended first, which the request already reports. */
export const isSinkClosed = (err: unknown): boolean => err instanceof SinkClosedError;

/** Destroys a `Readable`, cancels a `ReadableStream`, or ends an async iterator: the caller's stream must not stay open. */
function discardSource(source: AsyncIterable<unknown>): void {
    if (source instanceof Readable) source.destroy();
    else if (source instanceof ReadableStream) source.cancel().catch(() => {});
    else {
        try {
            void Promise.resolve(source[Symbol.asyncIterator]().return?.()).catch(() => {});
        } catch {
            // ponytail: a hostile iterator that throws here has nothing left to release.
        }
    }
}

/**
 * A request body that arrives as a stream (`Readable`, `ReadableStream` or any async iterable of bytes). Read once, chunk
 * by chunk, as the engine writes it: never buffered. Each chunk is checked against `maxRequestBodySize` and, when the
 * caller declared one, the `content-length`, so a body can never go out longer or shorter than promised.
 */
export class StreamedBody {
    /** The caller's `content-length`, when they set one: sent as is, and the stream must yield exactly that. */
    readonly length: number | undefined;
    /** `maxRequestBodySize`, set by the engine once the options are validated. */
    limit: number | undefined;
    readonly #source: AsyncIterable<unknown>;
    #used = false;

    constructor(source: AsyncIterable<unknown>, length: number | undefined) {
        this.#source = source;
        this.length = length;
    }

    /** The request failed before the body was ever read (a policy rejection, an abort, a closed client): release it. */
    discard(): void {
        if (this.#used) return;
        this.#used = true;
        discardSource(this.#source);
    }

    /**
     * Reads the source and writes each chunk to `sink`, reading the next one only once the sink took it. When the sink
     * closes first (the request was aborted, timed out or answered), the source is destroyed (a `ReadableStream` is
     * cancelled), even while it is waiting for data, and the pump rejects with a sink-closed error (see isSinkClosed).
     * @param afterWrite - Called after each chunk the sink took (the HTTP/2 engine counts it as activity).
     * @throws {TypeError} If a chunk is neither a Uint8Array nor a string, or the body was already sent.
     * @throws {UltraTonMemoryError} `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE` past `maxRequestBodySize`.
     * @throws {SecureHttpError} `ERR_ULTRATON_REQUEST_BODY_LENGTH` when the stream does not match `content-length`.
     */
    async pump(sink: BodySink, afterWrite?: () => void): Promise<void> {
        // ponytail: a stream is read once; retries skip it and a 307/308 is returned, so a second read is a bug here.
        if (this.#used) throw new TypeError('UltraTon: A streamed body can only be sent once.');
        this.#used = true;
        // One shape to read and to destroy: fromWeb cancels a ReadableStream even mid-read, which its own iterator cannot.
        const source = this.#source instanceof Readable ? this.#source
            : this.#source instanceof ReadableStream ? Readable.fromWeb(this.#source as NodeReadableStream)
            : Readable.from(this.#source);
        let sinkClosed = sink.destroyed;
        const stop = () => {
            sinkClosed = true;
            source.destroy();
        };
        if (sinkClosed) stop();
        sink.once('close', stop);
        try {
            let sent = 0;
            for await (const chunk of source) {
                const bytes: unknown = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
                if (!(bytes instanceof Uint8Array)) {
                    throw new TypeError(`UltraTon: A streamed body must yield Uint8Array or string chunks, received ${chunk === null ? 'null' : typeof chunk}.`);
                }
                sent += bytes.length;
                if (this.limit !== undefined && sent > this.limit) throw requestBodyTooLarge(this.limit);
                if (this.length !== undefined && sent > this.length) throw requestBodyLength(this.length);
                if (bytes.length > 0) {
                    await writeChunk(sink, bytes);
                    afterWrite?.();
                }
            }
            if (sinkClosed || sink.destroyed) throw ended();
            if (this.length !== undefined && sent !== this.length) throw requestBodyLength(this.length);
        } catch (err: unknown) {
            // Destroying the source to stop it ends its iteration with a premature-close error: that is the sink's doing.
            throw sinkClosed && !(err instanceof SinkClosedError) ? ended(err) : err;
        } finally {
            sink.off('close', stop);
            // Left early (a limit, a bad chunk): the caller's stream must not stay open.
            if (!source.readableEnded) source.destroy();
        }
    }
}

/** A streamed body: something to read with `for await` that is not one of the types sent as a whole. */
export const isStreamBody = (body: unknown): body is AsyncIterable<unknown> =>
    typeof body === 'object' && body !== null && typeof (body as Record<symbol, unknown>)[Symbol.asyncIterator] === 'function'
    && !(body instanceof Blob) && !(body instanceof FormData) && !(body instanceof URLSearchParams);

/** Releases a caller's stream body that will never be sent (the request failed before it got to it). */
export function discardBody(body: unknown): void {
    if (body instanceof StreamedBody) body.discard();
    else if (isStreamBody(body)) discardSource(body);
}

/**
 * Applies `maxRequestBodySize` to a request body. A buffered one too large, or a stream whose own `content-length` is
 * already larger, throws now, before connecting; any other stream is checked as it is read.
 * @throws {UltraTonMemoryError} `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE`.
 */
export function limitRequestBody(body: Buffer | StreamedBody | undefined, limit: number | undefined): void {
    if (limit === undefined || body === undefined) return;
    if (body instanceof StreamedBody) body.limit = limit;
    if (body.length !== undefined && body.length > limit) throw requestBodyTooLarge(limit);
}

/**
 * Writes one chunk and resolves once the sink has taken it (handed to the socket, or through HTTP/2 flow control).
 * Rejects with a sink-closed error when the sink is destroyed, closes first, or fails the write: the request is over.
 */
function writeChunk(sink: BodySink, chunk: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
        if (sink.destroyed) return reject(ended());
        const onClose = () => reject(ended());
        sink.once('close', onClose);
        sink.write(chunk, (err) => {
            sink.off('close', onClose);
            if (err) reject(ended(err));
            else resolve();
        });
    });
}
