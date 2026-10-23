import zlib from 'node:zlib';
import { pipeline, Transform, type Readable } from 'node:stream';
import { SecureHttpError, UltraTonNetworkError } from '../errors.ts';
import { incompleteResponse } from './response.ts';
import { atLeastFixed, NODE_OCT_2026_FIXES } from './node-release.ts';

/**
 * Whether this Node's Brotli decoder is safe to feed a server's bytes. Lines after 26 carry the fix; 23 and 25 are
 * end-of-life and never got it; a prerelease (`27.0.0-rc.1`, a nightly) may predate it, so it counts as unsafe. On an unsafe one, br is neither requested nor decoded (see CODINGS): a body a server
 * sends as br anyway comes back raw, as any coding this runtime cannot decode does.
 */
export function hasSafeBrotli(version: string = process.versions.node): boolean {
    return atLeastFixed(NODE_OCT_2026_FIXES, version);
}

const BROTLI = hasSafeBrotli();

/** The content-codings the reader decodes: br only on a Node whose decoder is fixed (see hasSafeBrotli). */
const CODINGS = new Set(BROTLI ? ['gzip', 'x-gzip', 'deflate', 'br'] : ['gzip', 'x-gzip', 'deflate']);

/**
 * A fresh decoder for a coding in CODINGS. A switch rather than a lookup table: no header value ever selects the
 * function that gets called.
 */
function createDecoder(coding: string): Transform {
    switch (coding) {
        case 'gzip':
        case 'x-gzip':
            return zlib.createGunzip();
        // ponytail: zlib-wrapped deflate only (RFC 9110). Raw deflate from very old servers fails as Z_DATA_ERROR; sniff
        // the first byte (inflate vs inflateRaw) if one ever matters.
        case 'deflate':
            return zlib.createInflate();
        // Brotli's ring buffer can take up to 16 MiB per layer whatever maxBodySize is; zlib has no knob to lower it.
        case 'br':
            return zlib.createBrotliDecompress();
        default:
            throw new Error(`UltraTon: No decoder for content-coding '${coding}'.`);
    }
}

// ponytail: no zstd yet. Node's decoder resolves a truncated frame without an error (a partial body would pass as
// complete) and its default window lets a few bytes allocate 128 MiB. Add it with ZSTD_d_windowLogMax 23 (RFC 9659)
// once a cut frame can be detected.

/** The accept-encoding sent by default: every coding the reader decodes. */
export const ACCEPT_ENCODING = BROTLI ? 'gzip, deflate, br' : 'gzip, deflate';

/** Each layer is another decompression to bound; two cover every real server (e.g. "gzip, br"). */
const MAX_LAYERS = 2;

/**
 * The codings to undo, in decoding order (the reverse of the header's), or an error. `identity` is skipped. A coding
 * this runtime cannot decode leaves the whole body raw, as fetch does.
 */
function codingsFor(header: string | string[] | undefined): string[] | Error {
    if (header === undefined) return [];
    const codings = (Array.isArray(header) ? header.join(',') : header)
        .split(',')
        .map(coding => coding.trim().toLowerCase())
        .filter(coding => coding !== '' && coding !== 'identity');
    if (codings.some(coding => !CODINGS.has(coding))) return [];
    if (codings.length > MAX_LAYERS) {
        return new SecureHttpError(`UltraTon: Response has more than ${MAX_LAYERS} content-encodings.`, { code: 'ERR_ULTRATON_CONTENT_ENCODING' });
    }
    return codings.reverse();
}

const decodeError = (err: unknown) => {
    const code = (err as NodeJS.ErrnoException | undefined)?.code ?? 'UNKNOWN';
    return new UltraTonNetworkError(`UltraTon: Response body could not be decoded (${code}).`, { code, cause: err });
};

export interface BodyReaderOptions {
    readonly maxBodySize: number;
    readonly contentEncoding: string | string[] | undefined;
    readonly decompress: boolean;
    /** The engine's own "body too large" error. */
    readonly tooLarge: () => Error;
    /** Called once when decoding fails or overflows asynchronously; the engine cancels the response. */
    readonly onError: (err: Error) => void;
}

/**
 * Collects one response body for both engines, decoding its content-encoding on the fly. `maxBodySize` bounds the
 * bytes on the wire and, separately, the decoded bytes, counted chunk by chunk as zlib produces them: a decompression
 * bomb stops at the limit and never reaches memory whole. `wireBytes` is what the content-length check compares.
 */
export class BodyReader {
    wireBytes = 0;
    readonly #options: BodyReaderOptions;
    readonly #codings: string[];
    readonly #chunks: Buffer[] = [];
    #size = 0;
    #error?: Error;
    /** Too many content-encodings: reported only if a body actually arrives, so a 204/304/HEAD still resolves. */
    #codingError?: Error;
    #destroyed = false;
    #first?: Transform;
    #done?: Promise<void>;

    constructor(options: BodyReaderOptions) {
        this.#options = options;
        const codings = options.decompress ? codingsFor(options.contentEncoding) : [];
        this.#codings = codings instanceof Error ? [] : codings;
        if (codings instanceof Error) this.#codingError = codings;
    }

    /** The error the body failed with, if any. */
    get error(): Error | undefined {
        return this.#error;
    }

    /**
     * Takes one chunk off the wire.
     * @throws The reader's error: too many content-encodings, or `maxBodySize` exceeded (wire or undecoded bytes).
     */
    write(chunk: Buffer): void {
        if (this.#codingError) this.#error ??= this.#codingError;
        if (this.#error) throw this.#error;
        this.wireBytes += chunk.length;
        if (this.wireBytes > this.#options.maxBodySize) throw this.#fail(this.#options.tooLarge());
        if (this.#codings.length === 0) {
            if (!this.#collect(chunk)) throw this.#error;
            return;
        }
        (this.#first ??= this.#start()).write(chunk);
    }

    /**
     * The whole decoded body, once the wire has ended.
     * @throws The reader's error, including a compressed body that is corrupt or cut short.
     */
    async end(): Promise<Buffer> {
        if (this.#destroyed) throw this.#error ?? new Error('UltraTon: BodyReader used after destroy().');
        if (this.#first) {
            this.#first.end();
            await this.#done;
        }
        if (this.#error) throw this.#error;
        return Buffer.concat(this.#chunks, this.#size);
    }

    /** Frees the decoders of a response the engine gave up (abort, timeout); reports nothing. */
    destroy(): void {
        this.#destroyed = true;
        this.#first?.destroy();
    }

    #collect(chunk: Buffer): boolean {
        this.#size += chunk.length;
        if (this.#size > this.#options.maxBodySize) {
            this.#fail(this.#options.tooLarge());
            return false;
        }
        this.#chunks.push(chunk);
        return true;
    }

    #fail(err: Error): Error {
        this.#error ??= err;
        this.#first?.destroy();
        return this.#error;
    }

    /** The decoding chain createBodyStream uses too: its last stage already holds the decoded bytes to maxBodySize. */
    #start(): Transform {
        const chain = decodingChain(this.#codings, this.#options);
        const { stages } = chain;
        stages[stages.length - 1].on('data', (chunk: Buffer) => {
            if (this.#error || this.#destroyed) return;
            this.#size += chunk.length;
            this.#chunks.push(chunk);
        });
        this.#done = new Promise<void>(resolve => {
            pipeline(stages, (err?: Error | null) => {
                if (err && !this.#error && !this.#destroyed) this.#options.onError(this.#fail(chain.isDecodeError(err) ? decodeError(err) : err));
                resolve();
            });
        });
        return stages[0];
    }
}

/** The decoding stages of a body, shared by both readers. See decodingChain. */
export interface DecodingChain {
    /** The decoders (decoding order), then a stage holding the decoded bytes to maxBodySize: pipe the wire bytes in. */
    readonly stages: Transform[];
    /** Records an error that happened before the chain (the source, the wire stage): it is never a decoding failure. */
    readonly upstreamFailed: (err: unknown) => void;
    /** Whether `err` is a decoder's own failure (map it with decodeError), not an error a decoder only passed on. */
    readonly isDecodeError: (err: unknown) => boolean;
}

/**
 * The decoders for `codings` and a last stage bounding the decoded bytes. When one stage of a pipeline fails, the
 * pipeline destroys every other stage with that same error and a decoder re-emits it: so only the first error seen, if
 * a decoder raised it, is a decoding failure. A body limit or a lost connection keeps its own class and code.
 */
export function decodingChain(codings: readonly string[], o: { readonly maxBodySize: number; readonly tooLarge: () => Error }): DecodingChain {
    let first: { err: unknown; fromDecoder: boolean } | undefined;
    const note = (err: unknown, fromDecoder: boolean) => { first ??= { err, fromDecoder }; };
    const decoders = codings.map(coding => {
        const decoder = createDecoder(coding);
        // A premature close is the pipeline's own error for a stage that ended without an error or an end (a source
        // closed mid-body): zlib never raises it.
        decoder.on('error', (err: NodeJS.ErrnoException) => note(err, err.code !== 'ERR_STREAM_PREMATURE_CLOSE'));
        return decoder;
    });
    let size = 0;
    const bounded = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
            size += chunk.length;
            if (size <= o.maxBodySize) return callback(null, chunk);
            const err = o.tooLarge();
            note(err, false);
            callback(err);
        },
    });
    return {
        stages: [...decoders, bounded],
        upstreamFailed: err => note(err, false),
        isDecodeError: err => first !== undefined && first.fromDecoder && first.err === err,
    };
}

export interface BodyStreamOptions {
    /** The response as it comes off the wire: an IncomingMessage (HTTP/1) or a ClientHttp2Stream (HTTP/2). */
    readonly source: Readable;
    readonly contentEncoding: string | string[] | undefined;
    readonly decompress: boolean;
    readonly maxBodySize: number;
    /** The content-length the wire bytes must match, if the response promised one (see declaredBodyLength). */
    readonly declaredLength: number | undefined;
    readonly socketTimeoutMs: number;
    readonly signal: AbortSignal | undefined;
    readonly tooLarge: () => Error;
    readonly idle: () => Error;
    /** Maps an error (socket, stream reset, a limit) to what the caller sees; a closed client wins over all of them. */
    readonly mapError: (err: unknown) => unknown;
    /** Called once when the body ended (no argument) or failed (the error the caller got); not on a cancel. */
    readonly onSettled?: (err?: unknown) => void;
    /**
     * Judged the moment the source ends, before any of it is handed on: an error when that end was not a complete
     * response (an HTTP/2 stream ends normally even when its connection was lost or the client closed). Called once.
     */
    readonly verifyEnd?: () => Error | undefined;
    /** Called once when the source has ended, with verifyEnd's verdict (an HTTP/2 upload still open can be ended then). */
    readonly onSourceEnd?: (error: Error | undefined) => void;
}

/**
 * The body of a streamed response, with the same limits as a buffered one: wire bytes and decoded bytes bounded by
 * `maxBodySize`, a body cut short of its content-length or a corrupt compressed body failing the stream (never ending it
 * cleanly), the signal's reason on abort. Backpressure reaches the socket (HTTP/1) or the flow-control window (HTTP/2).
 * `socketTimeoutMs` only runs while the consumer is waiting for data (highWaterMark 0 on the web stream; the Node stages
 * in between still read a few tens of KiB ahead), so a slow consumer never times out the server, while a server that
 * goes silent mid-body does. Cancelling it destroys the
 * source: the socket is closed or the HTTP/2 stream reset.
 */
export function createBodyStream(o: BodyStreamOptions): ReadableStream<Uint8Array> {
    const codings = o.decompress ? codingsFor(o.contentEncoding) : [];
    const codingError = codings instanceof Error ? codings : undefined;
    const chain = decodingChain(codingError ? [] : (codings as string[]), o);
    let wireBytes = 0;
    // Registered before the pipeline's own listeners, so the verdict exists by the time the wire stage flushes, and a
    // source error is known not to be a decoding failure before the pipeline hands it to the decoders.
    let endVerdict: Error | undefined;
    o.source.once('end', () => {
        endVerdict = o.verifyEnd?.();
        o.onSourceEnd?.(endVerdict);
    });
    o.source.on('error', chain.upstreamFailed);
    const fail = (callback: (err: Error) => void, err: Error) => {
        chain.upstreamFailed(err);
        callback(err);
    };
    const wire = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
            if (codingError) return fail(callback, codingError);
            wireBytes += chunk.length;
            if (wireBytes > o.maxBodySize) return fail(callback, o.tooLarge());
            callback(null, chunk);
        },
        flush(callback) {
            if (endVerdict) return fail(callback, endVerdict);
            if (o.declaredLength !== undefined && wireBytes !== o.declaredLength) return fail(callback, incompleteResponse());
            callback();
        },
    });
    // Errors reach the consumer through the iterator; the callback only drops the abort listener once every stage is done.
    const out = pipeline([o.source, wire, ...chain.stages], () => stopListening()) as unknown as Transform;
    const iterator = out[Symbol.asyncIterator]() as AsyncIterator<Buffer>;

    let settled = false;
    // A failure this function forced (abort, idle): it wins over whatever error the teardown produces.
    let forced: { error: unknown } | undefined;
    const stopListening = () => o.signal?.removeEventListener('abort', onAbort);
    const settle = (err?: unknown) => {
        if (settled) return;
        settled = true;
        stopListening();
        o.onSettled?.(err);
    };
    const force = (error: unknown) => {
        forced ??= { error };
        out.destroy();
    };
    const onAbort = () => force(o.signal!.reason);
    if (o.signal?.aborted) onAbort();
    else o.signal?.addEventListener('abort', onAbort, { once: true });

    const toCaller = (err: unknown) => {
        if (forced) return forced.error;
        // mapError keeps SecureHttpErrors as they are, unless the client was closed: then that is the reason.
        return o.mapError(chain.isDecodeError(err) ? decodeError(err) : err);
    };
    const whileWaiting = <V>(next: Promise<V>): Promise<V> => {
        if (o.socketTimeoutMs <= 0) return next;
        let timer: NodeJS.Timeout | undefined;
        const idle = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                force(o.idle());
                reject(forced!.error);
            }, o.socketTimeoutMs);
        });
        return Promise.race([next, idle]).finally(() => clearTimeout(timer));
    };

    return new ReadableStream<Uint8Array>({
        async pull(controller) {
            try {
                const next = await whileWaiting(iterator.next());
                if (next.done) {
                    settle();
                    controller.close();
                } else {
                    controller.enqueue(next.value);
                }
            } catch (err: unknown) {
                const error = toCaller(err);
                settle(error);
                controller.error(error);
            }
        },
        cancel() {
            settled = true;
            stopListening();
            forced ??= { error: undefined };
            out.destroy();
        },
    }, { highWaterMark: 0 });
}
