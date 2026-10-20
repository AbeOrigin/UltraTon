import zlib from 'node:zlib';
import { finished, pipeline, type Transform } from 'node:stream';
import { SecureHttpError, UltraTonNetworkError } from '../errors.ts';

/** The content-codings the reader decodes. */
const CODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br']);

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
export const ACCEPT_ENCODING = 'gzip, deflate, br';

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

    #start(): Transform {
        const decoders = this.#codings.map(createDecoder);
        const last = decoders[decoders.length - 1];
        last.on('data', (chunk: Buffer) => {
            if (this.#error || this.#destroyed) return;
            if (!this.#collect(chunk)) this.#options.onError(this.#error!);
        });
        this.#done = new Promise<void>(resolve => {
            const done = (err?: Error | null) => {
                if (err && !this.#error && !this.#destroyed) this.#options.onError(this.#fail(decodeError(err)));
                resolve();
            };
            if (decoders.length === 1) finished(last, done);
            else pipeline(decoders[0], decoders[1], done);
        });
        return decoders[0];
    }
}
