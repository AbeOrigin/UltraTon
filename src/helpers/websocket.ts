import { isUtf8 } from 'node:buffer';
import { createHash, randomBytes, randomFillSync } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import type { Duplex } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { LineBuffer } from './event-stream.ts';
import { incompleteResponse, responseHeaders } from './response.ts';
import { idleTimeout, toNetworkError, wsClosed, wsHandshake, wsMessageTooLarge, wsProtocol, wsSendBuffer } from '../errors.ts';
import { WS_MAX_BUFFERED_BYTES } from '../constants.ts';
import type { UltraTonWebSocket } from '../types/request-response.ts';

/** RFC 6455 opcodes. Every other value is reserved and fails the connection. */
export const Opcode = {
    Continuation: 0x0,
    Text: 0x1,
    Binary: 0x2,
    Close: 0x8,
    Ping: 0x9,
    Pong: 0xa,
} as const;
export type Opcode = (typeof Opcode)[keyof typeof Opcode];

/** A message, or a control frame, the parser has fully read. */
export type Incoming =
    | { readonly kind: 'message'; readonly data: string | Buffer }
    | { readonly kind: 'ping' | 'pong'; readonly payload: Buffer }
    | { readonly kind: 'close'; readonly code: number; readonly reason: string };

/** A violation by the server, with the close code to fail the connection with (1002, 1007 or 1009). The message is fixed text, never server data. */
export class FrameError extends Error {
    readonly closeCode: number;

    constructor(closeCode: number, message: string) {
        super(message);
        this.closeCode = closeCode;
    }
}

const protocolError = (message: string) => new FrameError(1002, message);

/** Close codes a peer may send (RFC 6455 7.4, and the IANA registry up to 1014); 1004-1006 and 1015 never go on the wire. */
export function isValidCloseCode(code: number): boolean {
    return (code >= 1000 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006) || (code >= 3000 && code <= 4999);
}

/**
 * Reads the frames a server sends, from bytes cut anywhere. Every bound is checked from the frame header, before any
 * payload is copied: a frame, or the fragments of a message so far plus the next one, past `maxMessageSize` fails
 * at once, however large the length it announces (the 64-bit form included). Fragments gather in one buffer that
 * doubles, so what a message holds stays within about twice its bytes however many fragments it comes in (an empty
 * fragment costs no object). Control frames may arrive between fragments, as RFC 6455 allows.
 */
export class FrameParser {
    readonly #maxMessageSize: number;
    readonly #header = Buffer.alloc(10);
    #headerHave = 0;
    /** A frame's header has been read and its payload is being read. */
    #inFrame = false;
    #fin = false;
    #opcode = 0;
    #remaining = 0;
    /** The payload of the control frame being read (at most 125 bytes). */
    #control: Buffer | undefined;
    #controlHave = 0;
    /** The opcode of the message whose fragments are being gathered; 0 when none. */
    #messageOpcode = 0;
    #message = new LineBuffer();

    constructor(maxMessageSize: number) {
        this.#maxMessageSize = maxMessageSize;
    }

    /** Feeds bytes; returns what is complete so far, in order. Throws a FrameError on the first violation. */
    push(chunk: Uint8Array): Incoming[] {
        const out: Incoming[] = [];
        let at = 0;
        for (;;) {
            if (!this.#inFrame) {
                if (at >= chunk.length) break;
                at = this.#readHeader(chunk, at);
                if (!this.#inFrame) break;
            }
            const take = Math.min(this.#remaining, chunk.length - at);
            if (take > 0) {
                const bytes = chunk.subarray(at, at + take);
                if (this.#control) {
                    this.#control.set(bytes, this.#controlHave);
                    this.#controlHave += take;
                } else {
                    this.#message.append(bytes);
                }
                at += take;
                this.#remaining -= take;
            }
            if (this.#remaining > 0) break;
            this.#inFrame = false;
            const done = this.#finishFrame();
            if (done) out.push(done);
        }
        return out;
    }

    #readHeader(chunk: Uint8Array, at: number): number {
        while (at < chunk.length) {
            this.#header[this.#headerHave++] = chunk[at++];
            if (this.#headerHave === 2) this.#checkFirstBytes();
            if (this.#headerHave >= 2 && this.#headerHave === headerLength(this.#header[1])) {
                this.#startFrame();
                return at;
            }
        }
        return at;
    }

    /** What the first two bytes alone can rule out. */
    #checkFirstBytes(): void {
        const b0 = this.#header[0];
        const b1 = this.#header[1];
        if (b0 & 0x70) throw protocolError('a reserved bit is set (no extension was negotiated)');
        const opcode = b0 & 0x0f;
        const fin = (b0 & 0x80) !== 0;
        if (b1 & 0x80) throw protocolError('the server masked a frame');
        if (opcode >= 0x8) {
            if (opcode > Opcode.Pong) throw protocolError('a reserved opcode');
            if (!fin) throw protocolError('a fragmented control frame');
            if ((b1 & 0x7f) > 125) throw protocolError('a control frame longer than 125 bytes');
        } else if (opcode === Opcode.Continuation) {
            if (this.#messageOpcode === 0) throw protocolError('a continuation frame with no message to continue');
        } else if (opcode === Opcode.Text || opcode === Opcode.Binary) {
            if (this.#messageOpcode !== 0) throw protocolError('a new message before the previous one ended');
        } else {
            throw protocolError('a reserved opcode');
        }
        this.#fin = fin;
        this.#opcode = opcode;
    }

    #startFrame(): void {
        const len7 = this.#header[1] & 0x7f;
        let length: number;
        if (len7 === 126) {
            length = this.#header.readUInt16BE(2);
        } else if (len7 === 127) {
            const high = this.#header.readUInt32BE(2);
            if (high & 0x80000000) throw protocolError('a 64-bit length with the most significant bit set');
            // Inexact only above 2^53, which is past any maxMessageSize: the comparison below still holds.
            length = high * 0x1_0000_0000 + this.#header.readUInt32BE(6);
        } else {
            length = len7;
        }
        this.#headerHave = 0;
        if (this.#opcode >= 0x8) {
            this.#control = Buffer.allocUnsafe(length);
            this.#controlHave = 0;
        } else {
            if (this.#message.length + length > this.#maxMessageSize) throw new FrameError(1009, 'a message over maxMessageSize');
            this.#control = undefined;
            if (this.#opcode !== Opcode.Continuation) this.#messageOpcode = this.#opcode;
        }
        this.#remaining = length;
        this.#inFrame = true;
    }

    #finishFrame(): Incoming | undefined {
        const control = this.#control;
        if (control) {
            this.#control = undefined;
            if (this.#opcode === Opcode.Ping) return { kind: 'ping', payload: control };
            if (this.#opcode === Opcode.Pong) return { kind: 'pong', payload: control };
            return readClose(control);
        }
        if (!this.#fin) return undefined;
        const opcode = this.#messageOpcode;
        this.#messageOpcode = 0;
        const bytes = this.#message.take(EMPTY);
        if (opcode === Opcode.Binary) return { kind: 'message', data: bytes };
        if (!isUtf8(bytes)) throw new FrameError(1007, 'a text message that is not valid UTF-8');
        return { kind: 'message', data: bytes.toString('utf8') };
    }
}

const EMPTY = new Uint8Array(0);

/** Bytes of a server frame's header, from its second byte (a server frame is never masked: checked before this is used). */
function headerLength(b1: number): number {
    const len7 = b1 & 0x7f;
    return len7 === 126 ? 4 : len7 === 127 ? 10 : 2;
}

function readClose(payload: Buffer): Incoming {
    if (payload.length === 0) return { kind: 'close', code: 1005, reason: '' };
    if (payload.length === 1) throw protocolError('a close frame of one byte');
    const code = payload.readUInt16BE(0);
    if (!isValidCloseCode(code)) throw protocolError('an invalid close code');
    const reason = payload.subarray(2);
    if (!isUtf8(reason)) throw new FrameError(1007, 'a close reason that is not valid UTF-8');
    return { kind: 'close', code, reason: reason.toString('utf8') };
}

/** One client frame, FIN set and masked with `mask` (4 bytes): the client never fragments what it sends. */
export function encodeFrame(opcode: Opcode, payload: Uint8Array, mask: Uint8Array): Buffer {
    const length = payload.length;
    const headerLen = length < 126 ? 2 : length < 0x1_0000 ? 4 : 10;
    const frame = Buffer.allocUnsafe(headerLen + 4 + length);
    frame[0] = 0x80 | opcode;
    if (length < 126) {
        frame[1] = 0x80 | length;
    } else if (length < 0x1_0000) {
        frame[1] = 0x80 | 126;
        frame.writeUInt16BE(length, 2);
    } else {
        frame[1] = 0x80 | 127;
        frame.writeUInt32BE(Math.floor(length / 0x1_0000_0000), 2);
        frame.writeUInt32BE(length >>> 0, 6);
    }
    frame.set(mask.subarray(0, 4), headerLen);
    const start = headerLen + 4;
    for (let i = 0; i < length; i++) frame[start + i] = payload[i] ^ mask[i & 3];
    return frame;
}

/** RFC 6455 1.3: what the server appends to the client's key before hashing it into `Sec-WebSocket-Accept`. */
const ACCEPT_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/** Header names the handshake owns: set by the caller, a client default or a `headers` function, they would break it. */
export const WS_RESERVED_HEADERS: ReadonlySet<string> = new Set(['connection', 'upgrade', 'sec-websocket-key', 'sec-websocket-version', 'sec-websocket-extensions', 'sec-websocket-protocol', 'sec-websocket-accept']);

/** The headers of a client upgrade (RFC 6455 4.1), with a fresh key; the server's accept is checked against `key`. No extension is offered. */
export function upgradeRequest(protocols: readonly string[]): { key: string; headers: Record<string, string> } {
    const key = randomBytes(16).toString('base64');
    const headers: Record<string, string> = {
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': key,
        'sec-websocket-version': '13',
    };
    if (protocols.length > 0) headers['sec-websocket-protocol'] = protocols.join(', ');
    return { key, headers };
}

/**
 * Checks the server's 101 (RFC 6455 4.2.2, from the client's side) and returns the subprotocol it chose, `''` for none.
 * @throws {SecureHttpError} `ERR_ULTRATON_WS_HANDSHAKE`: no `Upgrade: websocket` or `Connection: upgrade`, a wrong
 *   `Sec-WebSocket-Accept`, any extension (none is offered), or a subprotocol that was not offered.
 */
export function acceptedProtocol(headers: IncomingHttpHeaders, key: string, protocols: readonly string[]): string {
    const value = (name: string): string | undefined => {
        const raw = headers[name];
        return Array.isArray(raw) ? raw.join(', ') : raw;
    };
    if (value('upgrade')?.trim().toLowerCase() !== 'websocket') throw wsHandshake('no Upgrade: websocket');
    if (!value('connection')?.split(',').some(token => token.trim().toLowerCase() === 'upgrade')) throw wsHandshake('no Connection: upgrade');
    const expected = createHash('sha1').update(key + ACCEPT_GUID).digest('base64');
    if (value('sec-websocket-accept')?.trim() !== expected) throw wsHandshake('a wrong Sec-WebSocket-Accept');
    if (headers['sec-websocket-extensions'] !== undefined) throw wsHandshake('an extension the client did not offer');
    const chosen = value('sec-websocket-protocol')?.trim() ?? '';
    if (chosen !== '' && !protocols.includes(chosen)) throw wsHandshake('a subprotocol the client did not offer');
    return chosen;
}

// Masks come from the CSPRNG, 4 bytes per frame, drawn from a pool so a busy sender does not make a call per frame.
const maskPool = Buffer.allocUnsafe(4096);
let maskAt = maskPool.length;
function nextMask(): Buffer {
    if (maskAt === maskPool.length) {
        randomFillSync(maskPool);
        maskAt = 0;
    }
    maskAt += 4;
    return maskPool.subarray(maskAt - 4, maskAt);
}

/** The bounds and hooks of one connection, already validated. */
export interface WebSocketSettings {
    readonly url: string;
    /** The 101's headers, as Node parsed them. */
    readonly headers: IncomingHttpHeaders;
    readonly protocol: string;
    readonly maxMessageSize: number;
    /** Time without a frame while a message is awaited (or after a ping), and without progress on a write; 0 for none. */
    readonly socketTimeoutMs: number;
    readonly pingIntervalMs: number;
    readonly closeTimeoutMs: number;
    readonly signal?: AbortSignal;
    /** Called once, when the socket has closed for any reason. */
    readonly onClosed: () => void;
}

/**
 * One WebSocket connection over an upgraded socket. The socket is read only while someone waits on it (a message, or
 * the close handshake), so what the server sends past what is read stays in TCP; the timers run only then too. Once
 * it fails, every read and send rejects with the failure.
 */
export class WebSocketConnection implements UltraTonWebSocket {
    readonly url: string;
    readonly headers: IncomingHttpHeaders;
    readonly protocol: string;
    readonly #socket: Duplex;
    readonly #settings: WebSocketSettings;
    readonly #parser: FrameParser;
    readonly #closed: Promise<void>;
    /** 'open' until a close frame is sent ('closing') or the connection ends ('closed'). */
    #state: 'open' | 'closing' | 'closed' = 'open';
    #socketClosed = false;
    #failure: unknown;
    #closeCode: number | undefined;
    #closeReason: string | undefined;
    /** Messages read but not handed out: at most what one chunk from the socket held. */
    #messages: (string | Buffer)[] = [];
    #waiters: (() => void)[] = [];
    /** The idle or ping timer, armed only while someone waits. */
    #timer: NodeJS.Timeout | undefined;
    #writeTimer: NodeJS.Timeout | undefined;
    #closeTimer: NodeJS.Timeout | undefined;
    #lastFrameAt = performance.now();
    #pingSentAt: number | undefined;
    /** The answer to the latest ping, while the socket has writes queued: one at most, however many pings come. */
    #pendingPong: Buffer | undefined;
    /** How to reject each send() whose frame is not written yet. */
    #pendingWrites = new Set<(err: unknown) => void>();
    #closing: Promise<void> | undefined;
    #iterating = false;
    #onAbort: (() => void) | undefined;

    constructor(socket: Duplex, head: Buffer, settings: WebSocketSettings) {
        this.url = settings.url;
        this.headers = responseHeaders(settings.headers);
        this.protocol = settings.protocol;
        this.#socket = socket;
        this.#settings = settings;
        this.#parser = new FrameParser(settings.maxMessageSize);
        const net = socket as Duplex & { setTimeout?: (ms: number) => void; setNoDelay?: (on: boolean) => void };
        // The timeout the agent or the request armed on the socket would still fire: the timers here replace it.
        net.setTimeout?.(0);
        net.setNoDelay?.(true);
        this.#closed = new Promise(resolve => socket.once('close', resolve));
        socket.on('readable', () => this.#wakeAll());
        socket.on('drain', () => {
            const pong = this.#pendingPong;
            this.#pendingPong = undefined;
            if (pong && this.#state === 'open') socket.write(encodeFrame(Opcode.Pong, pong, nextMask()));
        });
        // A reset during the close handshake is how some servers end it: only an open connection fails.
        socket.on('error', (err: Error) => {
            if (this.#state === 'open' && this.#failure === undefined) this.#failure = toNetworkError(err);
            this.#wakeAll();
        });
        socket.once('close', () => this.#onSocketClose());
        if (socket.closed) queueMicrotask(() => this.#onSocketClose());
        const signal = settings.signal;
        if (signal) {
            this.#onAbort = () => this.destroy(signal.reason);
            if (signal.aborted) this.#onAbort();
            else signal.addEventListener('abort', this.#onAbort, { once: true });
        }
        if (head.length > 0) this.#feed(head);
    }

    get closeCode(): number | undefined {
        return this.#closeCode;
    }

    get closeReason(): string | undefined {
        return this.#closeReason;
    }

    /** Ends the connection now, without the close handshake: `reason` is what reads and sends reject with. */
    destroy(reason: unknown): void {
        if (this.#failure === undefined && !this.#socketClosed) this.#failure = reason;
        this.#socket.destroy();
        this.#wakeAll();
    }

    send(data: string | Uint8Array): Promise<void> {
        let opcode: Opcode;
        let payload: Uint8Array;
        if (typeof data === 'string') {
            opcode = Opcode.Text;
            payload = Buffer.from(data, 'utf8');
        } else if (data instanceof Uint8Array) {
            opcode = Opcode.Binary;
            payload = data;
        } else {
            const received = data === null ? 'null' : typeof data;
            return Promise.reject(new TypeError(`UltraTon: Expected send() to get a string or a Uint8Array, received ${received}.`));
        }
        if (this.#failure !== undefined) return Promise.reject(this.#failure);
        if (this.#state !== 'open') return Promise.reject(wsClosed());
        if (this.#socket.writableLength > WS_MAX_BUFFERED_BYTES) return Promise.reject(wsSendBuffer(WS_MAX_BUFFERED_BYTES));
        return this.#write(encodeFrame(opcode, payload, nextMask()));
    }

    close(code = 1000, reason = ''): Promise<void> {
        if (code !== 1000 && !(Number.isInteger(code) && code >= 3000 && code <= 4999)) {
            return Promise.reject(new TypeError(`UltraTon: Expected the close code to be 1000 or an integer from 3000 to 4999, received ${String(code)}.`));
        }
        if (typeof reason !== 'string' || Buffer.byteLength(reason) > 123) {
            return Promise.reject(new TypeError('UltraTon: Expected the close reason to be a string of at most 123 bytes of UTF-8.'));
        }
        return (this.#closing ??= this.#close(code, reason));
    }

    [Symbol.asyncIterator](): AsyncIterableIterator<string | Buffer> {
        if (this.#iterating) throw new TypeError('UltraTon: A WebSocket is read by one loop only.');
        this.#iterating = true;
        const iterator: AsyncIterableIterator<string | Buffer> = {
            next: () => this.#next(),
            // Leaving the loop closes the connection, as close() does.
            return: async () => {
                await this.close();
                return { done: true, value: undefined };
            },
            [Symbol.asyncIterator]: () => iterator,
        };
        return iterator;
    }

    async [Symbol.asyncDispose](): Promise<void> {
        await this.close();
    }

    async #next(): Promise<IteratorResult<string | Buffer, undefined>> {
        // The time the caller spent on the last message is not the server's: the idle clock starts again here. Only a
        // complete frame gets a caller here again, so a server dripping bytes cannot use it.
        this.#lastFrameAt = performance.now();
        for (;;) {
            if (this.#failure !== undefined) throw this.#failure;
            const message = this.#messages.shift();
            if (message !== undefined) return { done: false, value: message };
            if (this.#state !== 'open') return { done: true, value: undefined };
            const chunk = this.#socket.read() as Buffer | null;
            if (chunk !== null) {
                this.#feed(chunk);
                continue;
            }
            await this.#wait();
        }
    }

    async #close(code: number, reason: string): Promise<void> {
        if (this.#state === 'open' && this.#failure === undefined && !this.#socketClosed) {
            this.#writeClose(code, reason);
            this.#state = 'closing';
            this.#armCloseTimer();
            // A loop waiting for a message ends.
            this.#wakeAll();
            // Read until the server's close frame (messages are dropped) or the end of the connection; the close timer
            // bounds both.
            while (this.#state === 'closing' && !this.#socketClosed) {
                const chunk = this.#socket.read() as Buffer | null;
                if (chunk !== null) this.#feed(chunk);
                else await this.#wait();
            }
        }
        // The socket ends on its own now (the server's turn), or is destroyed by the close timer.
        await this.#closed;
    }

    #feed(chunk: Buffer): void {
        let items: Incoming[];
        try {
            items = this.#parser.push(chunk);
        } catch (err: unknown) {
            if (!(err instanceof FrameError)) throw err;
            this.#fail(err.closeCode === 1009 ? wsMessageTooLarge(this.#settings.maxMessageSize) : wsProtocol(err.message), err.closeCode);
            return;
        }
        if (items.length === 0) return;
        this.#lastFrameAt = performance.now();
        this.#pingSentAt = undefined;
        for (const item of items) {
            if (item.kind === 'message') {
                if (this.#state === 'open') this.#messages.push(item.data);
            } else if (item.kind === 'ping') {
                this.#pong(item.payload);
            } else if (item.kind === 'close') {
                // Nothing after a close frame is read.
                this.#serverClosed(item.code, item.reason);
                return;
            }
        }
    }

    #serverClosed(code: number, reason: string): void {
        this.#closeCode = code;
        this.#closeReason = reason;
        // Its own code back (an empty close for none: 1005 never goes on the wire), unless the client closed first.
        if (this.#state === 'open') this.#writeClose(code === 1005 ? undefined : code, '');
        this.#state = 'closed';
        this.#socket.end();
        this.#armCloseTimer();
        this.#wakeAll();
    }

    /** Fails the connection: with `closeCode`, the close frame is sent first (RFC 6455 7.1.7), then the socket ends. */
    #fail(error: unknown, closeCode?: number): void {
        if (this.#failure === undefined) this.#failure = error;
        if (closeCode !== undefined && this.#state === 'open' && !this.#socketClosed) {
            this.#writeClose(closeCode, '');
            this.#state = 'closed';
            this.#socket.end();
            this.#armCloseTimer();
        } else {
            this.#socket.destroy();
        }
        this.#wakeAll();
    }

    #onSocketClose(): void {
        if (this.#socketClosed) return;
        this.#socketClosed = true;
        clearTimeout(this.#timer);
        clearTimeout(this.#writeTimer);
        clearTimeout(this.#closeTimer);
        if (this.#onAbort) this.#settings.signal?.removeEventListener('abort', this.#onAbort);
        // Ended without a close frame: never a clean end.
        if (this.#state === 'open' && this.#failure === undefined) this.#failure = incompleteResponse();
        this.#state = 'closed';
        for (const fail of this.#pendingWrites) fail(this.#failure ?? wsClosed());
        this.#pendingWrites.clear();
        this.#wakeAll();
        this.#settings.onClosed();
    }

    #writeClose(code: number | undefined, reason: string): void {
        const payload = code === undefined ? Buffer.alloc(0) : Buffer.concat([Buffer.from([code >> 8, code & 0xff]), Buffer.from(reason)]);
        this.#socket.write(encodeFrame(Opcode.Close, payload, nextMask()));
    }

    #pong(payload: Buffer): void {
        if (this.#state !== 'open') return;
        if (this.#socket.writableNeedDrain) this.#pendingPong = payload;
        else this.#socket.write(encodeFrame(Opcode.Pong, payload, nextMask()));
    }

    #write(frame: Buffer): Promise<void> {
        return new Promise((resolve, reject) => {
            // Settled by the write's callback or, if the socket closes with the write still pending (a destroyed socket
            // need not call it back), by the close.
            const fail = (err: unknown) => reject(err);
            this.#pendingWrites.add(fail);
            this.#armWriteTimer();
            this.#socket.write(frame, (err?: Error | null) => {
                if (!this.#pendingWrites.delete(fail)) return;
                // Progress: the timer starts again for what is still queued.
                clearTimeout(this.#writeTimer);
                this.#writeTimer = undefined;
                if (this.#pendingWrites.size > 0) this.#armWriteTimer();
                if (err) reject(this.#failure ?? toNetworkError(err));
                else resolve();
            });
        });
    }

    #armWriteTimer(): void {
        const timeout = this.#settings.socketTimeoutMs;
        if (timeout > 0 && this.#writeTimer === undefined) this.#writeTimer = setTimeout(() => this.#fail(idleTimeout(timeout)), timeout);
    }

    #armCloseTimer(): void {
        if (this.#closeTimer !== undefined || this.#socketClosed) return;
        this.#closeTimer = setTimeout(() => this.#socket.destroy(), this.#settings.closeTimeoutMs);
        this.#closeTimer.unref();
    }

    #wait(): Promise<void> {
        return new Promise(resolve => {
            this.#waiters.push(resolve);
            this.#armIdle();
        });
    }

    #wakeAll(): void {
        clearTimeout(this.#timer);
        this.#timer = undefined;
        const waiters = this.#waiters;
        this.#waiters = [];
        for (const wake of waiters) wake();
    }

    /**
     * While a message is awaited: with `pingIntervalMs`, a ping once the server has been quiet that long, then
     * `socketTimeoutMs` for any frame to arrive; without it, `socketTimeoutMs` since the last frame. During the close
     * handshake the close timer bounds the wait instead.
     */
    #armIdle(): void {
        if (this.#state !== 'open' || this.#timer !== undefined) return;
        const { socketTimeoutMs: timeout, pingIntervalMs: interval } = this.#settings;
        const now = performance.now();
        let wakeAt: number | undefined;
        if (interval > 0 && this.#pingSentAt === undefined) {
            const pingAt = this.#lastFrameAt + interval;
            if (pingAt <= now) {
                this.#socket.write(encodeFrame(Opcode.Ping, EMPTY, nextMask()));
                this.#pingSentAt = now;
                if (timeout > 0) wakeAt = now + timeout;
            } else {
                wakeAt = pingAt;
            }
        } else if (timeout > 0) {
            const deadline = (this.#pingSentAt ?? this.#lastFrameAt) + timeout;
            if (deadline <= now) {
                this.#fail(idleTimeout(timeout));
                return;
            }
            wakeAt = deadline;
        }
        if (wakeAt !== undefined) this.#timer = setTimeout(() => this.#wakeAll(), Math.max(1, Math.ceil(wakeAt - now)));
    }
}
