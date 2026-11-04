import { isUtf8 } from 'node:buffer';
import { LineBuffer } from './event-stream.ts';

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
