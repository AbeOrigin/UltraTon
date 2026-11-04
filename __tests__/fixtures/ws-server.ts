/**
 * A WebSocket peer for tests, written by hand on top of node:http's 'upgrade' event so that it can send anything,
 * malformed frames and handshakes included: the server frame builder, the 101 a valid server answers with, and a
 * reader of the (masked) frames the client sends.
 */
import type { TestContext } from 'node:test';
import { createHash } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import type { Duplex } from 'node:stream';

/** A server frame: unmasked unless asked, FIN and RSV bits as given, the length as the payload's unless given. */
export function frame(opcode: number, payload: Uint8Array | string = '', { fin = true, rsv = 0, mask = false, length }: { fin?: boolean; rsv?: number; mask?: boolean; length?: number } = {}): Buffer {
    const body = Buffer.from(payload);
    const len = length ?? body.length;
    const head = len < 126 ? Buffer.from([0, len]) : len < 0x10000 ? Buffer.alloc(4) : Buffer.alloc(10);
    head[0] = (fin ? 0x80 : 0) | (rsv << 4) | opcode;
    if (len >= 126 && len < 0x10000) { head[1] = 126; head.writeUInt16BE(len, 2); }
    if (len >= 0x10000) { head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    if (mask) head[1] |= 0x80;
    return Buffer.concat([head, mask ? Buffer.alloc(4) : Buffer.alloc(0), body]);
}

/** A close frame's payload. */
export const closePayload = (code: number, reason = '') => Buffer.concat([Buffer.from([code >> 8, code & 0xff]), Buffer.from(reason)]);

export const acceptFor = (key: string) => createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');

/** The 101 of a valid server, with `extra` header lines (`name: value`) and without the lines named in `omit`. */
export function handshake(req: http.IncomingMessage, extra: string[] = [], omit: string[] = []): string {
    const lines = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${acceptFor(String(req.headers['sec-websocket-key']))}`,
        ...extra,
    ].filter(line => !omit.some(name => line.toLowerCase().startsWith(`${name.toLowerCase()}:`)));
    return `${lines.join('\r\n')}\r\n\r\n`;
}

export interface ClientFrame {
    readonly fin: boolean;
    readonly opcode: number;
    readonly masked: boolean;
    readonly payload: Buffer;
}

/** Reads the frames the client sends on `socket`, unmasking them. */
export class ClientFrames {
    readonly frames: ClientFrame[] = [];
    #buffer = Buffer.alloc(0);
    #waiters: (() => void)[] = [];
    #taken = 0;

    constructor(socket: Duplex) {
        socket.on('data', (chunk: Buffer) => {
            this.#buffer = Buffer.concat([this.#buffer, chunk]);
            this.#parse();
        });
    }

    #parse(): void {
        for (;;) {
            const b = this.#buffer;
            if (b.length < 2) return;
            let len = b[1] & 0x7f;
            let at = 2;
            if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); at = 4; }
            if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); at = 10; }
            const masked = (b[1] & 0x80) !== 0;
            const maskAt = at;
            if (masked) at += 4;
            if (b.length < at + len) return;
            const payload = Buffer.from(b.subarray(at, at + len));
            if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= b[maskAt + (i & 3)];
            this.frames.push({ fin: (b[0] & 0x80) !== 0, opcode: b[0] & 0x0f, masked, payload });
            this.#buffer = b.subarray(at + len);
            for (const wake of this.#waiters.splice(0)) wake();
        }
    }

    /** The next frame not taken yet, waiting for it. */
    async next(): Promise<ClientFrame> {
        while (this.#taken === this.frames.length) await new Promise<void>(resolve => this.#waiters.push(resolve));
        return this.frames[this.#taken++];
    }
}

export interface Peer {
    readonly req: http.IncomingMessage;
    readonly socket: Socket;
    readonly frames: ClientFrames;
}

/**
 * A loopback server whose upgrades go to `onUpgrade` (it writes its own answer: see handshake) and plain requests to
 * `onRequest` (404 by default). `peers` resolves each upgrade, in order. Every socket is destroyed after the test.
 */
export async function wsServer(t: TestContext, onUpgrade: (peer: Peer, head: Buffer) => void, onRequest?: http.RequestListener) {
    const sockets = new Set<Socket>();
    const server = http.createServer(onRequest ?? ((_req, res) => { res.writeHead(404); res.end(); }));
    let upgrades = 0;
    server.on('connection', socket => { sockets.add(socket); });
    server.on('upgrade', (req: http.IncomingMessage, socket: Socket, head: Buffer) => {
        upgrades++;
        socket.on('error', () => {});
        onUpgrade({ req, socket, frames: new ClientFrames(socket) }, head);
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
    });
    const port = (server.address() as AddressInfo).port;
    return { port, url: (path = '/') => `ws://127.0.0.1:${port}${path}`, upgrades: () => upgrades };
}

/** An upgrade handler that accepts and then runs `then` with the peer. */
export const accepting = (then: (peer: Peer) => void = () => {}) => (peer: Peer) => {
    peer.socket.write(handshake(peer.req));
    then(peer);
};

/** A peer that echoes every data frame and answers a close with the same code, then ends the connection. */
export const echo = accepting(({ socket, frames }) => {
    void (async () => {
        for (;;) {
            const f = await frames.next();
            if (f.opcode === 0x8) {
                socket.end(frame(0x8, f.payload));
                return;
            }
            if (f.opcode === 0x1 || f.opcode === 0x2) socket.write(frame(f.opcode, f.payload));
        }
    })();
});
