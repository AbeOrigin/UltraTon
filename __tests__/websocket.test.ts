/**
 * `client.websocket()` against loopback peers written by hand (fixtures/ws-server.ts), so that they can break every
 * rule: the handshake checks, the SSRF checks the upgrade gets from the HTTP/1 engine, the limits and timers of a
 * connection, the close handshake, and the send buffer. The frame parser itself is tested in websocket-frames.test.ts.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { Duplex } from 'node:stream';
import { UltraTonClient } from '../src/http-client.ts';
import { kWebSocketCloseTimeout } from '../src/internal.ts';
import { UltraTonHttpError } from '../src/errors.ts';
import { WebSocketConnection } from '../src/helpers/websocket.ts';
import { accepting, closePayload, echo, frame, handshake, wsServer, type Peer } from './fixtures/ws-server.ts';
import { mockDns, v4 } from './fixtures/net-fixtures.ts';

const TEXT = 0x1;
const BINARY = 0x2;
const CLOSE = 0x8;
const PING = 0x9;
const PONG = 0xa;

function client(t: TestContext, options: Record<string, unknown> = {}): UltraTonClient {
    const c = new UltraTonClient({ permitReservedIps: true, [kWebSocketCloseTimeout]: 300, ...options } as any);
    t.after(() => c.close());
    return c;
}

const code = (expected: string) => (err: any) => {
    assert.equal(err?.code, expected, String(err));
    return true;
};

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/** The close code in a close frame's payload. */
const closeCodeOf = (payload: Buffer) => (payload.length >= 2 ? payload.readUInt16BE(0) : undefined);

describe('websocket(): handshake', () => {
    it('opens with a valid handshake, sending only what the protocol and the client set', async (t) => {
        let seen: Peer['req'] | undefined;
        const server = await wsServer(t, accepting(peer => { seen = peer.req; }));
        const ws = await client(t, { headers: { 'x-team': 'a' } }).websocket(server.url('/chat?x=1'));
        assert.equal(ws.url, `ws://127.0.0.1:${server.port}/chat?x=1`);
        assert.equal(ws.protocol, '');
        assert.equal(ws.headers.upgrade, 'websocket');
        assert.equal(seen?.headers['sec-websocket-version'], '13');
        assert.equal(Buffer.from(String(seen?.headers['sec-websocket-key']), 'base64').length, 16);
        assert.equal(seen?.headers.origin, undefined);
        assert.equal(seen?.headers['sec-websocket-extensions'], undefined);
        assert.equal(seen?.headers['accept-encoding'], undefined);
        assert.equal(seen?.headers['x-team'], 'a');
        assert.match(String(seen?.headers['user-agent']), /^ultraton\//);
        await ws.close();
    });

    it('offers subprotocols and accepts only one of them', async (t) => {
        const pick = (name: string) => (peer: Peer) => peer.socket.write(handshake(peer.req, [`Sec-WebSocket-Protocol: ${name}`]));
        const good = await wsServer(t, pick('b'));
        const ws = await client(t).websocket(good.url(), { protocols: ['a', 'b'] });
        assert.equal(ws.protocol, 'b');
        await ws.close();
        const bad = await wsServer(t, pick('c'));
        await assert.rejects(client(t).websocket(bad.url(), { protocols: ['a', 'b'] }), code('ERR_ULTRATON_WS_HANDSHAKE'));
        await assert.rejects(client(t).websocket(bad.url()), code('ERR_ULTRATON_WS_HANDSHAKE'));
    });

    it('rejects a 101 that is not a valid handshake', async (t) => {
        const answers: ((peer: Peer) => string)[] = [
            peer => handshake(peer.req, [], ['sec-websocket-accept']).replace('\r\n\r\n', '\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n'),
            peer => handshake(peer.req, ['Sec-WebSocket-Extensions: permessage-deflate']),
            // Without the upgrade headers Node reads it as a plain response: still not a WebSocket.
            peer => handshake(peer.req, [], ['upgrade', 'connection']),
        ];
        for (const answer of answers) {
            const server = await wsServer(t, peer => peer.socket.write(answer(peer)));
            await assert.rejects(client(t).websocket(server.url()), code('ERR_ULTRATON_WS_HANDSHAKE'));
        }
    });

    it('a 2xx is a failed handshake; any other status an UltraTonHttpError, never followed', async (t) => {
        const ok = await wsServer(t, peer => peer.socket.end('HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n'));
        await assert.rejects(client(t).websocket(ok.url()), code('ERR_ULTRATON_WS_HANDSHAKE'));
        const denied = await wsServer(t, peer => peer.socket.end('HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer\r\ncontent-length: 0\r\n\r\n'));
        await assert.rejects(client(t).websocket(denied.url()), (err: unknown) => {
            assert.ok(err instanceof UltraTonHttpError);
            assert.equal(err.statusCode, 401);
            assert.equal(err.response.headers['www-authenticate'], 'Bearer');
            return true;
        });
        const target = await wsServer(t, accepting());
        const moved = await wsServer(t, peer => peer.socket.end(`HTTP/1.1 302 Found\r\nlocation: ${target.url()}\r\ncontent-length: 0\r\n\r\n`));
        await assert.rejects(client(t).websocket(moved.url()), (err: unknown) => err instanceof UltraTonHttpError && err.statusCode === 302);
        const metadata = await wsServer(t, peer => peer.socket.end('HTTP/1.1 302 Found\r\nlocation: ws://169.254.169.254/\r\ncontent-length: 0\r\n\r\n'));
        await assert.rejects(client(t).websocket(metadata.url()), (err: unknown) => err instanceof UltraTonHttpError && err.statusCode === 302);
        assert.equal(target.upgrades(), 0);
    });

    it('a 101 with headers over Node\'s 16 KiB cap rejects without an upgrade', async (t) => {
        const server = await wsServer(t, peer => peer.socket.write(handshake(peer.req, [`x-big: ${'a'.repeat(17 * 1024)}`])));
        await assert.rejects(client(t).websocket(server.url()), (err: any) => err?.name === 'UltraTonNetworkError');
    });

    it('frames sent right after the 101 are read first', async (t) => {
        const server = await wsServer(t, peer => peer.socket.write(Buffer.concat([Buffer.from(handshake(peer.req)), frame(TEXT, 'early')])));
        const ws = await client(t).websocket(server.url());
        const first = await ws[Symbol.asyncIterator]().next();
        assert.deepEqual(first, { done: false, value: 'early' });
        await ws.close();
    });

    it('refuses the handshake headers from the call, the client and a headers function', async (t) => {
        const server = await wsServer(t, accepting());
        await assert.rejects(client(t).websocket(server.url(), { headers: { 'Sec-WebSocket-Protocol': 'x' } }), /set by websocket\(\).*'protocols'/);
        await assert.rejects(client(t, { headers: { upgrade: 'h2c' } }).websocket(server.url()), TypeError);
        await assert.rejects(client(t, { headers: () => ({ 'sec-websocket-key': 'x' }) }).websocket(server.url()), TypeError);
        assert.equal(server.upgrades(), 0);
    });

    it('refuses options that do not apply to an upgrade, and invalid ones of its own', async (t) => {
        const c = client(t);
        for (const options of [{ body: 'x' }, { json: {} }, { method: 'POST' }, { maxRedirects: 1 }, { retry: 1 }, { timings: true }, { maxBodySize: 1 }, { decompress: false }]) {
            await assert.rejects(c.websocket('ws://127.0.0.1:9/', options as any), /websocket\(\) does not take/);
        }
        for (const protocols of ['chat', ['a', 'a'], ['a b'], [''], [1]]) {
            await assert.rejects(c.websocket('ws://127.0.0.1:9/', { protocols } as any), /'protocols'/);
        }
        await assert.rejects(c.websocket('ws://127.0.0.1:9/', { maxMessageSize: 0 }), code('ERR_ULTRATON_OPTION_RANGE'));
        await assert.rejects(c.websocket('ws://127.0.0.1:9/', { pingIntervalMs: -1 }), code('ERR_ULTRATON_OPTION_RANGE'));
        await assert.rejects(c.websocket('ws://127.0.0.1:9/', { bogus: 1 } as any), /Unknown option 'bogus'/);
    });

    it('takes ws: and wss: URLs, or a path under baseUrl', async (t) => {
        const server = await wsServer(t, echo);
        await assert.rejects(client(t).websocket(`http://127.0.0.1:${server.port}/`), /ws: or wss:/);
        await assert.rejects(client(t).websocket(`https://127.0.0.1:${server.port}/`), /ws: or wss:/);
        const based = client(t, { baseUrl: `http://127.0.0.1:${server.port}/api/` });
        const ws = await based.websocket('chat', { query: { room: 1 } });
        assert.equal(ws.url, `ws://127.0.0.1:${server.port}/api/chat?room=1`);
        await ws.close();
        await assert.rejects(based.websocket('../x'), TypeError);
        await assert.rejects(based.websocket(server.url()), TypeError);
    });

    it('timeoutMs bounds the wait for the answer', async (t) => {
        const server = await wsServer(t, () => {});
        await assert.rejects(client(t).websocket(server.url(), { timeoutMs: 200 }), code('ERR_ULTRATON_TIMEOUT'));
    });

    it('an http2 client upgrades over HTTP/1.1', async (t) => {
        const server = await wsServer(t, echo);
        const ws = await client(t, { http2: true }).websocket(server.url());
        await ws.send('over h1');
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'over h1' });
        await ws.close();
    });
});

describe('websocket(): SSRF', () => {
    it('rejects reserved addresses in any spelling, and names that resolve to them, before connecting', async (t) => {
        const c = client(t, { permitReservedIps: false });
        for (const url of ['wss://169.254.169.254/', 'wss://[::ffff:127.0.0.1]:9/', 'wss://10.0.0.1/', 'wss://0x7f000001/', 'ws://127.0.0.1:9/']) {
            await assert.rejects(c.websocket(url), code('ERR_ULTRATON_RESERVED_IP'));
        }
        mockDns(t, { 'internal.example': [v4('10.1.2.3')] });
        await assert.rejects(c.websocket('wss://internal.example/'), code('ERR_ULTRATON_RESERVED_IP'));
    });

    it('ws: is plain http: loopback only without allowPlainHttp', async (t) => {
        await assert.rejects(client(t).websocket('ws://example.com/'), code('ERR_ULTRATON_PLAIN_HTTP'));
    });
});

describe('websocket(): messages', () => {
    it('echoes text as a string and binary as a Buffer', async (t) => {
        const server = await wsServer(t, echo);
        const ws = await client(t).websocket(server.url());
        await ws.send('héllo');
        await ws.send(Uint8Array.of(1, 2, 255));
        const it = ws[Symbol.asyncIterator]();
        assert.deepEqual(await it.next(), { done: false, value: 'héllo' });
        const binary = (await it.next()).value;
        assert.ok(Buffer.isBuffer(binary));
        assert.deepEqual([...binary as Buffer], [1, 2, 255]);
        await assert.rejects(ws.send(42 as any), TypeError);
        await ws.close();
    });

    it('reads a message that arrives one byte at a time', async (t) => {
        const server = await wsServer(t, accepting(({ socket }) => {
            const bytes = frame(TEXT, 'drip'.repeat(10));
            let i = 0;
            const id = setInterval(() => { if (i < bytes.length) socket.write(bytes.subarray(i, ++i)); else clearInterval(id); }, 1);
            socket.on('close', () => clearInterval(id));
        }));
        const ws = await client(t).websocket(server.url());
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'drip'.repeat(10) });
        await ws.close();
    });

    it('a message over maxMessageSize fails with 1009', async (t) => {
        let peer: Peer | undefined;
        const server = await wsServer(t, accepting(p => { peer = p; p.socket.write(frame(BINARY, Buffer.alloc(1025))); }));
        const ws = await client(t).websocket(server.url(), { maxMessageSize: 1024 });
        await assert.rejects(ws[Symbol.asyncIterator]().next(), code('ERR_ULTRATON_WS_MESSAGE_TOO_LARGE'));
        const sent = await peer!.frames.next();
        assert.deepEqual([sent.opcode, closeCodeOf(sent.payload)], [CLOSE, 1009]);
        assert.ok(sent.masked);
    });

    it('a protocol violation fails with 1002, invalid UTF-8 with 1007', async (t) => {
        const cases: [Buffer, number][] = [[frame(TEXT, 'x', { mask: true }), 1002], [frame(TEXT, Buffer.from([0xff])), 1007]];
        for (const [bad, closeCode] of cases) {
            let peer: Peer | undefined;
            const server = await wsServer(t, accepting(p => { peer = p; p.socket.write(bad); }));
            const ws = await client(t).websocket(server.url());
            await assert.rejects(ws[Symbol.asyncIterator]().next(), code('ERR_ULTRATON_WS_PROTOCOL'));
            const sent = await peer!.frames.next();
            assert.deepEqual([sent.opcode, closeCodeOf(sent.payload)], [CLOSE, closeCode]);
        }
    });

    it('answers a ping with its payload, and a burst with no more pongs than pings', async (t) => {
        let peer: Peer | undefined;
        const server = await wsServer(t, accepting(p => {
            peer = p;
            p.socket.write(frame(PING, 'hey'));
            for (let i = 0; i < 50; i++) p.socket.write(frame(PING, String(i)));
            p.socket.write(frame(TEXT, 'after'));
        }));
        const ws = await client(t).websocket(server.url());
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'after' });
        const first = await peer!.frames.next();
        assert.deepEqual([first.opcode, first.payload.toString()], [PONG, 'hey']);
        await sleep(50);
        const pongs = peer!.frames.frames.filter(f => f.opcode === PONG);
        assert.ok(pongs.length >= 2 && pongs.length <= 51, `${pongs.length} pongs`);
        assert.equal(pongs.at(-1)?.payload.toString(), '49');
        await ws.close();
    });

    it('the server closing ends the loop cleanly, with its code and reason echoed', async (t) => {
        let peer: Peer | undefined;
        const server = await wsServer(t, accepting(p => { peer = p; p.socket.write(Buffer.concat([frame(TEXT, 'last'), frame(CLOSE, closePayload(4000, 'bye'))])); }));
        const ws = await client(t).websocket(server.url());
        const got: unknown[] = [];
        for await (const message of ws) got.push(message);
        assert.deepEqual(got, ['last']);
        assert.equal(ws.closeCode, 4000);
        assert.equal(ws.closeReason, 'bye');
        const echoed = await peer!.frames.next();
        assert.deepEqual([echoed.opcode, closeCodeOf(echoed.payload)], [CLOSE, 4000]);
        await assert.rejects(ws.send('late'), code('ERR_ULTRATON_WS_CLOSED'));
    });

    // A server that ends the TCP connection only some time after the close handshake (Autobahn's does): nothing reads
    // the socket once the connection is closed, so it must still reach its end. The close timer is 60 s here, so only
    // the server's end can settle close() within the test's timeout.
    it("close() after the server's close settles when the server ends the connection later", { timeout: 10_000 }, async (t) => {
        const server = await wsServer(t, accepting(async p => {
            p.socket.write(frame(CLOSE, closePayload(1000, '')));
            await p.frames.next(); // the client's answer
            setTimeout(() => p.socket.end(), 100);
        }));
        const ws = await client(t, { [kWebSocketCloseTimeout]: 60_000 }).websocket(server.url());
        for await (const _ of ws) assert.fail('no message');
        assert.equal(ws.closeCode, 1000);
        await ws.close();
    });

    // The same after the client fails the connection (here a reserved bit): its 1002 goes out and the socket ends, and
    // the server's end must close it. Autobahn's cases 21 and up waited out the whole close timer on Linux.
    it('close() after the client failed the connection settles when the server ends it later', { timeout: 10_000 }, async (t) => {
        let answer: number | undefined;
        const server = await wsServer(t, accepting(async p => {
            p.socket.write(frame(TEXT, 'x', { rsv: 4 }));
            answer = closeCodeOf((await p.frames.next()).payload);
            setTimeout(() => p.socket.end(), 100);
        }));
        const ws = await client(t, { [kWebSocketCloseTimeout]: 60_000 }).websocket(server.url());
        await assert.rejects(ws[Symbol.asyncIterator]().next(), code('ERR_ULTRATON_WS_PROTOCOL'));
        await ws.close();
        assert.equal(answer, 1002);
    });

    it('a close without a code is answered with an empty close, never 1005', async (t) => {
        let peer: Peer | undefined;
        const server = await wsServer(t, accepting(p => { peer = p; p.socket.write(frame(CLOSE)); }));
        const ws = await client(t).websocket(server.url());
        for await (const _ of ws) assert.fail('no message');
        assert.equal(ws.closeCode, 1005);
        const echoed = await peer!.frames.next();
        assert.deepEqual([echoed.opcode, echoed.payload.length], [CLOSE, 0]);
    });

    it('the connection ending without a close frame is an error, never a clean end', async (t) => {
        const server = await wsServer(t, accepting(({ socket }) => socket.end(frame(TEXT, 'cut'))));
        const ws = await client(t).websocket(server.url());
        await assert.rejects((async () => { for await (const _ of ws) { /* drain */ } })(), (err: any) => err?.name === 'UltraTonNetworkError');
    });
});

describe('websocket(): closing', () => {
    it('close() sends 1000 and waits for the server; a server that never answers is cut after the close timeout', async (t) => {
        const server = await wsServer(t, echo);
        const ws = await client(t).websocket(server.url());
        await ws.close();
        assert.equal(ws.closeCode, 1000);
        let peer: Peer | undefined;
        const silent = await wsServer(t, accepting(p => { peer = p; }));
        const stuck = await client(t).websocket(silent.url());
        const started = Date.now();
        await stuck.close(4001, 'done');
        assert.ok(Date.now() - started >= 250, 'waited for the close timeout');
        const sent = await peer!.frames.next();
        assert.deepEqual([sent.opcode, closeCodeOf(sent.payload), sent.payload.subarray(2).toString()], [CLOSE, 4001, 'done']);
        await assert.rejects(stuck.send('x'), code('ERR_ULTRATON_WS_CLOSED'));
    });

    it('close() refuses codes and reasons the protocol does not allow', async (t) => {
        const server = await wsServer(t, echo);
        const ws = await client(t).websocket(server.url());
        for (const bad of [1005, 1001, 2000, 5000, 3000.5]) await assert.rejects(ws.close(bad), TypeError);
        await assert.rejects(ws.close(1000, 'x'.repeat(124)), TypeError);
        await ws.close(1000, 'x'.repeat(123));
    });

    it('break closes with 1000; Symbol.asyncDispose (await using) closes too', async (t) => {
        const peers: Peer[] = [];
        const server = await wsServer(t, accepting(p => { peers.push(p); p.socket.write(frame(TEXT, 'one')); }));
        const ws = await client(t).websocket(server.url());
        for await (const _ of ws) break;
        assert.equal(closeCodeOf((await peers[0].frames.next()).payload), 1000);
        assert.throws(() => ws[Symbol.asyncIterator](), TypeError);
        // What `await using` calls at the end of its block; the syntax itself needs Node 24+ (as in dispose.test.ts).
        await (await client(t).websocket(server.url()))[Symbol.asyncDispose]();
        assert.equal(closeCodeOf((await peers[1].frames.next()).payload), 1000);
    });

    it('an abort rejects with the signal reason; client.close() ends every connection', async (t) => {
        const server = await wsServer(t, accepting());
        const controller = new AbortController();
        const ws = await client(t).websocket(server.url(), { signal: controller.signal });
        const pending = ws[Symbol.asyncIterator]().next();
        controller.abort(new Error('stop'));
        await assert.rejects(pending, /stop/);
        const c = client(t);
        const open = await c.websocket(server.url());
        const waiting = open[Symbol.asyncIterator]().next();
        await c.close();
        await assert.rejects(waiting, /Client is closed/);
        await assert.rejects(open.send('x'), /Client is closed/);
    });
});

describe('websocket(): time', () => {
    it('socketTimeoutMs cuts a quiet server only while a message is awaited', async (t) => {
        const server = await wsServer(t, accepting(({ socket }) => setTimeout(() => socket.writable && socket.write(frame(TEXT, 'late')), 600)));
        const ws = await client(t).websocket(server.url(), { socketTimeoutMs: 300 });
        // Nobody waits for 700 ms: nothing is cut, and the message that came meanwhile is there.
        await sleep(700);
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'late' });
        const quiet = await wsServer(t, accepting());
        const waiting = await client(t).websocket(quiet.url(), { socketTimeoutMs: 300 });
        await assert.rejects(waiting[Symbol.asyncIterator]().next(), code('ERR_ULTRATON_SOCKET_TIMEOUT'));
        await ws.close();
    });

    it('pingIntervalMs keeps an answering server alive and cuts one that does not answer', async (t) => {
        const answering = await wsServer(t, accepting(({ socket, frames }) => {
            void (async () => {
                for (;;) {
                    const f = await frames.next();
                    if (f.opcode === PING) socket.write(frame(PONG, f.payload));
                }
            })();
            setTimeout(() => socket.writable && socket.write(frame(TEXT, 'still here')), 1500);
        }));
        const ws = await client(t).websocket(answering.url(), { pingIntervalMs: 200, socketTimeoutMs: 300 });
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'still here' });
        await ws.close();
        const mute = await wsServer(t, accepting());
        const cut = await client(t).websocket(mute.url(), { pingIntervalMs: 200, socketTimeoutMs: 300 });
        await assert.rejects(cut[Symbol.asyncIterator]().next(), code('ERR_ULTRATON_SOCKET_TIMEOUT'));
    });

    it('fragments keep a slow message alive: the clock runs between frames, not messages', async (t) => {
        const server = await wsServer(t, accepting(({ socket }) => {
            let i = 0;
            const id = setInterval(() => {
                if (!socket.writable) return clearInterval(id);
                const last = ++i === 6;
                socket.write(frame(i === 1 ? TEXT : 0x0, 'ab', { fin: last }));
                if (last) clearInterval(id);
            }, 200);
            socket.on('close', () => clearInterval(id));
        }));
        const ws = await client(t).websocket(server.url(), { socketTimeoutMs: 300 });
        assert.deepEqual(await ws[Symbol.asyncIterator]().next(), { done: false, value: 'ab'.repeat(6) });
        await ws.close();
    });

    it('an http2 client closed while websocket() validates opens nothing', async (t) => {
        const server = await wsServer(t, echo);
        const c = client(t, { http2: true });
        const opening = c.websocket(server.url());
        await c.close();
        await assert.rejects(opening, /Client is closed/);
        await sleep(50);
        assert.equal(server.upgrades(), 0);
    });

    it('maxConcurrency: a second connection to the origin waits until the first one closes', async (t) => {
        const server = await wsServer(t, echo);
        const c = client(t, { maxConcurrency: 1 });
        const first = await c.websocket(server.url());
        let second: Awaited<ReturnType<UltraTonClient['websocket']>> | undefined;
        const opening = c.websocket(server.url()).then(ws => { second = ws; });
        await sleep(100);
        assert.equal(second, undefined);
        await first.close();
        await opening;
        assert.ok(second);
        await second.close();
    });
});

/** A socket whose writes never complete until `flush()`: a server that stopped reading, without sending megabytes. */
class StalledSocket extends Duplex {
    readonly #held: (() => void)[] = [];
    constructor() {
        super({ writableHighWaterMark: 16 * 1024 });
    }
    override _read(): void {}
    override _write(_chunk: Buffer, _encoding: BufferEncoding, callback: () => void): void {
        this.#held.push(callback);
    }
    flush(): void {
        for (const callback of this.#held.splice(0)) callback();
    }
}

function stalled(socketTimeoutMs = 0) {
    const socket = new StalledSocket();
    const ws = new WebSocketConnection(socket, Buffer.alloc(0), {
        url: 'ws://127.0.0.1/', headers: {}, protocol: '', maxMessageSize: 1024, socketTimeoutMs, pingIntervalMs: 0, closeTimeoutMs: 100, onClosed: () => {},
    });
    return { socket, ws };
}

describe('websocket(): a socket that closed before the connection was built', () => {
    it('close() still resolves', async () => {
        const socket = new StalledSocket();
        socket.destroy();
        await new Promise(resolve => socket.once('close', resolve));
        let closed = 0;
        const ws = new WebSocketConnection(socket, Buffer.alloc(0), {
            url: 'ws://127.0.0.1/', headers: {}, protocol: '', maxMessageSize: 1024, socketTimeoutMs: 0, pingIntervalMs: 0, closeTimeoutMs: 100, onClosed: () => { closed++; },
        });
        await assert.rejects(ws[Symbol.asyncIterator]().next(), (err: any) => err?.name === 'UltraTonNetworkError');
        await ws.close();
        assert.equal(closed, 1);
    });
});

describe('websocket(): a server that stops reading', () => {
    it('send() rejects once more than 1 MiB is queued, and resolves once written', async () => {
        const { socket, ws } = stalled();
        const chunk = Buffer.alloc(64 * 1024);
        const sends: Promise<void>[] = [];
        let refused: unknown;
        for (let i = 0; i < 40 && refused === undefined; i++) {
            const sent = ws.send(chunk);
            sent.catch((err: unknown) => { refused = err; });
            sends.push(sent);
            await Promise.resolve();
        }
        assert.equal((refused as any)?.code, 'ERR_ULTRATON_WS_SEND_BUFFER');
        assert.ok(socket.writableLength <= 1024 * 1024 + 2 * chunk.length, `${socket.writableLength} bytes queued`);
        socket.flush();
        socket.destroy();
    });

    it('a write that makes no progress for socketTimeoutMs fails the connection', async () => {
        const { ws } = stalled(100);
        await assert.rejects(ws.send('never written'), code('ERR_ULTRATON_SOCKET_TIMEOUT'));
    });

    it('holds one pong at most while writes are queued, the latest', async () => {
        const { socket, ws } = stalled();
        const written: Buffer[] = [];
        const write = socket.write.bind(socket);
        socket.write = ((chunk: Buffer, ...rest: any[]) => { written.push(chunk); return (write as any)(chunk, ...rest); }) as typeof socket.write;
        void ws.send(Buffer.alloc(32 * 1024)).catch(() => {});
        assert.ok(socket.writableNeedDrain);
        socket.push(Buffer.concat([frame(PING, 'a'), frame(PING, 'b'), frame(PING, 'c')]));
        const reading = ws[Symbol.asyncIterator]().next().catch(() => {});
        await sleep(20);
        assert.equal(written.length, 1, 'no pong while the socket needs a drain');
        socket.flush();
        await sleep(20);
        const pongs = written.slice(1).filter(f => (f[0] & 0x0f) === PONG);
        assert.equal(pongs.length, 1);
        const payload = pongs[0].subarray(6);
        const mask = pongs[0].subarray(2, 6);
        assert.equal(String.fromCharCode(payload[0] ^ mask[0]), 'c');
        socket.destroy();
        await reading;
    });
});
