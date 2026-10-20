/**
 * How long a pooled HTTP/2 session lives: the session idle timeout reaps sessions nobody uses, never one a request is
 * still waiting on. The timings are injected through the manager's constructor (internal), so the tests take
 * milliseconds instead of the production 10 s.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer as createH2Server, type ClientHttp2Session, type ServerHttp2Stream } from 'node:http2';
import net, { type AddressInfo, type Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager, type SessionTimings } from '../src/engines/http2-session-manager.ts';
import { kSessionManager } from '../src/internal.ts';
import { SecureHttpError, UltraTonNetworkError, UltraTonNetworkTimeoutError } from '../src/errors.ts';

/**
 * An h2c server that answers `/slow/<ms>` after that long and anything else at once. Counts closed connections.
 * With `quietOnGoaway`, it does not answer the client's GOAWAY with its own (Node's server does by default), the way a
 * peer still finishing streams may keep the connection open.
 */
async function slowServer(t: TestContext, { quietOnGoaway = false } = {}) {
    let closed = 0;
    let streams = 0;
    let connections = 0;
    const sockets = new Set<Socket>();
    const server = createH2Server();
    server.on('connection', (socket: Socket) => {
        connections++;
        sockets.add(socket);
        socket.on('close', () => closed++);
    });
    if (quietOnGoaway) server.on('session', session => { session.close = () => {}; });
    server.on('stream', (stream: ServerHttp2Stream, headers) => {
        streams++;
        stream.on('error', () => { /* the client may cancel */ });
        if (headers[':path'] === '/never') return;
        const delay = Number(/^\/slow\/(\d+)$/.exec(String(headers[':path']))?.[1] ?? 0);
        const timer = setTimeout(() => {
            if (stream.destroyed) return;
            stream.respond({ ':status': 200 });
            stream.end('late');
        }, delay);
        stream.on('close', () => clearTimeout(timer));
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    return { origin, closedConnections: () => closed, streams: () => streams, connections: () => connections };
}

/**
 * A TCP proxy to `port` that can blackhole its FIRST connection: both directions stop being forwarded while the
 * sockets stay open, like a peer that vanished without a FIN or RST. Later connections are forwarded normally.
 */
async function blackholingProxy(t: TestContext, port: number) {
    let connections = 0;
    let blackhole = false;
    const sockets = new Set<Socket>();
    const server = net.createServer(client => {
        const id = ++connections;
        const dead = () => blackhole && id === 1;
        const upstream = net.connect(port, '127.0.0.1');
        for (const s of [client, upstream]) {
            sockets.add(s);
            s.on('error', () => {});
        }
        client.on('data', d => { if (!dead()) upstream.write(d); });
        upstream.on('data', d => { if (!dead()) client.write(d); });
        client.on('close', () => upstream.destroy());
        upstream.on('close', () => client.destroy());
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return {
        origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        connections: () => connections,
        blackholeFirst: () => { blackhole = true; },
    };
}

function clientWith(t: TestContext, timings: SessionTimings) {
    const manager = new Http2SessionManager({}, undefined, timings);
    const client = new UltraTonClient({ http2: true, permitReservedIps: true, [kSessionManager]: manager } as any);
    t.after(() => client.close());
    /** The session the pool currently holds for `origin` (no request hold is taken). */
    const pooled = (origin: string): Promise<ClientHttp2Session> => manager.getSession(origin, undefined, true);
    return { client, pooled };
}

const within = <T>(promise: Promise<T>, ms: number, what: string): Promise<T> =>
    Promise.race([promise, new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`${what}: not within ${ms}ms`)), ms))]);

describe('HTTP/2 session idle timeout', () => {
    it('does not cut a stream that waits longer than the session idle timeout (socketTimeoutMs 2000)', async (t) => {
        const { origin } = await slowServer(t);
        const { client } = clientWith(t, { idleTimeoutMs: 150 });
        const res = await client.get(`${origin}/slow/600`, { socketTimeoutMs: 2000, timeoutMs: 5000 });
        assert.equal(res.statusCode, 200);
        assert.equal(res.text(), 'late');
    });

    it('does not cut a stream that waits longer than the session idle timeout (socketTimeoutMs 0)', async (t) => {
        const { origin } = await slowServer(t);
        const { client } = clientWith(t, { idleTimeoutMs: 150 });
        const res = await client.get(`${origin}/slow/600`, { socketTimeoutMs: 0, timeoutMs: 5000 });
        assert.equal(res.statusCode, 200);
        assert.equal(res.text(), 'late');
    });

    it('still reaps the session once its last stream is done', async (t) => {
        const { origin, closedConnections } = await slowServer(t);
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 150 });

        assert.equal((await client.get(`${origin}/slow/400`, { socketTimeoutMs: 0 })).statusCode, 200);
        const session = await pooled(origin);
        assert.equal(session.destroyed, false, 'kept open while the request was in flight');

        await within(once(session, 'close'), 2000, 'idle session reaped');
        assert.equal(session.destroyed, true);
        await within((async () => { while (closedConnections() < 1) await new Promise(r => setTimeout(r, 10)); })(), 2000, 'server saw the close');
    });

    it('still reaps the session once a stream that outlived the idle timeout is given up (no frame follows)', async (t) => {
        const { origin } = await slowServer(t);
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 150 });

        const pending = client.get(`${origin}/slow/60000`, { socketTimeoutMs: 400, timeoutMs: 0 });
        pending.catch(() => {});
        await new Promise(r => setTimeout(r, 50));
        const session = await pooled(origin);
        await assert.rejects(pending, { name: 'UltraTonNetworkTimeoutError' });
        await within(once(session, 'close'), 2000, 'idle session reaped after the stream was given up');
    });

    it('reaps a session that was only ever idle', async (t) => {
        const { origin } = await slowServer(t);
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 150 });
        assert.equal((await client.get(`${origin}/`)).statusCode, 200);
        const session = await pooled(origin);
        await within(once(session, 'close'), 2000, 'idle session reaped');
    });
});

describe('HTTP/2 session maximum lifespan', () => {
    it('an expired session still finishing a stream is destroyed by close()', async (t) => {
        // A server that answers GOAWAY with GOAWAY would put the session in the draining set through the 'goaway' event.
        const { origin, streams } = await slowServer(t, { quietOnGoaway: true });
        const { client, pooled } = clientWith(t, { maxLifespanMs: 200 });

        const inFlight = client.get(`${origin}/slow/5000`, { timeoutMs: 0, socketTimeoutMs: 0 });
        inFlight.catch(() => {});
        await within((async () => { while (streams() < 1) await new Promise(r => setTimeout(r, 5)); })(), 2000, 'stream reached the server');
        const expired = await pooled(origin);

        await new Promise(r => setTimeout(r, 300));
        // The next request finds the session expired: it leaves the pool and a new one serves this request.
        assert.equal((await client.get(`${origin}/`)).statusCode, 200);
        assert.notEqual(await pooled(origin), expired, 'replaced in the pool');
        assert.equal(expired.destroyed, false, 'retired gracefully: its stream may finish');

        await client.close();
        assert.equal(expired.destroyed, true, 'close() reaches the retired session');
        await assert.rejects(within(inFlight, 1000, 'in-flight request settled by close()'), (err: Error) => {
            assert.ok(err instanceof SecureHttpError);
            assert.equal(err.message, 'UltraTon: Client is closed.');
            return true;
        });
    });
});

describe('HTTP/2 held sessions are checked for liveness', () => {
    it('a peer that goes silent under a request with both timeouts at 0 is detected by PING; later requests get a fresh session', async (t) => {
        const { origin: target } = await slowServer(t);
        const proxy = await blackholingProxy(t, Number(new URL(target).port));
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 150 });

        const held = client.get(`${proxy.origin}/never`, { timeoutMs: 0, socketTimeoutMs: 0 });
        held.catch(() => {});
        await new Promise(r => setTimeout(r, 100));
        const dead = await pooled(proxy.origin);
        proxy.blackholeFirst();

        // No PING ACK comes back: the session is destroyed and the held request fails as a reset connection.
        await assert.rejects(within(held, 3000, 'held request settled'), (err: Error & { code?: string }) => {
            assert.ok(err instanceof UltraTonNetworkError && !(err instanceof UltraTonNetworkTimeoutError), `${err.name}: ${err.message}`);
            assert.equal(err.message, 'UltraTon: Connection failed (ECONNRESET).');
            assert.equal(err.code, 'ECONNRESET');
            return true;
        });
        assert.equal(dead.destroyed, true);

        for (let i = 0; i < 3; i++) {
            const res = await client.get(`${proxy.origin}/`, { timeoutMs: 2000, socketTimeoutMs: 400 });
            assert.equal(res.statusCode, 200);
            assert.notEqual(await pooled(proxy.origin), dead);
        }
        assert.equal(proxy.connections(), 2, 'one fresh connection serves the later requests');
    });

    it('a slow but alive peer answers the PINGs: a request waiting many idle periods succeeds on a live session', async (t) => {
        const { origin } = await slowServer(t);
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 100 });
        const pending = client.get(`${origin}/slow/1200`, { timeoutMs: 0, socketTimeoutMs: 0 });
        await new Promise(r => setTimeout(r, 50));
        const session = await pooled(origin);
        const res = await pending;
        assert.equal(res.statusCode, 200);
        assert.equal(res.text(), 'late');
        assert.equal(session.destroyed, false, 'never treated as dead');
        assert.equal(await pooled(origin), session, 'still the pooled session');
    });

    for (const [label, options] of [
        ['socketTimeoutMs', { socketTimeoutMs: 300, timeoutMs: 0 }],
        ['timeoutMs', { socketTimeoutMs: 0, timeoutMs: 300 }],
    ] as const) {
        it(`a stream abandoned by ${label} retires its session: the next request opens a new connection`, async (t) => {
            const { origin, connections } = await slowServer(t);
            const { client } = clientWith(t, {});
            await assert.rejects(client.get(`${origin}/never`, options), UltraTonNetworkTimeoutError);
            assert.equal(connections(), 1);
            assert.equal((await client.get(`${origin}/`)).statusCode, 200);
            assert.equal(connections(), 2, 'the possibly dead session was not reused');
        });
    }
});
