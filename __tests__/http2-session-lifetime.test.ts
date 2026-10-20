/**
 * How long a pooled HTTP/2 session lives: the session idle timeout reaps sessions nobody uses, never one a request is
 * still waiting on. The timings are injected through the manager's constructor (internal), so the tests take
 * milliseconds instead of the production 10 s.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer as createH2Server, type ClientHttp2Session, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager, type SessionTimings } from '../src/engines/http2-session-manager.ts';
import { kSessionManager } from '../src/internal.ts';

/** An h2c server that answers `/slow/<ms>` after that long and anything else at once. Counts closed connections. */
async function slowServer(t: TestContext) {
    let closed = 0;
    const sockets = new Set<Socket>();
    const server = createH2Server();
    server.on('connection', (socket: Socket) => {
        sockets.add(socket);
        socket.on('close', () => closed++);
    });
    server.on('stream', (stream: ServerHttp2Stream, headers) => {
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
    return { origin, closedConnections: () => closed };
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

    it('reaps a session that was only ever idle', async (t) => {
        const { origin } = await slowServer(t);
        const { client, pooled } = clientWith(t, { idleTimeoutMs: 150 });
        assert.equal((await client.get(`${origin}/`)).statusCode, 200);
        const session = await pooled(origin);
        await within(once(session, 'close'), 2000, 'idle session reaped');
    });
});
