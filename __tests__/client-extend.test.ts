/**
 * Q8: `client.extend(options)` makes a variant of a client. It keeps the base's options with the new ones on top, and
 * shares the base's engine (its connection pools) unless `http2`, `tls` or `proxy` change. Sharing is observed through
 * the test seams: a transport spy on HTTP/1, a connect spy on HTTP/2. Pools stay apart per `permitReservedIps` policy
 * inside a shared engine, and the engine closes with the last client, in whatever order the clients close.
 */
import { describe, it, mock, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { createServer as createH2Server, connect as nativeConnect, type ServerHttp2Session } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { kSessionManager, kTransport } from '../src/internal.ts';

/** A loopback server (HTTP/1 or h2c) that echoes the request headers as JSON; /slow answers after 600 ms. */
async function serve(t: TestContext, http2: boolean) {
    const sessions = new Set<ServerHttp2Session>();
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        const answer = () => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(req.headers)); };
        if (req.url === '/slow') setTimeout(answer, 600); else answer();
    };
    const server = http2 ? createH2Server(handler as never) : http.createServer(handler);
    if (http2) server.on('session', (s: ServerHttp2Session) => { sessions.add(s); s.on('close', () => sessions.delete(s)); });
    const sockets = new Set<Socket>();
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, openSessions: () => sessions.size };
}

const settle = () => new Promise(r => setTimeout(r, 100));

for (const http2 of [false, true]) {
    describe(`extend() (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('a variant keeps every default and merges headers, case-insensitively', async (t) => {
            const { url } = await serve(t, http2);
            const base = new UltraTonClient({ http2, permitReservedIps: true, headers: { a: '1', b: '1' }, timeoutMs: 300 });
            const v = base.extend({ headers: { B: '2' } });
            t.after(async () => { await base.close(); await v.close(); });
            const seen = (await v.get(`${url}/echo`)).json<Record<string, string>>();
            assert.equal(seen.a, '1');
            assert.equal(seen.b, '2');
            await assert.rejects(v.get(`${url}/slow`), (err: { code?: string }) => err.code === 'ERR_ULTRATON_TIMEOUT');
        });

        it('extend() on a closed client throws, and an unknown option is rejected as in the constructor', async () => {
            const base = new UltraTonClient({ http2 });
            assert.throws(() => base.extend({ nope: 1 } as never), /Unknown option 'nope'/);
            await base.close();
            assert.throws(() => base.extend(), /Client is closed/);
        });
    });
}

describe('extend() shares the engine (HTTP/1.1, through the transport seam)', () => {
    it('a variant that changes only headers goes through the base transport; one that sets tls does not', async (t) => {
        const { url } = await serve(t, false);
        const transport = mock.fn(http.request);
        const base = new UltraTonClient({ permitReservedIps: true, [kTransport]: transport } as never);
        const same = base.extend({ headers: { x: '1' } });
        const ownTls = base.extend({ tls: { ca: [] } });
        t.after(async () => { for (const c of [base, same, ownTls]) await c.close(); });
        await same.get(`${url}/`);
        assert.equal(transport.mock.callCount(), 1, 'the variant used the shared engine');
        await ownTls.get(`${url}/`);
        assert.equal(transport.mock.callCount(), 1, 'a variant with its own tls has its own engine (and the seam is not inherited)');
    });
});

describe('extend() shares the engine (HTTP/2, through the session manager seam)', () => {
    const shared = (t: TestContext, options: Record<string, unknown> = {}) => {
        const connect = mock.fn(nativeConnect);
        const manager = new Http2SessionManager({}, connect as typeof nativeConnect);
        const base = new UltraTonClient({ http2: true, permitReservedIps: true, ...options, [kSessionManager]: manager } as never);
        t.after(() => manager.closeAll());
        return { base, sessions: () => connect.mock.callCount() };
    };

    it('a variant that changes only headers reuses the session', async (t) => {
        const { url } = await serve(t, true);
        const { base, sessions } = shared(t);
        const v = base.extend({ headers: { x: '1' } });
        t.after(async () => { await base.close(); await v.close(); });
        await base.get(`${url}/`);
        await v.get(`${url}/`);
        assert.equal(sessions(), 1);
    });

    it('a variant with its own permitReservedIps policy takes no session from the base', async (t) => {
        const { url } = await serve(t, true);
        const { base, sessions } = shared(t);
        const v = base.extend({ permitReservedIps: ['127.0.0.1'] });
        t.after(async () => { await base.close(); await v.close(); });
        await base.get(`${url}/`);
        await v.get(`${url}/`);
        assert.equal(sessions(), 2, 'pools are keyed by policy inside the shared engine');
    });

    it('closing the base leaves the variant working; the last close closes the pool', async (t) => {
        const { url, openSessions } = await serve(t, true);
        const { base, sessions } = shared(t);
        const v = base.extend({ headers: { x: '1' } });
        await base.get(`${url}/`);
        await base.close();
        await assert.rejects(base.get(`${url}/`), /Client is closed/);
        assert.equal((await v.get(`${url}/`)).statusCode, 200);
        assert.equal(sessions(), 1, 'the variant still uses the session the base opened');
        assert.equal(openSessions(), 1);
        await v.close();
        await settle();
        assert.equal(openSessions(), 0, 'the last close closed the session');
    });

    it('variants of variants close the pool exactly once, in any order', async (t) => {
        const { url, openSessions } = await serve(t, true);
        const { base: a } = shared(t);
        const b = a.extend();
        const c = b.extend();
        await c.get(`${url}/`);
        await b.close();
        await a.close();
        await settle();
        assert.equal(openSessions(), 1, 'two of three closed: the session stays');
        assert.equal((await c.get(`${url}/`)).statusCode, 200);
        await c.close();
        await settle();
        assert.equal(openSessions(), 0);
    });
});

describe('extend() leaves the base and its options untouched', () => {
    it('a userAgent variant does not delete the base user-agent header', async (t) => {
        const { url } = await serve(t, false);
        const headers = { 'User-Agent': 'base/1', a: '1' };
        const base = new UltraTonClient({ permitReservedIps: true, headers });
        const v = base.extend({ userAgent: 'variant/2' });
        const again = base.extend({});
        t.after(async () => { for (const c of [base, v, again]) await c.close(); });
        assert.deepEqual(headers, { 'User-Agent': 'base/1', a: '1' }, "the caller's object is untouched");
        assert.equal((await again.get(`${url}/`)).json<Record<string, string>>()['user-agent'], 'base/1');
    });

    it('a variant takes the policy the base was built with, not the array as the caller mutated it later', async (t) => {
        const list = ['10.0.0.1'];
        const base = new UltraTonClient({ permitReservedIps: list });
        list.push('10.0.0.0/8');
        const v = base.extend({});
        t.after(async () => { await base.close(); await v.close(); });
        assert.equal((await base.explain('https://10.9.9.9/')).code, 'ERR_ULTRATON_RESERVED_IP');
        assert.equal((await v.explain('https://10.9.9.9/')).code, 'ERR_ULTRATON_RESERVED_IP');
    });
});

describe('extend() with userAgent', () => {
    it('a userAgent in the variant replaces a user-agent header of the base without the "one or the other" error', async (t) => {
        const { url } = await serve(t, false);
        const base = new UltraTonClient({ permitReservedIps: true, headers: { 'User-Agent': 'base/1' } });
        const v = base.extend({ userAgent: 'variant/2' });
        const w = v.extend({ headers: { 'user-agent': 'header/3' } });
        t.after(async () => { for (const c of [base, v, w]) await c.close(); });
        assert.equal((await v.get(`${url}/`)).json<Record<string, string>>()['user-agent'], 'variant/2');
        assert.equal((await w.get(`${url}/`)).json<Record<string, string>>()['user-agent'], 'header/3');
        // https is irrelevant here; the import keeps the seam types honest.
        void https;
    });
});
