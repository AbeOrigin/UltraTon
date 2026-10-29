/**
 * `client.request(method, url)` and `stream({ method })` send any method token in uppercase (PROPFIND, PURGE, REPORT),
 * on both engines, with the checks of the other methods. Lowercase, malformed methods and CONNECT throw before connecting.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

/** Echoes `METHOD body`; `/flaky` answers 503 once, then 200. */
async function server(t: TestContext, http2: boolean) {
    let flaky = 0;
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        const chunks: Buffer[] = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            if (req.url === '/flaky' && flaky++ === 0) res.writeHead(503, { 'retry-after': '0' });
            res.end(`${req.method} ${Buffer.concat(chunks)}`);
        });
    };
    const srv = http2 ? createH2Server(handler as any) : http.createServer(handler);
    const sockets = new Set<Socket>();
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ permitReservedIps: true, http2, ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`custom methods (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('sends a method of your own, with or without a body', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            assert.equal((await client.request('PROPFIND', `${base}/dav/`, { body: '<propfind/>', headers: { depth: '1' } })).text(), 'PROPFIND <propfind/>');
            assert.equal((await client.request('PURGE', `${base}/cached`)).text(), 'PURGE ');
            assert.equal((await client.request('M-SEARCH', `${base}/`)).text(), 'M-SEARCH ');
        });

        it('treats the standard methods as their own client methods do', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            assert.equal((await client.request('POST', `${base}/`, { json: { a: 1 } })).text(), 'POST {"a":1}');
            const head = await client.request('HEAD', `${base}/`);
            assert.equal(head.data.length, 0);
            await assert.rejects(client.request('GET', `${base}/`, { body: 'x' }), { message: 'UltraTon: GET and HEAD requests cannot have a body.' });
        });

        it('is not retried unless retry.methods lists it', async (t) => {
            const base = await server(t, http2);
            assert.equal((await clientOf(t, http2, { retry: 2 }).request('PURGE', `${base}/flaky`)).statusCode, 503);
            const retried = await clientOf(t, http2, { retry: { limit: 2, methods: ['PURGE'] } }).request('PURGE', `${base}/flaky`);
            assert.equal(retried.statusCode, 200);
        });

        it('works on stream() too', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/`, { method: 'REPORT', body: 'q' });
            assert.equal(await new Response(res.body).text(), 'REPORT q');
        });
    });
}

describe('custom methods: validation', () => {
    it('refuses lowercase, malformed and CONNECT before connecting, and in retry.methods', async (t) => {
        const client = new UltraTonClient();
        t.after(() => client.close());
        for (const method of ['propfind', 'GET\r\nX-Injected: 1', 'GE T', '', 'PÜRGE', 42]) {
            await assert.rejects(client.request(method as string, 'https://example.com/'), { name: 'TypeError', message: /^UltraTon: Expected 'method' to be an HTTP method in uppercase/ });
        }
        await assert.rejects(client.request('CONNECT', 'https://example.com/'), { name: 'TypeError', message: /CONNECT is not supported/ });
        assert.throws(() => new UltraTonClient({ retry: { methods: ['purge'] } }), { name: 'TypeError', message: /'retry\.methods' to be an array of HTTP methods in uppercase/ });
    });
});
