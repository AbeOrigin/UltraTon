/**
 * `redirectHopHeaders`: with it, each entry of `res.redirects` carries that hop's response headers, built as the final
 * response's are (no HTTP/2 pseudo-headers, a `__proto__` header kept as data). Off by default: without it the entries
 * are `{ url, statusCode }` as before. A hop's headers are bounded as a final response's: over the cap, the request fails.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

/**
 * /login: 302 to /home with a session cookie. /proto: 302 to /home with a `__proto__` header. /huge: 302 to /home with
 * 20 KiB of headers, over both engines' 16 KiB cap. /home: 200.
 */
async function server(t: TestContext, http2: boolean) {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        if (req.url === '/login') {
            res.setHeader('set-cookie', ['sid=1; Path=/; HttpOnly']);
            res.setHeader('location', '/home');
            res.statusCode = 302;
        } else if (req.url === '/proto') {
            res.setHeader('__proto__', 'polluted');
            res.setHeader('location', '/home');
            res.statusCode = 302;
        } else if (req.url === '/huge') {
            res.setHeader('x-big', 'a'.repeat(20 * 1024));
            res.setHeader('location', '/home');
            res.statusCode = 302;
        }
        res.end(req.url === '/home' ? 'home' : '');
    };
    const srv = http2 ? createH2Server(handler as never) : http.createServer(handler);
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
    describe(`redirectHopHeaders (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it("keeps each hop's response headers", async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/login`, { maxRedirects: 5, redirectHopHeaders: true });
            assert.equal(res.text(), 'home');
            assert.equal(res.redirects.length, 1);
            const hop = res.redirects[0];
            assert.deepEqual(hop.headers!['set-cookie'], ['sid=1; Path=/; HttpOnly']);
            assert.equal(hop.headers!.location, '/home');
            assert.ok(Object.isFrozen(hop));
            assert.ok(!Object.keys(hop.headers!).some(key => key.startsWith(':')), 'no pseudo-headers');
        });

        it('leaves the redirects as they were without the option', async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/login`, { maxRedirects: 5 });
            assert.deepEqual(Object.keys(res.redirects[0]), ['url', 'statusCode']);
        });

        it('a hop header named __proto__ stays data', async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/proto`, { maxRedirects: 5, redirectHopHeaders: true });
            const headers = res.redirects[0].headers!;
            assert.equal(Object.getPrototypeOf(headers), Object.prototype);
            // node:http2 hands the header over as an ordinary key, kept as data; node:http drops it before UltraTon sees it.
            assert.equal(Object.getOwnPropertyDescriptor(headers, '__proto__')?.value, http2 ? 'polluted' : undefined);
            assert.equal(({} as Record<string, unknown>).polluted, undefined);
        });

        // node:http fails the header overflow at its parser; on HTTP/2 UltraTon measures the header list itself, since
        // Node enforces the advertised SETTINGS only once the server acknowledges them.
        it("a hop's headers over the cap fail the request, as a final response's do", async t => {
            const base = await server(t, http2);
            await assert.rejects(clientOf(t, http2).get(`${base}/huge`, { maxRedirects: 5, redirectHopHeaders: true }),
                { name: http2 ? 'UltraTonMemoryError' : 'UltraTonNetworkError' });
        });

        it('takes a client default, which a request turns off', async t => {
            const base = await server(t, http2);
            const client = clientOf(t, http2, { redirectHopHeaders: true, maxRedirects: 5 });
            assert.ok((await client.get(`${base}/login`)).redirects[0].headers);
            assert.equal((await client.get(`${base}/login`, { redirectHopHeaders: false })).redirects[0].headers, undefined);
        });

        it('applies to stream() too', async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/login`, { maxRedirects: 5, redirectHopHeaders: true });
            await res.body.cancel();
            assert.deepEqual(res.redirects[0].headers!['set-cookie'], ['sid=1; Path=/; HttpOnly']);
        });
    });
}

describe('redirectHopHeaders validation', () => {
    it('rejects a value that is not a boolean, on a request and on the client', async t => {
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        const expected = (received: string) => ({ name: 'TypeError', message: `UltraTon: Expected 'redirectHopHeaders' to be a boolean, received ${received}` });
        await assert.rejects(client.get('http://127.0.0.1:1/', { redirectHopHeaders: 'yes' } as never), expected('string'));
        assert.throws(() => new UltraTonClient({ redirectHopHeaders: 1 } as never), expected('number'));
    });
});
