/**
 * `redirects` on the response: every redirect followed, in order, with the URL that answered and its status, on both
 * engines and on `stream()`. A redirect that is returned rather than followed is the response, not an entry.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

/** /a -> 301 /b -> 307 /c?x=1 -> 200, on HTTP/1.1 or h2c. */
async function server(t: TestContext, http2: boolean) {
    const handler = (req: { url?: string }, res: http.ServerResponse) => {
        if (req.url === '/a') res.writeHead(301, { location: '/b' });
        else if (req.url === '/b') res.writeHead(307, { location: '/c?x=1' });
        else res.writeHead(200);
        res.end(req.url);
    };
    const srv = http2 ? createH2Server(handler as any) : http.createServer(handler);
    const sockets = new Set<Socket>();
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, maxRedirects: number) {
    const client = new UltraTonClient({ permitReservedIps: true, http2, maxRedirects });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`redirects on the response (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('lists every hop followed, in order, with its URL and status', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2, 5).get(`${base}/a`);
            assert.equal(res.text(), '/c?x=1');
            assert.equal(res.url, `${base}/c?x=1`);
            assert.equal(res.redirected, true);
            assert.deepEqual(res.redirects, [
                { url: `${base}/a`, statusCode: 301 },
                { url: `${base}/b`, statusCode: 307 },
            ]);
            assert.ok(Object.isFrozen(res.redirects) && Object.isFrozen(res.redirects[0]));
        });

        it('is empty when no redirect was followed, and a returned redirect is the response', async (t) => {
            const base = await server(t, http2);
            const direct = await clientOf(t, http2, 5).get(`${base}/c`);
            assert.deepEqual(direct.redirects, []);
            assert.equal(direct.redirected, false);
            const returned = await clientOf(t, http2, 0).get(`${base}/a`);
            assert.equal(returned.statusCode, 301);
            assert.deepEqual(returned.redirects, []);
        });

        it('stops the list where maxRedirects stopped following', async (t) => {
            const base = await server(t, http2);
            await assert.rejects(clientOf(t, http2, 1).get(`${base}/a`), { name: 'UltraTonRedirectError' });
        });

        it('is on stream() too, also under maxConcurrency', async (t) => {
            const base = await server(t, http2);
            for (const client of [clientOf(t, http2, 5), new UltraTonClient({ permitReservedIps: true, http2, maxRedirects: 5, maxConcurrency: 1 })]) {
                t.after(() => client.close());
                const res = await client.stream(`${base}/a`);
                assert.deepEqual(res.redirects.map(r => r.statusCode), [301, 307]);
                assert.equal(res.redirected, true);
                await res.body.cancel();
            }
        });
    });
}
