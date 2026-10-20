/**
 * 3xx responses the same way on both engines: a redirect that is not followed is an ordinary response (its body is
 * read, limited by maxBodySize and returned), a redirect that is followed never buffers its body, and a plain-http
 * loopback origin can never redirect the client to a name that resolves off loopback. Real servers on loopback.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonMemoryError } from '../src/errors.ts';
import { PLAIN_HTTP, clientFor, mockDns, v4 } from './fixtures/net-fixtures.ts';

const BIG = 1024 * 1024;

/** What the server answers for a path: status, headers and a body. */
type Route = (port: number) => { status: number; headers?: Record<string, string>; body?: string | Buffer };

/** A server of either engine answering from `routes`. Counts accepted connections and requests per path. */
async function routedServer(t: TestContext, http2: boolean, routes: Record<string, Route>) {
    let accepted = 0;
    const hits: string[] = [];
    const sockets = new Set<Socket>();
    const answer = (path: string) => (Object.hasOwn(routes, path) ? routes[path] : () => ({ status: 404, body: 'none' }))(port);
    const server = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
            const path = String(headers[':path']);
            hits.push(path);
            const { status, headers: extra = {}, body = '' } = answer(path);
            stream.on('error', () => { /* the client may cancel a followed redirect mid-body */ });
            stream.respond({ ':status': status, 'content-length': String(Buffer.byteLength(body)), ...extra });
            stream.end(body);
        })
        : http.createServer((req, res) => {
            hits.push(String(req.url));
            const { status, headers: extra = {}, body = '' } = answer(String(req.url));
            res.on('error', () => { /* the client may drop a followed redirect mid-body */ });
            res.writeHead(status, { 'content-length': String(Buffer.byteLength(body)), ...extra });
            res.end(body);
        });
    server.on('connection', (socket: Socket) => {
        accepted++;
        sockets.add(socket);
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { base: `http://127.0.0.1:${port}`, port, accepted: () => accepted, hits: () => hits };
}

const newClient = (t: TestContext, http2: boolean, options: Record<string, unknown> = {}) => {
    const client = new UltraTonClient({ http2, permitReservedIps: true, timeoutMs: 5000, ...options });
    t.after(() => client.close());
    return client;
};

for (const http2 of [false, true]) {
    const engine = http2 ? 'HTTP/2' : 'HTTP/1';

    describe(`${engine}: a 3xx that is not followed is an ordinary response`, () => {
        for (const status of [301, 302, 303, 307, 308]) {
            it(`maxRedirects 0 + ${status} with Location and a body resolves with that body`, async (t) => {
                const s = await routedServer(t, http2, {
                    '/start': () => ({ status, headers: { location: '/next', 'content-type': 'text/plain' }, body: 'redirect-body' }),
                });
                const res = await newClient(t, http2).get(`${s.base}/start`);
                assert.strictEqual(res.statusCode, status);
                assert.equal(typeof res.statusCode, 'number');
                assert.equal(res.ok, false);
                assert.equal(res.headers.location, '/next');
                assert.equal(res.text(), 'redirect-body');
                assert.deepEqual(s.hits(), ['/start'], 'not followed');
            });
        }

        it('its body is held to maxBodySize like any other', async (t) => {
            const s = await routedServer(t, http2, {
                '/start': () => ({ status: 302, headers: { location: '/next' }, body: Buffer.alloc(BIG, 'r') }),
            });
            await assert.rejects(newClient(t, http2, { maxBodySize: 1024 }).get(`${s.base}/start`), UltraTonMemoryError);
        });
    });

    describe(`${engine}: a 3xx that is followed is never buffered`, () => {
        it('a redirect body far above maxBodySize does not fail the request', async (t) => {
            const s = await routedServer(t, http2, {
                '/start': () => ({ status: 302, headers: { location: '/final' }, body: Buffer.alloc(BIG, 'r') }),
                '/final': () => ({ status: 200, body: 'final' }),
            });
            const res = await newClient(t, http2, { maxBodySize: 1024, maxRedirects: 1 }).get(`${s.base}/start`);
            assert.equal(res.statusCode, 200);
            assert.equal(res.text(), 'final');
            assert.deepEqual(s.hits(), ['/start', '/final']);
        });
    });

    describe(`${engine}: a loopback origin cannot redirect plain http off loopback`, () => {
        it('http://127.0.0.1 -> http://evil.localhost (public in DNS) rejects with the plain-http error, no second connection', async (t) => {
            mockDns(t, { 'evil.localhost': [v4('93.184.216.34')] });
            const s = await routedServer(t, http2, {
                '/to-evil': port => ({ status: 302, headers: { location: `http://evil.localhost:${port}/x` } }),
            });
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true, maxRedirects: 3, timeoutMs: 3000 });

            await assert.rejects(client.get(`${s.base}/to-evil`), (err: Error) => {
                assert.match(err.message, PLAIN_HTTP);
                return true;
            });
            // HTTP/1 counts addresses its lookup handed to Node (none for the IP-literal first hop), HTTP/2 connects.
            assert.equal(opened(), http2 ? 1 : 0, 'no connection towards evil.localhost');
            assert.equal(s.accepted(), 1);
            assert.deepEqual(s.hits(), ['/to-evil']);
        });
    });
}
