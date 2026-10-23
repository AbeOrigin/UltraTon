/**
 * Q4: `assertOk()` on both response shapes and both engines. Opt-in: a non-2xx still resolves; the caller who wants it
 * to throw gets `UltraTonHttpError` with the status in the message and the response, non-enumerable, on the error. On
 * a stream the body is cancelled first, so a refused 5xx does not hold its connection.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import util from 'node:util';
import http from 'node:http';
import { createServer as createH2Server, type Http2Server, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonHttpError, isUltraTonError } from '../src/errors.ts';

type Req = http.IncomingMessage | Http2ServerRequest;
type Res = http.ServerResponse | Http2ServerResponse;

/** /ok 200 hello, /missing 404 secret-body, /down 503 with 64 KiB, /moved 302 to /ok. */
async function serve(t: TestContext, http2: boolean) {
    const handler = (req: Req, res: Res) => {
        switch (req.url) {
            case '/ok': res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('hello');
            case '/missing': res.writeHead(404); return res.end('secret-body');
            case '/down': res.writeHead(503); return res.end(Buffer.alloc(64 * 1024, 'x'));
            default: res.writeHead(302, { location: '/ok' }); return res.end();
        }
    };
    const server: http.Server | Http2Server = http2 ? createH2Server(handler) : http.createServer(handler);
    const sockets = new Set<Socket>();
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const client = new UltraTonClient({ http2, permitReservedIps: true });
    t.after(async () => {
        await client.close();
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { client, url: (path: string) => `http://127.0.0.1:${(server.address() as AddressInfo).port}${path}` };
}

for (const http2 of [false, true]) {
    describe(`assertOk() (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('returns the same response on 2xx', async (t) => {
            const { client, url } = await serve(t, http2);
            const res = await client.get(url('/ok'));
            assert.equal(res.assertOk(), res);
            assert.equal(res.assertOk().text(), 'hello');
        });

        it('throws UltraTonHttpError on a 404, with the response hidden from logs', async (t) => {
            const { client, url } = await serve(t, http2);
            const res = await client.get(url('/missing'));
            assert.equal(res.ok, false, 'a non-2xx still resolves');
            let caught: unknown;
            try { res.assertOk(); } catch (err) { caught = err; }
            assert.ok(caught instanceof UltraTonHttpError && caught instanceof SecureHttpError);
            assert.equal(caught.code, 'ERR_ULTRATON_HTTP_STATUS');
            assert.equal(caught.statusCode, 404);
            assert.equal(caught.message, 'UltraTon: HTTP 404.');
            assert.equal((caught.response as typeof res).text(), 'secret-body');
            assert.equal(isUltraTonError(caught, 'ERR_ULTRATON_HTTP_STATUS'), true);
            assert.doesNotMatch(JSON.stringify(caught), /secret-body/);
            assert.doesNotMatch(util.inspect(caught), /secret-body/);
        });

        it('a redirect that was not followed is not ok', async (t) => {
            const { client, url } = await serve(t, http2);
            const res = await client.get(url('/moved'));
            assert.throws(() => res.assertOk(), (err: UltraTonHttpError) => err.statusCode === 302);
        });

        it('stream().assertOk() on a 503 cancels the body and frees the connection', async (t) => {
            const { client, url } = await serve(t, http2);
            const res = await client.stream(url('/down'));
            assert.throws(() => res.assertOk(), UltraTonHttpError);
            assert.deepEqual(await res.body.getReader().read(), { done: true, value: undefined });
            const started = Date.now();
            assert.equal((await client.get(url('/ok'), { timeoutMs: 1000 })).text(), 'hello');
            assert.ok(Date.now() - started < 1000);
        });
    });
}
