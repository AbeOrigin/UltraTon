/**
 * Streamed request bodies (Readable, ReadableStream, async iterable), on both engines: what the server receives, the
 * content-length contract, maxRequestBodySize, no retries, 307/308 returned instead of followed, and the source being
 * destroyed when the request ends early. Bodies are a few KiB: the limits are proven small.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { Readable } from 'node:stream';
import { once } from 'node:events';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonMemoryError } from '../src/errors.ts';

type Echo = { method: string; path: string; headers: Record<string, string | undefined>; body: string };

/**
 * A loopback server of either engine. `/x` echoes method, path, headers and body (base64); `/307` and `/303` redirect
 * to `/x`; `/503` answers 503. `/early` sends its headers at once and the echo when the upload ends; `/413` answers 413
 * at once without reading the body. Requests are counted per path.
 */
async function server(t: TestContext, http2: boolean) {
    const sockets = new Set<Socket>();
    let connections = 0;
    const hits = new Map<string, number>();
    const answer = (method: string, path: string, headers: IncomingHttpHeaders, chunks: Buffer[]): [number, Record<string, string>, string] => {
        hits.set(path, (hits.get(path) ?? 0) + 1);
        if (path === '/307' || path === '/303') return [Number(path.slice(1)), { location: '/x' }, ''];
        if (path === '/503') return [503, {}, 'busy'];
        return [200, { 'content-type': 'application/json' }, JSON.stringify({ method, path, headers, body: Buffer.concat(chunks).toString('base64') })];
    };
    const srv = http2
        ? createH2Server().on('stream', (stream, headers: IncomingHttpHeaders) => {
            const path = String(headers[':path']);
            const chunks: Buffer[] = [];
            stream.on('error', () => {});
            if (path === '/413') {
                hits.set(path, (hits.get(path) ?? 0) + 1);
                stream.respond({ ':status': 413 });
                stream.end('too large');
                return;
            }
            if (path === '/early') stream.respond({ ':status': 200, 'content-type': 'application/json' });
            stream.on('data', (c: Buffer) => chunks.push(c));
            stream.on('end', () => {
                // The client may have cancelled the stream (a limit, an abort): there is nobody to answer.
                if (stream.destroyed || stream.closed) return;
                const [status, extra, body] = answer(String(headers[':method']), path === '/early' ? '/x' : path, headers, chunks);
                if (path !== '/early') stream.respond({ ':status': status, ...extra });
                stream.end(body);
            });
        })
        : http.createServer((req, res) => {
            const path = String(req.url);
            const chunks: Buffer[] = [];
            req.on('error', () => {});
            if (path === '/413') {
                hits.set(path, (hits.get(path) ?? 0) + 1);
                res.writeHead(413, { connection: 'close' });
                res.end('too large');
                return;
            }
            if (path === '/early') {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.flushHeaders();
            }
            req.on('data', (c: Buffer) => chunks.push(c));
            req.on('end', () => {
                const [status, extra, body] = answer(String(req.method), path === '/early' ? '/x' : path, req.headers, chunks);
                if (path !== '/early') res.writeHead(status, extra);
                res.end(body);
            });
        });
    srv.on('connection', (s: Socket) => { connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    const origin = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    return { origin, url: `${origin}/x`, connections: () => connections, hits: (path: string) => hits.get(path) ?? 0 };
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

const received = (echo: Echo) => Buffer.from(echo.body, 'base64');
const payload = Buffer.alloc(8 * 1024, 'ab');
const chunksOf = (buf: Buffer, size = 1024) => Array.from({ length: Math.ceil(buf.length / size) }, (_, i) => buf.subarray(i * size, (i + 1) * size));

/** Resolves once `source` is destroyed; fails the test after 2 s. */
const destroyed = (source: Readable) => source.destroyed ? Promise.resolve() : Promise.race([
    once(source, 'close'),
    new Promise((_, reject) => setTimeout(() => reject(new Error('the source was not destroyed')), 2000).unref()),
]);

/** A Readable that pushes one chunk and then waits for data that never comes. */
function stalled() {
    const source = new Readable({ read() {} });
    source.push(Buffer.from('first'));
    return source;
}

for (const http2 of [false, true]) {
    describe(`streamed request bodies (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('a Readable arrives whole, chunked on HTTP/1.1 and without content-length', async (t) => {
            const srv = await server(t, http2);
            const echo = (await clientOf(t, http2).post(srv.url, { body: Readable.from(chunksOf(payload)) })).json<Echo>();
            assert.deepEqual(received(echo), payload);
            assert.equal(echo.headers['content-length'], undefined);
            if (!http2) assert.equal(echo.headers['transfer-encoding'], 'chunked');
        });

        it('a ReadableStream and an async generator of strings arrive whole', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2);
            const web = new ReadableStream<Uint8Array>({
                start(controller) {
                    for (const chunk of chunksOf(payload)) controller.enqueue(chunk);
                    controller.close();
                },
            });
            assert.deepEqual(received((await client.put(srv.url, { body: web })).json<Echo>()), payload);
            async function* text() { yield 'héllo, '; yield Buffer.from('wörld'); }
            assert.equal(received((await client.post(srv.url, { body: text() })).json<Echo>()).toString(), 'héllo, wörld');
        });

        it("the caller's content-length is sent, and the stream must match it exactly", async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2);
            const echo = (await client.post(srv.url, { body: Readable.from(chunksOf(payload)), headers: { 'Content-Length': String(payload.length) } })).json<Echo>();
            assert.deepEqual(received(echo), payload);
            assert.equal(echo.headers['content-length'], String(payload.length));
            assert.equal(echo.headers['transfer-encoding'], undefined);
            for (const declared of [payload.length + 1, payload.length - 1]) {
                await assert.rejects(
                    client.post(srv.url, { body: Readable.from(chunksOf(payload)), headers: { 'content-length': String(declared) } }),
                    { code: 'ERR_ULTRATON_REQUEST_BODY_LENGTH' },
                );
            }
        });

        it('a content-length that is not a non-negative integer throws before connecting', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2);
            for (const bad of ['-1', '1.5', 'ten', '']) {
                await assert.rejects(client.post(srv.url, { body: Readable.from([payload]), headers: { 'content-length': bad } }), TypeError);
            }
            assert.equal(srv.connections(), 0);
        });

        it('maxRequestBodySize aborts a stream past it, and the stream is destroyed', async (t) => {
            const srv = await server(t, http2);
            const source = Readable.from(chunksOf(payload));
            await assert.rejects(
                clientOf(t, http2).post(srv.url, { body: source, maxRequestBodySize: 4096 }),
                (err: unknown) => err instanceof UltraTonMemoryError && err.code === 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE',
            );
            assert.equal(source.destroyed, true);
        });

        it('maxRequestBodySize rejects a buffered body before connecting, and the client default applies', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2, { maxRequestBodySize: 1024 });
            await assert.rejects(client.post(srv.url, { body: payload }), { code: 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE' });
            await assert.rejects(client.post(srv.url, { json: { big: payload.toString() } }), { code: 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE' });
            assert.equal(srv.connections(), 0);
            // A request's own value wins, and exactly the limit is allowed.
            const echo = (await client.post(srv.url, { body: payload, maxRequestBodySize: payload.length })).json<Echo>();
            assert.equal(received(echo).length, payload.length);
            await assert.rejects(client.post(srv.url, { body: 'x', maxRequestBodySize: -1 }), TypeError);
        });

        it('a request with a streamed body is never retried', async (t) => {
            const srv = await server(t, http2);
            const res = await clientOf(t, http2, { retry: { limit: 2, maxDelayMs: 1 } }).post(`${srv.origin}/503`, {
                body: Readable.from([payload]),
                retry: { limit: 2, methods: ['POST'], maxDelayMs: 1 },
            });
            assert.equal(res.statusCode, 503);
            assert.equal(srv.hits('/503'), 1);
        });

        it('a 307 resolves as the 3xx response; a 303 is followed as a GET without a body', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2, { maxRedirects: 3 });
            const kept = await client.post(`${srv.origin}/307`, { body: Readable.from([payload]) });
            assert.equal(kept.statusCode, 307);
            assert.equal(kept.headers.location, '/x');
            assert.equal(srv.hits('/x'), 0);
            const followed = (await client.post(`${srv.origin}/303`, { body: Readable.from([payload]) })).json<Echo>();
            assert.equal(followed.method, 'GET');
            assert.equal(received(followed).length, 0);
        });

        it('an abort while the stream waits for data rejects with the reason and destroys the stream', async (t) => {
            const srv = await server(t, http2);
            const source = stalled();
            const controller = new AbortController();
            const pending = clientOf(t, http2).post(srv.url, { body: source, signal: controller.signal });
            setTimeout(() => controller.abort(new Error('stop')), 50);
            await assert.rejects(pending, { message: 'stop' });
            await destroyed(source);
        });

        it('a timeout while the stream waits for data rejects and destroys the stream', async (t) => {
            const srv = await server(t, http2);
            const source = stalled();
            await assert.rejects(clientOf(t, http2).post(srv.url, { body: source, timeoutMs: 100 }), { code: 'ERR_ULTRATON_TIMEOUT' });
            await destroyed(source);
        });

        it("the stream's own error rejects the request as is", async (t) => {
            const srv = await server(t, http2);
            const boom = new Error('disk gone');
            async function* failing() { yield Buffer.from('a'); throw boom; }
            await assert.rejects(clientOf(t, http2).post(srv.url, { body: failing() }), (err: unknown) => err === boom);
        });

        it('a chunk that is not bytes or a string rejects with a TypeError', async (t) => {
            const srv = await server(t, http2);
            async function* numbers() { yield 42; }
            await assert.rejects(clientOf(t, http2).post(srv.url, { body: numbers() as unknown as AsyncIterable<Uint8Array> }), TypeError);
        });

        it('GET and HEAD with a streamed body throw before connecting', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2);
            await assert.rejects(client.get(srv.url, { body: Readable.from([payload]) }), TypeError);
            await assert.rejects(client.head(srv.url, { body: Readable.from([payload]) }), TypeError);
            assert.equal(srv.connections(), 0);
        });

        it('a client default content-length is never sent with a chunked stream', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2, { headers: { 'content-length': '3' } });
            const echo = (await client.post(srv.url, { body: Readable.from(chunksOf(payload)) })).json<Echo>();
            assert.deepEqual(received(echo), payload);
            assert.equal(echo.headers['content-length'], undefined);
            if (!http2) assert.equal(echo.headers['transfer-encoding'], 'chunked');
        });

        it("the stream's error after the response headers rejects with it, not a timeout", async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2, { timeoutMs: 5000 });
            const boom = new Error('disk gone');
            async function* failsLater() { yield Buffer.from('a'); await new Promise(r => setTimeout(r, 50)); throw boom; }
            await assert.rejects(client.post(`${srv.origin}/early`, { body: failsLater() }), (err: unknown) => err === boom);
            const res = await client.stream(`${srv.origin}/early`, { method: 'POST', body: failsLater() });
            assert.equal(res.statusCode, 200);
            await assert.rejects(new Response(res.body).arrayBuffer(), (err: unknown) => err === boom);
        });

        it('maxRequestBodySize tripped after the response headers rejects with its code', async (t) => {
            const srv = await server(t, http2);
            async function* slowly() { for (const chunk of chunksOf(payload)) { await new Promise(r => setTimeout(r, 5)); yield chunk; } }
            await assert.rejects(
                clientOf(t, http2, { timeoutMs: 5000 }).post(`${srv.origin}/early`, { body: slowly(), maxRequestBodySize: 2048 }),
                { code: 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE' },
            );
        });

        it('stream() hands the response over while the upload is still running', async (t) => {
            const srv = await server(t, http2);
            async function* slowly() { for (const chunk of chunksOf(payload)) { await new Promise(r => setTimeout(r, 5)); yield chunk; } }
            const res = await clientOf(t, http2).stream(`${srv.origin}/early`, { method: 'POST', body: slowly() });
            assert.equal(res.statusCode, 200);
            const echo = JSON.parse(Buffer.from(await new Response(res.body).arrayBuffer()).toString()) as Echo;
            assert.deepEqual(received(echo), payload);
        });

        it('an early final response stops the upload and destroys a stalled stream, with no idle timer', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2, { socketTimeoutMs: 0 });
            const buffered = stalled();
            const res = await client.post(`${srv.origin}/413`, { body: buffered });
            assert.equal(res.statusCode, 413);
            await destroyed(buffered);
            const streamed = stalled();
            const sres = await client.stream(`${srv.origin}/413`, { method: 'POST', body: streamed });
            assert.equal(sres.statusCode, 413);
            await new Response(sres.body).arrayBuffer();
            await destroyed(streamed);
        });

        it('a request that fails before sending destroys the stream body', async (t) => {
            const srv = await server(t, http2);
            const strict = new UltraTonClient({ http2 });
            t.after(() => strict.close());
            const client = clientOf(t, http2);
            const closed = new UltraTonClient({ http2, permitReservedIps: true });
            await closed.close();
            let cancelled = false;
            const web = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
            const failures: Array<[string, (body: Readable | ReadableStream<Uint8Array>) => Promise<unknown>]> = [
                ['reserved address', body => strict.post(`https://localhost:${new URL(srv.origin).port}/x`, { body })],
                ['aborted signal', body => client.post(srv.url, { body, signal: AbortSignal.abort() })],
                ['invalid option', body => client.post(srv.url, { body, timeoutMs: -1 })],
                ['GET with a body', body => client.get(srv.url, { body })],
                ['closed client', body => closed.post(srv.url, { body })],
            ];
            for (const [name, send] of failures) {
                const source = stalled();
                await assert.rejects(send(source), `${name} should reject`);
                await destroyed(source);
            }
            await assert.rejects(client.post(srv.url, { body: web, signal: AbortSignal.abort() }));
            assert.equal(cancelled, true);
            assert.equal(srv.connections(), 0);
        });

        it('close() during an upload rejects and destroys the stream', async (t) => {
            const srv = await server(t, http2);
            const client = clientOf(t, http2);
            const source = stalled();
            const pending = client.post(srv.url, { body: source });
            setTimeout(() => void client.close(), 50);
            await assert.rejects(pending);
            await destroyed(source);
        });

        it('client.fetch streams a ReadableStream body', async (t) => {
            const srv = await server(t, http2);
            const body = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(payload);
                    controller.close();
                },
            });
            const res = await clientOf(t, http2).fetch(srv.url, { method: 'POST', body, duplex: 'half' } as RequestInit);
            assert.deepEqual(received(await res.json() as Echo), payload);
        });
    });
}
