import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { createServer as createH2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonMemoryError, UltraTonNetworkError, UltraTonNetworkTimeoutError } from '../src/errors.ts';

const KiB = 1024;
const MiB = 1024 * KiB;
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

/** A minimal response writer both engines share: headers, then body writes and an end or a hang. */
interface Out {
    head(status: number, headers: Record<string, string>): void;
    write(chunk: string | Buffer): boolean;
    end(chunk?: string | Buffer): void;
    cut(): void;
    onClose(fn: () => void): void;
    onDrain(fn: () => void): void;
    /** Drops the connection under the response (h2: destroys the session). */
    kill(): void;
}

/** Routes: /data?n=BYTES, /slow-first, /stall, /short, /gzip, /redir, /track (slow 1 MiB that records its close). */
async function server(t: TestContext, http2: boolean) {
    const closed: string[] = [];
    const route = (path: string, method: string, out: Out) => {
        const url = new URL(path, 'http://x');
        switch (url.pathname) {
            case '/data': {
                const n = Number(url.searchParams.get('n') ?? 0);
                out.head(200, { 'content-length': String(n), 'x-method': method });
                const chunk = Buffer.alloc(64 * KiB, 'a');
                let sent = 0;
                const pump = () => {
                    while (sent < n) {
                        const size = Math.min(chunk.length, n - sent);
                        sent += size;
                        if (!out.write(chunk.subarray(0, size))) return out.onDrain(pump);
                    }
                    out.end();
                };
                return pump();
            }
            case '/slow-first':
                out.head(200, { 'content-length': '10' });
                out.write('first');
                return void setTimeout(() => out.end('-rest'), 400);
            case '/stall':
                out.head(200, { 'content-length': '100' });
                return void out.write('first');
            case '/short':
                out.head(200, { 'content-length': '100' });
                out.write('only ten b');
                return out.cut();
            // No content-length: only the end of the stream says whether the body is complete.
            case '/nolen-kill':
                out.head(200, {});
                out.write('part');
                return void setTimeout(() => out.kill(), 50);
            case '/nolen-hold':
                out.head(200, {});
                return void out.write('part');
            case '/gzip':
                return out.end((out.head(200, { 'content-encoding': 'gzip' }), zlib.gzipSync('decoded!'.repeat(1000))));
            case '/redir':
                out.head(302, { location: '/data?n=10', 'content-length': '0' });
                return out.end();
            case '/track': {
                out.onClose(() => closed.push('/track'));
                out.head(200, { 'content-length': String(MiB) });
                let sent = 0;
                const timer = setInterval(() => {
                    if (sent >= MiB) { clearInterval(timer); return out.end(); }
                    out.write(Buffer.alloc(16 * KiB, 'b'));
                    sent += 16 * KiB;
                }, 5);
                out.onClose(() => clearInterval(timer));
                return;
            }
            default:
                out.head(404, { 'content-length': '0' });
                return out.end();
        }
    };

    const sockets = new Set<Socket>();
    const srv = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, h: IncomingHttpHeaders) => {
            stream.on('error', () => {});
            stream.resume();
            route(String(h[':path']), String(h[':method']), {
                head: (status, headers) => stream.respond({ ':status': status, ...headers }),
                write: chunk => stream.write(chunk),
                end: chunk => stream.end(chunk),
                cut: () => stream.end(),
                onClose: fn => stream.on('close', fn),
                onDrain: fn => stream.once('drain', fn),
                kill: () => stream.session?.destroy(),
            });
        })
        : http.createServer((req, res) => {
            res.on('error', () => {});
            req.resume();
            route(req.url ?? '/', req.method ?? 'GET', {
                head: (status, headers) => res.writeHead(status, headers),
                write: chunk => res.write(chunk),
                end: chunk => res.end(chunk),
                cut: () => res.socket?.end(),
                onClose: fn => res.on('close', fn),
                onDrain: fn => res.once('drain', fn),
                kill: () => res.socket?.destroy(),
            });
        });
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return { base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, closed };
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

async function readAll(body: ReadableStream<Uint8Array>): Promise<Buffer> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of body) chunks.push(chunk);
    return Buffer.concat(chunks);
}

for (const http2 of [false, true]) {
    describe(`client.stream() (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('streams a body larger than the buffered default once maxBodySize allows it', async (t) => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.stream(`${base}/data?n=${3 * MiB}`, { maxBodySize: 4 * MiB });
            assert.equal(res.statusCode, 200);
            assert.equal(res.ok, true);
            assert.equal(res.headers['content-length'], String(3 * MiB));
            assert.equal(res.url, `${base}/data?n=${3 * MiB}`);
            assert.equal(res.redirected, false);
            assert.ok(res.body instanceof ReadableStream);
            assert.equal((await readAll(res.body)).length, 3 * MiB);
            // The buffered methods keep their own limit.
            await assert.rejects(client.get(`${base}/data?n=${3 * MiB}`), UltraTonMemoryError);
        });

        it('resolves on the headers, before the body has arrived', async (t) => {
            const { base } = await server(t, http2);
            const started = Date.now();
            const res = await clientOf(t, http2).stream(`${base}/slow-first`);
            assert.ok(Date.now() - started < 300, 'waited for the whole body');
            assert.equal((await readAll(res.body)).toString(), 'first-rest');
        });

        it('fails the stream with UltraTonMemoryError once maxBodySize is crossed', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/data?n=${MiB}`, { maxBodySize: 200 * KiB });
            await assert.rejects(readAll(res.body), UltraTonMemoryError);
        });

        it('fails the stream when the body is cut short of its content-length', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/short`);
            await assert.rejects(readAll(res.body), UltraTonNetworkError);
        });

        it('times out while waiting on a silent server, but never because the consumer is slow', async (t) => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2, { socketTimeoutMs: 200 });
            const stalled = await client.stream(`${base}/stall`);
            await assert.rejects(readAll(stalled.body), UltraTonNetworkTimeoutError);

            const res = await client.stream(`${base}/data?n=${64 * KiB}`);
            const reader = res.body.getReader();
            let total = 0;
            for (;;) {
                await sleep(300); // longer than socketTimeoutMs between reads
                const { done, value } = await reader.read();
                if (done) break;
                total += value.length;
            }
            assert.equal(total, 64 * KiB);
        });

        it('cancelling the body releases the connection, and the client keeps working', async (t) => {
            const { base, closed } = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.stream(`${base}/track`);
            const reader = res.body.getReader();
            await reader.read();
            await reader.cancel();
            for (let i = 0; i < 50 && closed.length === 0; i++) await sleep(20);
            assert.deepEqual(closed, ['/track'], 'the server never saw the response closed');
            assert.equal((await readAll((await client.stream(`${base}/data?n=10`)).body)).length, 10);
        });

        it('an abort mid-body fails the stream with the signal reason', async (t) => {
            const { base } = await server(t, http2);
            const controller = new AbortController();
            const res = await clientOf(t, http2).stream(`${base}/track`, { signal: controller.signal });
            const reader = res.body.getReader();
            await reader.read();
            const reason = new Error('stop');
            controller.abort(reason);
            await assert.rejects(reader.read(), (err: unknown) => err === reason);
        });

        it('close() fails an open stream with Client is closed', async (t) => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.stream(`${base}/track`);
            const reader = res.body.getReader();
            await reader.read();
            await client.close();
            await assert.rejects(async () => { for (;;) if ((await reader.read()).done) break; },
                (err: unknown) => err instanceof SecureHttpError && (err as Error).message === 'UltraTon: Client is closed.');
        });

        it('fails, never ends, a body without content-length whose connection drops', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/nolen-kill`);
            await assert.rejects(readAll(res.body), UltraTonNetworkError);
        });

        it('close() fails a body without content-length instead of ending it', async (t) => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.stream(`${base}/nolen-hold`);
            const reader = res.body.getReader();
            await reader.read();
            await client.close();
            await assert.rejects(async () => { for (;;) if ((await reader.read()).done) break; },
                (err: unknown) => err instanceof SecureHttpError && (err as Error).message === 'UltraTon: Client is closed.');
        });

        it('decodes gzip on the fly', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/gzip`);
            assert.equal((await readAll(res.body)).toString(), 'decoded!'.repeat(1000));
        });

        it('follows redirects before resolving and reports the final url', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2, { maxRedirects: 1 }).stream(`${base}/redir`);
            assert.equal(res.statusCode, 200);
            assert.equal(res.url, `${base}/data?n=10`);
            assert.equal(res.redirected, true);
            assert.equal((await readAll(res.body)).length, 10);
        });

        it('takes the method as an option and sends a body', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/data?n=3`, { method: 'POST', json: { a: 1 } });
            assert.equal(res.headers['x-method'], 'POST');
            assert.equal((await readAll(res.body)).length, 3);
        });

        it('gives HEAD an empty body', async (t) => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/data?n=10`, { method: 'HEAD' });
            assert.equal((await readAll(res.body)).length, 0);
        });
    });
}

describe('client.stream() validation', () => {
    const client = new UltraTonClient();

    it('accepts maxBodySize up to Number.MAX_SAFE_INTEGER only in stream()', async () => {
        await assert.rejects(client.get('https://example.com/', { maxBodySize: 2 ** 40 }), TypeError);
        for (const maxBodySize of [Infinity, -1, 1.5, 2 ** 53, '10']) {
            await assert.rejects(client.stream('https://example.com/', { maxBodySize } as any), (err: Error) =>
                err instanceof TypeError && /^UltraTon: Expected 'maxBodySize' to be an integer from 0 to 9007199254740991/.test(err.message));
        }
    });

    it('validates the method', async () => {
        for (const method of ['get', 'TRACE', 'CONNECT', '', 1]) {
            await assert.rejects(client.stream('https://example.com/', { method } as any), (err: Error) =>
                err instanceof TypeError && /^UltraTon: Expected 'method' to be one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS/.test(err.message));
        }
        await assert.rejects(client.stream('https://example.com/', { json: {} }), { message: 'UltraTon: GET and HEAD requests cannot have a body.' });
    });
});
