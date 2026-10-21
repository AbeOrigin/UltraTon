/**
 * A buffered body (get) and a streamed one (stream, read to the end) go through two readers, BodyReader and
 * createBodyStream. Whatever the body, both must end the same way: the same bytes, or an error of the same class with
 * the same code and message. Never a partial body on one side.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import zlib from 'node:zlib';
import { createServer as createH2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { hasSafeBrotli } from '../src/helpers/body-reader.ts';

const MAX = 1024 * 1024;
const PAYLOAD = JSON.stringify({ hello: 'wörld', list: Array.from({ length: 200 }, (_, i) => i) });
const GZIP = zlib.gzipSync(PAYLOAD);
// Random bytes do not compress: on the wire this is already past MAX.
const OVER_WIRE = zlib.gzipSync(crypto.randomBytes(MAX + 64 * 1024));
// 4 MiB of zeros, a few KiB on the wire: only the decoded bytes cross MAX.
const OVER_DECODED = zlib.gzipSync(Buffer.alloc(4 * MAX));

type Route = { encoding?: string; body: Buffer; cut?: boolean };
const routes: Record<string, Route> = {
    '/identity': { encoding: 'identity', body: Buffer.from(PAYLOAD) },
    '/gzip': { encoding: 'gzip', body: GZIP },
    '/deflate': { encoding: 'deflate', body: zlib.deflateSync(PAYLOAD) },
    '/br': { encoding: 'br', body: zlib.brotliCompressSync(PAYLOAD) },
    '/layers': { encoding: 'gzip, br', body: zlib.brotliCompressSync(GZIP) },
    '/three': { encoding: 'gzip, gzip, gzip', body: zlib.gzipSync(zlib.gzipSync(GZIP)) },
    '/unknown': { encoding: 'compress', body: Buffer.from('raw-bytes') },
    '/zstd': { encoding: 'zstd', body: Buffer.from('zstd-bytes') },
    '/corrupt': { encoding: 'gzip', body: Buffer.from('definitely not gzip data at all') },
    '/truncated': { encoding: 'gzip', body: GZIP.subarray(0, 40) },
    '/over-limit': { encoding: 'gzip', body: OVER_DECODED },
    '/gzip-over-limit-wire': { encoding: 'gzip', body: OVER_WIRE },
    // Half a valid gzip, then the connection is gone: decoding had already started.
    '/gzip-cut-after-decoding-started': { encoding: 'gzip', body: GZIP.subarray(0, Math.floor(GZIP.length / 2)), cut: true },
};

async function server(t: TestContext, http2: boolean) {
    const sockets = new Set<Socket>();
    const headersFor = (r: Route) => ({
        ...(r.encoding ? { 'content-encoding': r.encoding } : {}),
        // A cut body declares nothing: only the missing end tells it was cut.
        ...(r.cut ? {} : { 'content-length': String(r.body.length) }),
    });
    const srv = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, h: IncomingHttpHeaders) => {
            const r = routes[String(h[':path'])];
            stream.on('error', () => {});
            stream.respond({ ':status': 200, ...headersFor(r) });
            if (r.cut) stream.write(r.body, () => stream.session?.destroy());
            else stream.end(r.body);
        })
        : http.createServer((req, res) => {
            const r = routes[req.url ?? '/'];
            res.on('error', () => {});
            res.writeHead(200, headersFor(r));
            if (r.cut) res.write(r.body, () => res.socket?.destroy());
            else res.end(r.body);
        });
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

type Ending = { data: string } | { error: { name: string; code: unknown; message: string } };
const ending = (err: unknown): Ending => {
    const e = err as Error & { code?: unknown };
    return { error: { name: e?.constructor?.name ?? typeof err, code: e?.code, message: String(e?.message) } };
};

async function viaGet(client: UltraTonClient, url: string): Promise<Ending> {
    try {
        return { data: (await client.get(url)).data.toString('hex') };
    } catch (err) {
        return ending(err);
    }
}

async function viaStream(client: UltraTonClient, url: string): Promise<Ending> {
    try {
        const res = await client.stream(url);
        const chunks: Buffer[] = [];
        for await (const chunk of res.body) chunks.push(Buffer.from(chunk));
        return { data: Buffer.concat(chunks).toString('hex') };
    } catch (err) {
        return ending(err);
    }
}

for (const http2 of [false, true]) {
    const label = http2 ? 'HTTP/2' : 'HTTP/1';
    describe(`body parity (${label}), Brotli ${hasSafeBrotli() ? 'on' : 'off'} on this Node`, () => {
        for (const path of Object.keys(routes)) {
            it(`${label}: get() and stream() end the same way for ${path}`, async (t) => {
                const base = await server(t, http2);
                // A fresh client for each side: a cut connection must not leave anything pooled for the other.
                const clients = [0, 1].map(() => new UltraTonClient({ http2, permitReservedIps: true, maxBodySize: MAX }));
                t.after(() => Promise.all(clients.map(c => c.close())));
                const [buffered, streamed] = [await viaGet(clients[0], `${base}${path}`), await viaStream(clients[1], `${base}${path}`)];
                assert.deepEqual(streamed, buffered);
            });
        }
    });
}
