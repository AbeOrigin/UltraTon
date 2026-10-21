import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonMemoryError, UltraTonNetworkError } from '../src/errors.ts';
import { hasSafeBrotli } from '../src/helpers/body-reader.ts';

// br is requested and decoded only on a Node with the Brotli decoder fix (CVE-2026-111497); these tests run on both.
const BROTLI = hasSafeBrotli();

const PAYLOAD = JSON.stringify({ hello: 'wörld', list: Array.from({ length: 200 }, (_, i) => i) });
// 4 MiB of zeros, about 4 KiB on the wire: small, but past the 1 MiB maxBodySize the test sets, which only the decoded bytes cross.
const OVER_LIMIT = zlib.gzipSync(Buffer.alloc(4 * 1024 * 1024));

type Reply = { status?: number; encoding?: string; body: Buffer; length?: number };
const routes: Record<string, () => Reply> = {
    '/gzip': () => ({ encoding: 'gzip', body: zlib.gzipSync(PAYLOAD) }),
    '/x-gzip': () => ({ encoding: 'x-gzip', body: zlib.gzipSync(PAYLOAD) }),
    '/deflate': () => ({ encoding: 'deflate', body: zlib.deflateSync(PAYLOAD) }),
    '/br': () => ({ encoding: 'br', body: zlib.brotliCompressSync(PAYLOAD) }),
    // Listed in the order applied: gzip first, then br. Decoded br first, then gzip.
    '/layers': () => ({ encoding: 'gzip, br', body: zlib.brotliCompressSync(zlib.gzipSync(PAYLOAD)) }),
    '/identity': () => ({ encoding: 'identity', body: Buffer.from(PAYLOAD) }),
    '/three': () => ({ encoding: 'gzip, gzip, gzip', body: zlib.gzipSync(zlib.gzipSync(zlib.gzipSync(PAYLOAD))) }),
    '/unknown': () => ({ encoding: 'compress', body: Buffer.from('raw-bytes') }),
    '/over-limit': () => ({ encoding: 'gzip', body: OVER_LIMIT }),
    '/corrupt': () => ({ encoding: 'gzip', body: Buffer.from('definitely not gzip data at all') }),
    '/truncated': () => ({ encoding: 'gzip', body: zlib.gzipSync(PAYLOAD).subarray(0, 40) }),
    '/no-content': () => ({ status: 204, encoding: 'gzip', body: Buffer.alloc(0) }),
    '/no-content-three': () => ({ status: 204, encoding: 'gzip, gzip, gzip', body: Buffer.alloc(0) }),
    // A coding the reader does not decode is left raw, zstd included.
    '/zstd': () => ({ encoding: 'zstd', body: Buffer.from('zstd-bytes') }),
};

/** A loopback server of either engine. Every response echoes the accept-encoding it received in x-seen-ae. */
async function server(t: TestContext, http2: boolean) {
    const sockets = new Set<Socket>();
    const reply = (path: string, ae: unknown) => {
        const r = Object.hasOwn(routes, path) ? routes[path]() : { body: Buffer.from('plain') };
        const headers: Record<string, string> = { 'x-seen-ae': String(ae), 'content-length': String(r.body.length) };
        if (r.encoding) headers['content-encoding'] = r.encoding;
        if (r.status === 204) delete headers['content-length'];
        return { status: r.status ?? 200, headers, body: r.body };
    };
    const srv = http2
        ? createH2Server().on('stream', (stream, h: IncomingHttpHeaders) => {
            const { status, headers, body } = reply(String(h[':path']), h['accept-encoding']);
            stream.on('error', () => {});
            stream.respond({ ':status': status, ...headers });
            stream.end(status === 204 || h[':method'] === 'HEAD' ? undefined : body);
        })
        : http.createServer((req, res) => {
            const { status, headers, body } = reply(req.url ?? '/', req.headers['accept-encoding']);
            res.on('error', () => {});
            res.writeHead(status, headers);
            res.end(status === 204 || req.method === 'HEAD' ? undefined : body);
        });
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`response decompression (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it(`asks for gzip, deflate${BROTLI ? ' and br' : ', and not br on this Node'} by default`, async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/plain`);
            assert.equal(res.headers['x-seen-ae'], BROTLI ? 'gzip, deflate, br' : 'gzip, deflate');
        });

        if (!BROTLI) {
            it('leaves a br body raw on a Node without the Brotli fix, layered ones too', async (t) => {
                const base = await server(t, http2);
                const client = clientOf(t, http2);
                assert.deepEqual((await client.get(`${base}/br`)).data, routes['/br']().body);
                assert.deepEqual((await client.get(`${base}/layers`)).data, routes['/layers']().body);
            });
        }

        for (const path of ['/gzip', '/x-gzip', '/deflate', ...(BROTLI ? ['/br', '/layers'] : []), '/identity']) {
            it(`decodes ${path.slice(1)} into data, text() and json()`, async (t) => {
                const base = await server(t, http2);
                const res = await clientOf(t, http2).get(`${base}${path}`);
                assert.equal(res.text(), PAYLOAD);
                assert.deepEqual(res.json(), JSON.parse(PAYLOAD));
                // Headers stay as received: content-length is the wire length, content-encoding is kept.
                assert.equal(Number(res.headers['content-length']), routes[path]().body.length);
            });
        }

        it('applies maxBodySize to the decoded bytes, not only to the few on the wire', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2, { maxBodySize: 1024 * 1024 });
            await assert.rejects(client.get(`${base}/over-limit`), UltraTonMemoryError);
            // The same body undecoded fits: the limit was hit by decoding, not by the wire.
            assert.equal((await client.get(`${base}/over-limit`, { decompress: false })).data.length, OVER_LIMIT.length);
        });

        it('rejects more than two content-encodings', async (t) => {
            const base = await server(t, http2);
            await assert.rejects(clientOf(t, http2).get(`${base}/three`), (err: Error) =>
                err instanceof SecureHttpError && (err as SecureHttpError).code === 'ERR_ULTRATON_CONTENT_ENCODING');
        });

        it('rejects a corrupt and a truncated compressed body as a network error, never a partial success', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            for (const path of ['/corrupt', '/truncated']) {
                await assert.rejects(client.get(`${base}${path}`), (err: Error) => {
                    assert.ok(err instanceof UltraTonNetworkError, `${path}: ${err.name}`);
                    assert.match(err.message, /^UltraTon: Response body could not be decoded \(Z_[A-Z_]+\)\.$/);
                    return true;
                });
            }
        });

        it('leaves an unknown encoding raw', async (t) => {
            const base = await server(t, http2);
            assert.equal((await clientOf(t, http2).get(`${base}/unknown`)).text(), 'raw-bytes');
            assert.equal((await clientOf(t, http2).get(`${base}/zstd`)).text(), 'zstd-bytes');
        });

        it('treats a bodiless response with content-encoding as empty', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            assert.equal((await client.get(`${base}/no-content`)).data.length, 0);
            assert.equal((await client.head(`${base}/gzip`)).data.length, 0);
            // Too many encodings only matter when there is a body to decode.
            assert.equal((await client.get(`${base}/no-content-three`)).statusCode, 204);
        });

        it('with decompress: false sends no accept-encoding and returns the raw bytes', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/gzip`, { decompress: false });
            assert.equal(res.headers['x-seen-ae'], 'undefined');
            assert.deepEqual(res.data, routes['/gzip']().body);
        });

        it('honours decompress: false as a client default, and a request can turn it back on', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2, { decompress: false });
            assert.deepEqual((await client.get(`${base}/gzip`)).data, routes['/gzip']().body);
            assert.equal((await client.get(`${base}/gzip`, { decompress: true })).text(), PAYLOAD);
        });

        it("keeps the caller's own accept-encoding and still decodes what it knows", async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/gzip`, { headers: { 'Accept-Encoding': 'gzip' } });
            assert.equal(res.headers['x-seen-ae'], 'gzip');
            assert.equal(res.text(), PAYLOAD);
        });
    });
}

describe('decompress option validation', () => {
    it('must be a boolean, per request and on the client', async () => {
        await assert.rejects(new UltraTonClient().get('https://example.com/', { decompress: 'yes' } as any), TypeError);
        assert.throws(() => new UltraTonClient({ decompress: 1 } as any), TypeError);
    });
});

describe('hasSafeBrotli (CVE-2026-111497)', () => {
    it('is true from the fixed release of each line on, and after 26', () => {
        for (const v of ['22.23.4', '22.24.0', '24.22.1', '24.23.0', '26.12.1', '26.13.0', '27.0.0', '28.1.0']) assert.equal(hasSafeBrotli(v), true, v);
    });

    it('is false before the fix, on end-of-life lines and on anything it cannot read', () => {
        for (const v of ['22.12.0', '22.23.3', '24.14.1', '24.22.0', '26.12.0', '23.11.0', '25.9.0', '20.19.0', 'x', '26.12.1-pre']) assert.equal(hasSafeBrotli(v), false, v);
    });
});
