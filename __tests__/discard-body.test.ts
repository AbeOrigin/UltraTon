/**
 * `discardBody: true` reads the body to the end (so the connection can be reused) and keeps none of it: `data` is
 * empty and `bodySize` says how many bytes came, decoded. Every limit still applies: `maxBodySize` on the wire and
 * decoded, the timeouts, and a body cut short fails instead of resolving. A request option only.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { gzipSync } from 'node:zlib';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonMemoryError } from '../src/errors.ts';
import { KEEP_ALIVE } from '../src/helpers/keep-alive.ts';

const KIB = 1024;
const HALF_MIB = Buffer.alloc(512 * KIB, 'x');
const MIB_AND_HALF = Buffer.alloc(1536 * KIB, 'x');
// 2 MiB of zeros, a few KiB once gzipped: over a 1 MiB limit only once decoded.
const GZIPPED_2MIB = gzipSync(Buffer.alloc(2048 * KIB));

/** /half: 512 KiB. /big: 1.5 MiB. /gzip: 2 MiB decoded. /short: says 1000 bytes, sends 500 and closes. /json: '{"a":1}'. */
async function server(t: TestContext, http2: boolean) {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        if (req.url === '/half') return res.end(HALF_MIB);
        if (req.url === '/big') return res.end(MIB_AND_HALF);
        if (req.url === '/gzip') { res.setHeader('content-encoding', 'gzip'); return res.end(GZIPPED_2MIB); }
        if (req.url === '/short') {
            res.writeHead(200, { 'content-length': '1000' });
            res.write(Buffer.alloc(500, 'x'));
            return setTimeout(() => (http2 ? (res as unknown as { stream: { close: (code: number) => void } }).stream.close(2) : res.socket?.destroy()), 20);
        }
        res.setHeader('content-type', 'application/json');
        res.end('{"a":1}');
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
    describe(`discardBody (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('keeps none of the body and says how many bytes came', async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/half`, { discardBody: true, maxBodySize: 1024 * KIB });
            assert.equal(res.statusCode, 200);
            assert.equal(res.data.length, 0);
            assert.equal(res.bodySize, 512 * KIB);
        });

        it('reads the body to the end, so the next request reuses the connection', { skip: !http2 && !KEEP_ALIVE }, async t => {
            const base = await server(t, http2);
            const client = clientOf(t, http2, { timings: true });
            await client.get(`${base}/half`, { discardBody: true, maxBodySize: 1024 * KIB });
            const second = await client.get(`${base}/half`, { discardBody: true, maxBodySize: 1024 * KIB });
            assert.equal(second.timings?.reusedConnection, true);
        });

        it('still fails a body over maxBodySize', async t => {
            const base = await server(t, http2);
            await assert.rejects(clientOf(t, http2).get(`${base}/big`, { discardBody: true, maxBodySize: 1024 * KIB }), UltraTonMemoryError);
        });

        it('counts decoded bytes, and still fails a decoded body over maxBodySize', async t => {
            const base = await server(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/gzip`, { discardBody: true, maxBodySize: 4096 * KIB });
            assert.equal(res.bodySize, 2048 * KIB);
            await assert.rejects(client.get(`${base}/gzip`, { discardBody: true, maxBodySize: 1024 * KIB }), UltraTonMemoryError);
        });

        it('fails a body cut short instead of reporting it complete', async t => {
            const base = await server(t, http2);
            await assert.rejects(clientOf(t, http2).get(`${base}/short`, { discardBody: true }), (err: Error) => err.name === 'UltraTonNetworkError');
        });

        it('changes nothing without the option', async t => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/json`);
            assert.deepEqual(res.json(), { a: 1 });
            assert.equal('bodySize' in res, false);
        });
    });
}

describe('discardBody is a request option of the buffered methods only', () => {
    it('is refused by the constructor, stream() and paginate()', async t => {
        assert.throws(() => new UltraTonClient({ discardBody: true } as never), { name: 'TypeError', message: /Unknown option 'discardBody'\. 'discardBody' is a per-request option/ });
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        await assert.rejects(client.stream('http://127.0.0.1:1/', { discardBody: true } as never), { name: 'TypeError', message: /'discardBody'/ });
        // paginate() checks its options when called, as it does for json, form and body.
        assert.throws(() => client.paginate('http://127.0.0.1:1/', { discardBody: true } as never), { name: 'TypeError', message: /'discardBody'/ });
    });

    it('must be a boolean', async t => {
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        await assert.rejects(client.get('http://127.0.0.1:1/', { discardBody: 'yes' } as never), { name: 'TypeError', message: "UltraTon: Expected 'discardBody' to be a boolean, received string" });
    });
});
