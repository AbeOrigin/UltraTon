/**
 * Q6: what the README's "Coming from axios, got or fetch" guide states, run against a loopback server: the option
 * names, and the four defaults it says change on migration (redirects off, 2 MB, a total timeout, non-2xx resolves).
 * If one of these fails, the guide is what is wrong.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonHttpError, UltraTonMemoryError, UltraTonNetworkTimeoutError } from '../src/errors.ts';

async function serve(t: TestContext) {
    const server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            const url = new URL(req.url!, 'http://x');
            switch (url.pathname) {
                case '/echo':
                    res.writeHead(200, { 'content-type': 'application/json' });
                    return res.end(JSON.stringify({ url: req.url, contentType: req.headers['content-type'], body: Buffer.concat(chunks).toString() }));
                case '/slow': return void setTimeout(() => { res.writeHead(200); res.end('late'); }, 300);
                case '/big': res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end(Buffer.alloc(3 * 1024 * 1024, 'x'));
                case '/moved': res.writeHead(302, { location: '/echo' }); return res.end();
                default: res.writeHead(404); return res.end('nope');
            }
        });
    });
    const sockets = new Set<Socket>();
    server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const client = new UltraTonClient({ baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`, permitReservedIps: true });
    t.after(async () => {
        await client.close();
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return client;
}

describe('Coming from axios, got or fetch', () => {
    it('query, json and form encode as the guide says', async (t) => {
        const client = await serve(t);
        const query = (await client.get('echo', { query: { a: 1 } })).json<{ url: string }>();
        assert.equal(query.url, '/echo?a=1');
        const json = (await client.post('echo', { json: { a: 1 } })).json<{ contentType: string; body: string }>();
        assert.equal(json.contentType, 'application/json');
        assert.equal(json.body, '{"a":1}');
        const form = (await client.post('echo', { form: { a: '1' } })).json<{ contentType: string; body: string }>();
        assert.match(form.contentType, /^application\/x-www-form-urlencoded/);
        assert.equal(form.body, 'a=1');
    });

    it('timeoutMs, maxBodySize and maxRedirects defaults are the ones the guide states', { timeout: 10_000 }, async (t) => {
        const client = await serve(t);
        await assert.rejects(client.get('slow', { timeoutMs: 50 }), (err: UltraTonNetworkTimeoutError) => err.code === 'ERR_ULTRATON_TIMEOUT');
        await assert.rejects(client.get('big'), UltraTonMemoryError);
        assert.equal((await client.get('moved')).statusCode, 302);
    });

    it('a non-2xx resolves, and assertOk() is what throws', async (t) => {
        const client = await serve(t);
        const res = await client.get('missing');
        assert.equal(res.ok, false);
        assert.throws(() => res.assertOk(), (err: UltraTonHttpError) => err.statusCode === 404);
    });
});
