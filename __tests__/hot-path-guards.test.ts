/**
 * Guards for the HTTP/1.1 hot path, where the default accept-encoding is added while the call's headers are merged over
 * the client's. What a call brings (its headers, its options) must still be checked on every call, with UltraTon's own
 * messages, whatever the client already checked; and the merge must keep the rules it replaced.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

/** A loopback server that echoes the request headers as JSON and counts the requests it saw. */
async function serve(t: TestContext) {
    const seen = { count: 0 };
    const server = http.createServer((req, res) => {
        seen.count++;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(req.headers));
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`, seen };
}

describe('hot path: what the client checked once, and what each call must still check', () => {
    it('a call header with CRLF still throws when the client has default headers', async t => {
        const { url, seen } = await serve(t);
        const client = new UltraTonClient({ headers: { 'x-a': '1' }, permitReservedIps: true });
        t.after(() => client.close());
        // UltraTon's own message: Node would also refuse these, so a bare TypeError would not show who checked.
        await assert.rejects(client.get(url, { headers: { 'x-b': 'a\r\nb' } }), { name: 'TypeError', message: /^UltraTon: Header value for 'x-b' contains invalid CRLF/ });
        await assert.rejects(client.get(url, { headers: { 'x-c': ['ok', 'a\0b'] } }), { name: 'TypeError', message: /^UltraTon: Header array value for 'x-c'/ });
        await assert.rejects(client.get(url, { headers: { ':path': '/x' } }), { name: 'TypeError', message: /^UltraTon: Header key ':path' is an HTTP\/2 pseudo-header/ });
        assert.equal(seen.count, 0);
    });

    it('changing the headers object after construction does not change what the client sends', async t => {
        const { url } = await serve(t);
        const headers: Record<string, string> = { 'x-a': '1' };
        const client = new UltraTonClient({ headers, permitReservedIps: true });
        t.after(() => client.close());
        headers['x-a'] = 'a\r\nb';
        headers['x-late'] = '2';
        const echoed = (await client.get(url)).json<Record<string, string>>();
        assert.equal(echoed['x-a'], '1');
        assert.equal(echoed['x-late'], undefined);
    });

    it('a call header overrides a default one case-insensitively, and the default comes back on the next call', async t => {
        const { url } = await serve(t);
        const client = new UltraTonClient({ headers: { 'x-a': '1', accept: 'text/plain' }, permitReservedIps: true });
        t.after(() => client.close());
        const first = (await client.get(url, { headers: { 'X-A': '2' } })).json<Record<string, string>>();
        assert.equal(first['x-a'], '2');
        const second = (await client.get(url)).json<Record<string, string>>();
        assert.equal(second['x-a'], '1');
        assert.equal(second.accept, 'text/plain');
    });

    it('a call accept-encoding replaces the default one, and decompress: false sends none', async t => {
        const { url } = await serve(t);
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        const own = (await client.get(url, { headers: { 'Accept-Encoding': 'identity' } })).json<Record<string, string>>();
        assert.equal(own['accept-encoding'], 'identity');
        const off = (await client.get(url, { decompress: false })).json<Record<string, string>>();
        assert.equal(off['accept-encoding'], undefined);
        const byDefault = (await client.get(url)).json<Record<string, string>>();
        assert.match(byDefault['accept-encoding'], /gzip/);
    });

    it('an unknown option on the call still throws', async t => {
        const { url, seen } = await serve(t);
        const client = new UltraTonClient({ headers: { 'x-a': '1' }, permitReservedIps: true });
        t.after(() => client.close());
        await assert.rejects(client.get(url, { timeout: 5 } as never), TypeError);
        await assert.rejects(client.get(url, { timeoutMs: -1 }), TypeError);
        assert.equal(seen.count, 0);
    });
});
