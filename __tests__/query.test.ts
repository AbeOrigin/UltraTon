import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

/** A loopback server of either engine that answers with the request target it received (path and query). */
async function echoTarget(t: TestContext, http2: boolean) {
    const sockets = new Set<Socket>();
    const server = http2
        ? createH2Server().on('stream', (stream, headers: IncomingHttpHeaders) => {
            stream.respond({ ':status': 200 });
            stream.end(String(headers[':path']));
        })
        : http.createServer((req, res) => res.end(req.url));
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`query option (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('encodes keys and values with URLSearchParams rules', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/search`, { query: { q: 'café & té', 'a=b': '#x?y', page: 2, on: true } });
            assert.equal(res.text(), '/search?q=caf%C3%A9+%26+t%C3%A9&a%3Db=%23x%3Fy&page=2&on=true');
        });

        it('repeats the key for an array and skips undefined', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/x`, { query: { tags: ['a', 'b', 3], draft: undefined, empty: [] } });
            assert.equal(res.text(), '/x?tags=a&tags=b&tags=3');
        });

        it("appends to the URL's own query without re-encoding it", async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/x?flag&a=b%20c&a=1`, { query: { a: '2' } });
            assert.equal(res.text(), '/x?flag&a=b%20c&a=1&a=2');
        });

        it('leaves the URL untouched when every value is undefined', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            assert.equal((await client.get(`${base}/x`, { query: { a: undefined } })).text(), '/x');
            assert.equal((await client.get(`${base}/x?keep`, { query: {} })).text(), '/x?keep');
        });

        it('accepts URLSearchParams', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            const res = await client.get(`${base}/x`, { query: new URLSearchParams([['a', '1'], ['a', '2 3']]) });
            assert.equal(res.text(), '/x?a=1&a=2+3');
        });

        it('works with baseUrl and can never change the path, whatever the values', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2, { baseUrl: `${base}/api/v1/` });
            const res = await client.get('users', { query: { next: '../../admin', frag: '#/admin', slash: '/etc/passwd' } });
            assert.equal(res.text(), '/api/v1/users?next=..%2F..%2Fadmin&frag=%23%2Fadmin&slash=%2Fetc%2Fpasswd');
        });

        it('keeps a fragment out of the request and the query before it', async (t) => {
            const base = await echoTarget(t, http2);
            const client = clientOf(t, http2);
            assert.equal((await client.get(`${base}/x#section`, { query: { a: '1' } })).text(), '/x?a=1');
        });
    });
}

describe('query option validation', () => {
    const client = new UltraTonClient();
    const QUERY_TYPE = /^UltraTon: Expected 'query' to be a plain object or URLSearchParams, received /;
    const VALUE_TYPE = (key: string) => new RegExp(`^UltraTon: Expected query parameter '${key}' to be a string, a finite number or a boolean, received `);

    it('rejects a query that is not a plain object or URLSearchParams, before connecting', async () => {
        for (const query of ['a=1', 42, null, ['a'], new Map([['a', '1']])]) {
            await assert.rejects(client.get('https://example.com/', { query } as any), (err: Error) => {
                assert.ok(err instanceof TypeError, String(query));
                assert.match(err.message, QUERY_TYPE);
                return true;
            });
        }
    });

    it('rejects null, nested objects, functions, symbols, bigints and non-finite numbers as values', async () => {
        const bad: Record<string, unknown> = {
            n: null, o: { a: 1 }, f: () => 1, s: Symbol('x'), b: 10n, nan: NaN, inf: Infinity, nested: [['a']], hole: [undefined],
        };
        for (const [key, value] of Object.entries(bad)) {
            await assert.rejects(client.get('https://example.com/', { query: { [key]: value } } as any), (err: Error) => {
                assert.ok(err instanceof TypeError, key);
                assert.match(err.message, VALUE_TYPE(key));
                return true;
            });
        }
    });

    it('is not inherited from a polluted Object.prototype', async (t) => {
        const base = await echoTarget(t, false);
        const local = clientOf(t, false);
        (Object.prototype as any).query = { injected: '1' };
        try {
            assert.equal((await local.get(`${base}/x`)).text(), '/x');
        } finally {
            delete (Object.prototype as any).query;
        }
    });

    it('points params and searchParams at query, and query on the constructor at the request', async () => {
        for (const key of ['params', 'searchParams']) {
            await assert.rejects(client.get('https://example.com/', { [key]: { a: 1 } } as any), { message: `UltraTon: Unknown option '${key}'. Use 'query'.` });
        }
        assert.throws(() => new UltraTonClient({ query: { a: 1 } } as any), { message: "UltraTon: Unknown option 'query'. 'query' is a per-request option, not a client option." });
    });
});
