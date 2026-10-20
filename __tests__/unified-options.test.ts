/**
 * Uniform `(url, options)` methods, the `json` option, an always-present content-length and rejection of unknown
 * options. Real sockets on loopback for both engines: what the server receives is the contract.
 */
import { afterEach, beforeEach, describe, it, mock, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import { createServer as createH2Server, type Http2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import { type AddressInfo, isIP } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonHTTP2 } from '../src/http2-client.ts';
import { Http2SessionManager } from '../src/classes/http-session-mannager.ts';
import { buildSafeRequestOptions } from '../src/helpers/request-options.ts';

type Echo = { method: string; headers: Record<string, string | undefined>; body: string };

interface Engine {
    name: string;
    base: string;
    post(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    put(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    patch(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    get(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    head(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    delete(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    options(url: string, options?: any): Promise<{ statusCode: number; json<T>(): T }>;
    /** Number of sockets the client opened, so "throws before connecting" can be proven. */
    connections(): number;
}

/** One server and one client per engine, both over loopback. Cleaned up when the test ends. */
async function startHttp1(t: TestContext): Promise<Engine> {
    let connections = 0;
    const server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() }));
        });
    });
    server.on('connection', () => connections++);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(() => { server.closeAllConnections(); server.close(); });
    const client = new UltraTonClient();
    const opts = (o?: any) => (typeof o === 'string' ? o : { permitReservedIps: true, ...o });
    return {
        name: 'HTTP/1',
        base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        post: (u, o) => client.post(u, opts(o)),
        put: (u, o) => client.put(u, opts(o)),
        patch: (u, o) => client.patch(u, opts(o)),
        get: (u, o) => client.get(u, opts(o)),
        head: (u, o) => client.head(u, opts(o)),
        delete: (u, o) => client.delete(u, opts(o)),
        options: (u, o) => client.options(u, opts(o)),
        connections: () => connections,
    };
}

const h2echo = (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
    const chunks: Buffer[] = [];
    stream.on('data', (c: Buffer) => chunks.push(c));
    stream.on('end', () => {
        stream.respond({ ':status': 200, 'content-type': 'application/json' });
        stream.end(JSON.stringify({ method: headers[':method'], headers, body: Buffer.concat(chunks).toString() }));
    });
};

async function startHttp2(t: TestContext, onStream = h2echo): Promise<Engine & { server: Http2Server }> {
    let connections = 0;
    const manager = new Http2SessionManager();
    const server = createH2Server();
    server.on('stream', onStream);
    server.on('connection', () => connections++);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        manager.closeAll();
        await new Promise<void>(r => server.close(() => r()));
    });
    const client = new UltraTonHTTP2({}, manager);
    const opts = (o?: any) => (typeof o === 'string' ? o : { permitReservedIps: true, ...o });
    return {
        server,
        name: 'HTTP/2',
        base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        post: (u, o) => client.post(u, opts(o)),
        put: (u, o) => client.put(u, opts(o)),
        patch: (u, o) => client.patch(u, opts(o)),
        get: (u, o) => client.get(u, opts(o)),
        head: (u, o) => client.head(u, opts(o)),
        delete: (u, o) => client.delete(u, opts(o)),
        options: (u, o) => client.options(u, opts(o)),
        connections: () => connections,
    };
}

const engines: Array<[string, (t: TestContext) => Promise<Engine>]> = [
    ['HTTP/1', startHttp1],
    ['HTTP/2', startHttp2],
];

describe('Unified API: json option and content-length (real servers)', () => {
    beforeEach(() => {
        // The HTTP/2 client resolves IP literals through dns.promises; echo them, never touch a resolver.
        mock.method(dnsPromises, 'lookup', async (host: string) => ({ address: host, family: isIP(host) || 4 }));
    });
    afterEach(() => mock.restoreAll());

    for (const [name, start] of engines) {
        describe(name, () => {
            it('post({ json }) sends the JSON with content-type and a byte-exact content-length', async (t) => {
                const e = await start(t);
                const payload = { a: 1, text: 'héllo €' };
                const res = await e.post(`${e.base}/x`, { json: payload });
                const echo = res.json<Echo>();
                const expected = JSON.stringify(payload);

                assert.strictEqual(echo.method, 'POST');
                assert.strictEqual(echo.body, expected);
                assert.strictEqual(echo.headers['content-type'], 'application/json');
                assert.strictEqual(echo.headers['content-length'], String(Buffer.byteLength(expected)));
                assert.strictEqual(echo.headers['transfer-encoding'], undefined);
            });

            it('put and patch take json the same way', async (t) => {
                const e = await start(t);
                for (const verb of ['put', 'patch'] as const) {
                    const echo = (await e[verb](`${e.base}/x`, { json: { v: verb } })).json<Echo>();
                    assert.strictEqual(echo.method, verb.toUpperCase());
                    assert.strictEqual(echo.body, JSON.stringify({ v: verb }));
                    assert.strictEqual(echo.headers['content-type'], 'application/json');
                }
            });

            it('a multibyte string body reports content-length in bytes, not characters', async (t) => {
                const e = await start(t);
                const body = 'ñandú €€ 日本語';
                assert.ok(Buffer.byteLength(body) > body.length);
                const echo = (await e.post(`${e.base}/x`, { body })).json<Echo>();
                assert.strictEqual(echo.body, body);
                assert.strictEqual(echo.headers['content-length'], String(Buffer.byteLength(body)));
                assert.strictEqual(echo.headers['transfer-encoding'], undefined);
            });

            it('accepts Buffer and Uint8Array bodies', async (t) => {
                const e = await start(t);
                const bytes = [0x68, 0x69, 0x21];
                for (const body of [Buffer.from(bytes), new Uint8Array(bytes)]) {
                    const echo = (await e.post(`${e.base}/x`, { body })).json<Echo>();
                    assert.strictEqual(echo.body, 'hi!');
                    assert.strictEqual(echo.headers['content-length'], '3');
                }
            });

            it('keeps a content-type the caller already set (any case) with json', async (t) => {
                const e = await start(t);
                const echo = (await e.post(`${e.base}/x`, {
                    json: { a: 1 },
                    headers: { 'Content-Type': 'application/vnd.api+json' },
                })).json<Echo>();
                assert.strictEqual(echo.headers['content-type'], 'application/vnd.api+json');
                assert.strictEqual(echo.body, '{"a":1}');
            });

            it('does not add a content-type to a plain body', async (t) => {
                const e = await start(t);
                const echo = (await e.post(`${e.base}/x`, { body: 'raw' })).json<Echo>();
                assert.strictEqual(echo.headers['content-type'], undefined);
            });

            it('a caller content-length can never disagree with the real body', async (t) => {
                const e = await start(t);
                const echo = (await e.post(`${e.base}/x`, { body: 'abcd', headers: { 'Content-Length': '1' } })).json<Echo>();
                assert.strictEqual(echo.body, 'abcd');
                assert.strictEqual(echo.headers['content-length'], '4');
            });

            it('json: null is a body ("null"); json: undefined is no body', async (t) => {
                const e = await start(t);
                assert.strictEqual((await e.post(`${e.base}/x`, { json: null })).json<Echo>().body, 'null');
                const none = (await e.post(`${e.base}/x`, { json: undefined })).json<Echo>();
                assert.strictEqual(none.body, '');
            });

            it('json together with body throws before connecting', async (t) => {
                const e = await start(t);
                await assert.rejects(
                    e.post(`${e.base}/x`, { json: { a: 1 }, body: 'x' }),
                    (err: unknown) => err instanceof TypeError && err.message === "UltraTon: Use either 'json' or 'body', not both.",
                );
                assert.strictEqual(e.connections(), 0);
            });

            it('a json value that cannot be serialized throws before connecting', async (t) => {
                const e = await start(t);
                const cyclic: any = {}; cyclic.self = cyclic;
                for (const json of [cyclic, () => 1, 10n]) {
                    await assert.rejects(e.post(`${e.base}/x`, { json }), TypeError);
                }
                assert.strictEqual(e.connections(), 0);
            });

            it('a json serialization failure keeps the original error as cause', async (t) => {
                const e = await start(t);
                const cyclic: any = {}; cyclic.self = cyclic;
                for (const json of [cyclic, 10n]) {
                    await assert.rejects(e.post(`${e.base}/x`, { json }), (err: unknown) => err instanceof TypeError && (err as Error).cause instanceof TypeError);
                }
            });

            it('get and head with json or body throw a TypeError before connecting', async (t) => {
                const e = await start(t);
                for (const verb of ['get', 'head'] as const) {
                    for (const options of [{ json: { a: 1 } }, { body: 'x' }]) {
                        await assert.rejects(
                            e[verb](`${e.base}/x`, options),
                            (err: unknown) => err instanceof TypeError && err.message === 'UltraTon: GET and HEAD requests cannot have a body.',
                            `${verb} ${Object.keys(options)}`,
                        );
                    }
                }
                assert.strictEqual(e.connections(), 0);
            });

            it('delete and options deliver a json body with content-type and content-length', async (t) => {
                const e = await start(t);
                const expected = JSON.stringify({ a: 'é' });
                for (const verb of ['delete', 'options'] as const) {
                    const echo = (await e[verb](`${e.base}/x`, { json: { a: 'é' } })).json<Echo>();
                    assert.strictEqual(echo.method, verb.toUpperCase());
                    assert.strictEqual(echo.body, expected);
                    assert.strictEqual(echo.headers['content-type'], 'application/json');
                    assert.strictEqual(echo.headers['content-length'], String(Buffer.byteLength(expected)));
                }
            });

            it('delete and options without a body still work', async (t) => {
                const e = await start(t);
                for (const verb of ['delete', 'options'] as const) {
                    const echo = (await e[verb](`${e.base}/x`)).json<Echo>();
                    assert.strictEqual(echo.method, verb.toUpperCase());
                    assert.strictEqual(echo.body, '');
                }
            });

            it('a caller transfer-encoding never reaches the wire when a body is sent', async (t) => {
                const e = await start(t);
                const echo = (await e.post(`${e.base}/x`, { body: 'abcd', headers: { 'Transfer-Encoding': 'chunked' } })).json<Echo>();
                assert.strictEqual(echo.body, 'abcd');
                assert.strictEqual(echo.headers['content-length'], '4');
                assert.strictEqual(echo.headers['transfer-encoding'], undefined);
            });

            it('a body that is not string, Buffer or Uint8Array throws before connecting', async (t) => {
                const e = await start(t);
                for (const body of [{ a: 1 }, 42, true, ['a'], new ArrayBuffer(2), null]) {
                    await assert.rejects(e.post(`${e.base}/x`, { body }), (err: unknown) => err instanceof TypeError && /body/.test((err as Error).message));
                }
                assert.strictEqual(e.connections(), 0);
            });

            it('unknown options throw with their hint before connecting', async (t) => {
                const e = await start(t);
                const cases: Array<[string, RegExp]> = [
                    ['timeout', /Unknown option 'timeout'\..*timeoutMs/],
                    ['params', /Unknown option 'params'\..*query string in the URL/i],
                    ['query', /query string in the URL/i],
                    ['searchParams', /query string in the URL/i],
                    ['data', /Unknown option 'data'\..*json.*body/],
                    ['baseURL', /baseUrl/],
                    ['prefixUrl', /baseUrl/],
                    ['agent', /tls/],
                    ['ca', /tls/],
                    ['rejectUnauthorized', /Unknown option 'rejectUnauthorized'\..*tls/],
                ];
                for (const [key, pattern] of cases) {
                    await assert.rejects(
                        e.get(`${e.base}/x`, { [key]: 1 }),
                        (err: unknown) => err instanceof TypeError && pattern.test((err as Error).message),
                        key,
                    );
                }
                assert.strictEqual(e.connections(), 0);
            });

            it('an invented option throws and lists the valid ones; undefined values count too', async (t) => {
                const e = await start(t);
                for (const options of [{ foo: 1 }, { foo: undefined }]) {
                    await assert.rejects(e.get(`${e.base}/x`, options), (err: unknown) => {
                        const msg = (err as Error).message;
                        return err instanceof TypeError
                            && msg.startsWith("UltraTon: Unknown option 'foo'.")
                            && ['headers', 'timeoutMs', 'socketTimeoutMs', 'maxBodySize', 'maxRedirects', 'permitReservedIps', 'signal', 'auth', 'json', 'body']
                                .every(k => msg.includes(k));
                    });
                }
                assert.strictEqual(e.connections(), 0);
            });

            it('a caller-supplied method option is rejected instead of silently overridden', async (t) => {
                const e = await start(t);
                await assert.rejects(e.get(`${e.base}/x`, { method: 'POST' }), (err: unknown) => err instanceof TypeError && /Unknown option 'method'/.test((err as Error).message));
                assert.strictEqual(e.connections(), 0);
            });

            it('options that is not an object throws a clear error (old post(url, body) call shape)', async (t) => {
                const e = await start(t);
                await assert.rejects(e.post(`${e.base}/x`, '{"a":1}'), (err: unknown) => err instanceof TypeError && /options.*object.*json.*body/.test((err as Error).message));
                assert.strictEqual(e.connections(), 0);
            });

            it('every documented option is accepted together', async (t) => {
                const e = await start(t);
                const res = await e.post(`${e.base}/x`, {
                    headers: { 'x-a': '1' },
                    timeoutMs: 5000,
                    socketTimeoutMs: 5000,
                    maxBodySize: 1_000_000,
                    maxRedirects: 2,
                    permitReservedIps: true,
                    signal: new AbortController().signal,
                    json: { ok: true },
                });
                assert.strictEqual(res.statusCode, 200);
            });

            it('auth becomes a Basic authorization header', async (t) => {
                const e = await start(t);
                const echo = (await e.get(`${e.base}/x`, { auth: 'user:pass' })).json<Echo>();
                assert.strictEqual(echo.headers['authorization'], `Basic ${Buffer.from('user:pass').toString('base64')}`);
            });
        });
    }

    it('HTTP/2: auth is dropped on a cross-origin redirect and kept on same-origin', async (t) => {
        const target = await startHttp2(t);
        const origin = await startHttp2(t, (stream, headers) => {
            stream.resume();
            const path = headers[':path'];
            if (path === '/cross') stream.respond({ ':status': 302, location: `${target.base}/echo` });
            else if (path === '/same') stream.respond({ ':status': 302, location: '/echo' });
            else return h2echo(stream, headers);
            stream.end();
        });

        const cross = (await origin.get(`${origin.base}/cross`, { auth: 'u:p', maxRedirects: 1 })).json<Echo>();
        assert.strictEqual(cross.headers[':authority'], new URL(target.base).host);
        assert.strictEqual(cross.headers['authorization'], undefined);

        const same = (await origin.get(`${origin.base}/same`, { auth: 'u:p', maxRedirects: 1 })).json<Echo>();
        assert.strictEqual(same.headers[':authority'], new URL(origin.base).host);
        assert.strictEqual(same.headers['authorization'], `Basic ${Buffer.from('u:p').toString('base64')}`);
    });

    it('HTTP/2: an explicit authorization header wins over auth', async (t) => {
        const e = await startHttp2(t);
        const echo = (await e.get(`${e.base}/x`, { auth: 'u:p', headers: { Authorization: 'Bearer t' } })).json<Echo>();
        assert.strictEqual(echo.headers['authorization'], 'Bearer t');
    });
});

describe('Unified API: buildSafeRequestOptions unknown-key firewall', () => {
    it('accepts every valid per-request key, plus the internal method', () => {
        const out = buildSafeRequestOptions({
            method: 'POST', headers: { a: 'b' }, timeoutMs: 1, socketTimeoutMs: 1, maxBodySize: 1, maxRedirects: 1,
            permitReservedIps: false, signal: new AbortController().signal, auth: 'u:p', body: 'x',
        } as any);
        assert.strictEqual(out.method, 'POST');
        assert.strictEqual(out.timeoutMs, 1);
    });

    it('accepts json (alone) too', () => {
        assert.doesNotThrow(() => buildSafeRequestOptions({ json: { a: 1 } } as any));
    });

    it('throws TypeError on json together with body', () => {
        assert.throws(() => buildSafeRequestOptions({ json: {}, body: 'x' } as any), { name: 'TypeError', message: "UltraTon: Use either 'json' or 'body', not both." });
    });

    it('throws on an unknown key, even when its value is undefined', () => {
        assert.throws(() => buildSafeRequestOptions({ agent: undefined } as any), TypeError);
        assert.throws(() => buildSafeRequestOptions({ foo: 1 } as any), /Unknown option 'foo'/);
    });

    it('rejects __proto__ own keys and prototype-pollution shaped input', () => {
        const hostile = JSON.parse('{"__proto__": {"permitReservedIps": true}}');
        assert.throws(() => buildSafeRequestOptions(hostile), /Unknown option '__proto__'/);
    });

    it('rejectUnauthorized is explicitly unsupported', () => {
        assert.throws(() => buildSafeRequestOptions({ rejectUnauthorized: false } as any), /rejectUnauthorized.*tls/);
    });
});
