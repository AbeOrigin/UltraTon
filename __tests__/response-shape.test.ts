import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import { createServer } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { UltraTonParseError } from '../src/errors.ts';
import { createResponse } from '../src/helpers/response.ts';
import { kSessionManager } from '../src/internal.ts';
import { UltraTonClient } from '../src/http-client.ts';

const MULTIBYTE = 'héllo wörld ✓ 日本語 🚀';
const BIG_BYTES = 5 * 1024 * 1024 + 1024; // over the old 5 MB auto-parse threshold

// One route table shared by both engines: [status, content-type, body].
const routes: Record<string, [number, string, string | Buffer]> = {
    '/ok': [200, 'application/json', '{"a":1}'],
    '/missing': [404, 'application/json', '{"error":"nope"}'],
    '/multibyte': [200, 'text/plain; charset=utf-8', MULTIBYTE],
    '/problem': [400, 'application/problem+json', '{"title":"bad","status":400}'],
    '/plain-json': [200, 'text/plain', '{"a":1}'],
    '/empty': [204, 'application/json', ''],
    '/malformed': [200, 'application/json', '{not json'],
    '/proto': [200, 'application/json', '{"a":1,"__proto__":{"polluted":true},"n":{"constructor":1,"prototype":2,"b":3}}'],
    '/big': [200, 'application/json', Buffer.from('{"v":"' + 'x'.repeat(BIG_BYTES) + '"}')],
};

interface Api {
    get: (path: string) => Promise<any>;
    head: (path: string) => Promise<any>;
    stop: () => Promise<void>;
}

const startHttp1 = async (): Promise<Api> => {
    const server = http.createServer((req, res) => {
        const [status, type, body] = routes[req.url!] ?? [404, 'text/plain', ''];
        res.writeHead(status, { 'content-type': type });
        res.end(req.method === 'HEAD' ? undefined : body);
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const client = new UltraTonClient();
    const o = { permitReservedIps: true, maxBodySize: 20 * 1024 * 1024 };
    return {
        get: (p) => client.get(base + p, o),
        head: (p) => client.head(base + p, o),
        stop: async () => { server.closeAllConnections(); await new Promise<void>(r => server.close(() => r())); },
    };
};

const startHttp2 = async (): Promise<Api> => {
    const server = createServer();
    server.on('stream', (stream, headers) => {
        stream.resume();
        stream.on('error', () => {}); // the client resets a HEAD stream as soon as the headers arrive
        const [status, type, body] = routes[headers[':path'] as string] ?? [404, 'text/plain', ''];
        if (stream.destroyed) return;
        stream.respond({ ':status': status, 'content-type': type });
        stream.end(headers[':method'] === 'HEAD' ? undefined : body);
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const manager = new Http2SessionManager();
    const client = new UltraTonClient({ http2: true, [kSessionManager]: manager } as any);
    const o = { permitReservedIps: true, maxBodySize: 20 * 1024 * 1024 };
    return {
        get: (p) => client.get(base + p, o),
        head: (p) => client.head(base + p, o),
        stop: async () => { manager.closeAll(); await new Promise<void>(r => server.close(() => r())); },
    };
};

for (const [name, start] of [['HTTP/1', startHttp1], ['HTTP/2', startHttp2]] as const) {
    describe(`${name} response shape: data / json() / text() / ok`, () => {
        let api: Api;
        before(async () => { api = await start(); });
        after(async () => { await api.stop(); });

        it('ok is true on 200 and false on 404, and the 404 still resolves', async () => {
            const good = await api.get('/ok');
            const bad = await api.get('/missing');
            assert.strictEqual(good.statusCode, 200);
            assert.strictEqual(good.ok, true);
            assert.strictEqual(bad.statusCode, 404);
            assert.strictEqual(bad.ok, false);
            assert.strictEqual(typeof bad.statusCode, 'number');
        });

        it('data is always a raw Buffer, even for application/json (no auto-parse)', async () => {
            const res = await api.get('/ok');
            assert.ok(Buffer.isBuffer(res.data));
            assert.strictEqual(res.data.toString(), '{"a":1}');
            assert.strictEqual('body' in res, false);
        });

        it('text() decodes multibyte UTF-8', async () => {
            const res = await api.get('/multibyte');
            assert.strictEqual(res.text(), MULTIBYTE);
            assert.strictEqual(res.data.length, Buffer.byteLength(MULTIBYTE));
        });

        it('json() works on application/problem+json and on text/plain: it does not depend on content-type', async () => {
            assert.deepStrictEqual((await api.get('/problem')).json(), { title: 'bad', status: 400 });
            assert.deepStrictEqual((await api.get('/plain-json')).json(), { a: 1 });
        });

        it('json() is lazy and parses fresh on every call', async () => {
            const res = await api.get('/ok');
            const a = res.json();
            const b = res.json();
            assert.deepStrictEqual(a, b);
            assert.notStrictEqual(a, b);
        });

        it('json() on an empty body gives {}', async () => {
            const res = await api.get('/empty');
            assert.strictEqual(res.data.length, 0);
            assert.deepStrictEqual(res.json(), {});
        });

        it('malformed JSON resolves the request; json() throws UltraTonParseError with a cause', async () => {
            const res = await api.get('/malformed');
            assert.strictEqual(res.statusCode, 200);
            assert.throws(() => res.json(), (err: unknown) => {
                assert.ok(err instanceof UltraTonParseError);
                assert.ok(err.cause instanceof SyntaxError);
                assert.match(err.message, /Failed to parse JSON/);
                return true;
            });
        });

        it('json() strips __proto__, constructor and prototype keys at every depth', async () => {
            const parsed = (await api.get('/proto')).json() as any;
            assert.strictEqual(parsed.a, 1);
            assert.deepStrictEqual(Object.keys(parsed).sort(), ['a', 'n']);
            assert.deepStrictEqual(parsed.n, { b: 3 });
            assert.strictEqual(({} as any).polluted, undefined);
        });

        it('a body over 5 MB is retrievable as data and still parses with json()', async () => {
            const res = await api.get('/big');
            assert.ok(Buffer.isBuffer(res.data));
            assert.ok(res.data.length > 5 * 1024 * 1024);
            assert.strictEqual((res.json() as any).v.length, BIG_BYTES);
        });

        it('HEAD resolves with an empty data Buffer', async () => {
            const res = await api.head('/ok');
            assert.strictEqual(res.statusCode, 200);
            assert.strictEqual(res.ok, true);
            assert.ok(Buffer.isBuffer(res.data));
            assert.strictEqual(res.data.length, 0);
            assert.strictEqual(res.text(), '');
        });

        it('headers carry no pseudo-headers (keys starting with ":")', async () => {
            const res = await api.get('/ok');
            assert.strictEqual(res.headers[':status'], undefined);
            assert.deepStrictEqual(Object.keys(res.headers).filter((k) => k.startsWith(':')), []);
            assert.strictEqual(res.headers['content-type'], 'application/json');
            const head = await api.head('/ok');
            assert.deepStrictEqual(Object.keys(head.headers).filter((k) => k.startsWith(':')), []);
        });
    });
}

describe('response headers named __proto__ are kept as data', () => {
    it('createResponse copies an own __proto__ key as an own property, prototype untouched', () => {
        // node:http2 hands headers over on a null-prototype object, where __proto__ is an ordinary key.
        const raw = Object.assign(Object.create(null), { ':status': 200, 'x-ok': '1' });
        Object.defineProperty(raw, '__proto__', { value: 'evil', enumerable: true, writable: true, configurable: true });
        const res = createResponse(200, raw, Buffer.alloc(0));
        assert.strictEqual(Object.getPrototypeOf(res.headers), Object.prototype);
        assert.ok(Object.hasOwn(res.headers, '__proto__'));
        assert.strictEqual(Object.getOwnPropertyDescriptor(res.headers, '__proto__')?.value, 'evil');
        assert.strictEqual(res.headers['x-ok'], '1');
        assert.strictEqual(res.headers[':status'], undefined);
    });

    it('headers named after other Object.prototype members are own data, prototype untouched', () => {
        const raw = Object.assign(Object.create(null), { constructor: 'c', toString: 't', hasOwnProperty: 'h', 'x-ok': '1' });
        const res = createResponse(200, raw, Buffer.alloc(0));
        for (const key of ['constructor', 'toString', 'hasOwnProperty']) {
            assert.ok(Object.hasOwn(res.headers, key), key);
            assert.strictEqual((res.headers as Record<string, unknown>)[key], key[0]);
        }
        assert.strictEqual(Object.getPrototypeOf(res.headers), Object.prototype);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(res.headers, 'x-ok'), true);
    });

    it('an object value (set-cookie style array) under __proto__ never becomes the prototype', () => {
        const raw = Object.create(null);
        Object.defineProperty(raw, '__proto__', { value: ['a', 'b'], enumerable: true, writable: true, configurable: true });
        const res = createResponse(200, raw, Buffer.alloc(0));
        assert.strictEqual(Object.getPrototypeOf(res.headers), Object.prototype);
        assert.deepStrictEqual(Object.getOwnPropertyDescriptor(res.headers, '__proto__')?.value, ['a', 'b']);
        assert.strictEqual((res.headers as any).length, undefined, 'not an array');
    });

    it('HTTP/2: a server header named __proto__ reaches the caller as data', async () => {
        const server = createServer();
        server.on('stream', (stream) => {
            const headers: Record<string, unknown> = { ':status': 200, 'x-ok': '1' };
            Object.defineProperty(headers, '__proto__', { value: 'evil', enumerable: true, writable: true, configurable: true });
            stream.respond(headers as any);
            stream.end('ok');
        });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const manager = new Http2SessionManager();
        const client = new UltraTonClient({ http2: true, [kSessionManager]: manager } as any);
        try {
            const res = await client.get(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`, { permitReservedIps: true });
            assert.strictEqual(Object.getPrototypeOf(res.headers), Object.prototype);
            assert.strictEqual(Object.getOwnPropertyDescriptor(res.headers, '__proto__')?.value, 'evil');
            assert.strictEqual(res.headers['x-ok'], '1');
        } finally {
            manager.closeAll();
            await new Promise<void>(r => server.close(() => r()));
        }
    });
});
