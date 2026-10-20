/**
 * The single public client: constructor defaults merged per request, the default user-agent, `baseUrl` that cannot be
 * escaped, `http2: true`, `tls` (ca/cert/key only), per-client pools and `close()`. Real loopback sockets throughout:
 * what the server receives, and how many connections it sees, is the contract.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { constants as h2constants, createSecureServer, createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonNetworkError, UltraTonNetworkTimeoutError } from '../src/errors.ts';
import { VERSION } from '../src/constants.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CA = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

type Echo = { method: string; path: string; headers: Record<string, string | undefined> };

interface Fixture {
    base: string;
    /** Paths the server started answering, in order. */
    seen(): string[];
    /** Connections the server accepted so far. */
    accepted(): number;
    /** Connections the server still holds open. */
    open(): number;
}

/**
 * Answers every request with its method, path and headers as JSON; `/slow/<ms>` answers after that many ms.
 * Special routes (both engines): `/partial` declares content-length 100, sends 7 bytes and hangs; `/short` declares
 * content-length 20, sends 7 bytes and ends; `/not-modified` is a 304 and `/head-length` (for HEAD) a 200, both
 * declaring content-length 20 with no body, as HTTP allows.
 */
const respond = (path: string, send: () => void) => {
    const slow = /^\/slow\/(\d+)/.exec(path);
    if (slow) setTimeout(send, Math.min(Number(slow[1]), 60_000));
    else send();
};

function track(server: http.Server | ReturnType<typeof createH2Server>, t: TestContext) {
    let accepted = 0;
    const sockets = new Set<Socket>();
    server.on('connection', (s: Socket) => {
        accepted++;
        sockets.add(s);
        s.on('close', () => sockets.delete(s));
    });
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { accepted: () => accepted, open: () => sockets.size };
}

async function startHttp1(t: TestContext): Promise<Fixture> {
    const seen: string[] = [];
    const server = http.createServer((req, res) => {
        req.resume();
        req.on('end', () => respond(req.url ?? '/', () => {
            seen.push(req.url ?? '/');
            if (req.url === '/partial' || req.url === '/short') {
                res.writeHead(200, { 'content-length': req.url === '/partial' ? '100' : '20' });
                res.write('partial');
                if (req.url === '/short') res.socket?.end();
                return;
            }
            if (req.url === '/not-modified' || req.url === '/head-length') {
                res.writeHead(req.url === '/not-modified' ? 304 : 200, { 'content-length': '20' });
                res.end();
                return;
            }
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ method: req.method, path: req.url, headers: req.headers }));
        }));
    });
    const counters = track(server, t);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen: () => seen, ...counters };
}

async function startHttp2(t: TestContext): Promise<Fixture> {
    const seen: string[] = [];
    const server = createH2Server();
    server.on('stream', (stream, headers: IncomingHttpHeaders) => {
        stream.resume();
        stream.on('end', () => respond(String(headers[':path']), () => {
            if (stream.closed) return;
            const path = String(headers[':path']);
            seen.push(path);
            if (path === '/partial' || path === '/short') {
                stream.respond({ ':status': 200, 'content-length': path === '/partial' ? '100' : '20' });
                stream.write('partial');
                if (path === '/short') stream.end();
                return;
            }
            if (path === '/goaway') {
                // A graceful GOAWAY that covers this stream: the server promises to finish it, then does.
                stream.respond({ ':status': 200, 'content-length': '20' });
                stream.write('partial');
                stream.session?.goaway(h2constants.NGHTTP2_NO_ERROR, stream.id);
                setTimeout(() => stream.end('-and-the-rest'), 50);
                return;
            }
            if (path === '/not-modified' || path === '/head-length') {
                stream.respond({ ':status': path === '/not-modified' ? 304 : 200, 'content-length': '20' }, { endStream: true });
                return;
            }
            stream.respond({ ':status': 200, 'content-type': 'application/json' });
            stream.end(JSON.stringify({ method: headers[':method'], path: headers[':path'], headers }));
        }));
    });
    const counters = track(server, t);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen: () => seen, ...counters };
}

/** A client that is always closed when the test ends, so no pooled socket outlives it. */
function clientFor(t: TestContext, options?: ConstructorParameters<typeof UltraTonClient>[0]): UltraTonClient {
    const client = new UltraTonClient(options);
    t.after(() => client.close());
    return client;
}

async function until(condition: () => boolean, ms = 2000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('condition not met in time');
        await new Promise(r => setTimeout(r, 10));
    }
}

const engines: Array<[string, boolean, (t: TestContext) => Promise<Fixture>]> = [
    ['HTTP/1', false, startHttp1],
    ['HTTP/2 (h2c)', true, startHttp2],
];

describe('VERSION', () => {
    it('equals package.json version', () => {
        const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
        assert.equal(VERSION, pkg.version);
    });
});

for (const [name, http2, start] of engines) {
    describe(`UltraTonClient facade over ${name}`, () => {
        it('sends the constructor headers; a request header (any case) overrides them', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, headers: { 'X-Team': 'core', 'x-keep': 'yes' } });

            const plain = (await client.get(`${f.base}/a`)).json<Echo>();
            assert.equal(plain.headers['x-team'], 'core');
            assert.equal(plain.headers['x-keep'], 'yes');

            const overridden = (await client.get(`${f.base}/b`, { headers: { 'x-TEAM': 'edge' } })).json<Echo>();
            assert.equal(overridden.headers['x-team'], 'edge');
            assert.equal(overridden.headers['x-keep'], 'yes');
        });

        it('applies the constructor timeoutMs; a request timeoutMs overrides it', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, timeoutMs: 150 });

            const started = Date.now();
            await assert.rejects(client.get(`${f.base}/slow/600`), UltraTonNetworkTimeoutError);
            assert.ok(Date.now() - started < 550, 'the client default bounded the request');

            const res = await client.get(`${f.base}/slow/300`, { timeoutMs: 3000 });
            assert.equal(res.statusCode, 200);
        });

        it(`sends user-agent ultraton/${VERSION} by default; userAgent and a request header replace it`, async (t) => {
            const f = await start(t);
            const plain = clientFor(t, { http2, permitReservedIps: true });
            assert.equal((await plain.get(`${f.base}/`)).json<Echo>().headers['user-agent'], `ultraton/${VERSION}`);

            const custom = clientFor(t, { http2, permitReservedIps: true, userAgent: 'my-app/2.1' });
            assert.equal((await custom.get(`${f.base}/`)).json<Echo>().headers['user-agent'], 'my-app/2.1');

            const perRequest = await custom.get(`${f.base}/`, { headers: { 'User-Agent': 'one-off/1' } });
            assert.equal(perRequest.json<Echo>().headers['user-agent'], 'one-off/1');

            const viaHeaders = clientFor(t, { http2, permitReservedIps: true, headers: { 'User-Agent': 'hdr/1' } });
            assert.equal((await viaHeaders.get(`${f.base}/`)).json<Echo>().headers['user-agent'], 'hdr/1');
        });

        it('resolves relative paths against baseUrl (leading slash or not, query kept)', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, baseUrl: `${f.base}/api/v1` });

            assert.equal((await client.get('users?page=2')).json<Echo>().path, '/api/v1/users?page=2');
            assert.equal((await client.get('/users/7')).json<Echo>().path, '/api/v1/users/7');
            assert.equal((await client.get('')).json<Echo>().path, '/api/v1/');
        });

        it('rejects every path that would leave baseUrl, before connecting', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, baseUrl: `${f.base}/api/v1/` });
            const RELATIVE = /^UltraTon: With baseUrl set, request paths must be relative\.$/;
            const ESCAPES = /^UltraTon: Request path escapes baseUrl\.$/;

            const notRelative = [
                'https://evil.com/x',
                `${f.base}/api/v1/users`, // absolute even when it points inside the base
                '//evil.com',
                '//evil.com/api/v1/x',
                '\\\\evil.com',
                '/\\evil.com',
                '\\/evil.com',
                ' //evil.com',
                '\t//evil.com',
                '/\t/evil.com',
                'javascript:alert(1)',
                'mailto:a@b.c',
            ];
            for (const path of notRelative) {
                await assert.rejects(client.get(path), (err: Error) => {
                    assert.ok(err instanceof TypeError, `${JSON.stringify(path)} -> ${err.message}`);
                    assert.match(err.message, RELATIVE);
                    return true;
                });
            }

            const escapes = [
                '../admin',
                '/../admin',
                'users/../../admin',
                '..',
                '%2e%2e/admin',
                '.%2E/admin',
                '%2e./admin',
                '..\\admin',
                '../v1-admin/x', // a sibling that shares the prefix 'v1'
                './../../x',
            ];
            for (const path of escapes) {
                await assert.rejects(client.get(path), (err: Error) => {
                    assert.ok(err instanceof TypeError, `${JSON.stringify(path)} -> ${err.message}`);
                    assert.match(err.message, ESCAPES);
                    return true;
                });
            }

            assert.equal(f.accepted(), 0);
        });

        it('judges a path with a long inner run of controls in linear time', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, baseUrl: `${f.base}/api/v1/` });
            // A trailing-whitespace regex retried from every position took ~10 s on this input.
            const path = `//evil.com${'\u0000'.repeat(200_000)}x`;
            const started = performance.now();
            await assert.rejects(client.get(path), TypeError);
            assert.ok(performance.now() - started < 1000, `took ${Math.round(performance.now() - started)} ms`);
        });

        it('two clients never share a socket or session, even under the same permitReservedIps policy', async (t) => {
            const f = await start(t);
            const permissive = clientFor(t, { http2, permitReservedIps: true });
            const strict = clientFor(t, { http2 });

            await permissive.get(`${f.base}/1`);
            await permissive.get(`${f.base}/2`);
            assert.equal(f.accepted(), 1, 'one client reuses its own pooled connection');

            await strict.get(`${f.base}/3`, { permitReservedIps: true });
            assert.equal(f.accepted(), 2, 'another client opens its own connection');

            // The strict client's default policy still applies: the permissive client's pool is not reachable.
            await assert.rejects(strict.get(`${f.base}/4`), SecureHttpError);
            assert.equal(f.accepted(), 2);
        });

        it('close() releases every pooled connection and later requests throw "Client is closed"', async (t) => {
            const f = await start(t);
            const client = new UltraTonClient({ http2, permitReservedIps: true });

            await client.get(`${f.base}/1`);
            assert.equal(f.open(), 1);

            await client.close();
            await until(() => f.open() === 0);
            await client.close(); // idempotent

            await assert.rejects(client.get(`${f.base}/2`), (err: Error) => {
                assert.ok(err instanceof SecureHttpError);
                assert.equal(err.message, 'UltraTon: Client is closed.');
                return true;
            });
            assert.equal(f.accepted(), 1);
        });

        it('a request in flight when close() runs rejects with "Client is closed", not a network error', async (t) => {
            const f = await start(t);
            const client = new UltraTonClient({ http2, permitReservedIps: true });

            const pending = client.get(`${f.base}/slow/1000`);
            await until(() => f.accepted() === 1);
            await new Promise(r => setTimeout(r, 50)); // let the request reach the server
            await client.close();

            await assert.rejects(pending, (err: Error) => {
                assert.ok(err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError), `${err.name}: ${err.message}`);
                assert.equal(err.message, 'UltraTon: Client is closed.');
                return true;
            });
        });

        it('close() while the body is still arriving rejects with "Client is closed", never a truncated success', async (t) => {
            const f = await start(t);
            const client = new UltraTonClient({ http2, permitReservedIps: true });

            const pending = client.get(`${f.base}/partial`);
            await until(() => f.seen().includes('/partial'));
            await new Promise(r => setTimeout(r, 50)); // headers and the first 7 bytes reach the client
            await client.close();

            await assert.rejects(pending, (err: Error) => {
                assert.ok(err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError), `${err.name}: ${err.message}`);
                assert.equal(err.message, 'UltraTon: Client is closed.');
                return true;
            });
        });

        it('a body shorter than its content-length rejects as a reset connection', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true });
            await assert.rejects(client.get(`${f.base}/short`), (err: Error & { code?: string }) => {
                assert.ok(err instanceof UltraTonNetworkError, `${err.name}: ${err.message}`);
                assert.equal(err.message, 'UltraTon: Connection failed (ECONNRESET).');
                assert.equal(err.code, 'ECONNRESET');
                return true;
            });
        });

        it('HEAD and 304 declaring a content-length without a body still resolve', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true });
            const head = await client.head(`${f.base}/head-length`);
            assert.equal(head.statusCode, 200);
            assert.equal(head.data.length, 0);
            const notModified = await client.get(`${f.base}/not-modified`);
            assert.equal(notModified.statusCode, 304);
            assert.equal(notModified.data.length, 0);
        });

        it('options that are not plain objects throw instead of being silently stripped', async (t) => {
            const f = await start(t);
            class ClientOpts { get http2() { return true; } }
            assert.throws(() => new UltraTonClient(new ClientOpts() as any), { name: 'TypeError', message: 'UltraTon: Options must be a plain object.' });
            assert.throws(() => new UltraTonClient(Object.create({ http2 }) as any), { name: 'TypeError', message: 'UltraTon: Options must be a plain object.' });
            assert.throws(() => new UltraTonClient({ tls: new (class { ca = CA })() } as any), { name: 'TypeError', message: 'UltraTon: Options must be a plain object.' });

            // A null-prototype object is plain.
            const client = clientFor(t, Object.assign(Object.create(null), { http2, permitReservedIps: true }));
            class RequestOpts { permitReservedIps = true; }
            await assert.rejects(client.get(`${f.base}/`, new RequestOpts() as any), { name: 'TypeError', message: 'UltraTon: Options must be a plain object.' });
            assert.equal((await client.get(`${f.base}/ok`, Object.assign(Object.create(null), { timeoutMs: 2000 }))).statusCode, 200);
            assert.deepEqual(f.seen(), ['/ok']);
        });

        it('rejects percent-encoded and ;-param traversal under baseUrl; encoded slashes inside a segment still work', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, baseUrl: `${f.base}/api/v1/` });

            const traversals = [
                '..%2fadmin', '..%2F..%2Fadmin', '%2e%2e%2fadmin', '%2e%2E%2fadmin', '..%5cadmin', '..;/admin',
                'x/..;jsessionid=1/..;/admin', '.;/admin', 'a/%2e%2e%2f%2e%2e%2fadmin',
                // double (and deeper) encoding
                '%252e%252e%252fadmin', '%25252e%25252e%25252fadmin', '%252e%252e%252f%25admin',
                // unicode lookalikes: fullwidth dot, two-dot leader, fullwidth slash, division slash, small reverse solidus, reverse solidus operator
                '\uFF0E\uFF0E/admin', '\u2025/admin', '..\uFF0Fadmin', '..\u2215admin', '..\uFE68admin', '..\u29F5admin',
                // trailing junk a lenient server trims
                '..%00/admin', '..%20/admin', '..%09/admin', '...%2fadmin', '.. ./admin', '..%2e%20/admin', '..%7f/admin',
                // an encoded query or fragment ends the segment for some servers
                '..%3f/admin', '..%23', '..%3fx=1/admin',
                // a later decoding pass that is not UTF-8: double-encoded overlong dots, a lone continuation byte
                '%25c0%25ae%25c0%25ae/admin', '%25c0%25ae%25c0%25ae%252fadmin', 'x/%25ff/y',
            ];
            for (const path of traversals) {
                await assert.rejects(client.get(path), (err: Error) => {
                    assert.ok(err instanceof TypeError, `${JSON.stringify(path)} -> ${err.message}`);
                    assert.equal(err.message, 'UltraTon: Request path escapes baseUrl.');
                    return true;
                });
            }
            await assert.rejects(client.get('bad%zzencoding'), { name: 'TypeError', message: 'UltraTon: Request path has malformed percent-encoding.' });
            // Still decoding after 5 passes: refused rather than guessed.
            await assert.rejects(client.get('%25252525252e%25252525252e/admin'), { name: 'TypeError', message: 'UltraTon: Request path escapes baseUrl.' });
            assert.equal(f.accepted(), 0);

            assert.equal((await client.get('group%2Fproject/issues')).json<Echo>().path, '/api/v1/group%2Fproject/issues');
            assert.equal((await client.get('a/b/c;v=1')).json<Echo>().path, '/api/v1/a/b/c;v=1');
            assert.equal((await client.get('.well-known/x')).json<Echo>().path, '/api/v1/.well-known/x');
            assert.equal((await client.get('files/...')).json<Echo>().path, '/api/v1/files/...');
            assert.equal((await client.get('100%25')).json<Echo>().path, '/api/v1/100%25');
            assert.equal((await client.get('100%25%25x')).json<Echo>().path, '/api/v1/100%25%25x');
            // A later pass that is valid UTF-8 still decodes (and is judged) normally.
            assert.equal((await client.get('caf%25C3%25A9')).json<Echo>().path, '/api/v1/caf%25C3%25A9');
            assert.equal((await client.get('a..b/c.d./..e')).json<Echo>().path, '/api/v1/a..b/c.d./..e');
        });

        it('a null request option throws instead of taking the client default', async (t) => {
            const f = await start(t);
            const client = clientFor(t, { http2, permitReservedIps: true, timeoutMs: 1000, maxBodySize: 1000 });

            await assert.rejects(client.get(`${f.base}/`, { permitReservedIps: null as any }), /^TypeError: UltraTon: Expected 'permitReservedIps' to be a boolean/);
            await assert.rejects(client.get(`${f.base}/`, { timeoutMs: null as any }), /^TypeError: UltraTon: Expected 'timeoutMs' to be a number/);
            await assert.rejects(client.get(`${f.base}/`, { maxBodySize: null as any }), /^TypeError: UltraTon: Expected 'maxBodySize' to be a number/);
            assert.equal(f.accepted(), 0);
        });

        it('options inherited from Object.prototype are ignored (constructor and request)', async (t) => {
            const f = await start(t);
            const proto = Object.prototype as Record<string, unknown>;
            proto.baseUrl = 'https://evil.example/';
            proto.permitReservedIps = true;
            try {
                const client = clientFor(t, { http2 });
                // No baseUrl crept in (an absolute URL is still accepted) and the default policy still blocks loopback.
                await assert.rejects(client.get(`${f.base}/`), (err: Error) => {
                    assert.ok(err instanceof SecureHttpError, `${err.name}: ${err.message}`);
                    assert.match(err.message, /prohibited internal\/reserved/);
                    return true;
                });
                await assert.rejects(client.get(`${f.base}/`, {}), /prohibited internal\/reserved/);
                assert.equal(f.accepted(), 0);
            } finally {
                delete proto.baseUrl;
                delete proto.permitReservedIps;
            }
        });
    });
}

describe('UltraTonClient http2: true', () => {
    it('speaks HTTP/2 to the h2c fixture', async (t) => {
        let streams = 0;
        const server = createH2Server();
        server.on('stream', (stream) => {
            streams++;
            stream.respond({ ':status': 200 });
            stream.end('h2');
        });
        track(server, t);
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));

        const client = clientFor(t, { http2: true, permitReservedIps: true });
        const res = await client.get(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`);
        assert.equal(res.text(), 'h2');
        assert.equal(streams, 1);
    });

    it('a graceful GOAWAY drains the in-flight stream (no truncated success) and the next request opens a new session', async (t) => {
        const f = await startHttp2(t);
        const client = clientFor(t, { http2: true, permitReservedIps: true });

        const res = await client.get(`${f.base}/goaway`);
        assert.equal(res.statusCode, 200);
        assert.equal(res.text(), 'partial-and-the-rest');

        assert.equal((await client.get(`${f.base}/after`)).statusCode, 200);
        assert.equal(f.accepted(), 2, 'the session that got GOAWAY left the pool');
    });
});

describe('UltraTonClient tls', () => {
    async function startTls(t: TestContext, h2: boolean): Promise<string> {
        const server = h2
            ? createSecureServer({ cert: CA, key: KEY }, (_req, res) => res.end('tls-ok'))
            : https.createServer({ cert: CA, key: KEY }, (_req, res) => res.end('tls-ok'));
        track(server as http.Server, t);
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        return `https://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    }

    for (const http2 of [false, true]) {
        const label = http2 ? 'HTTP/2' : 'HTTP/1';

        it(`${label}: a self-signed server works with tls: { ca }`, async (t) => {
            const url = await startTls(t, http2);
            const client = clientFor(t, { http2, permitReservedIps: true, tls: { ca: CA } });
            const res = await client.get(url);
            assert.equal(res.statusCode, 200);
            assert.equal(res.text(), 'tls-ok');
        });

        it(`${label}: with tls.ca set, a host the certificate does not name is still rejected`, async (t) => {
            // 127.0.0.2 is loopback but not in the fixture's SAN (localhost, 127.0.0.1, ::1).
            const server = http2
                ? createSecureServer({ cert: CA, key: KEY }, (_req, res) => res.end('tls-ok'))
                : https.createServer({ cert: CA, key: KEY }, (_req, res) => res.end('tls-ok'));
            track(server as http.Server, t);
            await new Promise<void>(r => server.listen(0, '127.0.0.2', r));
            const url = `https://127.0.0.2:${(server.address() as AddressInfo).port}/`;

            const client = clientFor(t, { http2, permitReservedIps: true, tls: { ca: CA } });
            await assert.rejects(client.get(url), (err: Error) => {
                assert.ok(err instanceof UltraTonNetworkError, `${err.name}: ${err.message}`);
                assert.equal(err.message, 'UltraTon: TLS handshake failed (ERR_TLS_CERT_ALTNAME_INVALID).');
                return true;
            });
        });

        it(`${label}: another client's tls never applies (the self-signed cert is rejected)`, async (t) => {
            const url = await startTls(t, http2);
            const trusting = clientFor(t, { http2, permitReservedIps: true, tls: { ca: [CA.toString()] } });
            await trusting.get(url);

            const plain = clientFor(t, { http2, permitReservedIps: true });
            await assert.rejects(plain.get(url), (err: Error) => {
                assert.ok(err instanceof UltraTonNetworkError);
                assert.match(err.message, /^UltraTon: TLS handshake failed \(/);
                return true;
            });
        });
    }
});

describe('UltraTonClient constructor validation', () => {
    const rejects = (options: unknown, message: RegExp) =>
        assert.throws(() => new UltraTonClient(options as any), (err: Error) => {
            assert.ok(err instanceof TypeError, `${err.name}: ${err.message}`);
            assert.match(err.message, message);
            return true;
        });

    it('accepts no options, an empty object and every documented key together', () => {
        new UltraTonClient();
        new UltraTonClient({});
        new UltraTonClient({
            baseUrl: 'https://api.example.com/v1',
            headers: { 'x-a': '1', 'x-b': ['2', '3'] },
            timeoutMs: 1000,
            socketTimeoutMs: 500,
            maxBodySize: 1024,
            maxRedirects: 3,
            permitReservedIps: ['10.0.0.0/8'],
            http2: false,
            tls: { ca: CA, cert: CA.toString(), key: [KEY] },
            userAgent: 'x/1',
        });
    });

    it('tls accepts only ca, cert and key; rejectUnauthorized is never accepted', () => {
        rejects({ tls: { rejectUnauthorized: false } }, /^UltraTon: Unknown tls option 'rejectUnauthorized'\. Disabling certificate verification is not supported/);
        rejects({ tls: { rejectUnauthorized: true } }, /'rejectUnauthorized'/);
        rejects({ tls: { servername: 'evil.com' } }, /^UltraTon: Unknown tls option 'servername'\. Valid tls options: ca, cert, key\.$/);
        rejects({ tls: { checkServerIdentity: () => undefined } }, /Unknown tls option 'checkServerIdentity'/);
        rejects({ tls: { ca: 123 } }, /^UltraTon: Expected 'tls\.ca' to be a string, Buffer or an array of them/);
        rejects({ tls: { cert: [CA, 1] } }, /'tls\.cert'/);
        rejects({ tls: 'ca.pem' }, /^UltraTon: Expected 'tls' to be a object/);
    });

    it('unknown constructor options throw with a hint', () => {
        rejects({ timeout: 10 }, /^UltraTon: Unknown option 'timeout'\. Use 'timeoutMs' \(milliseconds\)\.$/);
        rejects({ baseURL: 'https://x.com' }, /^UltraTon: Unknown option 'baseURL'\. Use 'baseUrl'\.$/);
        rejects({ rejectUnauthorized: false }, /^UltraTon: Unknown option 'rejectUnauthorized'\. Disabling certificate verification is not supported/);
        rejects({ ca: CA }, /Unknown option 'ca'\. Pass it as tls: \{ ca \}\.$/);
        rejects({ signal: AbortSignal.timeout(1) }, /^UltraTon: Unknown option 'signal'\. 'signal' is a per-request option/);
        rejects({ json: {} }, /'json' is a per-request option/);
        rejects({ isolatePool: true }, /^UltraTon: Unknown option 'isolatePool'\. Every client has its own connection pool\.$/);
        rejects({ tlsSettings: {} }, /^UltraTon: Unknown option 'tlsSettings'\. Use 'tls' \(\{ ca, cert, key \}\)\.$/);
        rejects({ retries: 3 }, /^UltraTon: Unknown option 'retries'\. Valid options: baseUrl, headers, timeoutMs, socketTimeoutMs, maxBodySize, maxRedirects, permitReservedIps, http2, tls, userAgent\.$/);
        rejects({ whatever: undefined }, /Unknown option 'whatever'/);
    });

    it('validates value types like the per-request options', () => {
        rejects('https://x.com', /^UltraTon: Client options must be an object\.$/);
        rejects({ http2: 'yes' }, /^UltraTon: Expected 'http2' to be a boolean/);
        rejects({ timeoutMs: '100' }, /^UltraTon: Expected 'timeoutMs' to be a number/);
        rejects({ headers: { 'x-a': 'v\r\nx-b: 1' } }, /CRLF/);
        rejects({ headers: { ':authority': 'x' } }, /pseudo-header/);
        rejects({ permitReservedIps: ['not a cidr/99'] }, /Invalid permitReservedIps entry/);
        rejects({ userAgent: 7 }, /^UltraTon: Expected 'userAgent' to be a string/);
        rejects({ userAgent: 'a\r\nb' }, /CRLF/);
        rejects({ userAgent: 'a/1', headers: { 'User-Agent': 'b/1' } }, /^UltraTon: Set the user agent with either 'userAgent' or a 'user-agent' header, not both\.$/);
        rejects({ baseUrl: 42 }, /^UltraTon: Expected 'baseUrl' to be a string/);
    });

    it('validates baseUrl with parseSafeUrl and refuses a query or fragment', () => {
        const unsafe = (baseUrl: string, message: RegExp) =>
            assert.throws(() => new UltraTonClient({ baseUrl }), (err: Error) => {
                assert.ok(err instanceof SecureHttpError || err instanceof TypeError, err.message);
                assert.match(err.message, message);
                return true;
            });
        unsafe('ftp://example.com/', /Unsupported protocol/);
        unsafe('http://example.com/', /^UltraTon: Plain http is only allowed for loopback hosts; use https\.$/);
        unsafe('https://user:pw@example.com/', /Credentials in URL authority/);
        unsafe('not a url', /Invalid URL/);
        unsafe('https://example.com/v1?key=1', /^UltraTon: 'baseUrl' cannot contain a query string or fragment\.$/);
        unsafe('https://example.com/v1#x', /query string or fragment/);
    });

    it('without baseUrl a relative path is still an invalid URL', async () => {
        await assert.rejects(new UltraTonClient().get('/users'), { name: 'SecureHttpError', message: 'UltraTon: Invalid URL provided.' });
    });

    it('a permitReservedIps list cannot be widened by mutating it after construction', async (t) => {
        const f = await startHttp1(t);
        const list = ['10.0.0.0/8'];
        const client = clientFor(t, { permitReservedIps: list });
        list.push('127.0.0.0/8');
        await assert.rejects(client.get(`${f.base}/`), SecureHttpError);
        assert.equal(f.accepted(), 0);
    });

    it('per-request hints point constructor-only options at the constructor', async () => {
        const client = new UltraTonClient();
        await assert.rejects(client.get('https://example.com/', { baseUrl: 'https://x.com' } as any), /Unknown option 'baseUrl'\. 'baseUrl' is an option of the client constructor/);
        await assert.rejects(client.get('https://example.com/', { tls: {} } as any), /Unknown option 'tls'\. TLS is configured with the 'tls' option of the client constructor/);
        await assert.rejects(client.get('https://example.com/', { http2: true } as any), /Unknown option 'http2'\. 'http2' is an option of the client constructor/);
        await assert.rejects(client.get('https://example.com/', { userAgent: 'x' } as any), /Unknown option 'userAgent'\. Set a 'user-agent' header, or 'userAgent' in the client constructor/);
    });
});
