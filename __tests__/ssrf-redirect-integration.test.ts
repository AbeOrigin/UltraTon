import { describe, it, before, after } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { kTransport } from '../src/internal.ts';
import { SecureHttpError, UltraTonNetworkError } from '../src/errors.ts';

// Real sockets on purpose: Node skips the custom `lookup` for IP literals, so mocks cannot catch this class of bug.
describe('UltraTonClient - IP literal SSRF and auth redirect leaks (real sockets)', () => {
    let hits = 0;
    let lastAuth: string | undefined;
    let lastHost: string | undefined;
    let server: http.Server;
    let port = 0;

    before(async () => {
        server = http.createServer((req, res) => {
            hits++;
            lastAuth = req.headers.authorization;
            lastHost = req.headers.host;
            if (req.url === '/same-origin') {
                res.writeHead(302, { location: '/landing' });
                return res.end();
            }
            if (req.url?.startsWith('/cross-origin/')) {
                res.writeHead(302, { location: `http://127.0.0.1:${req.url.split('/')[2]}/landing` });
                return res.end();
            }
            res.end('INTERNAL');
        });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        port = (server.address() as AddressInfo).port;
    });

    after(() => server.close());

    for (const literal of ['http://127.0.0.1', 'http://2130706433', 'https://[::ffff:127.0.0.1]', 'https://[::127.0.0.1]']) {
        it(`Blocks reserved IP literal ${literal} by default without opening a connection`, async () => {
            hits = 0;
            await assert.rejects(
                new UltraTonClient().get(`${literal}:${port}/`),
                (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
            );
            assert.equal(hits, 0);
        });
    }

    it('Still reaches a reserved IP literal when permitReservedIps is true', async () => {
        const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true });
        assert.equal(res.text(), 'INTERNAL');
    });

    it('permitReservedIps: a CIDR allowlist reaches a reserved IP literal inside it', async () => {
        const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: ['127.0.0.0/8'] });
        assert.equal(res.text(), 'INTERNAL');
    });

    it('permitReservedIps: a CIDR allowlist that excludes the target blocks it without connecting', async () => {
        hits = 0;
        await assert.rejects(
            new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: ['10.0.0.0/8'] }),
            (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message) && !err.message.includes('127.0.0.1')
        );
        assert.equal(hits, 0);
    });

    it('permitReservedIps: an IPv6 allowlist entry (::/0) does not reach a native IPv4 reserved literal', async () => {
        hits = 0;
        for (const entry of ['::/0', '::ffff:0:0/96']) {
            await assert.rejects(
                new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: [entry] }),
                (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message),
                entry
            );
        }
        assert.equal(hits, 0);
    });

    // http is only accepted for localhost/127.0.0.1, so these use https: the literal is rejected before any connection.
    it('permitReservedIps: an IPv6 allowlist (::/0) does not reach an IPv4-embedding IPv6 literal, directly or by redirect', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        const mapped = `[::ffff:127.0.0.1]:${port}`;
        const redirector = http.createServer((_req, res) => { res.writeHead(302, { location: `https://${mapped}/landing` }); res.end(); });
        await new Promise<void>(r => redirector.listen(0, '127.0.0.1', r));
        const redirectorPort = (redirector.address() as AddressInfo).port;
        try {
            hits = 0;
            await assert.rejects(
                new UltraTonClient().get(`https://${mapped}/`, { permitReservedIps: ['::/0'] }),
                (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
            );
            await assert.rejects(
                new UltraTonClient().get(`http://localhost:${redirectorPort}/`, { maxRedirects: 1, permitReservedIps: ['localhost', '::/0'] }),
                (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
            );
            assert.equal(hits, 0);
        } finally {
            redirector.close();
        }
    });

    it('permitReservedIps: an IPv4 allowlist reaches the IPv6 literal that embeds an address it covers', async () => {
        // The literal check passes; the https handshake then fails against the plain-http fixture, which is not a policy error.
        await assert.rejects(
            new UltraTonClient().get(`https://[::ffff:127.0.0.1]:${port}/`, { permitReservedIps: ['127.0.0.0/8'], timeoutMs: 2000 }),
            (err: unknown) => !(err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message))
        );
    });

    it('permitReservedIps: a hostname entry lets that host through, but a redirect to a reserved IP literal is still blocked', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        const other = http.createServer((_req, res) => { hits++; res.end('OTHER'); });
        await new Promise<void>(r => other.listen(0, '127.0.0.1', r));
        const otherPort = (other.address() as AddressInfo).port;
        try {
            const reached = await new UltraTonClient().get(`http://localhost:${port}/`, { permitReservedIps: ['localhost'] });
            assert.equal(reached.text(), 'INTERNAL');

            hits = 0;
            await assert.rejects(
                new UltraTonClient().get(`http://localhost:${port}/cross-origin/${otherPort}`, { maxRedirects: 1, permitReservedIps: ['localhost'] }),
                (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
            );
            // Only the first hop reached a server; the redirected-to literal was never contacted.
            assert.equal(hits, 1);
        } finally {
            other.close();
        }
    });

    it('permitReservedIps: a hostname entry does not cover a different hostname resolving to a reserved IP', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        hits = 0;
        await assert.rejects(
            new UltraTonClient().get(`https://rebound.example:${port}/`, { permitReservedIps: ['localhost'] }),
            (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message) && !/rebound/.test(err.message)
        );
        assert.equal(hits, 0);
    });

    it('Keeps the auth option on a same-origin redirect', async () => {
        await new UltraTonClient().get(`http://127.0.0.1:${port}/same-origin`, { auth: 'user:secret', maxRedirects: 1, permitReservedIps: true });
        assert.equal(lastAuth, `Basic ${Buffer.from('user:secret').toString('base64')}`);
    });

    it('Drops the auth option on a cross-origin redirect', async () => {
        const other = http.createServer((req, res) => { lastAuth = req.headers.authorization; res.end('OTHER'); });
        await new Promise<void>(r => other.listen(0, '127.0.0.1', r));
        const otherPort = (other.address() as AddressInfo).port;
        try {
            lastAuth = 'unset';
            const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/cross-origin/${otherPort}`, { auth: 'user:secret', maxRedirects: 1, permitReservedIps: true });
            assert.equal(res.text(), 'OTHER');
            assert.equal(lastAuth, undefined);
        } finally {
            other.close();
        }
    });

    it('drops a caller host header on cross-origin redirects', async () => {
        let hostSeenByB: string | undefined;
        const other = http.createServer((req, res) => { hostSeenByB = req.headers.host; res.end('OTHER'); });
        await new Promise<void>(r => other.listen(0, '127.0.0.1', r));
        const otherPort = (other.address() as AddressInfo).port;
        try {
            const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/cross-origin/${otherPort}`, {
                headers: { Host: 'attacker.example' },
                maxRedirects: 1,
                permitReservedIps: true
            });
            assert.equal(res.text(), 'OTHER');
            // HTTP/1 still honours a custom Host on the first hop...
            assert.equal(lastHost, 'attacker.example');
            // ...but it must not follow the request to another origin.
            assert.equal(hostSeenByB, `127.0.0.1:${otherPort}`);
        } finally {
            other.close();
        }
    });

    it('Keeps auth dropped after returning to the original origin (A→B→A)', async () => {
        const authSeenByB: Array<string | undefined> = [];
        const other = http.createServer((req, res) => {
            authSeenByB.push(req.headers.authorization);
            res.writeHead(302, { location: `http://127.0.0.1:${port}/landing` });
            res.end();
        });
        await new Promise<void>(r => other.listen(0, '127.0.0.1', r));
        const otherPort = (other.address() as AddressInfo).port;
        try {
            lastAuth = 'unset';
            const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/cross-origin/${otherPort}`, { auth: 'user:secret', maxRedirects: 2, permitReservedIps: true });
            assert.equal(res.text(), 'INTERNAL');
            assert.deepEqual(authSeenByB, [undefined]);
            assert.equal(lastAuth, undefined);
        } finally {
            other.close();
        }
    });
});

// The SSRF check lives in the custom `lookup`, which Node only calls when it opens a NEW socket. A pooled keep-alive socket
// therefore skips the check, so sockets must never be shared between requests that carry different reserved-IP policies.
describe('UltraTonClient - HTTP/1 keep-alive pools are isolated per reserved-IP policy (real sockets)', () => {
    // One server per test: the keep-alive agents are module-level, so a shared port would leak pooled sockets between tests.
    async function startCountingServer(t: TestContext) {
        const server = http.createServer((_req, res) => { res.end('INTERNAL'); });
        let connections = 0;
        server.on('connection', () => { connections++; });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        // Free keep-alive sockets are unref'd client-side; closing the server side ends them so nothing outlives the test.
        t.after(() => { server.closeAllConnections(); server.close(); });
        return { port: (server.address() as AddressInfo).port, connections: () => connections };
    }

    const reservedBlocked = (err: unknown) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message);

    it('never reuses a keep-alive socket across reserved-IP policies', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        const { port, connections } = await startCountingServer(t);
        const client = new UltraTonClient();
        const url = `http://localhost:${port}/`;

        // (A) default-deny is rejected by the lookup before any connection.
        await assert.rejects(client.get(url), reservedBlocked);
        assert.equal(connections(), 0);

        // (B) permitReservedIps: true connects, and the socket goes back to the pool.
        const allowed = await client.get(url, { permitReservedIps: true });
        assert.equal(allowed.text(), 'INTERNAL');
        assert.equal(connections(), 1);

        // (C) the identical default-deny request must NOT ride (B)'s pooled socket.
        await assert.rejects(client.get(url), reservedBlocked);
        assert.equal(connections(), 1);
    });

    it('gives each distinct allowlist its own keep-alive pool', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        const { port, connections } = await startCountingServer(t);
        const client = new UltraTonClient();
        const url = `http://localhost:${port}/`;

        await client.get(url, { permitReservedIps: ['127.0.0.0/8'] });
        assert.equal(connections(), 1);

        await client.get(url, { permitReservedIps: ['127.0.0.0/8', '10.0.0.0/8'] });
        assert.equal(connections(), 2);
    });

    it('still reuses the keep-alive socket within one policy, however its allowlist is ordered or cased', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '127.0.0.1', family: 4 }));
        const { port, connections } = await startCountingServer(t);
        const client = new UltraTonClient();
        const url = `http://localhost:${port}/`;

        await client.get(url, { permitReservedIps: ['127.0.0.0/8', 'Localhost'] });
        await client.get(url, { permitReservedIps: ['localhost', '127.0.0.0/8'] });
        assert.equal(connections(), 1);
    });

    // Parity with Node's global agent (keepAlive, 5s idle timeout): without the timeout an idle pooled socket lives until
    // the server closes it, so a hostile server reached through N hostnames pins N file descriptors.
    it('hands each protocol its own keep-alive agent with the 5s idle timeout', async () => {
        const agents: unknown[] = [];
        const transport = ((_url: URL, options: { agent?: unknown }) => {
            agents.push(options.agent);
            const req = new EventEmitter() as EventEmitter & Record<string, unknown>;
            req.write = () => {};
            req.destroy = () => {};
            req.end = () => {
                const res = Object.assign(Readable.from([Buffer.from('{}')]), { statusCode: 200, headers: {} });
                req.emit('response', res);
            };
            return req;
        }) as unknown as typeof http.request;
        const client = new UltraTonClient({ [kTransport]: transport } as any);

        await client.get('http://localhost/');
        await client.get('https://example.com/');

        const [httpAgent, httpsAgent] = agents as [http.Agent, https.Agent];
        assert.ok(httpAgent instanceof http.Agent && !(httpAgent instanceof https.Agent), 'http URL gets an http.Agent');
        assert.ok(httpsAgent instanceof https.Agent, 'https URL gets an https.Agent');
        for (const agent of [httpAgent, httpsAgent]) {
            const { keepAlive, timeout } = (agent as unknown as { options: { keepAlive?: boolean, timeout?: number } }).options;
            assert.equal(keepAlive, true);
            assert.equal(timeout, 5000);
        }
    });
});

// Real sockets: the point is what Node itself reports (ECONNREFUSED, ECONNRESET, OpenSSL errors), and that none of it leaks.
describe('UltraTonClient - network errors are actionable and never echo addresses (real sockets)', () => {
    /** A port nothing listens on: bind an ephemeral one, then release it. */
    const closedPort = async (): Promise<number> => {
        const probe = net.createServer();
        await new Promise<void>(r => probe.listen(0, '127.0.0.1', r));
        const { port } = probe.address() as AddressInfo;
        await new Promise<void>(r => probe.close(() => r()));
        return port;
    };

    const assertNoAddress = (message: string, port: number) => {
        assert.ok(!message.includes('127.0.0.1'), `message leaks the IP: ${message}`);
        assert.ok(!message.includes(String(port)), `message leaks the port: ${message}`);
    };

    it('ECONNREFUSED on a closed port becomes UltraTonNetworkError with code and cause, without IP or port', async () => {
        const port = await closedPort();
        await assert.rejects(
            new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true }),
            (err: unknown) => {
                assert.ok(err instanceof UltraTonNetworkError);
                assert.ok(err instanceof SecureHttpError);
                assert.equal(err.name, 'UltraTonNetworkError');
                assert.equal(err.code, 'ECONNREFUSED');
                assert.equal((err.cause as NodeJS.ErrnoException).code, 'ECONNREFUSED');
                assert.equal(err.message, 'UltraTon: Connection failed (ECONNREFUSED).');
                assertNoAddress(err.message, port);
                return true;
            }
        );
    });

    it('ECONNRESET becomes UltraTonNetworkError carrying the original code', async () => {
        const server = net.createServer(socket => socket.destroy());
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const { port } = server.address() as AddressInfo;
        try {
            await assert.rejects(
                new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true }),
                (err: unknown) => {
                    assert.ok(err instanceof UltraTonNetworkError);
                    assert.equal(err.code, 'ECONNRESET');
                    assert.equal((err.cause as NodeJS.ErrnoException).code, 'ECONNRESET');
                    assertNoAddress(err.message, port);
                    return true;
                }
            );
        } finally {
            server.close();
        }
    });

    it('a TLS handshake against a plain-HTTP server becomes UltraTonNetworkError with a TLS message and no IP', async () => {
        const server = http.createServer((_req, res) => res.end('plain'));
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const { port } = server.address() as AddressInfo;
        try {
            await assert.rejects(
                new UltraTonClient().get(`https://127.0.0.1:${port}/`, { permitReservedIps: true }),
                (err: unknown) => {
                    assert.ok(err instanceof UltraTonNetworkError);
                    assert.match(err.message, /^UltraTon: TLS handshake failed \(.+\)\.$/);
                    assert.ok(err.code, 'keeps the original code');
                    assert.ok(err.cause instanceof Error, 'keeps the original error as cause');
                    assertNoAddress(err.message, port);
                    return true;
                }
            );
        } finally {
            server.close();
        }
    });

    it('does not wrap errors that are already SecureHttpError (reserved IP) nor a caller abort', async () => {
        await assert.rejects(
            new UltraTonClient().get('http://127.0.0.1:1/'),
            (err: unknown) => err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError) && /prohibited internal\/reserved/.test(err.message)
        );

        const hanging = http.createServer(() => { /* never answers */ });
        await new Promise<void>(r => hanging.listen(0, '127.0.0.1', r));
        const { port } = hanging.address() as AddressInfo;
        try {
            const controller = new AbortController();
            const pending = new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true, signal: controller.signal });
            setTimeout(() => controller.abort(), 50);
            await assert.rejects(pending, (err: unknown) => {
                assert.ok(!(err instanceof UltraTonNetworkError), 'abort must stay an AbortError');
                assert.equal((err as Error).name, 'AbortError');
                return true;
            });
        } finally {
            hanging.closeAllConnections();
            hanging.close();
        }
    });
});

describe('UltraTonClient - truncated and malformed responses are network errors, not TLS (real sockets)', () => {
    /** A raw TCP server that writes `payload` to every client and then ends with a clean FIN. */
    const rawServer = async (payload: string) => {
        const server = net.createServer(socket => {
            socket.on('error', () => {});
            socket.once('data', () => socket.end(payload));
        });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        return { server, port: (server.address() as AddressInfo).port };
    };

    it('a body cut short by a clean FIN rejects with UltraTonNetworkError carrying a code and cause', async () => {
        const { server, port } = await rawServer('HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nabc');
        try {
            await assert.rejects(
                new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true }),
                (err: unknown) => {
                    assert.ok(err instanceof UltraTonNetworkError);
                    assert.ok(err.code, 'has a code');
                    assert.ok(err.cause instanceof Error, 'keeps the original error as cause');
                    assert.ok(!err.message.includes('127.0.0.1') && !err.message.includes(String(port)));
                    return true;
                }
            );
        } finally {
            server.close();
        }
    });

    it('a garbage non-HTTP response is not labelled a TLS failure', async () => {
        const { server, port } = await rawServer('this is not http\r\n\r\n');
        try {
            await assert.rejects(
                new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: true }),
                (err: unknown) => {
                    assert.ok(err instanceof UltraTonNetworkError);
                    assert.match(err.message, /^UltraTon: Connection failed \(.+\)\.$/);
                    assert.doesNotMatch(err.message, /TLS/);
                    return true;
                }
            );
        } finally {
            server.close();
        }
    });
});
