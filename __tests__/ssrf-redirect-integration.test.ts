import { describe, it, before, after } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import dnsPromises from 'node:dns/promises';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError } from '../src/errors.ts';

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
        assert.equal((res.body as Buffer).toString(), 'INTERNAL');
    });

    it('permitReservedIps: a CIDR allowlist reaches a reserved IP literal inside it', async () => {
        const res = await new UltraTonClient().get(`http://127.0.0.1:${port}/`, { permitReservedIps: ['127.0.0.0/8'] });
        assert.equal((res.body as Buffer).toString(), 'INTERNAL');
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
            assert.equal((reached.body as Buffer).toString(), 'INTERNAL');

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
            assert.equal((res.body as Buffer).toString(), 'OTHER');
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
            assert.equal((res.body as Buffer).toString(), 'OTHER');
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
            assert.equal((res.body as Buffer).toString(), 'INTERNAL');
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
        assert.equal((allowed.body as Buffer).toString(), 'INTERNAL');
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
});
