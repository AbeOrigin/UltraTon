import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError } from '../src/errors.ts';

// Real sockets on purpose: Node skips the custom `lookup` for IP literals, so mocks cannot catch this class of bug.
describe('UltraTonClient - IP literal SSRF and auth redirect leaks (real sockets)', () => {
    let hits = 0;
    let lastAuth: string | undefined;
    let server: http.Server;
    let port = 0;

    before(async () => {
        server = http.createServer((req, res) => {
            hits++;
            lastAuth = req.headers.authorization;
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
