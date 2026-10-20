/**
 * Plain http for every loopback name, and only ever to loopback addresses, in both engines. Kept apart from
 * happy-eyeballs.test.ts on purpose: on Windows, under the full parallel run, a test file whose result stream outgrows
 * the runner's pipe blocks in a synchronous stdout write until the runner drains it, stalling its event loop for
 * seconds and failing whatever request is in flight. Helpers live in fixtures/net-fixtures.ts.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SecureHttpError } from '../src/errors.ts';
import { parseSafeUrl } from '../src/helpers/url-parser.ts';
import { isLoopbackIp } from '../src/security/dns-pinner.ts';
import { PLAIN_HTTP, RESERVED, clientFor, ipv6Available, mockDns, serve, v4, v6 } from './fixtures/net-fixtures.ts';

for (const http2 of [false, true]) {
    const engine = http2 ? 'HTTP/2' : 'HTTP/1';

    describe(`${engine}: plain http only ever reaches loopback addresses`, () => {
        for (const answer of [
            [v4('93.184.216.34')],
            [v4('127.0.0.1'), v4('93.184.216.34')],
            [v6('::1'), v6('2606:4700::1111')],
            [v4('127.0.0.1'), v4('10.0.0.1')],
        ]) {
            for (const permitReservedIps of [false, true]) {
                const label = `[${answer.map(a => a.address).join(', ')}], permitReservedIps: ${permitReservedIps}`;
                it(`http://api.localhost resolving to ${label} is rejected with 0 connections`, async (t) => {
                    const server = await serve(t, http2, '127.0.0.1');
                    mockDns(t, { 'api.localhost': answer });
                    const { client, opened } = clientFor(t, http2, { permitReservedIps });

                    await assert.rejects(
                        client.get(`http://api.localhost:${server.port}/`, { auth: 'user:secret', timeoutMs: 2000 }),
                        (err: unknown) => {
                            assert.ok(err instanceof SecureHttpError);
                            assert.match(err.message, PLAIN_HTTP);
                            return true;
                        },
                    );
                    assert.equal(opened(), 0);
                    assert.equal(server.accepted(), 0);
                });
            }
        }

        it('http://api.localhost resolving to 127.0.0.1 still works with permitReservedIps', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { 'api.localhost': [v4('127.0.0.1')] });
            const { client } = clientFor(t, http2, { permitReservedIps: true });

            const res = await client.get(`http://api.localhost:${server.port}/`, { timeoutMs: 5000 });
            assert.equal(res.statusCode, 200);
        });

        it('https to a *.localhost name is not restricted to loopback (only the reserved-IP policy applies)', async (t) => {
            mockDns(t, { 'api.localhost': [v4('10.0.0.1')] });
            const { client, opened } = clientFor(t, http2);

            await assert.rejects(client.get('https://api.localhost/', { timeoutMs: 2000 }), RESERVED);
            assert.equal(opened(), 0);
        });
    });

    describe(`${engine}: plain http for every loopback name`, () => {
        it('http://app.localhost works with permitReservedIps and is rejected without it', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { 'app.localhost': [v6('::1'), v4('127.0.0.1')] });
            const url = `http://app.localhost:${server.port}/`;

            const denied = clientFor(t, http2);
            await assert.rejects(denied.client.get(url, { timeoutMs: 2000 }), RESERVED);
            assert.equal(denied.opened(), 0);
            assert.equal(server.accepted(), 0);

            const res = await clientFor(t, http2, { permitReservedIps: true }).client.get(url, { timeoutMs: 5000 });
            assert.equal(res.statusCode, 200);
        });

        it('http://127.0.0.2 works with permitReservedIps and is rejected without it', async (t) => {
            const server = await serve(t, http2, '127.0.0.2');
            const url = `http://127.0.0.2:${server.port}/`;

            await assert.rejects(clientFor(t, http2).client.get(url, { timeoutMs: 2000 }), RESERVED);
            assert.equal(server.accepted(), 0);

            const res = await clientFor(t, http2, { permitReservedIps: true }).client.get(url, { timeoutMs: 5000 });
            assert.equal(res.statusCode, 200);
            assert.equal(server.accepted(), 1);
        });

        it('http://[::1] works with permitReservedIps and is rejected without it', { skip: !ipv6Available && 'no IPv6 loopback' }, async (t) => {
            const server = await serve(t, http2, '::1');
            const url = `http://[::1]:${server.port}/`;

            await assert.rejects(clientFor(t, http2).client.get(url, { timeoutMs: 2000 }), RESERVED);
            assert.equal(server.accepted(), 0);

            const res = await clientFor(t, http2, { permitReservedIps: true }).client.get(url, { timeoutMs: 5000 });
            assert.equal(res.text(), 'peer ::1');
        });
    });
}

describe('parseSafeUrl: plain http only for loopback names', () => {
    it('accepts http for localhost, *.localhost, 127.0.0.0/8 literals and [::1]', () => {
        for (const url of [
            'http://localhost/',
            'http://LOCALHOST:8080/',
            'http://app.localhost/',
            'http://A.b.LocalHost/x',
            'http://127.0.0.1/',
            'http://127.0.0.2/',
            'http://127.255.255.254/',
            'http://127.1/',
            'http://[::1]:3000/',
            'http://[0:0:0:0:0:0:0:1]/',
        ]) {
            assert.equal(parseSafeUrl(url).protocol, 'http:', url);
        }
    });

    it('every IP literal it accepts over http is a loopback address by the same rule the engines apply', () => {
        for (const url of ['http://127.0.0.1/', 'http://127.0.0.2/', 'http://127.255.255.254/', 'http://127.1/', 'http://2130706433/', 'http://[::1]/', 'http://[0:0:0:0:0:0:0:1]/']) {
            const host = parseSafeUrl(url).hostname.replace(/^\[|\]$/g, '');
            assert.ok(isLoopbackIp(host), url);
        }
    });

    it('still refuses http for every other host', () => {
        for (const url of [
            'http://example.com/',
            'http://localhost.example.com/',
            'http://notlocalhost/',
            'http://localhostx/',
            'http://10.0.0.1/',
            'http://128.0.0.1/',
            'http://0.0.0.0/',
            'http://[::2]/',
            'http://[::ffff:127.0.0.1]/',
            'http://[fe80::1]/',
            'http://.localhost/',
            'http://..localhost/',
            'http://a..localhost/',
            'http://a.localhost./',
        ]) {
            assert.throws(() => parseSafeUrl(url), (err: unknown) => {
                assert.ok(err instanceof SecureHttpError, url);
                assert.equal(err.message, 'UltraTon: Plain http is only allowed for loopback hosts; use https.', url);
                assert.equal(err.code, 'ERR_ULTRATON_PLAIN_HTTP', url);
                return true;
            });
        }
    });
});
