/**
 * Q9: `client.explain(url)` says what a request would do before connecting, from the same functions a request uses, and
 * never opens a socket. Each blocked case is checked against `get()` rejecting with the same code. DNS is mocked; the
 * connection counters of net-fixtures prove nothing connected, on both engines.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { UltraTonClient } from '../src/http-client.ts';
import { clientFor, mockDns, v4, v6 } from './fixtures/net-fixtures.ts';

const PUBLIC = '93.184.216.34';

for (const http2 of [false, true]) {
    describe(`explain() (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        const setup = (t: TestContext, options: Record<string, unknown> = {}) => {
            mockDns(t, {
                'public.example': [v4(PUBLIC), v6('2606:2800:220:1:248:1893:25c8:1946')],
                'internal.example': [v4('10.0.0.5')],
                'mixed.example': [v4(PUBLIC), v4('10.0.0.5')],
            });
            return clientFor(t, http2, options);
        };

        it('a public name is allowed, with every address listed, and nothing connects', async (t) => {
            const { client, opened } = setup(t);
            const result = await client.explain('https://public.example/a?b=1');
            assert.equal(result.verdict, 'allowed');
            assert.equal(result.href, 'https://public.example/a?b=1');
            assert.equal(result.code, undefined);
            assert.deepEqual(result.addresses.map(a => [a.address, a.family, a.allowed]), [[PUBLIC, 4, true], ['2606:2800:220:1:248:1893:25c8:1946', 6, true]]);
            assert.equal(opened(), 0);
        });

        it('a name on a reserved address is blocked with the code get() rejects with, and the address is flagged', async (t) => {
            const { client, opened } = setup(t);
            const result = await client.explain('https://internal.example/');
            assert.equal(result.verdict, 'blocked');
            assert.equal(result.code, 'ERR_ULTRATON_RESERVED_IP');
            assert.match(result.reason!, /permitReservedIps/);
            assert.deepEqual(result.addresses, [{ address: '10.0.0.5', family: 4, allowed: false }]);
            await assert.rejects(client.get('https://internal.example/'), (err: { code?: string }) => err.code === 'ERR_ULTRATON_RESERVED_IP');
            assert.equal(opened(), 0);
        });

        it('a mixed answer is blocked and says which address', async (t) => {
            const { client } = setup(t);
            const result = await client.explain('https://mixed.example/');
            assert.equal(result.verdict, 'blocked');
            assert.deepEqual(result.addresses.map(a => a.allowed), [true, false]);
        });

        it('an allowlist entry (IP, CIDR or hostname) allows it, per call or from the client', async (t) => {
            const { client } = setup(t);
            for (const permitReservedIps of [['10.0.0.5'], ['10.0.0.0/8'], ['internal.example']]) {
                assert.equal((await client.explain('https://internal.example/', { permitReservedIps })).verdict, 'allowed', String(permitReservedIps));
            }
            assert.equal((await client.explain('https://internal.example/', { permitReservedIps: ['10.0.0.6'] })).verdict, 'blocked');
            const permissive = setup(t, { permitReservedIps: true }).client;
            assert.equal((await permissive.explain('https://internal.example/')).verdict, 'allowed');
        });

        it('an IP literal is judged as itself', async (t) => {
            const { client, opened } = setup(t);
            assert.equal((await client.explain('https://10.0.0.5/')).code, 'ERR_ULTRATON_RESERVED_IP');
            const result = await client.explain(`https://${PUBLIC}/`);
            assert.equal(result.verdict, 'allowed');
            assert.deepEqual(result.addresses, [{ address: PUBLIC, family: 4, allowed: true }]);
            assert.equal(opened(), 0);
        });

        it('plain http to a public name is blocked before resolving', async (t) => {
            const { client } = setup(t);
            const result = await client.explain('http://public.example/');
            assert.equal(result.verdict, 'blocked');
            assert.equal(result.code, 'ERR_ULTRATON_PLAIN_HTTP');
            assert.deepEqual(result.addresses, []);
        });

        it('a name that does not resolve is blocked with the resolver code', async (t) => {
            const { client } = setup(t);
            const result = await client.explain('https://nowhere.example/');
            assert.equal(result.verdict, 'blocked');
            assert.equal(result.code, 'ENOTFOUND');
            assert.equal(result.href, 'https://nowhere.example/');
        });

        it('an invalid URL is blocked with the parser message and no href', async (t) => {
            const { client } = setup(t);
            const result = await client.explain('ftp://public.example/');
            assert.equal(result.verdict, 'blocked');
            assert.equal(result.href, undefined);
            assert.match(result.reason!, /^UltraTon: /);
        });
    });
}

describe('explain() with baseUrl and a proxy', () => {
    it('a path that escapes baseUrl is blocked before resolving; one inside it resolves against the base', async (t) => {
        mockDns(t, { 'api.example': [v4(PUBLIC)] });
        const client = new UltraTonClient({ baseUrl: 'https://api.example/v1/' });
        t.after(() => client.close());
        const escaped = await client.explain('../admin');
        assert.equal(escaped.verdict, 'blocked');
        assert.equal(escaped.href, undefined);
        assert.deepEqual(escaped.addresses, []);
        const inside = await client.explain('users?page=2');
        assert.equal(inside.verdict, 'allowed');
        assert.equal(inside.href, 'https://api.example/v1/users?page=2');
    });

    it("with resolve: 'proxy' nothing is resolved here and the result says so", async (t) => {
        mockDns(t, {});
        const client = new UltraTonClient({ proxy: { url: 'http://proxy.internal:3128', resolve: 'proxy' } });
        t.after(() => client.close());
        const result = await client.explain('https://public.example/');
        assert.equal(result.verdict, 'allowed');
        assert.deepEqual(result.addresses, []);
        assert.match(result.reason!, /proxy resolves the name/);
        // An IP literal is still judged, proxy or not.
        assert.equal((await client.explain('https://10.0.0.5/')).code, 'ERR_ULTRATON_RESERVED_IP');
    });
});
