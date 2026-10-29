/**
 * `allowPlainHttp`: plain http to a host that is not loopback (an internal service without TLS), on both engines, only
 * when the client opts in. It lifts the scheme rule alone: the address policy, the https-to-http refusal and the proxy
 * stay as they were.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { SecureHttpError } from '../src/errors.ts';
import { UltraTonClient } from '../src/http-client.ts';
import { followRedirect } from '../src/helpers/redirect-headers.ts';
import { buildSafeRequestOptions } from '../src/helpers/request-options.ts';
import { clientFor, mockDns, serve, v4 } from './fixtures/net-fixtures.ts';

const isCode = (code: string) => (err: unknown) => err instanceof SecureHttpError && err.code === code;

for (const http2 of [false, true]) {
    const engine = http2 ? 'HTTP/2 (h2c)' : 'HTTP/1.1';

    describe(`${engine}: allowPlainHttp`, () => {
        it('without it, plain http to a name that is not loopback is refused before connecting', async (t) => {
            const server = await serve(t, http2);
            mockDns(t, { 'api.staging.internal': [v4('127.0.0.1')] });
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true });
            await assert.rejects(client.get(`http://api.staging.internal:${server.port}/`), isCode('ERR_ULTRATON_PLAIN_HTTP'));
            assert.equal(opened(), 0);
        });

        it('with it, plain http reaches a host that is not loopback', async (t) => {
            const server = await serve(t, http2);
            mockDns(t, { 'api.staging.internal': [v4('127.0.0.1')] });
            const { client } = clientFor(t, http2, { permitReservedIps: true, allowPlainHttp: true });
            const res = await client.get(`http://api.staging.internal:${server.port}/`);
            assert.equal(res.statusCode, 200);
        });

        it('still judges every address by permitReservedIps', async (t) => {
            mockDns(t, { 'api.staging.internal': [v4('10.0.0.5')] });
            const { client, opened } = clientFor(t, http2, { allowPlainHttp: true });
            await assert.rejects(client.get('http://api.staging.internal/'), isCode('ERR_ULTRATON_RESERVED_IP'));
            assert.equal(opened(), 0);
        });

        it('follows an http redirect to another plain-http host, still under the policy', async (t) => {
            const target = await serve(t, http2);
            mockDns(t, { 'other.internal': [v4('127.0.0.1')] });
            const redirect = (_req: unknown, res: http.ServerResponse) => {
                res.writeHead(302, { location: `http://other.internal:${target.port}/b` });
                res.end();
            };
            const origin = http2 ? createH2Server(redirect as any) : http.createServer(redirect);
            await new Promise<void>(r => origin.listen(0, '127.0.0.1', r));
            t.after(() => new Promise<void>(r => origin.close(() => r())));
            const { client } = clientFor(t, http2, { permitReservedIps: true, allowPlainHttp: true, maxRedirects: 1 });
            const res = await client.get(`http://127.0.0.1:${(origin.address() as AddressInfo).port}/a`);
            assert.equal(res.statusCode, 200);
            assert.equal(res.url, `http://other.internal:${target.port}/b`);
        });
    });
}

describe('allowPlainHttp: what it does not change', () => {
    it('a redirect from https to http is still refused', () => {
        const options = { method: 'GET' };
        assert.throws(
            () => followRedirect(302, 'http://api.staging.internal/', new URL('https://api.example.com/'), options, buildSafeRequestOptions({ ...options, maxRedirects: 5 }), 0, true),
            isCode('ERR_ULTRATON_DOWNGRADE'),
        );
    });

    it('cannot be combined with proxy, is a client option only, and must be a boolean', () => {
        assert.throws(() => new UltraTonClient({ allowPlainHttp: true, proxy: 'http://egress.corp:3128' }), { name: 'TypeError', message: /'allowPlainHttp' cannot be combined with 'proxy'/ });
        assert.throws(() => new UltraTonClient({ allowPlainHttp: 'yes' as any }), { name: 'TypeError', message: /'allowPlainHttp'/ });
        const client = new UltraTonClient();
        assert.rejects(client.get('http://127.0.0.1/', { allowPlainHttp: true } as any), { name: 'TypeError', message: /'allowPlainHttp' is an option of the client constructor/ });
        return client.close();
    });

    it('lets baseUrl be plain http, and explain() agrees with the request', async (t) => {
        assert.throws(() => new UltraTonClient({ baseUrl: 'http://api.staging.internal/v1' }), isCode('ERR_ULTRATON_PLAIN_HTTP'));
        mockDns(t, { 'api.staging.internal': [v4('10.0.0.5')] });
        const client = new UltraTonClient({ baseUrl: 'http://api.staging.internal/v1', allowPlainHttp: true, permitReservedIps: ['10.0.0.0/8'] });
        t.after(() => client.close());
        const explained = await client.explain('users');
        assert.equal(explained.verdict, 'allowed');
        assert.equal(explained.href, 'http://api.staging.internal/v1/users');
        const strict = new UltraTonClient({ allowPlainHttp: true });
        t.after(() => strict.close());
        assert.equal((await strict.explain('http://api.staging.internal/')).code, 'ERR_ULTRATON_RESERVED_IP');
    });

    it('a variant from extend() can turn it off, with pools of its own', async (t) => {
        mockDns(t, { 'api.staging.internal': [v4('127.0.0.1')] });
        const base = new UltraTonClient({ allowPlainHttp: true, permitReservedIps: true });
        t.after(() => base.close());
        const strict = base.extend({ allowPlainHttp: false });
        t.after(() => strict.close());
        await assert.rejects(strict.get('http://api.staging.internal:1/'), isCode('ERR_ULTRATON_PLAIN_HTTP'));
    });
});
