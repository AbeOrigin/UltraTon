/**
 * Errors a caller can act on, and options that fail loudly instead of being dropped or replaced:
 * - every policy rejection carries a stable `code`, DNS failures are network errors like connect failures;
 * - `headers` must be a plain object, `signal` an AbortSignal, numeric options in range;
 * - a timeout is a network error too.
 * Both engines; DNS is mocked, connections are counted, so "throws before connecting" is proven.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonNetworkError, UltraTonNetworkTimeoutError } from '../src/errors.ts';
import { buildSafeRequestOptions } from '../src/helpers/request-options.ts';
import { parseSafeUrl } from '../src/helpers/url-parser.ts';
import { assertAllowedIp, assertLoopbackIp, resolveAndPinAll } from '../src/security/dns-pinner.ts';
import { clientFor, mockDns, serve, v4 } from './fixtures/net-fixtures.ts';

const INT32_MAX = 2147483647;

/** A nameserver that fails every lookup with `code`, its message naming the host like getaddrinfo does. */
const failingDns = (t: TestContext, code: string) =>
    t.mock.method(dnsPromises, 'lookup', (async (host: string) => {
        throw Object.assign(new Error(`getaddrinfo ${code} ${host}`), { code, hostname: host });
    }) as any);

describe('error codes', () => {
    for (const http2 of [false, true]) {
        const engine = http2 ? 'HTTP/2' : 'HTTP/1';

        for (const code of ['ENOTFOUND', 'EAI_AGAIN', 'ENODATA', 'ESERVFAIL']) {
            it(`${engine}: a DNS failure (${code}) is an UltraTonNetworkError with that code and no hostname`, async (t) => {
                failingDns(t, code);
                const { client, opened } = clientFor(t, http2);
                await assert.rejects(client.get('https://secret-host.example/'), (err: Error & { code?: string }) => {
                    assert.ok(err instanceof UltraTonNetworkError, `${err.name}: ${err.message}`);
                    assert.equal(err.message, `UltraTon: Hostname resolution failed (${code}).`);
                    assert.equal(err.code, code);
                    assert.doesNotMatch(err.message, /secret-host/);
                    return true;
                });
                assert.equal(opened(), 0);
            });
        }

        it(`${engine}: a reserved IP is refused with ERR_ULTRATON_RESERVED_IP (literal and resolved)`, async (t) => {
            mockDns(t, { 'intranet.example': [v4('10.0.0.5')] });
            const { client, opened } = clientFor(t, http2);
            for (const url of ['https://10.0.0.5/', 'https://intranet.example/', 'http://127.0.0.1:1/']) {
                await assert.rejects(client.get(url), (err: Error & { code?: string }) => {
                    assert.ok(err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError), `${url} ${err.name}`);
                    assert.match(err.message, /prohibited internal\/reserved network IP/);
                    assert.equal(err.code, 'ERR_ULTRATON_RESERVED_IP', url);
                    return true;
                });
            }
            assert.equal(opened(), 0);
        });

        it(`${engine}: a loopback name resolving off loopback is refused with ERR_ULTRATON_PLAIN_HTTP`, async (t) => {
            mockDns(t, { 'api.localhost': [v4('10.0.0.5')] });
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true });
            await assert.rejects(client.get('http://api.localhost:1/'), (err: Error & { code?: string }) => {
                assert.ok(err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError), err.name);
                assert.equal(err.message, 'UltraTon: Plain http is only allowed to loopback addresses.');
                assert.equal(err.code, 'ERR_ULTRATON_PLAIN_HTTP');
                return true;
            });
            assert.equal(opened(), 0);
        });

        it(`${engine}: plain http to a public host says to use https, with ERR_ULTRATON_PLAIN_HTTP`, async (t) => {
            const { client, opened } = clientFor(t, http2);
            await assert.rejects(client.get('http://example.com/'), (err: Error & { code?: string }) => {
                assert.ok(err instanceof SecureHttpError && !(err instanceof UltraTonNetworkError), err.name);
                assert.equal(err.message, 'UltraTon: Plain http is only allowed for loopback hosts; use https.');
                assert.equal(err.code, 'ERR_ULTRATON_PLAIN_HTTP');
                return true;
            });
            assert.equal(opened(), 0);
        });
    }

    it('the helpers carry the same codes', async () => {
        assert.throws(() => assertAllowedIp('169.254.169.254', false), { code: 'ERR_ULTRATON_RESERVED_IP' });
        assert.throws(() => assertLoopbackIp('8.8.8.8'), { code: 'ERR_ULTRATON_PLAIN_HTTP' });
        assert.throws(() => parseSafeUrl('http://example.com/'), { code: 'ERR_ULTRATON_PLAIN_HTTP' });
        // Another scheme is still an unsupported protocol, and has no code.
        assert.throws(() => parseSafeUrl('ftp://example.com/'), (err: Error & { code?: string }) =>
            err.message === 'UltraTon: Unsupported protocol "ftp:"' && err.code === undefined);
    });

    it('an empty or malformed DNS answer is an UltraTonNetworkError too (ENODATA, EBADRESP)', async (t) => {
        const answers: unknown[] = [[], [{ address: 'not-an-ip', family: 4 }]];
        t.mock.method(dnsPromises, 'lookup', (async () => answers.shift()) as any);
        await assert.rejects(resolveAndPinAll('a.example'), (err: Error & { code?: string }) =>
            err instanceof UltraTonNetworkError && err.code === 'ENODATA');
        await assert.rejects(resolveAndPinAll('a.example'), (err: Error & { code?: string }) =>
            err instanceof UltraTonNetworkError && err.code === 'EBADRESP');
    });

    it('a baseUrl escape stays a TypeError', async () => {
        const client = new UltraTonClient({ baseUrl: 'https://api.example.com/v1/' });
        await assert.rejects(client.get('../admin'), (err: Error) => err instanceof TypeError && !(err instanceof SecureHttpError));
        await assert.rejects(client.get('https://evil.example/'), TypeError);
        await client.close();
    });
});

describe('UltraTonNetworkTimeoutError is an UltraTonNetworkError', () => {
    it('by class', () => {
        const err = new UltraTonNetworkTimeoutError('UltraTon: x');
        assert.ok(err instanceof UltraTonNetworkError);
        assert.ok(err instanceof SecureHttpError);
        assert.equal(err.name, 'UltraTonNetworkTimeoutError');
    });

    for (const http2 of [false, true]) {
        it(`${http2 ? 'HTTP/2' : 'HTTP/1'}: a real timeout is caught by instanceof UltraTonNetworkError`, async (t) => {
            // Accepts the connection and never says a word.
            const sockets = new Set<net.Socket>();
            const silent = net.createServer(socket => sockets.add(socket));
            await new Promise<void>(r => silent.listen(0, '127.0.0.1', r));
            t.after(() => { for (const s of sockets) s.destroy(); silent.close(); });
            const { client } = clientFor(t, http2, { permitReservedIps: true });
            const url = `http://127.0.0.1:${(silent.address() as net.AddressInfo).port}/`;
            await assert.rejects(client.get(url, { timeoutMs: 200 }), (err: Error) =>
                err instanceof UltraTonNetworkTimeoutError && err instanceof UltraTonNetworkError);
        });
    }
});

describe('option validation', () => {
    for (const http2 of [false, true]) {
        const engine = http2 ? 'HTTP/2' : 'HTTP/1';

        it(`${engine}: headers that are not a plain object throw, per request and in the constructor`, async (t) => {
            const { port } = await serve(t, http2);
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true });
            const plainHint = /^UltraTon: Expected 'headers' to be a plain object, received a (Headers|Map|Custom) instance; pass a plain object/;
            class Custom { authorization = 'Bearer t'; }
            for (const headers of [new Headers({ authorization: 'Bearer t' }), new Map([['authorization', 'Bearer t']]), new Custom()]) {
                await assert.rejects(client.get(`http://127.0.0.1:${port}/`, { headers: headers as any }), (err: Error) => {
                    assert.ok(err instanceof TypeError, err.name);
                    assert.match(err.message, plainHint);
                    return true;
                });
                assert.throws(() => new UltraTonClient({ http2, headers: headers as any }), (err: Error) =>
                    err instanceof TypeError && plainHint.test(err.message));
            }
            assert.equal(opened(), 0);
            // A null-prototype object is plain.
            const nullProto = Object.assign(Object.create(null), { 'x-a': '1' });
            assert.equal((await client.get(`http://127.0.0.1:${port}/`, { headers: nullProto })).statusCode, 200);
        });

        it(`${engine}: signal must be an AbortSignal`, async (t) => {
            const { port } = await serve(t, http2);
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true });
            const duck = { aborted: false, reason: undefined, addEventListener() {}, removeEventListener() {}, throwIfAborted() {} };
            for (const [signal, received] of [[{}, 'object'], [duck, 'object'], [null, 'null'], ['x', 'string']] as const) {
                await assert.rejects(client.get(`http://127.0.0.1:${port}/`, { signal: signal as any }), (err: Error) => {
                    assert.ok(err instanceof TypeError, err.name);
                    assert.equal(err.message, `UltraTon: Expected 'signal' to be an AbortSignal, received ${received}.`);
                    return true;
                });
            }
            assert.equal(opened(), 0);
            assert.equal((await client.get(`http://127.0.0.1:${port}/`, { signal: new AbortController().signal })).statusCode, 200);
            assert.equal((await client.get(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(5000) })).statusCode, 200);
        });

        it(`${engine}: an out-of-range number throws, naming the range, per request and in the constructor`, async (t) => {
            const { port } = await serve(t, http2);
            const { client, opened } = clientFor(t, http2, { permitReservedIps: true });
            const cases: Array<[string, number, number]> = [
                ['timeoutMs', -1, INT32_MAX], ['timeoutMs', 1.5, INT32_MAX], ['timeoutMs', 2 ** 31, INT32_MAX], ['timeoutMs', Infinity, INT32_MAX],
                ['socketTimeoutMs', -1, INT32_MAX], ['socketTimeoutMs', 2 ** 40, INT32_MAX],
                ['maxBodySize', 2 ** 40, INT32_MAX], ['maxBodySize', -5, INT32_MAX], ['maxBodySize', 0.5, INT32_MAX],
                ['maxRedirects', 21, 20], ['maxRedirects', 1000, 20], ['maxRedirects', -1, 20], ['maxRedirects', 1.5, 20],
            ];
            for (const [name, value, max] of cases) {
                const message = `UltraTon: Expected '${name}' to be an integer from 0 to ${max}, received ${value}.`;
                await assert.rejects(client.get(`http://127.0.0.1:${port}/`, { [name]: value }), (err: Error) => {
                    assert.ok(err instanceof TypeError, `${name}=${value}: ${err.name}`);
                    assert.equal(err.message, message);
                    return true;
                });
                assert.throws(() => new UltraTonClient({ http2, [name]: value }), { name: 'TypeError', message });
            }
            assert.equal(opened(), 0);
        });
    }

    it('the bounds themselves are accepted, and 0 keeps its meaning', () => {
        const low = buildSafeRequestOptions({ timeoutMs: 0, socketTimeoutMs: 0, maxBodySize: 0, maxRedirects: 0 });
        assert.deepEqual([low.timeoutMs, low.socketTimeoutMs, low.maxBodySize, low.maxRedirects], [0, 0, 0, 0]);
        const high = buildSafeRequestOptions({ timeoutMs: INT32_MAX, socketTimeoutMs: INT32_MAX, maxBodySize: INT32_MAX, maxRedirects: 20 });
        assert.deepEqual([high.timeoutMs, high.socketTimeoutMs, high.maxBodySize, high.maxRedirects], [INT32_MAX, INT32_MAX, INT32_MAX, 20]);
        const unset = buildSafeRequestOptions({});
        assert.deepEqual([unset.timeoutMs, unset.socketTimeoutMs, unset.maxBodySize, unset.maxRedirects], [30_000, 10_000, 2 * 1024 * 1024, 0]);
    });
});
