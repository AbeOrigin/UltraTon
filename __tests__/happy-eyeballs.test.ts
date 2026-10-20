/**
 * Happy Eyeballs over fully validated address sets (both engines), and plain http for every loopback name.
 *
 * DNS is mocked with `t.mock.method(dnsPromises, 'lookup')`, honouring `{ all: true }` like the real one, so nothing
 * here reaches a real resolver. Real loopback sockets everywhere else: which addresses Node may connect to, and how
 * many connections a server sees, is the contract. "Connections opened" is counted on the client side: for HTTP/1 the
 * addresses the client's `lookup` handed to Node (a failed lookup hands none, so no socket can connect), for HTTP/2 the
 * calls to a spy around `http2.connect`.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import EventEmitter from 'node:events';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net, { BlockList, type AddressInfo } from 'node:net';
import { connect as nativeConnect, createServer as createH2Server } from 'node:http2';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { kSessionManager, kTransport } from '../src/internal.ts';
import { SecureHttpError } from '../src/errors.ts';
import { parseSafeUrl } from '../src/helpers/url-parser.ts';

type Answer = { address: string; family: number };
const v4 = (address: string): Answer => ({ address, family: 4 });
const v6 = (address: string): Answer => ({ address, family: 6 });

const RESERVED = /prohibited internal\/reserved network IP/;

/** `table[host]` is what the nameserver answers; `{ all: true }` gets the list, anything else its first entry. */
const mockDns = (t: TestContext, table: Record<string, Answer[]>) =>
    t.mock.method(dnsPromises, 'lookup', (async (host: string, options?: { all?: boolean }) => {
        const answer = table[host];
        if (!answer) throw Object.assign(new Error('no resolver in tests'), { code: 'ENOTFOUND' });
        return options?.all ? answer : answer[0];
    }) as any);

/** A server on `host` that answers 200 with the peer address (HTTP/1 or h2c), and counts the connections it accepted. */
async function serve(t: TestContext, http2: boolean, host = '127.0.0.1') {
    let accepted = 0;
    const server = http2
        ? createH2Server((req, res) => res.end(`peer ${req.socket.remoteAddress}`))
        : http.createServer((req, res) => res.end(`peer ${req.socket.remoteAddress}`));
    const sockets = new Set<net.Socket>();
    server.on('connection', (socket: net.Socket) => {
        accepted++;
        sockets.add(socket);
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, host, resolve);
    });
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
    });
    return { port: (server.address() as AddressInfo).port, accepted: () => accepted };
}

/** A TCP server that accepts and drops: counts connection attempts that got through, whatever the protocol. */
async function tcpCounter(t: TestContext) {
    let accepted = 0;
    const server = net.createServer(socket => {
        accepted++;
        socket.destroy();
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
    return { port: (server.address() as AddressInfo).port, accepted: () => accepted };
}

/**
 * A client of either engine plus the number of connections it opened. HTTP/1 runs over the real `http`/`https`
 * request with the engine's own `lookup`, wrapped only to record the addresses it handed to Node.
 */
function clientFor(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    if (http2) {
        const connect = t.mock.fn(nativeConnect);
        const manager = new Http2SessionManager({}, connect);
        const client = new UltraTonClient({ http2: true, ...options, [kSessionManager]: manager } as any);
        t.after(() => client.close());
        return { client, opened: () => connect.mock.callCount() };
    }
    const handed: unknown[] = [];
    const transport = (url: URL, requestOptions: any) => {
        const lookup = requestOptions.lookup;
        return (url.protocol === 'http:' ? http.request : https.request)(url, {
            ...requestOptions,
            lookup: (host: string, lookupOptions: object, callback: (...args: unknown[]) => void) =>
                lookup(host, lookupOptions, (err: unknown, address: unknown, family: unknown) => {
                    if (!err) handed.push(address);
                    callback(err, address, family);
                }),
        });
    };
    const client = new UltraTonClient({ ...options, [kTransport]: transport } as any);
    t.after(() => client.close());
    return { client, opened: () => handed.length };
}

const ipv6Available = await new Promise<boolean>(resolve => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '::1', () => probe.close(() => resolve(true)));
});

for (const http2 of [false, true]) {
    const engine = http2 ? 'HTTP/2' : 'HTTP/1';

    describe(`${engine}: every address DNS returns is validated (fail closed)`, () => {
        for (const answer of [
            [v4('93.184.216.34'), v4('10.0.0.1')],
            [v4('10.0.0.1'), v4('93.184.216.34')],
            [v6('2606:2800:220:1:248:1893:25c8:1946'), v6('fd00::1')],
        ]) {
            const label = answer.map(a => a.address).join(', ');
            it(`a mixed public + private answer [${label}] is rejected with 0 connections`, async (t) => {
                mockDns(t, { 'mixed.test': answer });
                const { client, opened } = clientFor(t, http2);

                await assert.rejects(client.get('https://mixed.test/', { timeoutMs: 2000 }), (err: unknown) => {
                    assert.ok(err instanceof SecureHttpError);
                    assert.match(err.message, RESERVED);
                    assert.ok(!err.message.includes('10.0.0.1') && !err.message.includes('mixed.test'), err.message);
                    return true;
                });
                assert.equal(opened(), 0);
            });
        }

        it('one disallowed address in the answer blocks the allowed ones too: the server sees no connection', async (t) => {
            const server = await tcpCounter(t);
            mockDns(t, { 'mixed.test': [v4('127.0.0.1'), v4('10.0.0.1')] });
            const { client, opened } = clientFor(t, http2);

            await assert.rejects(
                client.get(`https://mixed.test:${server.port}/`, { permitReservedIps: ['127.0.0.0/8'], timeoutMs: 2000 }),
                RESERVED,
            );
            assert.equal(opened(), 0);
            assert.equal(server.accepted(), 0);
        });

        it('an empty DNS answer is an error, not a connection', async (t) => {
            mockDns(t, { 'empty.test': [] });
            const { client, opened } = clientFor(t, http2);

            await assert.rejects(client.get('https://empty.test/', { timeoutMs: 2000 }), (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match(err.message, /^UltraTon: Hostname resolution failed \(.+\)\.$/);
                return true;
            });
            assert.equal(opened(), 0);
        });
    });

    describe(`${engine}: Happy Eyeballs over the validated set`, () => {
        it('localhost resolving to [::1, 127.0.0.1] reaches a server bound only on 127.0.0.1', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { localhost: [v6('::1'), v4('127.0.0.1')] });
            const { client } = clientFor(t, http2, { permitReservedIps: true });

            const res = await client.get(`http://localhost:${server.port}/`, { timeoutMs: 5000 });

            assert.equal(res.statusCode, 200);
            assert.equal(res.text(), 'peer 127.0.0.1');
        });

        it('localhost with a list covering both loopback families also reaches it', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { localhost: [v6('::1'), v4('127.0.0.1')] });
            const { client } = clientFor(t, http2, { permitReservedIps: ['127.0.0.0/8', '::1'] });

            const res = await client.get(`http://localhost:${server.port}/`, { timeoutMs: 5000 });
            assert.equal(res.statusCode, 200);
        });

        it('a list covering only one of the two loopback addresses is rejected without connecting', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { localhost: [v6('::1'), v4('127.0.0.1')] });
            const { client, opened } = clientFor(t, http2, { permitReservedIps: ['127.0.0.0/8'] });

            await assert.rejects(client.get(`http://localhost:${server.port}/`, { timeoutMs: 2000 }), RESERVED);
            assert.equal(opened(), 0);
            assert.equal(server.accepted(), 0);
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
        ]) {
            assert.throws(() => parseSafeUrl(url), (err: unknown) => {
                assert.ok(err instanceof SecureHttpError, url);
                assert.equal(err.message, 'UltraTon: Unsupported protocol "http:"', url);
                return true;
            });
        }
    });
});

const fakeSession = () =>
    Object.assign(new EventEmitter(), {
        closed: false,
        destroyed: false,
        setTimeout: () => {},
        ref: () => {},
        unref: () => {},
        close() {
            this.closed = true;
            this.emit('close');
        },
        destroy() {
            this.destroyed = true;
        },
    });

describe('HTTP/2 session manager: connect by name, pinned to the validated set', () => {
    it('connects with the hostname URL, SNI set to the name, and a lookup that answers only with the validated set', async (t) => {
        const lookup = mockDns(t, { 'dual.test': [v6('2606:4700::1111'), v4('93.184.216.34')] });
        const connect = t.mock.fn((_url: string, _options: any) => fakeSession());
        const manager = new Http2SessionManager({}, connect as any);

        await manager.getSession('https://dual.test:8443');

        assert.equal(connect.mock.callCount(), 1);
        const [url, options] = connect.mock.calls[0].arguments;
        assert.equal(url, 'https://dual.test:8443');
        assert.equal(options.servername, 'dual.test');
        assert.equal(typeof options.lookup, 'function');

        const ask = (all: boolean) =>
            new Promise<unknown[]>((resolve, reject) =>
                options.lookup('dual.test', { all }, (err: unknown, ...rest: unknown[]) => (err ? reject(err) : resolve(rest))));
        assert.deepEqual((await ask(true))[0], [v6('2606:4700::1111'), v4('93.184.216.34')]);
        assert.deepEqual((await ask(false)).slice(0, 2), ['2606:4700::1111', 6]);
        // Answered from the pinned set: the nameserver was asked once, before connecting, and never again.
        assert.equal(lookup.mock.callCount(), 1);
    });

    it('an IP-literal host gets no SNI, is judged by the policy, and never touches DNS', async (t) => {
        const lookup = mockDns(t, {});
        const connect = t.mock.fn((_url: string, _options: any) => fakeSession());
        const manager = new Http2SessionManager({}, connect as any);

        await assert.rejects(manager.getSession('https://[::1]:8443'), RESERVED);
        assert.equal(connect.mock.callCount(), 0);

        await manager.getSession('https://[::1]:8443', undefined, true);
        const [url, options] = connect.mock.calls[0].arguments;
        assert.equal(url, 'https://[::1]:8443');
        assert.equal(options.servername, undefined, 'an IP literal must not be sent as SNI (DEP0123)');
        assert.equal(lookup.mock.callCount(), 0);
    });

    it('a reused session re-validates every address it was pinned to, not just the first', async (t) => {
        mockDns(t, { 'multi.test': [v4('93.184.216.34'), v4('93.184.216.35')] });
        const connect = t.mock.fn(() => fakeSession());
        const manager = new Http2SessionManager({}, connect as any);
        const first = await manager.getSession('https://multi.test');

        // From now on the reserved-range check sees the second pinned address as reserved (as if the ranges had grown).
        const checked: string[] = [];
        const realCheck = BlockList.prototype.check;
        t.mock.method(BlockList.prototype, 'check', function (this: BlockList, address: string, family?: string) {
            checked.push(address);
            return address === '93.184.216.35' || realCheck.call(this, address, family as any);
        });

        await assert.rejects(manager.getSession('https://multi.test'), RESERVED);
        assert.ok(checked.includes('93.184.216.34') && checked.includes('93.184.216.35'), checked.join(','));
        assert.equal(connect.mock.callCount(), 1, 'the pooled session was judged, not replaced');
        assert.ok(!first.destroyed);
    });

    it('a real TLS connect to an IP literal emits no DEP0123 warning', async (t) => {
        const server = await tcpCounter(t);
        const manager = new Http2SessionManager();
        const client = new UltraTonClient({ http2: true, permitReservedIps: true, [kSessionManager]: manager } as any);
        t.after(() => client.close());
        const warnings: string[] = [];
        const onWarning = (w: Error & { code?: string }) => warnings.push(w.code ?? w.name);
        process.on('warning', onWarning);
        t.after(() => process.off('warning', onWarning));

        await assert.rejects(client.get(`https://127.0.0.1:${server.port}/`, { timeoutMs: 2000 }));
        await new Promise<void>(resolve => setImmediate(resolve));

        assert.equal(server.accepted(), 1);
        assert.ok(!warnings.includes('DEP0123'), warnings.join(','));
    });
});
