/**
 * Happy Eyeballs over fully validated address sets, in both engines: every address DNS returns is judged (fail closed),
 * Node races only validated addresses, and an HTTP/2 session connects by name but is pinned to the validated set.
 * Helpers (mocked DNS, real loopback servers, connection counting) live in fixtures/net-fixtures.ts.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import EventEmitter from 'node:events';
import { BlockList } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { kSessionManager } from '../src/internal.ts';
import { SecureHttpError } from '../src/errors.ts';
import { RESERVED, clientFor, mockDns, serve, tcpCounter, v4, v6 } from './fixtures/net-fixtures.ts';

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
        // he.localhost never resolves to 127.0.0.2 for real (here it does not resolve at all; where *.localhost resolves,
        // it is to ::1/127.0.0.1), so a 200 from a server bound only on 127.0.0.2 proves the connection used the
        // validated answer: the HTTP/1 lookup's list, or the HTTP/2 pinned lookup, not a second resolution.
        it('he.localhost resolving to [::1, 127.0.0.2] reaches a server bound only on 127.0.0.2 through the pinned answer', async (t) => {
            const server = await serve(t, http2, '127.0.0.2');
            mockDns(t, { 'he.localhost': [v6('::1'), v4('127.0.0.2')] });
            const { client } = clientFor(t, http2, { permitReservedIps: true });

            const res = await client.get(`http://he.localhost:${server.port}/`, { timeoutMs: 5000 });

            assert.equal(res.statusCode, 200);
            assert.equal(server.accepted(), 1);
        });

        it('localhost resolving to [::1, 127.0.0.1] reaches a server bound only on 127.0.0.1', async (t) => {
            const server = await serve(t, http2, '127.0.0.1');
            mockDns(t, { localhost: [v6('::1'), v4('127.0.0.1')] });
            const { client } = clientFor(t, http2, { permitReservedIps: true });

            const res = await client.get(`http://localhost:${server.port}/`, { timeoutMs: 5000 });

            assert.equal(res.statusCode, 200);
            assert.equal(res.text(), 'peer 127.0.0.1');
        });

        it('a list covering both loopback families also reaches it', async (t) => {
            const server = await serve(t, http2, '127.0.0.2');
            mockDns(t, { 'he.localhost': [v6('::1'), v4('127.0.0.2')] });
            const { client } = clientFor(t, http2, { permitReservedIps: ['127.0.0.0/8', '::1'] });

            const res = await client.get(`http://he.localhost:${server.port}/`, { timeoutMs: 5000 });
            assert.equal(res.statusCode, 200);
        });

        it('a list covering only one of the two loopback addresses is rejected without connecting', async (t) => {
            const server = await serve(t, http2, '127.0.0.2');
            mockDns(t, { 'he.localhost': [v6('::1'), v4('127.0.0.2')] });
            const { client, opened } = clientFor(t, http2, { permitReservedIps: ['127.0.0.0/8'] });

            await assert.rejects(client.get(`http://he.localhost:${server.port}/`, { timeoutMs: 2000 }), RESERVED);
            assert.equal(opened(), 0);
            assert.equal(server.accepted(), 0);
        });
    });

}

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

    // Before 22.14, http2.connect itself sets an IP literal as SNI (initializeTLSOptions(options, host)), whatever the
    // caller passes; Node then warns DEP0123 once per process. Nothing to fix on our side there.
    const [major, minor] = process.versions.node.split('.').map(Number);
    const coreSendsIpSni = major === 22 && minor < 14;
    it('a real TLS connect to an IP literal emits no DEP0123 warning', { skip: coreSendsIpSni && 'Node < 22.14 sends IP SNI itself' }, async (t) => {
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
