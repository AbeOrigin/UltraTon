import { describe, it, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import EventEmitter from 'node:events';
import dnsPromises from 'node:dns/promises';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { MAX_SESSION_LIFESPAN } from '../src/constants.ts';
import { SecureHttpError } from '../src/errors.ts';

describe('Http2SessionManager - DNS Pinning & Rotation', () => {
    let mockConnect: any;
    const originalDateNow = Date.now;

    afterEach(() => {
        if (mockConnect) {
            mockConnect.mock.resetCalls();
        }
        global.Date.now = originalDateNow;
        mock.restoreAll();
    });

    const createMockSession = () => Object.assign(new EventEmitter(), {
        closed: false,
        destroyed: false,
        setTimeout: () => {},
        ref: () => {},
        unref: () => {},
        close() { this.closed = true; this.emit('close'); },
        destroy() { this.destroyed = true; }
    });

    /** What the `lookup` connect option of the `n`th connect answers when Node asks it for every address. */
    const pinnedAnswer = (n = 0) => new Promise<unknown>((resolve, reject) =>
        mockConnect.mock.calls[n].arguments[1].lookup('any', { all: true }, (err: unknown, list: unknown) => err ? reject(err) : resolve(list)));

    it('DNS Injection: http2.connect only ever turns the name into the pinned IP', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => [{ address: '8.8.8.8', family: 4 }]);
        
        mockConnect = mock.fn(() => createMockSession());
        
        const manager = new Http2SessionManager({}, mockConnect as any);
        await manager.getSession('example.com');

        assert.equal(mockConnect.mock.callCount(), 1);
        const args = mockConnect.mock.calls[0].arguments;
        
        assert.equal(args[0], 'https://example.com', 'connect by name: the lookup option supplies the address');
        assert.deepEqual(await pinnedAnswer(), [{ address: '8.8.8.8', family: 4 }], 'the lookup answers with the pinned IP');
        assert.equal(args[1].servername, 'example.com', 'SNI/authority must be preserved');
    });

    it('an http origin is plain http whatever the case of its scheme: every address must be loopback', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => [{ address: '93.184.216.34', family: 4 }]);
        mockConnect = mock.fn(() => createMockSession());
        const manager = new Http2SessionManager({}, mockConnect as any);

        await assert.rejects(manager.getSession('HTTP://api.localhost:1', undefined, true), (err: Error & { code?: string }) => {
            assert.equal(err.message, 'UltraTon: Plain http is only allowed to loopback addresses.');
            assert.equal(err.code, 'ERR_ULTRATON_PLAIN_HTTP');
            return true;
        });
        assert.equal(mockConnect.mock.callCount(), 0, 'never connected');
    });

    it('Forced Rotation: session is strictly recreated after MAX_SESSION_LIFESPAN', async (t) => {
        let currentTime = 1000000;
        global.Date.now = () => currentTime;

        let dnsCalls = 0;
        t.mock.method(dnsPromises, 'lookup', async () => {
            dnsCalls++;
            return [{ address: `8.8.8.${dnsCalls + 10}`, family: 4 }]; // e.g. 8.8.8.11 then 8.8.8.12
        });

        const sess1 = createMockSession();
        const sess2 = createMockSession();

        let connectCalls = 0;
        mockConnect = mock.fn(() => {
            connectCalls++;
            return connectCalls === 1 ? sess1 : sess2;
        });

        const manager = new Http2SessionManager({}, mockConnect as any);
        
        // First connection established
        const s1 = await manager.getSession('secure.com');
        assert.strictEqual(s1, sess1);
        
        // Request well within lifespan must use the cache
        currentTime += 1000; // +1s
        const s1_cached = await manager.getSession('secure.com');
        assert.strictEqual(s1_cached, sess1);
        
        // Fast-forward slightly past lifespan
        currentTime += MAX_SESSION_LIFESPAN + 1;
        
        // Rotation triggers purely upon access
        const s2 = await manager.getSession('secure.com');
        assert.strictEqual(s2, sess2); // Must be the brand new mocked Session 2
        
        // Drain check
        assert.equal(sess1.closed, true, 'Old session must be closed to gracefully drain streams');
        assert.equal(dnsCalls, 2, 'DNS pinner resolver must be triggered absolutely again for the rotated session');
    });

    it('Security Test: Simulates checking that DNS constraints prevent internal SSRF routing even on rotation', async (t) => {
        let currentTime = 1000000;
        global.Date.now = () => currentTime;
        
        let currentIp = '8.8.8.8';
        t.mock.method(dnsPromises, 'lookup', async () => [{ address: currentIp, family: 4 }]);

        mockConnect = mock.fn(() => createMockSession());
        const manager = new Http2SessionManager({}, mockConnect as any);
        
        await manager.getSession('rebind.com');
        assert.deepEqual(await pinnedAnswer(), [{ address: '8.8.8.8', family: 4 }], 'Safe DNS applies initially');
        
        // Fast forward cache duration
        currentTime += MAX_SESSION_LIFESPAN + 500;
        
        // Attacker rebinding resolves to AWS metadata IP
        currentIp = '169.254.169.254'; 
        
        await assert.rejects(
            () => manager.getSession('rebind.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as Error).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
        
        // Ensure connect was not hijacked or called via rebinding bypass
        assert.equal(mockConnect.mock.callCount(), 1, 'Refused to establish connection using rebound IP');
    });
});
