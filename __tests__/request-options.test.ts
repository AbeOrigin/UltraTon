import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSafeRequestOptions } from '../src/helpers/request-options.ts';

describe('Unit Test: buildSafeRequestOptions (Firewall Helper)', () => {

    it('Should return standard options with all secure defaults injected when passed empty options', () => {
        const result = buildSafeRequestOptions({});
        assert.deepStrictEqual(result, { 
            maxBodySize: 2097152, 
            socketTimeoutMs: 10000, 
            timeoutMs: 30000,
            maxRedirects: 0,
            permitReservedIps: false
        });
    });

    it('Should perfectly allow valid properties and pass them through structurally via the transparent mapping', () => {
        const dummySignal = new AbortController().signal;
        
        const result = buildSafeRequestOptions({
            method: 'POST',
            timeout: 5000,
            auth: 'user:pass',
            headers: { 'x-request-id': '999' },
            signal: dummySignal,
            maxBodySize: 4096,
            socketTimeoutMs: 100,
            timeoutMs: 0 // Explicit opt-out test block
        });

        assert.strictEqual(result.method, 'POST');
        assert.strictEqual(result.timeout, 5000); 
        assert.strictEqual(result.auth, 'user:pass');
        assert.deepStrictEqual(result.headers, { 'x-request-id': '999' });
        assert.strictEqual(result.signal, dummySignal);
        assert.strictEqual(result.maxBodySize, 4096);
        assert.strictEqual(result.socketTimeoutMs, 100);
        assert.strictEqual(result.timeoutMs, 0);
    });

    it('Should ruthlessly strip out malicious networking overrides (Strict Allowlist Check)', () => {
        const result = buildSafeRequestOptions({
            method: 'GET',
            agent: {}, // Malicious injected interceptor
            createConnection: () => {}, // Sandbox socket bypass
            rejectUnauthorized: false,  // TLS verification bypass (MITM enabling)
        } as any);

        assert.strictEqual(result.method, 'GET');
        assert.strictEqual(result.maxBodySize, 2097152);
        assert.strictEqual(result.socketTimeoutMs, 10000);
        assert.strictEqual(result.timeoutMs, 30000);

        // Security assertion: Malicious overrides dropped instantly at runtime
        assert.strictEqual((result as any).agent, undefined);
        assert.strictEqual((result as any).createConnection, undefined);
        assert.strictEqual((result as any).rejectUnauthorized, undefined);
    });

    it('Should throw synchronous TypeErrors when developers bypass TS compilation for strings', () => {
        assert.throws(() => {
            buildSafeRequestOptions({ socketTimeoutMs: "5000" } as any);
        }, {
            name: 'TypeError',
            message: "UltraTon: Expected 'socketTimeoutMs' to be a number, received string"
        });
    });

    it('Should throw synchronous TypeErrors when developers pass arrays to the object map', () => {
        assert.throws(() => {
            buildSafeRequestOptions({ headers: ['Bearer token'] } as any); 
        }, {
            name: 'TypeError',
            message: "UltraTon: Expected 'headers' to be a object, received object" 
        });
    });

});
