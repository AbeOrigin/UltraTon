import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildSafeRequestOptions } from '../src/helpers/request-options.ts';

describe('Unit Test: buildSafeRequestOptions (Firewall Helper)', () => {

    it('Should return standard options with all secure defaults injected when passed empty options', () => {
        const result = buildSafeRequestOptions({});
        // The result has no prototype (inherited properties never read as options): compare its own properties.
        assert.deepStrictEqual({ ...result }, { 
            decompress: true,
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
            auth: 'user:pass',
            headers: { 'x-request-id': '999' },
            signal: dummySignal,
            maxBodySize: 4096,
            socketTimeoutMs: 100,
            timeoutMs: 0 // Explicit opt-out test block
        });

        assert.strictEqual(result.method, 'POST');
        assert.strictEqual(result.auth, 'user:pass');
        assert.deepStrictEqual(result.headers, { 'x-request-id': '999' });
        assert.strictEqual(result.signal, dummySignal);
        assert.strictEqual(result.maxBodySize, 4096);
        assert.strictEqual(result.socketTimeoutMs, 100);
        assert.strictEqual(result.timeoutMs, 0);
    });

    it('Should reject malicious networking overrides instead of passing or silently dropping them (Strict Allowlist Check)', () => {
        const malicious: Record<string, unknown> = {
            agent: {}, // Malicious injected interceptor
            createConnection: () => {}, // Sandbox socket bypass
            rejectUnauthorized: false,  // TLS verification bypass (MITM enabling)
        };

        // Security assertion: none of them gets through, and none is ignored without telling the caller
        for (const [key, value] of Object.entries(malicious)) {
            assert.throws(
                () => buildSafeRequestOptions({ method: 'GET', [key]: value } as any),
                { name: 'TypeError', message: new RegExp(`^UltraTon: Unknown option '${key}'\\.`) },
            );
        }
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

    it('rejects pseudo-header keys', () => {
        assert.throws(() => {
            buildSafeRequestOptions({ headers: { ':path': '/x' } });
        }, TypeError);
    });

    it('accepts permitReservedIps as an allowlist of IPs, CIDRs and hostnames', () => {
        const list = ['10.0.0.0/8', 'api.internal', '::1', 'fd00::/8', '192.168.1.5'];
        const result = buildSafeRequestOptions({ permitReservedIps: list });
        assert.deepStrictEqual(result.permitReservedIps, list);
    });

    it('copies the allowlist so later mutation of the caller array cannot widen the policy', () => {
        const list = ['10.0.0.0/8'];
        const result = buildSafeRequestOptions({ permitReservedIps: list });
        list.push('http://evil');
        assert.deepStrictEqual(result.permitReservedIps, ['10.0.0.0/8']);
    });

    it('reuses a list it already validated, and still validates a frozen list it did not freeze', () => {
        const validated = buildSafeRequestOptions({ permitReservedIps: ['10.0.0.0/8'] }).permitReservedIps;
        assert.ok(Object.isFrozen(validated));
        assert.strictEqual(buildSafeRequestOptions({ permitReservedIps: validated }).permitReservedIps, validated);
        // Frozen by the caller, not by the validator: checked and copied like any other list.
        assert.throws(() => buildSafeRequestOptions({ permitReservedIps: Object.freeze(['http://evil']) }), TypeError);
        const callerFrozen = Object.freeze(['10.0.0.0/8']);
        assert.notStrictEqual(buildSafeRequestOptions({ permitReservedIps: callerFrozen }).permitReservedIps, callerFrozen);
    });

    it('treats an empty permitReservedIps array as a valid (blocking) policy', () => {
        assert.deepStrictEqual(buildSafeRequestOptions({ permitReservedIps: [] }).permitReservedIps, []);
        assert.strictEqual(buildSafeRequestOptions({ permitReservedIps: true }).permitReservedIps, true);
    });

    it('rejects malformed permitReservedIps entries with a TypeError', () => {
        const bad: unknown[] = [
            'http://x', '10.0.0.0/33', 42, '::1/129', '10.0.0.0/', '10.0.0.0/-1', '10.0.0.0/8/8',
            '', '.internal', 'internal.', 'a b', 'host_name', 'a/b', null, {}, ['10.0.0.0/8']
        ];
        for (const entry of bad) {
            assert.throws(
                () => buildSafeRequestOptions({ permitReservedIps: [entry] } as any),
                { name: 'TypeError', message: /Invalid permitReservedIps entry/ },
                `entry ${JSON.stringify(entry)} must be rejected`
            );
        }
        assert.throws(
            () => buildSafeRequestOptions({ permitReservedIps: ['http://x'] }),
            { message: "UltraTon: Invalid permitReservedIps entry 'http://x': expected an IP, CIDR or hostname." }
        );
    });

    it('still rejects a permitReservedIps value that is neither boolean nor array', () => {
        assert.throws(() => buildSafeRequestOptions({ permitReservedIps: 'localhost' } as any), TypeError);
    });

    it('Should correctly stringify valid numeric or boolean header values without throwing them away', () => {
        const result = buildSafeRequestOptions({
            headers: {
                'Content-Length': 100,
                'x-custom-bool': true,
                'x-dropped': false,
                'x-number-zero': 0,
                'x-array-mixed': ['string', 123, true]
            } as any
        });

        assert.deepStrictEqual(result.headers, {
            'content-length': '100',
            'x-custom-bool': 'true',
            'x-dropped': 'false',
            'x-number-zero': '0',
            'x-array-mixed': ['string', '123', 'true']
        });
    });

});
