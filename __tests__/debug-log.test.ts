/**
 * Q5: NODE_DEBUG=ultraton writes one line per response, retry and error, with nothing secret in it; paths only with
 * ULTRATON_DEBUG_PATHS=1 (never with NODE_DEBUG=*); off, nothing subscribes. The format is unit-tested; what reaches
 * stderr is checked in a child process (debuglog decides at load time).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import diagnosticsChannel from 'node:diagnostics_channel';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { formatDebugLine } from '../src/helpers/debug-log.ts';

const request = { method: 'GET', origin: 'https://a.example', path: '/x' };

describe('formatDebugLine', () => {
    it('formats a response line, with the path only when asked', () => {
        const message = { request, statusCode: 200, durationMs: 12.6 };
        assert.equal(formatDebugLine('response', message, false), 'GET https://a.example -> 200 (13 ms)');
        assert.equal(formatDebugLine('response', message, true), 'GET https://a.example/x -> 200 (13 ms)');
    });

    it('formats a retry and an error line', () => {
        assert.equal(formatDebugLine('retry', { request, attempt: 1, delayMs: 300, statusCode: 503 }, false), 'GET https://a.example retry 1 in 300 ms (503)');
        assert.equal(formatDebugLine('retry', { request, attempt: 2, delayMs: 600, error: { name: 'UltraTonNetworkError', code: 'ECONNRESET' } }, false), 'GET https://a.example retry 2 in 600 ms (ECONNRESET)');
        assert.equal(formatDebugLine('error', { request, error: { name: 'UltraTonNetworkError', code: 'ECONNREFUSED' }, durationMs: 3.2 }, false), 'GET https://a.example failed: UltraTonNetworkError ECONNREFUSED (3 ms)');
        assert.equal(formatDebugLine('error', { request, error: { name: 'AbortError', code: undefined }, durationMs: 0.4 }, false), 'GET https://a.example failed: AbortError (0 ms)');
    });

    it('ends the response and error lines with the phases of the timings, leaving out those not gone through', () => {
        const fresh = { dnsMs: 2.6, connectMs: 12.2, tlsMs: 28, firstByteMs: 40.4, totalMs: 84.3, reusedConnection: false };
        assert.equal(formatDebugLine('response', { request, statusCode: 200, durationMs: 84.3, timings: fresh }, false),
            'GET https://a.example -> 200 (84 ms) [dns 3 ms, connect 12 ms, tls 28 ms, ttfb 40 ms]');
        const reused = { firstByteMs: 9.2, totalMs: 10, reusedConnection: true };
        assert.equal(formatDebugLine('response', { request, statusCode: 200, durationMs: 10, timings: reused }, false),
            'GET https://a.example -> 200 (10 ms) [reused, ttfb 9 ms]');
        const refused = { connectMs: undefined, totalMs: 3.2, reusedConnection: false };
        assert.equal(formatDebugLine('error', { request, error: { name: 'UltraTonNetworkError', code: 'ECONNREFUSED' }, durationMs: 3.2, timings: refused }, false),
            'GET https://a.example failed: UltraTonNetworkError ECONNREFUSED (3 ms)');
        const literal = { connectMs: 1.4, totalMs: 3.2, reusedConnection: false };
        assert.equal(formatDebugLine('error', { request, error: { name: 'UltraTonNetworkTimeoutError', code: 'ERR_ULTRATON_TIMEOUT' }, durationMs: 3.2, timings: literal }, false),
            'GET https://a.example failed: UltraTonNetworkTimeoutError ERR_ULTRATON_TIMEOUT (3 ms) [connect 1 ms]');
    });
});

describe('NODE_DEBUG=ultraton', () => {
    const child = fileURLToPath(new URL('./fixtures/debug-log-child.ts', import.meta.url));
    // --import takes a URL (a Windows path has a drive letter where a scheme goes); the script argument takes a path.
    const guard = new URL('./fixtures/loopback-only.ts', import.meta.url).href;
    /**
     * The ULTRATON lines the child wrote, as one string. Only those are ours to judge: Node itself writes to stderr too
     * (an ExperimentalWarning on 22.12.0 where type stripping is behind a flag; megabytes about module loading with
     * NODE_DEBUG=*).
     */
    const run = async (env: Record<string, string | undefined>) => {
        const { NODE_DEBUG: _off, ULTRATON_DEBUG_PATHS: _paths, ...base } = process.env;
        const { stderr } = await promisify(execFile)(process.execPath, ['--import', guard, child], { env: { ...base, ...env }, maxBuffer: 64 * 1024 * 1024 });
        return stderr.split('\n').filter(line => line.startsWith('ULTRATON ')).join('\n');
    };

    it('logs the response and the error without any secret or path', { timeout: 20_000 }, async () => {
        const ours = await run({ NODE_DEBUG: 'ultraton' });
        assert.match(ours, /ULTRATON \d+: GET http:\/\/127\.0\.0\.1:\d+ -> 200 \(\d+ ms\)/);
        // A new connection to an IP literal: no lookup, no TLS.
        assert.match(ours, /-> 200 \(\d+ ms\) \[connect \d+ ms, ttfb \d+ ms\]/);
        assert.match(ours, /ULTRATON \d+: GET http:\/\/127\.0\.0\.1:1 failed: UltraTonNetworkError ECONNREFUSED \(\d+ ms\)/);
        assert.doesNotMatch(ours, /s3cret|\/a|\/b|\/down/);
    });

    it('ULTRATON_DEBUG_PATHS=1 adds the path, still without secrets; NODE_DEBUG=* alone does not', { timeout: 20_000 }, async () => {
        const withPaths = await run({ NODE_DEBUG: 'ultraton', ULTRATON_DEBUG_PATHS: '1' });
        assert.match(withPaths, /GET http:\/\/127\.0\.0\.1:\d+\/a\/b -> 200/);
        assert.doesNotMatch(withPaths, /s3cret/);
        const star = await run({ NODE_DEBUG: '*' });
        assert.match(star, /GET http:\/\/127\.0\.0\.1:\d+ -> 200/);
        assert.doesNotMatch(star, /\/a\/b/);
    });

    it('without NODE_DEBUG nothing is written and nothing subscribes', { timeout: 20_000 }, async () => {
        assert.equal(await run({}), '');
        // This process loaded the module with NODE_DEBUG unset.
        assert.equal(diagnosticsChannel.hasSubscribers('ultraton:request:response'), false);
    });
});
