/**
 * The `retry` option: which failures and statuses are retried, `Retry-After`, the `timeoutMs` budget, abort, the
 * `onRetry` hook, and that every attempt is a full request (DNS validated again). Both engines, loopback only.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import { connect as nativeH2Connect, constants as h2constants, createServer as createH2Server, type ClientHttp2Session, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import { kSessionManager } from '../src/internal.ts';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonNetworkTimeoutError } from '../src/errors.ts';
import { clientFor, PLAIN_HTTP, RESERVED } from './fixtures/net-fixtures.ts';

/** What the server does with the n-th request (0-based): answer a status (with headers), hang, or drop the connection. */
type Step = { status: number; headers?: Record<string, string>; body?: string } | 'hang' | 'drop';

/** A loopback server of either engine that plays `steps` in order (the last one repeats) and counts requests. */
async function scripted(t: TestContext, http2: boolean, steps: Step[]) {
    const sockets = new Set<Socket>();
    const methods: string[] = [];
    const next = () => steps[Math.min(methods.length - 1, steps.length - 1)];
    const server = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
            methods.push(String(headers[':method']));
            const step = next();
            stream.resume();
            if (step === 'hang') return;
            if (step === 'drop') { stream.session?.destroy(); return; }
            const head = headers[':method'] === 'HEAD';
            stream.respond({ ':status': step.status, 'content-type': 'text/plain', ...step.headers }, { endStream: head });
            if (!head) stream.end(step.body ?? String(step.status));
        })
        : http.createServer((req, res) => {
            methods.push(String(req.method));
            const step = next();
            req.resume();
            if (step === 'hang') return;
            if (step === 'drop') { req.socket.destroy(); return; }
            res.writeHead(step.status, { 'content-type': 'text/plain', ...step.headers });
            res.end(step.body ?? String(step.status));
        });
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    const port = (server.address() as AddressInfo).port;
    return { url: `http://127.0.0.1:${port}/x`, port, requests: () => methods.length, methods };
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

const ok = { status: 200 } as const;
const unavailable = { status: 503, headers: { 'retry-after': '0' } } as const;

for (const http2 of [false, true]) {
    describe(`retry (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('is off by default', async (t) => {
            const server = await scripted(t, http2, [unavailable, ok]);
            const res = await clientOf(t, http2).get(server.url);
            assert.equal(res.statusCode, 503);
            assert.equal(server.requests(), 1);
        });

        it('retries a retryable status up to limit, then returns the last response', async (t) => {
            const server = await scripted(t, http2, [unavailable, unavailable, ok]);
            assert.equal((await clientOf(t, http2, { retry: 2 }).get(server.url)).statusCode, 200);
            assert.equal(server.requests(), 3);

            const failing = await scripted(t, http2, [unavailable]);
            const res = await clientOf(t, http2).get(failing.url, { retry: 1 });
            assert.equal(res.statusCode, 503);
            assert.equal(res.text(), '503');
            assert.equal(failing.requests(), 2);
        });

        it('retries 408, 429, 502, 503 and 504 by default, not 500 or 404 unless listed', async (t) => {
            for (const status of [408, 429, 502, 504]) {
                const server = await scripted(t, http2, [{ status, headers: { 'retry-after': '0' } }, ok]);
                assert.equal((await clientOf(t, http2, { retry: 1 }).get(server.url)).statusCode, 200, String(status));
            }
            for (const status of [500, 404]) {
                const server = await scripted(t, http2, [{ status, headers: { 'retry-after': '0' } }, ok]);
                assert.equal((await clientOf(t, http2, { retry: 1 }).get(server.url)).statusCode, status);
                assert.equal(server.requests(), 1);
            }
            const listed = await scripted(t, http2, [{ status: 500, headers: { 'retry-after': '0' } }, ok]);
            const res = await clientOf(t, http2).get(listed.url, { retry: { limit: 1, statusCodes: [500] } });
            assert.equal(res.statusCode, 200);
            // statusCodes replaces the default list.
            const replaced = await scripted(t, http2, [unavailable, ok]);
            assert.equal((await clientOf(t, http2).get(replaced.url, { retry: { limit: 1, statusCodes: [500] } })).statusCode, 503);
        });

        it('never retries POST or PATCH unless listed in methods', async (t) => {
            const server = await scripted(t, http2, [unavailable]);
            const client = clientOf(t, http2, { retry: 2 });
            assert.equal((await client.post(server.url, { json: {} })).statusCode, 503);
            assert.equal((await client.patch(server.url, { json: {} })).statusCode, 503);
            assert.equal(server.requests(), 2);

            const listed = await scripted(t, http2, [unavailable, ok]);
            const res = await client.post(listed.url, { json: { a: 1 }, retry: { methods: ['POST'] } });
            assert.equal(res.statusCode, 200);
            assert.deepEqual(listed.methods, ['POST', 'POST']);
        });

        it('retries PUT, DELETE, HEAD and OPTIONS by default, resending the same body', async (t) => {
            for (const verb of ['put', 'delete', 'head', 'options'] as const) {
                const server = await scripted(t, http2, [unavailable, ok]);
                const res = await clientOf(t, http2, { retry: 1 })[verb](server.url);
                assert.equal(res.statusCode, 200, verb);
                assert.equal(server.requests(), 2, verb);
            }
        });

        it('retries a dropped connection with a fresh one', async (t) => {
            const server = await scripted(t, http2, ['drop', ok]);
            t.mock.method(Math, 'random', () => 0);
            const res = await clientOf(t, http2, { retry: 1 }).get(server.url);
            assert.equal(res.statusCode, 200);
            assert.equal(server.requests(), 2);
        });

        it('retries an idle socket timeout, which has its own code', async (t) => {
            const server = await scripted(t, http2, ['hang', ok]);
            t.mock.method(Math, 'random', () => 0);
            const client = clientOf(t, http2, { socketTimeoutMs: 100 });
            assert.equal((await client.get(server.url, { retry: 1 })).statusCode, 200);

            const hanging = await scripted(t, http2, ['hang']);
            await assert.rejects(client.get(hanging.url), (err: unknown) => {
                assert.ok(err instanceof UltraTonNetworkTimeoutError);
                assert.equal(err.code, 'ERR_ULTRATON_SOCKET_TIMEOUT');
                assert.equal(err.message, 'UltraTon: Socket completely idle for 100ms.');
                return true;
            });
        });

        it('keeps timeoutMs as the budget of every attempt and wait together', async (t) => {
            const server = await scripted(t, http2, ['hang']);
            t.mock.method(Math, 'random', () => 0);
            const client = clientOf(t, http2, { socketTimeoutMs: 120, timeoutMs: 400, retry: 10 });
            const started = Date.now();
            await assert.rejects(client.get(server.url), (err: unknown) => {
                assert.ok(err instanceof UltraTonNetworkTimeoutError);
                assert.equal(err.code, 'ERR_ULTRATON_TIMEOUT');
                assert.equal(err.message, 'UltraTon: Absolute execution time of 400ms exceeded.');
                return true;
            });
            // 400ms budget; the slack only absorbs a slow CI machine.
            assert.ok(Date.now() - started < 1500, `took ${Date.now() - started}ms`);
            assert.ok(server.requests() >= 2 && server.requests() <= 4, `${server.requests()} attempts`);
        });

        it('timeoutMs: 0 means no budget: retries run to the limit', async (t) => {
            const server = await scripted(t, http2, [unavailable, unavailable, ok]);
            const res = await clientOf(t, http2, { timeoutMs: 0, retry: 2 }).get(server.url);
            assert.equal(res.statusCode, 200);
            assert.equal(server.requests(), 3);
        });

        it('an abort during an attempt is not retried', async (t) => {
            const server = await scripted(t, http2, ['hang', ok]);
            const reason = new Error('stop');
            const controller = new AbortController();
            setTimeout(() => controller.abort(reason), 50);
            await assert.rejects(clientOf(t, http2, { retry: 3 }).get(server.url, { signal: controller.signal }), (err: unknown) => err === reason);
            assert.equal(server.requests(), 1);
        });

        it('the absolute timeout has its own code and is never retried', async (t) => {
            const server = await scripted(t, http2, ['hang', ok]);
            const client = clientOf(t, http2, { timeoutMs: 150, socketTimeoutMs: 0, retry: 3 });
            await assert.rejects(client.get(server.url), { code: 'ERR_ULTRATON_TIMEOUT', message: 'UltraTon: Absolute execution time of 150ms exceeded.' });
            assert.equal(server.requests(), 1);
        });

        it('waits Retry-After seconds, and accepts an HTTP date', async (t) => {
            const server = await scripted(t, http2, [{ status: 429, headers: { 'retry-after': '1' } }, ok]);
            const client = clientOf(t, http2, { retry: 1 });
            const started = Date.now();
            assert.equal((await client.get(server.url)).statusCode, 200);
            assert.ok(Date.now() - started >= 950, `waited ${Date.now() - started}ms`);

            const dated = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': new Date(Date.now() - 5000).toUTCString() } }, ok]);
            assert.equal((await client.get(dated.url)).statusCode, 200);
            assert.equal(dated.requests(), 2);
        });

        it('does not retry when Retry-After asks for more than maxDelayMs or the budget left', async (t) => {
            const client = clientOf(t, http2, { retry: 3 });
            const long = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': '5' } }, ok]);
            assert.equal((await client.get(long.url, { retry: { maxDelayMs: 1000 } })).statusCode, 503);
            assert.equal(long.requests(), 1);

            const dated = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': new Date(Date.now() + 60_000).toUTCString() } }, ok]);
            assert.equal((await client.get(dated.url)).statusCode, 503);

            const overBudget = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': '2' } }, ok]);
            assert.equal((await client.get(overBudget.url, { timeoutMs: 1000 })).statusCode, 503);
            assert.equal(overBudget.requests(), 1);
        });

        it('falls back to backoff on a malformed Retry-After', async (t) => {
            t.mock.method(Math, 'random', () => 0);
            for (const value of ['soon', '-1', '1.5', '']) {
                const server = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': value } }, ok]);
                assert.equal((await clientOf(t, http2, { retry: 1 }).get(server.url)).statusCode, 200, value);
            }
        });

        it('a signal aborts the wait between attempts', async (t) => {
            const server = await scripted(t, http2, [{ status: 503, headers: { 'retry-after': '20' } }, ok]);
            const reason = new Error('stop');
            const controller = new AbortController();
            setTimeout(() => controller.abort(reason), 50);
            const started = Date.now();
            await assert.rejects(clientOf(t, http2).get(server.url, { signal: controller.signal, retry: { limit: 1, maxDelayMs: 30_000 } }), (err: unknown) => err === reason);
            assert.ok(Date.now() - started < 1000);
            assert.equal(server.requests(), 1);
        });

        it('never retries a policy, memory or redirect error', async (t) => {
            const big = await scripted(t, http2, [{ status: 200, body: 'x'.repeat(64) }]);
            const client = clientOf(t, http2, { retry: 3 });
            await assert.rejects(client.get(big.url, { maxBodySize: 8 }), { name: 'UltraTonMemoryError' });
            assert.equal(big.requests(), 1);

            const loop = await scripted(t, http2, [{ status: 302, headers: { location: '/x' } }]);
            await assert.rejects(client.get(loop.url, { maxRedirects: 1 }), { name: 'UltraTonRedirectError' });
            assert.equal(loop.requests(), 2);

            const strict = new UltraTonClient({ http2, retry: 3 });
            t.after(() => strict.close());
            const blocked = await scripted(t, http2, [ok]);
            await assert.rejects(strict.get(blocked.url), { code: 'ERR_ULTRATON_RESERVED_IP' });
            assert.equal(blocked.requests(), 0);
        });

        it('validates DNS again on the attempt after a dropped connection (rebinding is blocked)', async (t) => {
            const server = await scripted(t, http2, ['drop', ok]);
            const answers = [{ address: '127.0.0.1', family: 4 }, { address: '10.0.0.7', family: 4 }];
            let lookups = 0;
            t.mock.method(dnsPromises, 'lookup', (async (_host: string, options?: { all?: boolean }) => {
                const answer = answers[Math.min(lookups++, answers.length - 1)];
                return options?.all ? [answer] : answer;
            }) as any);
            t.mock.method(Math, 'random', () => 0);
            const { client } = clientFor(t, http2, { permitReservedIps: ['127.0.0.1'], retry: 3 });
            // Blocked by the loopback-only rule for plain http, or by the reserved-IP policy: either way, not retried.
            await assert.rejects(client.get(`http://rebind.localhost:${server.port}/x`), (err: Error) => PLAIN_HTTP.test(err.message) || RESERVED.test(err.message));
            assert.equal(server.requests(), 1);
            assert.equal(lookups, 2);
        });

        it('calls onRetry before each wait, and a throwing onRetry ends the request with its error', async (t) => {
            const server = await scripted(t, http2, [unavailable, 'drop', ok]);
            t.mock.method(Math, 'random', () => 0);
            const seen: unknown[] = [];
            const client = clientOf(t, http2, { retry: { limit: 2, onRetry: (info: any) => seen.push(info) } });
            // A request's own retry object merges over the client's: the hook stays.
            assert.equal((await client.get(server.url, { retry: { maxDelayMs: 5000 } })).statusCode, 200);
            assert.equal(seen.length, 2);
            assert.deepEqual(seen[0], { attempt: 1, delayMs: 0, statusCode: 503 });
            const second = seen[1] as { attempt: number; delayMs: number; error: Error };
            assert.equal(second.attempt, 2);
            assert.equal(second.delayMs, 0);
            assert.equal(second.error.name, 'UltraTonNetworkError');

            const stop = new Error('give up');
            const failing = await scripted(t, http2, [unavailable, ok]);
            await assert.rejects(clientOf(t, http2).get(failing.url, { retry: { limit: 2, onRetry: () => { throw stop; } } }), (err: unknown) => err === stop);
            assert.equal(failing.requests(), 1);
        });

        it('retry: 0 on a request turns off the client retry', async (t) => {
            const server = await scripted(t, http2, [unavailable, ok]);
            assert.equal((await clientOf(t, http2, { retry: 3 }).get(server.url, { retry: 0 })).statusCode, 503);
            assert.equal(server.requests(), 1);
        });

        it('stream() retries until the headers arrive', async (t) => {
            const server = await scripted(t, http2, [unavailable, { status: 200, body: 'streamed' }]);
            const res = await clientOf(t, http2, { retry: 1 }).stream(server.url);
            assert.equal(res.statusCode, 200);
            assert.equal(await new Response(res.body).text(), 'streamed');
            assert.equal(server.requests(), 2);
        });

        it('fetch() never retries, whatever the client says', async (t) => {
            const server = await scripted(t, http2, [unavailable, ok]);
            const res = await clientOf(t, http2, { retry: 3 }).fetch(server.url);
            assert.equal(res.status, 503);
            await res.arrayBuffer();
            assert.equal(server.requests(), 1);
        });
    });
}

/**
 * An h2c server whose n-th stream (0-based, across sessions) is refused, reset, or hit by a GOAWAY, as `steps` says; the
 * last step repeats. Server-side resets emit 'error' on the server stream too, which is expected here.
 */
type H2Step = 'refuse' | 'internal' | 'goaway' | 'goawayError' | 'goawayCovering' | 'answerThenGoaway' | 'ok';
async function h2Scripted(t: TestContext, steps: H2Step[]) {
    let streams = 0;
    const server = createH2Server().on('stream', (stream: ServerHttp2Stream) => {
        const step = steps[Math.min(streams++, steps.length - 1)];
        stream.on('error', () => undefined);
        stream.resume();
        const respond = () => { stream.respond({ ':status': 200, 'content-type': 'text/plain' }); stream.end('ok'); };
        if (step === 'refuse') stream.close(h2constants.NGHTTP2_REFUSED_STREAM);
        else if (step === 'internal') stream.close(h2constants.NGHTTP2_INTERNAL_ERROR);
        // The previous stream of the session is the last one processed: this one never will be. (A lastStreamID of 0
        // cannot be sent: Node raises it to the last stream received.)
        else if (step === 'goaway') stream.session!.goaway(h2constants.NGHTTP2_NO_ERROR, stream.id! - 2);
        else if (step === 'goawayError') stream.session!.goaway(h2constants.NGHTTP2_INTERNAL_ERROR, stream.id! - 2);
        // Covers this stream: it must still complete normally.
        else if (step === 'goawayCovering') { stream.session!.goaway(h2constants.NGHTTP2_NO_ERROR, stream.id); respond(); }
        // Answers, then disowns the stream with a GOAWAY below it: a broken (or hostile) server.
        else if (step === 'answerThenGoaway') {
            stream.respond({ ':status': 200, 'content-type': 'text/plain' });
            stream.write('part', () => stream.session!.goaway(h2constants.NGHTTP2_NO_ERROR, stream.id! - 2));
        }
        else respond();
    });
    const sockets = new Set<Socket>();
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/x`, streams: () => streams };
}

describe('retry of unprocessed HTTP/2 streams (RFC 9113 8.7)', () => {
    const REFUSED = { name: 'UltraTonNetworkError', code: 'NGHTTP2_REFUSED_STREAM', message: 'UltraTon: The server did not process the request (REFUSED_STREAM).' };

    it('a REFUSED_STREAM fails with its own code, and is retried', async (t) => {
        const once = await h2Scripted(t, ['refuse', 'ok']);
        await assert.rejects(clientOf(t, true).get(once.url), REFUSED);

        const server = await h2Scripted(t, ['refuse', 'ok']);
        assert.equal((await clientOf(t, true, { retry: 1 }).get(server.url)).statusCode, 200);
        assert.equal(server.streams(), 2);
    });

    it('any other reset (INTERNAL_ERROR) is not retried', async (t) => {
        const server = await h2Scripted(t, ['internal', 'ok']);
        await assert.rejects(clientOf(t, true, { retry: 3 }).get(server.url), { code: 'ERR_HTTP2_STREAM_ERROR' });
        assert.equal(server.streams(), 1);
    });

    it('a stream above the last one a GOAWAY processed fails as refused, with or without an error code', async (t) => {
        for (const step of ['goaway', 'goawayError'] as const) {
            const server = await h2Scripted(t, ['ok', step, 'ok']);
            const client = clientOf(t, true);
            assert.equal((await client.get(server.url)).text(), 'ok');
            await assert.rejects(client.get(server.url), REFUSED, step);
        }
    });

    it('is retried on a new session after a GOAWAY, with or without an error code', async (t) => {
        for (const step of ['goaway', 'goawayError'] as const) {
            const server = await h2Scripted(t, ['ok', step, 'ok']);
            const client = clientOf(t, true, { retry: 1, timeoutMs: 5000 });
            await client.get(server.url);
            const res = await client.get(server.url);
            assert.equal(res.statusCode, 200, step);
            assert.equal(res.text(), 'ok');
            assert.equal(server.streams(), 3, step);
        }
    });

    it('a stream already answered is never taken for refused, even if a GOAWAY disowns it', async (t) => {
        const server = await h2Scripted(t, ['ok', 'answerThenGoaway', 'ok']);
        const client = clientOf(t, true, { timeoutMs: 3000 });
        await client.post(server.url, { json: {} });
        await assert.rejects(
            client.post(server.url, { json: {}, retry: { limit: 1, methods: ['POST'] } }),
            (err: any) => err.code !== 'NGHTTP2_REFUSED_STREAM',
        );
        assert.equal(server.streams(), 2);
    });

    it('a stream the GOAWAY covers still completes', async (t) => {
        const server = await h2Scripted(t, ['goawayCovering', 'ok']);
        const client = clientOf(t, true);
        assert.equal((await client.get(server.url)).text(), 'ok');
        // The retired session is replaced by a new one for the next request.
        assert.equal((await client.get(server.url)).text(), 'ok');
        assert.equal(server.streams(), 2);
    });

    it('watches GOAWAY with one listener per session, however many streams are in flight', async (t) => {
        const server = await h2Scripted(t, ['ok']);
        const warnings: Error[] = [];
        const onWarning = (w: Error) => warnings.push(w);
        process.on('warning', onWarning);
        t.after(() => process.off('warning', onWarning));
        const connect = t.mock.fn(nativeH2Connect);
        const client = new UltraTonClient({ http2: true, permitReservedIps: true, [kSessionManager]: new Http2SessionManager({}, connect) } as any);
        t.after(() => client.close());
        const before = await Promise.all(Array.from({ length: 20 }, () => client.get(server.url)));
        assert.ok(before.every(res => res.statusCode === 200));
        assert.equal(connect.mock.callCount(), 1);
        const session = connect.mock.calls[0].result as ClientHttp2Session;
        const listeners = session.listenerCount('goaway');
        await Promise.all(Array.from({ length: 20 }, () => client.get(server.url)));
        assert.equal(session.listenerCount('goaway'), listeners);
        assert.ok(listeners <= 2, `${listeners} goaway listeners`);
        await new Promise(r => setImmediate(r));
        assert.deepEqual(warnings.filter(w => w.name === 'MaxListenersExceededWarning'), []);
    });

    it('POST is still only retried when listed', async (t) => {
        const server = await h2Scripted(t, ['refuse', 'ok']);
        await assert.rejects(clientOf(t, true, { retry: 2 }).post(server.url, { json: {} }), REFUSED);
        const listed = await h2Scripted(t, ['refuse', 'ok']);
        assert.equal((await clientOf(t, true).post(listed.url, { json: {}, retry: { limit: 1, methods: ['POST'] } })).statusCode, 200);
    });
});

describe('retry option validation', () => {
    const url = 'https://example.com/';
    const client = new UltraTonClient();
    const cases: Array<[unknown, RegExp]> = [
        [11, /^UltraTon: Expected 'retry' to be an integer from 0 to 10, received 11\.$/],
        [-1, /'retry' to be an integer from 0 to 10/],
        [1.5, /'retry' to be an integer from 0 to 10/],
        [true, /^UltraTon: Expected 'retry' to be a number or a plain object, received boolean\.$/],
        [null, /^UltraTon: Expected 'retry' to be a number or a plain object, received null\.$/],
        [{ limit: 11 }, /'retry\.limit' to be an integer from 0 to 10/],
        [{ maxDelayMs: -1 }, /'retry\.maxDelayMs' to be an integer from 0 to 2147483647/],
        [{ methods: ['post'] }, /^UltraTon: Expected 'retry\.methods' to be an array of HTTP methods in uppercase, received 'post'\.$/],
        [{ methods: 'GET' }, /'retry\.methods' to be an array/],
        [{ statusCodes: [200] }, /^UltraTon: Expected 'retry\.statusCodes' to be an array of integers from 400 to 599/],
        [{ statusCodes: [503.5] }, /'retry\.statusCodes' to be an array of integers from 400 to 599/],
        [{ onRetry: 'log' }, /^UltraTon: Expected 'retry\.onRetry' to be a function, received string\.$/],
        [{ retries: 2 }, /^UltraTon: Unknown retry option 'retries'\. Valid retry options: limit, methods, statusCodes, maxDelayMs, onRetry\.$/],
    ];

    it('rejects a bad retry on a request, before connecting', async () => {
        for (const [retry, pattern] of cases) {
            await assert.rejects(client.get(url, { retry } as any), (err: Error) => {
                assert.ok(err instanceof TypeError, String(retry));
                assert.match(err.message, pattern);
                return true;
            });
        }
    });

    it('rejects a bad retry on the constructor', () => {
        for (const [retry, pattern] of cases) {
            assert.throws(() => new UltraTonClient({ retry } as any), (err: Error) => err instanceof TypeError && pattern.test(err.message));
        }
    });

    it('points retries and maxRetries at retry', async () => {
        for (const key of ['retries', 'maxRetries']) {
            await assert.rejects(client.get(url, { [key]: 2 } as any), { message: `UltraTon: Unknown option '${key}'. Use 'retry': a number of retries, or { limit, methods, statusCodes, maxDelayMs, onRetry }.` });
            assert.throws(() => new UltraTonClient({ [key]: 2 } as any), { message: `UltraTon: Unknown option '${key}'. Use 'retry': a number of retries, or { limit, methods, statusCodes, maxDelayMs, onRetry }.` });
        }
    });

    it('copies the lists, so mutating them later changes nothing', async (t) => {
        const statusCodes = [503];
        const local = new UltraTonClient({ permitReservedIps: true, retry: { limit: 1, statusCodes } });
        t.after(() => local.close());
        statusCodes.push(500);
        const server = await scripted(t, false, [{ status: 500, headers: { 'retry-after': '0' } }, ok]);
        assert.equal((await local.get(server.url)).statusCode, 500);
    });

    it('is not inherited from a polluted Object.prototype', async (t) => {
        const server = await scripted(t, false, [unavailable, ok]);
        const local = clientOf(t, false);
        (Object.prototype as any).retry = 3;
        try {
            assert.equal((await local.get(server.url)).statusCode, 503);
        } finally {
            delete (Object.prototype as any).retry;
        }
    });

    it('never takes a retry field from a polluted Object.prototype', async (t) => {
        const server = await scripted(t, false, [unavailable]);
        const local = clientOf(t, false, { retry: { maxDelayMs: 5 } });
        const polluted = { limit: 'x', methods: ['POST'], statusCodes: [503], onRetry: () => { throw new Error('polluted hook'); } };
        Object.assign(Object.prototype, polluted);
        try {
            // POST is not retried (methods stays the default), and GET stops at the default limit of 2.
            assert.equal((await local.post(server.url, { json: {} })).statusCode, 503);
            assert.equal(server.requests(), 1);
            assert.equal((await local.get(server.url)).statusCode, 503);
            assert.equal(server.requests(), 4);
        } finally {
            for (const key of Object.keys(polluted)) delete (Object.prototype as any)[key];
        }
    });
});
