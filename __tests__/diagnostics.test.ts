/**
 * diagnostics_channel events: one start and one response-or-error per client call (get, stream, fetch), retry events
 * in between, and nothing sensitive in any payload (no headers, query, body, credentials, cause or address). The
 * response and error events carry the per-phase timings of the call's last hop, measured only while someone listens.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import diagnosticsChannel from 'node:diagnostics_channel';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createSecureServer, createServer as createH2Server } from 'node:http2';
import net, { type AddressInfo, type Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { Http1Engine } from '../src/engines/http1.ts';
import { Http2Engine } from '../src/engines/http2.ts';
import { observeRequest, TimingsCollector } from '../src/helpers/diagnostics.ts';
import { KEEP_ALIVE } from '../src/helpers/keep-alive.ts';
import { mockDns, v4 } from './fixtures/net-fixtures.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

const CHANNELS = ['ultraton:request:start', 'ultraton:request:response', 'ultraton:request:error', 'ultraton:request:retry'] as const;

/** Records every event of the four channels, in order, until the test ends. */
function record(t: TestContext) {
    const events: Array<{ channel: string; message: any }> = [];
    for (const name of CHANNELS) {
        const listener = (message: unknown) => events.push({ channel: name.slice('ultraton:request:'.length), message });
        diagnosticsChannel.subscribe(name, listener);
        t.after(() => diagnosticsChannel.unsubscribe(name, listener));
    }
    return events;
}

/** A loopback server answering each request with the next status in `statuses` (the last one repeats). */
async function server(t: TestContext, statuses: number[] = [200], retryAfter = '0') {
    let n = 0;
    const sockets = new Set<Socket>();
    const srv = http.createServer((_req, res) => {
        const status = statuses[Math.min(n++, statuses.length - 1)];
        res.writeHead(status, { 'content-type': 'text/plain', 'retry-after': retryAfter });
        res.end(String(status));
    });
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

describe('diagnostics_channel', () => {
    it('publishes start then response, with method, origin, path (no query), status and duration', async (t) => {
        const base = await server(t);
        const events = record(t);
        await clientOf(t).get(`${base}/users/7?token=s3cret`, { headers: { authorization: 'Bearer x' } });
        assert.deepEqual(events.map(e => e.channel), ['start', 'response']);
        const [start, response] = events;
        assert.deepEqual({ ...start.message.request }, { method: 'GET', origin: base, path: '/users/7' });
        // The same request object on every event of one call, so a subscriber can key spans on it.
        assert.equal(response.message.request, start.message.request);
        assert.equal(response.message.statusCode, 200);
        assert.ok(typeof response.message.durationMs === 'number' && response.message.durationMs >= 0);
        assert.ok(Object.isFrozen(start.message.request));
    });

    it('never carries headers, the query, the body, credentials or addresses', async (t) => {
        const base = await server(t);
        const events = record(t);
        await clientOf(t).post(`${base}/x?api_key=s3cret`, { json: { password: 'hunter2' }, auth: 'user:pw', headers: { cookie: 'sid=abc' } });
        const serialized = JSON.stringify(events.map(e => e.message));
        for (const secret of ['s3cret', 'hunter2', 'user:pw', 'sid=abc', 'authorization', 'cookie']) {
            assert.ok(!serialized.includes(secret), `${secret} leaked: ${serialized}`);
        }
    });

    it('publishes error with only the name and code, and the duration', async (t) => {
        const events = record(t);
        // Reserved address with the default policy: a policy error, before any socket.
        const strict = new UltraTonClient();
        t.after(() => strict.close());
        await assert.rejects(strict.get('https://10.0.0.1/admin?x=1'));
        assert.deepEqual(events.map(e => e.channel), ['start', 'error']);
        const { error, durationMs, request } = events[1].message;
        assert.deepEqual(error, { name: 'SecureHttpError', code: 'ERR_ULTRATON_RESERVED_IP' });
        assert.equal(request.path, '/admin');
        assert.ok(durationMs >= 0);
    });

    it('publishes a retry event before each wait, then the final response', async (t) => {
        const base = await server(t, [503, 503, 200]);
        const events = record(t);
        const res = await clientOf(t, { retry: 2 }).get(`${base}/flaky`);
        assert.equal(res.statusCode, 200);
        assert.deepEqual(events.map(e => e.channel), ['start', 'retry', 'retry', 'response']);
        assert.deepEqual(events.slice(1, 3).map(e => [e.message.attempt, e.message.statusCode]), [[1, 503], [2, 503]]);
        assert.equal(events[1].message.request, events[0].message.request);
    });

    it("keeps the caller's own onRetry working alongside the channel", async (t) => {
        const base = await server(t, [503, 200]);
        const events = record(t);
        const seen: number[] = [];
        await clientOf(t).get(`${base}/x`, { retry: { limit: 1, onRetry: info => seen.push(info.attempt) } });
        assert.deepEqual(seen, [1]);
        assert.deepEqual(events.map(e => e.channel), ['start', 'retry', 'response']);
    });

    it('covers stream() and fetch() too', async (t) => {
        const base = await server(t);
        const events = record(t);
        const client = clientOf(t);
        const streamed = await client.stream(`${base}/s`);
        await streamed.body.cancel();
        const fetched = await client.fetch(`${base}/f`);
        await fetched.arrayBuffer();
        assert.deepEqual(events.map(e => [e.channel, e.message.request.path]), [['start', '/s'], ['response', '/s'], ['start', '/f'], ['response', '/f']]);
    });

    it('publishes nothing for invalid options (thrown before any request starts)', async (t) => {
        const events = record(t);
        await assert.rejects(clientOf(t).get('https://example.com/', { bogus: 1 } as any), TypeError);
        assert.deepEqual(events, []);
    });

    it('drops ;params from the path, and never puts URL credentials in origin', async (t) => {
        const base = await server(t);
        const events = record(t);
        await clientOf(t).get(`${base}/a;jsessionid=SECRET1/b;v=2/c`);
        assert.equal(events[0].message.request.path, '/a/b/c');
        // Credentials in the URL are refused by the engine; the events still never carry them.
        await assert.rejects(clientOf(t).get(`${base.replace('http://', 'http://user:SECRET2@')}/x`));
        const serialized = JSON.stringify(events.map(e => e.message));
        assert.ok(!serialized.includes('SECRET1') && !serialized.includes('SECRET2') && !serialized.includes('user'), serialized);
        assert.deepEqual(events.slice(2).map(e => e.channel), ['start', 'error']);
    });

    it('a throwing onRetry ends the call with one error event and no retry event', async (t) => {
        const base = await server(t, [503, 200]);
        const events = record(t);
        const stop = new Error('give up');
        await assert.rejects(clientOf(t).get(`${base}/x`, { retry: { limit: 2, onRetry: () => { throw stop; } } }), (err: unknown) => err === stop);
        assert.deepEqual(events.map(e => e.channel), ['start', 'error']);
    });

    it('an abort during the retry wait, or close() mid-request, publishes error exactly once', async (t) => {
        // Retry-After: 5, so the retry waits and the abort lands in the wait.
        const base = await server(t, [503], '5');
        const events = record(t);
        const controller = new AbortController();
        const waiting = clientOf(t, { retry: { limit: 1, maxDelayMs: 60_000 } }).get(`${base}/x`, { signal: controller.signal });
        setTimeout(() => controller.abort(new Error('stop')), 50);
        await assert.rejects(waiting, { message: 'stop' });
        assert.equal(events.filter(e => e.channel === 'error').length, 1);

        const hanging = http.createServer(() => undefined);
        await new Promise<void>(r => hanging.listen(0, '127.0.0.1', r));
        t.after(() => new Promise<void>(r => { hanging.closeAllConnections(); hanging.close(() => r()); }));
        const client = clientOf(t);
        const pending = client.get(`http://127.0.0.1:${(hanging.address() as AddressInfo).port}/slow`);
        setTimeout(() => client.close(), 20);
        await assert.rejects(pending, { message: 'UltraTon: Client is closed.' });
        const slow = events.filter(e => e.message.request.path === '/slow');
        assert.deepEqual(slow.map(e => e.channel), ['start', 'error']);
    });

    it('an abort is reported with the reason name, and no code', async (t) => {
        const base = await server(t);
        const events = record(t);
        await assert.rejects(clientOf(t).get(`${base}/x`, { signal: AbortSignal.abort(new Error('stop')) }));
        assert.deepEqual(events[1].message.error, { name: 'Error', code: undefined });
    });
});

/**
 * A loopback server of either engine (h2c or h2 for HTTP/2), plain or TLS for `localhost` (DNS mocked), answering each
 * request with the next status in `statuses` (the last one repeats); the first answer waits `firstDelayMs`.
 */
async function serveEngine(t: TestContext, http2: boolean, { secure = false, statuses = [200], firstDelayMs = 0 } = {}) {
    let n = 0;
    const handler = (_req: unknown, res: http.ServerResponse) => {
        const index = n++;
        const status = statuses[Math.min(index, statuses.length - 1)];
        const send = () => { res.writeHead(status, { 'retry-after': '0' }); res.end(String(status)); };
        if (index === 0 && firstDelayMs > 0) setTimeout(send, firstDelayMs);
        else send();
    };
    const tlsOptions = { cert: CERT, key: KEY };
    const srv: net.Server = http2
        ? (secure ? createSecureServer(tlsOptions, handler as any) : createH2Server(handler as any))
        : (secure ? https.createServer(tlsOptions, handler) : http.createServer(handler));
    const sockets = new Set<Socket>();
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    const port = (srv.address() as AddressInfo).port;
    if (!secure) return `http://127.0.0.1:${port}`;
    mockDns(t, { localhost: [v4('127.0.0.1')] });
    return `https://localhost:${port}`;
}

/** The timings of the last response or error event recorded. */
const lastTimings = (events: Array<{ channel: string; message: any }>) =>
    events.filter(e => e.channel === 'response' || e.channel === 'error').at(-1)!.message.timings;

const isDuration = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0;

describe('timings on the diagnostics events', () => {
    it('the response event carries timings with totalMs (the durationMs) and reusedConnection', async (t) => {
        const base = await server(t);
        const events = record(t);
        await clientOf(t).get(`${base}/x`);
        const { timings, durationMs } = events[1].message;
        assert.ok(isDuration(timings.totalMs));
        assert.equal(timings.totalMs, durationMs);
        assert.equal(typeof timings.reusedConnection, 'boolean');
        // Only numbers and one boolean: nothing else can ever leak through them.
        for (const value of Object.values(timings)) assert.ok(typeof value === 'number' || typeof value === 'boolean', String(value));
    });

    it('without subscribers nothing is measured: no observer, and the engine gets no collector', async (t) => {
        const base = await server(t);
        const h1 = t.mock.method(Http1Engine.prototype, 'request');
        const h2 = t.mock.method(Http2Engine.prototype, 'request');
        assert.equal(observeRequest('GET', `${base}/x`), undefined);
        await clientOf(t).get(`${base}/x`);
        assert.equal(h1.mock.calls[0].arguments[3], undefined);
        const h2Base = await serveEngine(t, true);
        await clientOf(t, { http2: true }).get(`${h2Base}/x`);
        assert.equal(h2.mock.calls[0].arguments[3], undefined);

        // With one, the same call hands the engine a collector.
        record(t);
        await clientOf(t).get(`${base}/x`);
        assert.ok(h1.mock.calls[1].arguments[3] instanceof TimingsCollector);
    });

    for (const http2 of [false, true]) {
        const engine = http2 ? 'HTTP/2' : 'HTTP/1.1';

        it(`${engine} over TLS on a new connection: dns, connect, ${http2 ? 'no tls (in connect)' : 'tls'} and first byte`, { timeout: 5000 }, async (t) => {
            const url = await serveEngine(t, http2, { secure: true });
            const events = record(t);
            await clientOf(t, { http2, tls: { ca: CERT } }).get(`${url}/x`);
            const timings = lastTimings(events);
            assert.ok(isDuration(timings.dnsMs), `dnsMs ${timings.dnsMs}`);
            assert.ok(isDuration(timings.connectMs), `connectMs ${timings.connectMs}`);
            // Node reports TCP and TLS of an HTTP/2 session as one connect.
            if (http2) assert.equal(timings.tlsMs, undefined);
            else assert.ok(isDuration(timings.tlsMs), `tlsMs ${timings.tlsMs}`);
            assert.ok(isDuration(timings.firstByteMs), `firstByteMs ${timings.firstByteMs}`);
            assert.equal(timings.reusedConnection, false);
            assert.ok(timings.totalMs >= timings.firstByteMs);
        });

        it(`${engine} over http to an IP literal: no lookup, no tls; the second call says whether it reused the connection`, { timeout: 5000 }, async (t) => {
            const base = await serveEngine(t, http2);
            const events = record(t);
            const client = clientOf(t, { http2 });
            await client.get(`${base}/one`);
            const first = lastTimings(events);
            assert.equal(first.dnsMs, undefined);
            assert.equal(first.tlsMs, undefined);
            assert.ok(isDuration(first.connectMs));
            assert.ok(isDuration(first.firstByteMs));
            assert.equal(first.reusedConnection, false);

            await client.get(`${base}/two`);
            const second = lastTimings(events);
            // HTTP/2 always pools its session; HTTP/1.1 pools sockets only on a Node with the keep-alive fix.
            const reused = http2 || KEEP_ALIVE;
            assert.equal(second.reusedConnection, reused);
            if (reused) {
                assert.equal(second.dnsMs, undefined);
                assert.equal(second.connectMs, undefined);
            }
            assert.ok(isDuration(second.firstByteMs));
        });

        it(`${engine}: a refused connection publishes error with timings and no first byte`, { timeout: 10_000 }, async (t) => {
            // A port that was just free: nothing listens on it.
            const probe = net.createServer();
            await new Promise<void>(r => probe.listen(0, '127.0.0.1', r));
            const port = (probe.address() as AddressInfo).port;
            await new Promise<void>(r => probe.close(() => r()));
            const events = record(t);
            await assert.rejects(clientOf(t, { http2 }).get(`http://127.0.0.1:${port}/x`), { code: 'ECONNREFUSED' });
            assert.deepEqual(events.map(e => e.channel), ['start', 'error']);
            const { timings, durationMs } = events[1].message;
            assert.ok(isDuration(timings.totalMs));
            assert.equal(timings.totalMs, durationMs);
            assert.equal(timings.reusedConnection, false);
            assert.equal(timings.firstByteMs, undefined);
        });

        it(`${engine}: after a retry the phases are those of the attempt that answered`, { timeout: 5000 }, async (t) => {
            // The first attempt waits 400 ms for its first byte; the second answers at once.
            const base = await serveEngine(t, http2, { statuses: [503, 200], firstDelayMs: 400 });
            const events = record(t);
            const res = await clientOf(t, { http2, retry: 1 }).get(`${base}/x`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual(events.map(e => e.channel), ['start', 'retry', 'response']);
            const timings = lastTimings(events);
            assert.ok(timings.totalMs >= 390 + events[1].message.delayMs, `totalMs ${timings.totalMs}`);
            assert.ok(isDuration(timings.firstByteMs));
            assert.ok(timings.firstByteMs < 400, `firstByteMs ${timings.firstByteMs}`);
            assert.ok(timings.firstByteMs < timings.totalMs);
        });
    }
});
