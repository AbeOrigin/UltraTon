/**
 * diagnostics_channel events: one start and one response-or-error per client call (get, stream, fetch), retry events
 * in between, and nothing sensitive in any payload (no headers, query, body, credentials, cause or address).
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import diagnosticsChannel from 'node:diagnostics_channel';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

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
