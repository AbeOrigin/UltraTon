/**
 * `maxConcurrency`: at most N calls in flight per origin, the rest waiting in order. The wait counts against
 * `timeoutMs`, an abort or `close()` takes a call out of the queue, and every call gives its slot back exactly once
 * (for `stream()`, when its body ends, fails or is cancelled). Unit tests of OriginLimiter first, then the client
 * against loopback servers on both engines.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import diagnosticsChannel from 'node:diagnostics_channel';
import http from 'node:http';
import { createServer as createH2Server, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { OriginLimiter } from '../src/helpers/concurrency.ts';
import { SecureHttpError } from '../src/errors.ts';
import { UltraTonClient } from '../src/http-client.ts';

const A = 'https://a.example';
const B = 'https://b.example';

/** Resolves with 'pending' if `promise` has not settled within `ms`. */
const settledWithin = <T>(promise: Promise<T>, ms: number): Promise<T | 'pending'> =>
    Promise.race([promise, new Promise<'pending'>(resolve => setTimeout(() => resolve('pending'), ms))]);

describe('OriginLimiter', () => {
    it('grants up to the limit at once and the rest in the order they asked', async () => {
        const limiter = new OriginLimiter(2);
        const order: string[] = [];
        const first = await limiter.acquire(A, undefined, 0);
        const second = await limiter.acquire(A, undefined, 0);
        const waiting = ['c', 'd', 'e'].map(name => limiter.acquire(A, undefined, 0).then(release => { order.push(name); return release; }));
        assert.equal(await settledWithin(waiting[0], 20), 'pending');
        first();
        const c = await waiting[0];
        assert.deepEqual(order, ['c']);
        second();
        c();
        const [, d, e] = await Promise.all(waiting);
        assert.deepEqual(order, ['c', 'd', 'e']);
        d();
        e();
    });

    it('keeps each origin apart', async () => {
        const limiter = new OriginLimiter(1);
        const a = await limiter.acquire(A, undefined, 0);
        const b = await settledWithin(limiter.acquire(B, undefined, 0), 20);
        assert.equal(typeof b, 'function');
        a();
        (b as () => void)();
    });

    it('a release called twice gives back one slot', async () => {
        const limiter = new OriginLimiter(1);
        const first = await limiter.acquire(A, undefined, 0);
        first();
        first();
        const second = await limiter.acquire(A, undefined, 0);
        // Had the second call of first() freed another slot, this one would not wait.
        assert.equal(await settledWithin(limiter.acquire(A, undefined, 0), 30), 'pending');
        second();
    });

    it('an abort while waiting rejects with the reason and leaves the queue', async () => {
        const limiter = new OriginLimiter(1);
        const held = await limiter.acquire(A, undefined, 0);
        const controller = new AbortController();
        const aborted = limiter.acquire(A, controller.signal, 0);
        const next = limiter.acquire(A, undefined, 0);
        const reason = new Error('stop');
        controller.abort(reason);
        await assert.rejects(aborted, error => error === reason);
        held();
        // The aborted call took no slot: the one behind it gets the only one.
        const release = await next;
        assert.equal(await settledWithin(limiter.acquire(A, undefined, 0), 30), 'pending');
        release();
    });

    it('an already aborted signal never queues', async () => {
        const limiter = new OriginLimiter(1);
        const held = await limiter.acquire(A, undefined, 0);
        const reason = new Error('before');
        await assert.rejects(limiter.acquire(A, AbortSignal.abort(reason), 0), error => error === reason);
        held();
        (await limiter.acquire(A, undefined, 0))();
    });

    it('rejects with ERR_ULTRATON_TIMEOUT when remainingMs runs out first, naming it', async () => {
        const limiter = new OriginLimiter(1);
        const held = await limiter.acquire(A, undefined, 0);
        await assert.rejects(limiter.acquire(A, undefined, 40), { code: 'ERR_ULTRATON_TIMEOUT', message: 'UltraTon: Absolute execution time of 40ms exceeded.' });
        held();
        (await limiter.acquire(A, undefined, 40))();
    });

    it('close() rejects everyone waiting and every later call; a slot in use is still given back', async () => {
        const limiter = new OriginLimiter(1);
        const held = await limiter.acquire(A, undefined, 0);
        const b = await limiter.acquire(B, undefined, 0);
        const waiting = limiter.acquire(A, undefined, 0);
        const closed = new SecureHttpError('UltraTon: Client is closed.');
        limiter.close(closed);
        await assert.rejects(waiting, error => error === closed);
        await assert.rejects(limiter.acquire(B, undefined, 0), error => error === closed);
        held();
        b();
    });

    it('counts every slot back on every path', async () => {
        const limiter = new OriginLimiter(2);
        let granted = 0;
        let released = 0;
        const counted = async (signal?: AbortSignal, remainingMs = 0) => {
            const release = await limiter.acquire(A, signal, remainingMs);
            granted++;
            return () => { released++; release(); release(); };
        };
        const one = await counted();
        const two = await counted();
        const controller = new AbortController();
        const outcomes = Promise.allSettled([counted(controller.signal), counted(undefined, 20), counted()]);
        controller.abort();
        await new Promise(resolve => setTimeout(resolve, 40));
        one();
        two();
        const results = await outcomes;
        assert.deepEqual(results.map(r => r.status), ['rejected', 'rejected', 'fulfilled']);
        (results[2] as PromiseFulfilledResult<() => void>).value();
        assert.equal(granted, 3);
        assert.equal(released, 3);
        // Both slots are free again.
        const again = [await counted(), await counted()];
        again.forEach(release => release());
    });
});

type Engine = 'http1' | 'http2';
const ENGINES: Engine[] = ['http1', 'http2'];

/**
 * A loopback server that answers every request after `delayMs` (or as `respond` says), counting what it saw: `seen`
 * requests in all, `open` at this moment, `maxOpen` at most at once.
 */
async function server(t: TestContext, engine: Engine, delayMs: number, respond?: (path: string, reply: (status: number, body: string, end?: boolean) => void, kill: () => void) => void) {
    const stats = { seen: 0, open: 0, maxOpen: 0 };
    const sockets = new Set<Socket>();
    const handle = (path: string, reply: (status: number, body: string, end?: boolean) => void, kill: () => void, onDone: (fn: () => void) => void) => {
        stats.seen++;
        stats.open++;
        stats.maxOpen = Math.max(stats.maxOpen, stats.open);
        let done = false;
        onDone(() => { if (!done) { done = true; stats.open--; } });
        if (respond) return respond(path, reply, kill);
        setTimeout(() => reply(200, 'ok'), delayMs);
    };
    let srv: http.Server | ReturnType<typeof createH2Server>;
    if (engine === 'http1') {
        srv = http.createServer((req, res) => handle(req.url ?? '/', (status, body, end = true) => {
            if (res.destroyed) return;
            res.writeHead(status, { 'content-type': 'text/plain' });
            if (end) res.end(body);
            else res.write(body);
        }, () => res.socket?.destroy(), fn => res.on('close', fn)));
    } else {
        const h2 = createH2Server();
        h2.on('session', session => session.on('error', () => {}));
        h2.on('stream', (stream: ServerHttp2Stream, headers) => {
            stream.on('error', () => {});
            handle(String(headers[':path']), (status, body, end = true) => {
                if (stream.destroyed || stream.closed) return;
                stream.respond({ ':status': status, 'content-type': 'text/plain' });
                if (end) stream.end(body);
                else stream.write(body);
            }, () => stream.session?.destroy(), fn => stream.on('close', fn));
        });
        srv = h2;
    }
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, stats };
}

function clientOf(t: TestContext, engine: Engine, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2: engine === 'http2', permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

/** The events of `channel` (the response one by default) of every call until the test ends. */
function responses(t: TestContext, channel = 'ultraton:request:response') {
    const events: any[] = [];
    const listener = (message: unknown) => events.push(message);
    diagnosticsChannel.subscribe(channel, listener);
    t.after(() => diagnosticsChannel.unsubscribe(channel, listener));
    return events;
}

for (const engine of ENGINES) {
    describe(`maxConcurrency (${engine})`, () => {
        it('five calls with maxConcurrency 2: never more than 2 in flight, all five answered, the queued ones with queuedMs', async (t) => {
            const { url, stats } = await server(t, engine, 150);
            const events = responses(t);
            const client = clientOf(t, engine, { maxConcurrency: 2 });
            const results = await Promise.all(Array.from({ length: 5 }, (_, i) => client.get(`${url}/${i}`)));
            assert.deepEqual(results.map(r => r.statusCode), [200, 200, 200, 200, 200]);
            assert.equal(stats.seen, 5);
            assert.equal(stats.maxOpen, 2);
            const queued = events.map(e => e.timings.queuedMs).filter(ms => ms !== undefined);
            assert.equal(queued.length, 3);
            assert.ok(queued.every(ms => typeof ms === 'number' && ms > 0), String(queued));
            // The wait is part of the call: totalMs covers it.
            for (const e of events) if (e.timings.queuedMs !== undefined) assert.ok(e.timings.totalMs >= e.timings.queuedMs);
        });

        it('without the option, five calls reach the server together and nothing is queued', async (t) => {
            const { url, stats } = await server(t, engine, 150);
            const events = responses(t);
            const client = clientOf(t, engine);
            await Promise.all(Array.from({ length: 5 }, (_, i) => client.get(`${url}/${i}`)));
            assert.equal(stats.maxOpen, 5);
            assert.equal(events.length, 5);
            assert.ok(events.every(e => e.timings.queuedMs === undefined && !('queuedMs' in e.timings)));
        });

        it('another origin does not wait for a saturated one', async (t) => {
            const slow = await server(t, engine, 500);
            const fast = await server(t, engine, 0);
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            let slowDone = false;
            const first = client.get(slow.url).then(r => { slowDone = true; return r; });
            await new Promise(resolve => setTimeout(resolve, 50));
            assert.equal((await client.get(fast.url)).statusCode, 200);
            assert.equal(slowDone, false);
            await first;
        });

        it('a call still queued when timeoutMs runs out rejects with ERR_ULTRATON_TIMEOUT, unseen by the server', async (t) => {
            const { url, stats } = await server(t, engine, 500);
            const errors = responses(t, 'ultraton:request:error');
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const first = client.get(url);
            const started = Date.now();
            await assert.rejects(client.get(url, { timeoutMs: 100 }), { code: 'ERR_ULTRATON_TIMEOUT', message: 'UltraTon: Absolute execution time of 100ms exceeded.' });
            assert.ok(Date.now() - started < 400);
            assert.equal(stats.seen, 1);
            // The error event says where the time went: all of it in the queue.
            assert.equal(errors.length, 1);
            assert.ok(errors[0].timings.queuedMs >= 90, String(errors[0].timings.queuedMs));
            assert.equal((await first).statusCode, 200);
            assert.equal(stats.seen, 1);
        });

        it('the wait comes out of timeoutMs: a call granted late gets what is left, and the error names the whole budget', async (t) => {
            const { url, stats } = await server(t, engine, 150);
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const first = client.get(url);
            // 150 ms queued + 150 ms answering > 250 ms, though either alone fits.
            await assert.rejects(client.get(url, { timeoutMs: 250 }), { code: 'ERR_ULTRATON_TIMEOUT', message: 'UltraTon: Absolute execution time of 250ms exceeded.' });
            assert.equal(stats.seen, 2);
            await first;
        });

        it('an abort while queued rejects with signal.reason, unseen by the server', async (t) => {
            const { url, stats } = await server(t, engine, 500);
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const first = client.get(url);
            const controller = new AbortController();
            const reason = new Error('changed my mind');
            setTimeout(() => controller.abort(reason), 50);
            await assert.rejects(client.get(url, { signal: controller.signal }), error => error === reason);
            assert.equal(stats.seen, 1);
            await first;
            assert.equal(stats.seen, 1);
        });

        it('close() rejects the queued calls with Client is closed', async (t) => {
            const { url, stats } = await server(t, engine, 300);
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const inFlight = client.get(url);
            const queued = [client.get(url), client.stream(url)];
            await new Promise(resolve => setTimeout(resolve, 50));
            await client.close();
            for (const call of queued) await assert.rejects(call, /Client is closed/);
            // The call in flight ends as it does today on close(): whatever it is, it settles.
            await Promise.allSettled([inFlight]);
            assert.equal(stats.seen, 1);
        });

        it('stream() holds its slot until the body is cancelled', async (t) => {
            const { url } = await server(t, engine, 0);
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const res = await client.stream(url);
            const next = client.get(url);
            assert.equal(await settledWithin(next, 150), 'pending');
            await res.body.cancel();
            assert.equal((await next).statusCode, 200);
        });

        it('stream() gives its slot back when the body is read to the end, or when assertOk() refuses it', async (t) => {
            const { url } = await server(t, engine, 0, (path, reply) => reply(path === '/fail' ? 500 : 200, 'body'));
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            const read = await client.stream(url);
            assert.equal(await new Response(read.body).text(), 'body');
            assert.equal((await client.get(url, { timeoutMs: 2000 })).statusCode, 200);
            const refused = await client.stream(`${url}/fail`);
            assert.throws(() => refused.assertOk(), { code: 'ERR_ULTRATON_HTTP_STATUS' });
            assert.equal((await client.get(url, { timeoutMs: 2000 })).statusCode, 200);
            // HEAD has no body to read: its slot is free at once.
            await client.stream(url, { method: 'HEAD' });
            assert.equal((await client.get(url, { timeoutMs: 2000 })).statusCode, 200);
            // fetch() goes through stream(): its body read to the end gives the slot back too.
            const fetched = await client.fetch(url);
            assert.equal(await fetched.text(), 'body');
            assert.equal((await client.get(url, { timeoutMs: 2000 })).statusCode, 200);
        });

        it('every failure path gives its slot back', async (t) => {
            const { url, stats } = await server(t, engine, 0, (path, reply, kill) => {
                if (path === '/kill') return kill();
                if (path === '/partial') return reply(200, 'part', false);
                setTimeout(() => reply(200, 'ok'), path === '/slow' ? 300 : 0);
            });
            const client = clientOf(t, engine, { maxConcurrency: 1 });
            // A network error, a timeout in flight, an abort in flight, a bad option, then a stream body that fails.
            await assert.rejects(client.get(`${url}/kill`));
            await assert.rejects(client.get(`${url}/slow`, { timeoutMs: 50 }), { code: 'ERR_ULTRATON_TIMEOUT' });
            await assert.rejects(client.get(`${url}/slow`, { signal: AbortSignal.timeout(50) }));
            await assert.rejects(client.get(url, { timeoutMs: -1 }), TypeError);
            const controller = new AbortController();
            const res = await client.stream(`${url}/partial`, { signal: controller.signal });
            controller.abort();
            await assert.rejects(new Response(res.body).text());
            // With a slot leaked anywhere above, this one would wait in the queue until it timed out.
            assert.equal((await client.get(url, { timeoutMs: 1000 })).statusCode, 200);
            assert.ok(stats.seen >= 4);
        });
    });
}

describe('maxConcurrency (client)', () => {
    it('accepts an integer from 1, and throws on anything else', () => {
        for (const value of [0, -1, 1.5]) {
            assert.throws(() => new UltraTonClient({ maxConcurrency: value }), { name: 'TypeError', message: `UltraTon: Expected 'maxConcurrency' to be an integer from 1 to 2147483647, received ${value}.` });
        }
        assert.throws(() => new UltraTonClient({ maxConcurrency: '2' as unknown as number }), { name: 'TypeError', message: "UltraTon: Expected 'maxConcurrency' to be a number, received string" });
        new UltraTonClient({ maxConcurrency: 1 }).close();
    });

    it('a variant from extend() has a counter of its own', async (t) => {
        const { url, stats } = await server(t, 'http1', 200);
        const client = clientOf(t, 'http1', { maxConcurrency: 1 });
        const variant = client.extend({});
        t.after(() => variant.close());
        await Promise.all([client.get(url), variant.get(url)]);
        assert.equal(stats.maxOpen, 2);
    });
});
