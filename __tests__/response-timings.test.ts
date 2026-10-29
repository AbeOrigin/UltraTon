/**
 * The `timings` option: each response carries the per-phase timings of its own call, on both engines, so calls in
 * flight at the same time never mix them. Off by default; the diagnostics events report the same measurement.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import diagnosticsChannel from 'node:diagnostics_channel';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { KEEP_ALIVE } from '../src/helpers/keep-alive.ts';

/** A loopback server (HTTP/1.1 or h2c) that answers `/slow` after `delayMs` and anything else at once. */
async function server(t: TestContext, http2: boolean, delayMs = 150) {
    const handler = (req: http.IncomingMessage | any, res: http.ServerResponse | any) => {
        const answer = () => res.end(req.url);
        if (req.url === '/slow') setTimeout(answer, delayMs);
        else answer();
    };
    const srv = http2 ? createH2Server(handler) : http.createServer(handler);
    const sockets = new Set<Socket>();
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ permitReservedIps: true, http2, ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`timings option (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('is off by default: no timings on the response', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).get(`${base}/x`);
            assert.equal(res.timings, undefined);
        });

        it('puts the phases of the call on the response, and assertOk() returns it with them', async (t) => {
            const base = await server(t, http2);
            const client = clientOf(t, http2, { timings: true });
            const res = await client.get(`${base}/x`);
            const timings = res.timings!;
            assert.ok(timings.totalMs >= 0 && typeof timings.firstByteMs === 'number', JSON.stringify(timings));
            assert.equal(typeof timings.connectMs, 'number');
            assert.equal(timings.reusedConnection, false);
            assert.equal(res.assertOk().timings, timings);
            // The second call reuses the connection (or session): no connect of its own. HTTP/1.1 pools sockets only on
            // a Node release with the keep-alive fix.
            if (!http2 && !KEEP_ALIVE) return;
            const again = await client.get(`${base}/x`);
            assert.equal(again.timings!.reusedConnection, true);
            assert.equal(again.timings!.connectMs, undefined);
        });

        it('keeps the timings of concurrent calls apart', async (t) => {
            const base = await server(t, http2, 200);
            const client = clientOf(t, http2, { timings: true });
            const [slow, fast] = await Promise.all([client.get(`${base}/slow`), client.get(`${base}/fast`)]);
            assert.equal(slow.text(), '/slow');
            assert.ok(slow.timings!.firstByteMs! >= 150, `slow: ${JSON.stringify(slow.timings)}`);
            assert.ok(fast.timings!.firstByteMs! < 150, `fast: ${JSON.stringify(fast.timings)}`);
            assert.ok(slow.timings!.totalMs > fast.timings!.totalMs);
        });

        it('is set per request too: a request overrides the client either way', async (t) => {
            const base = await server(t, http2);
            assert.equal(typeof (await clientOf(t, http2).get(`${base}/x`, { timings: true })).timings?.totalMs, 'number');
            assert.equal((await clientOf(t, http2, { timings: true }).get(`${base}/x`, { timings: false })).timings, undefined);
        });

        it('measures stream() until the headers', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2, { timings: true }).stream(`${base}/x`);
            assert.equal(typeof res.timings?.firstByteMs, 'number');
            assert.equal(res.assertOk().timings, res.timings);
            await res.body.cancel();
        });

        it('reports the same measurement on the response and on ultraton:request:response', async (t) => {
            const base = await server(t, http2);
            const events: any[] = [];
            const listener = (message: unknown) => events.push(message);
            diagnosticsChannel.subscribe('ultraton:request:response', listener);
            t.after(() => diagnosticsChannel.unsubscribe('ultraton:request:response', listener));
            const res = await clientOf(t, http2, { timings: true }).get(`${base}/x`);
            assert.equal(events.length, 1);
            assert.equal(events[0].timings, res.timings);
            assert.equal(events[0].durationMs, res.timings!.totalMs);
        });

        it('covers the queue of maxConcurrency', async (t) => {
            const base = await server(t, http2, 100);
            const client = clientOf(t, http2, { timings: true, maxConcurrency: 1 });
            const [, second] = await Promise.all([client.get(`${base}/slow`), client.get(`${base}/x`)]);
            assert.ok(second.timings!.queuedMs! >= 50, JSON.stringify(second.timings));
        });
    });
}

describe('timings option validation', () => {
    it('throws a TypeError for anything but a boolean, on the client and on a request', async (t) => {
        assert.throws(() => new UltraTonClient({ timings: 'yes' as any }), { name: 'TypeError', message: /'timings'/ });
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        await assert.rejects(client.get('http://127.0.0.1:1/', { timings: 1 as any }), { name: 'TypeError', message: /'timings'/ });
    });
});
