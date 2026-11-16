/**
 * `res.events()` on a `client.stream()` response: for an API that may answer the same request with a JSON document or
 * an event stream, the caller looks at the content type and reads the body either way. On both engines, against
 * loopback servers: the checks, the limits and the idle clock `client.events()` has, and releasing the connection.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonNetworkTimeoutError } from '../src/errors.ts';
import type { UltraTonEvent } from '../src/types/request-response.ts';

const SSE = { 'content-type': 'text/event-stream' };

/** The server's routes; `closed` lists the path of every response whose stream closed (the client let go). */
async function server(t: TestContext, http2: boolean) {
    const closed: string[] = [];
    const timers = new Set<NodeJS.Timeout>();
    const every = (ms: number, fn: () => void) => { const id = setInterval(fn, ms); timers.add(id); return id; };
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        const path = req.url ?? '/';
        res.on('close', () => closed.push(path));
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => route(path, req.method ?? '', Buffer.concat(chunks).toString(), res));
    };
    const route = (path: string, method: string, body: string, res: http.ServerResponse) => {
        switch (path) {
            case '/either':
                // The same POST, answered as an event stream or as JSON, as the request asks.
                if (body.includes('"sse":true')) {
                    res.writeHead(200, SSE);
                    return res.end(`data: ${method}\n\ndata: ${body}\n\nevent: done\ndata: 3\n\n`);
                }
                res.writeHead(200, { 'content-type': 'application/json' });
                return res.end(JSON.stringify({ method, body }));
            case '/json-open':
                // A JSON answer that never ends: only the client letting go closes it.
                res.writeHead(200, { 'content-type': 'application/json' });
                return res.write('{"a":');
            case '/missing':
                res.writeHead(404, SSE);
                return res.end('data: no\n\n');
            case '/big':
                res.writeHead(200, SSE);
                return res.end(`data: ${'x'.repeat(17)}\n\n`);
            case '/one-then-drip': {
                res.writeHead(200, SSE);
                res.write('data: first\n\n');
                const id = every(200, () => res.write('x'));
                return res.on('close', () => clearInterval(id));
            }
            case '/endless': {
                res.writeHead(200, SSE);
                res.write('data: 0\n\n');
                let n = 0;
                const id = every(50, () => res.write(`data: ${++n}\n\n`));
                return res.on('close', () => clearInterval(id));
            }
            default:
                res.writeHead(500);
                res.end();
        }
    };
    const srv = http2 ? createH2Server(handler as never) : http.createServer(handler);
    const sockets = new Set<Socket>();
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const id of timers) clearInterval(id);
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return { base: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, closed };
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ permitReservedIps: true, http2, ...options });
    t.after(() => client.close());
    return client;
}

async function all(stream: AsyncIterable<UltraTonEvent>): Promise<UltraTonEvent[]> {
    const events: UltraTonEvent[] = [];
    for await (const event of stream) events.push(event);
    return events;
}

const waitFor = async (check: () => boolean, ms = 1000) => {
    const end = Date.now() + ms;
    while (!check()) {
        if (Date.now() > end) return false;
        await new Promise(r => setTimeout(r, 10));
    }
    return true;
};

for (const http2 of [false, true]) {
    describe(`res.events() (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('reads a POST answered with an event stream', async t => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/either`, { method: 'POST', json: { sse: true } });
            const events = await all(res.events());
            assert.deepEqual(events.map(e => [e.event, e.data]), [['message', 'POST'], ['message', '{"sse":true}'], ['done', '3']]);
        });

        it('leaves a JSON answer to the caller, who branches on the content type', async t => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/either`, { method: 'POST', json: { sse: false } });
            assert.equal(res.headers['content-type'], 'application/json');
            assert.deepEqual(JSON.parse(await new Response(res.body).text()), { method: 'POST', body: '{"sse":false}' });
        });

        it('refuses anything but a 200 text/event-stream, and lets the connection go', async t => {
            const { base, closed } = await server(t, http2);
            const client = clientOf(t, http2);
            const json = await client.stream(`${base}/json-open`);
            assert.throws(() => json.events(), { name: 'SecureHttpError', code: 'ERR_ULTRATON_EVENT_STREAM' });
            assert.ok(await waitFor(() => closed.includes('/json-open')), 'the server saw the stream end');
            const missing = await client.stream(`${base}/missing`);
            assert.throws(() => missing.events(), { code: 'ERR_ULTRATON_EVENT_STREAM' });
        });

        it('maxEventSize bounds one event', async t => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/big`);
            await assert.rejects(all(res.events({ maxEventSize: 16 })), { name: 'UltraTonMemoryError', code: 'ERR_ULTRATON_EVENT_TOO_LARGE' });
        });

        it("is idle after the call's socketTimeoutMs without a complete line, else the client's", { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const isIdle = (err: unknown) => err instanceof UltraTonNetworkTimeoutError && (err as { code?: string }).code === 'ERR_ULTRATON_SOCKET_TIMEOUT';
            const own = await clientOf(t, http2).stream(`${base}/one-then-drip`, { socketTimeoutMs: 500 });
            const seen: string[] = [];
            await assert.rejects((async () => { for await (const event of own.events()) seen.push(event.data); })(), isIdle);
            assert.deepEqual(seen, ['first']);
            const started = Date.now();
            const byDefault = await clientOf(t, http2, { socketTimeoutMs: 500 }).stream(`${base}/one-then-drip`);
            await assert.rejects(all(byDefault.events()), isIdle);
            assert.ok(Date.now() - started < 2000, `cut after ${Date.now() - started} ms`);
        });

        it('cancel() ends an endless stream and releases the connection', async t => {
            const { base, closed } = await server(t, http2);
            const events = (await clientOf(t, http2).stream(`${base}/endless`)).events();
            const seen: string[] = [];
            for await (const event of events) {
                seen.push(event.data);
                await events.cancel();
            }
            assert.deepEqual(seen, ['0']);
            assert.ok(await waitFor(() => closed.includes('/endless')), 'the server saw the stream end');
        });

        it('reads the body once: a locked or read body is refused, a second call gives the same stream', async t => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            const locked = await client.stream(`${base}/endless`);
            const reader = locked.body.getReader();
            assert.throws(() => locked.events(), TypeError);
            await reader.read();
            reader.releaseLock();
            assert.throws(() => locked.events(), TypeError, 'a body already read from');
            await locked.body.cancel();
            const res = await client.stream(`${base}/endless`);
            const first = res.events();
            assert.equal(res.events(), first);
            assert.equal(res.events({ maxEventSize: 65536 }), first, 'the same limit, the default');
            assert.throws(() => res.events({ maxEventSize: 16 }), TypeError, 'another limit');
            await first.cancel();
        });

        it('refuses a maxEventSize that is not an integer from 1, and any other option, before reading anything', async t => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/endless`);
            for (const maxEventSize of [0, 1.5, -1, 'x']) {
                assert.throws(() => res.events({ maxEventSize } as never), TypeError, String(maxEventSize));
            }
            for (const options of [[], { socketTimeoutMs: 1 }]) {
                assert.throws(() => res.events(options as never), TypeError, JSON.stringify(options));
            }
            assert.equal(res.body.locked, false);
            await res.body.cancel();
        });

        it('a refused response gives back its maxConcurrency slot', { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2, { maxConcurrency: 1 });
            const json = await client.stream(`${base}/json-open`);
            assert.throws(() => json.events(), { code: 'ERR_ULTRATON_EVENT_STREAM' });
            const next = await client.stream(`${base}/endless`);
            await next.body.cancel();
        });

        it("maxBodySize of the stream() call bounds the whole stream", async t => {
            const { base } = await server(t, http2);
            const res = await clientOf(t, http2).stream(`${base}/endless`, { maxBodySize: 64 });
            await assert.rejects(all(res.events()), { name: 'UltraTonMemoryError' });
        });
    });
}
