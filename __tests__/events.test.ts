/**
 * `client.events()`: Server-Sent Events over the `stream()` path, on both engines, against loopback servers. The parser
 * itself is tested in event-stream.test.ts; here, what the client adds: the response checks, the limits and the idle
 * clock on real sockets, releasing the connection, and the SSRF checks, which events() gets from stream().
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonHttpError, UltraTonMemoryError, UltraTonNetworkTimeoutError } from '../src/errors.ts';
import type { UltraTonEvent } from '../src/types/request-response.ts';

const SSE = { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' };

/** The server's routes; `closed` resolves the path of every response whose stream closed (the client let go). */
async function server(t: TestContext, http2: boolean) {
    const closed: string[] = [];
    const timers = new Set<NodeJS.Timeout>();
    const every = (ms: number, fn: () => void) => { const id = setInterval(fn, ms); timers.add(id); return id; };
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        const path = req.url ?? '/';
        res.on('close', () => closed.push(path));
        switch (path) {
            case '/events':
                res.writeHead(200, SSE);
                res.write('data: one\n\n');
                setTimeout(() => { res.write('data: t'); res.write('wo\n\n'); res.write('event: done\nid: 3\ndata: x\n\n'); }, 20);
                return;
            case '/finite':
                res.writeHead(200, SSE);
                return res.end('data: a\n\ndata: b\n\n');
            case '/accept':
                res.writeHead(200, SSE);
                return res.end(`data: ${req.headers.accept}|${req.headers['cache-control']}\n\n`);
            case '/redirect':
                res.writeHead(302, { location: '/finite' });
                return res.end();
            case '/missing':
                res.writeHead(404, SSE);
                return res.end('data: no\n\n');
            case '/plain':
                res.writeHead(200, { 'content-type': 'text/plain' });
                return res.end('data: no\n\n');
            case '/charset':
                res.writeHead(200, { 'content-type': 'Text/Event-Stream; charset=utf-8' });
                return res.end('data: yes\n\n');
            case '/empty':
                res.writeHead(204);
                return res.end();
            case '/trickle': {
                // Bytes keep coming, a line never ends.
                res.writeHead(200, SSE);
                const id = every(100, () => res.write('x'));
                return res.on('close', () => clearInterval(id));
            }
            case '/ping': {
                res.writeHead(200, SSE);
                const id = every(100, () => res.write(': ping\n'));
                return res.on('close', () => clearInterval(id));
            }
            case '/two-then-ping': {
                res.writeHead(200, SSE);
                res.write('data: 1\n\n');
                setTimeout(() => res.write('data: 2\n\n'), 50);
                const id = every(100, () => res.write(': ping\n'));
                return res.on('close', () => clearInterval(id));
            }
            case '/flood':
                res.writeHead(200, SSE);
                for (let i = 0; i < 10; i++) res.write(`: ${'x'.repeat(1000)}\n`);
                return;
            case '/big-event':
                res.writeHead(200, SSE);
                return res.end(`data: ${'x'.repeat(5000)}\n\n`);
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
    describe(`client.events() (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('yields the events as they come, across chunks, and break releases the connection', async t => {
            const { base, closed } = await server(t, http2);
            const stream = await clientOf(t, http2).events(`${base}/events`);
            assert.equal(stream.statusCode, 200);
            assert.equal(stream.headers['content-type'], 'text/event-stream');
            const got: Array<[string, string, string]> = [];
            for await (const event of stream) {
                got.push([event.event, event.data, event.id]);
                if (event.event === 'done') break;
            }
            assert.deepEqual(got, [['message', 'one', ''], ['message', 'two', ''], ['done', 'x', '3']]);
            assert.ok(await waitFor(() => closed.includes('/events')), 'the server saw the stream end');
        });

        it('ends when the server ends the stream', async t => {
            const { base } = await server(t, http2);
            assert.deepEqual((await all(await clientOf(t, http2).events(`${base}/finite`))).map(e => e.data), ['a', 'b']);
        });

        it('cancel() ends a stream nobody iterated, and a loop in progress', async t => {
            const { base, closed } = await server(t, http2);
            const client = clientOf(t, http2);
            const idle = await client.events(`${base}/ping`);
            await idle.cancel();
            await idle.cancel();
            assert.ok(await waitFor(() => closed.includes('/ping')));
            const live = await client.events(`${base}/events`);
            const seen: string[] = [];
            for await (const event of live) {
                seen.push(event.data);
                await live.cancel();
            }
            assert.deepEqual(seen, ['one']);
        });

        it('asks for an event stream, over a client default accept, unless the call sets its own', async t => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2, { headers: { accept: 'application/json' } });
            assert.equal((await all(await client.events(`${base}/accept`)))[0].data, 'text/event-stream|no-cache');
            const own = await all(await client.events(`${base}/accept`, { headers: { Accept: 'text/event-stream; q=1' } }));
            assert.equal(own[0].data, 'text/event-stream; q=1|no-cache');
        });

        it('follows redirects only when asked, and lists them', async t => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            const stream = await client.events(`${base}/redirect`, { maxRedirects: 1 });
            assert.equal(stream.redirects.length, 1);
            assert.equal(stream.url, `${base}/finite`);
            await stream.cancel();
            // Not followed: a 302 is not 2xx.
            await assert.rejects(client.events(`${base}/redirect`), (err: unknown) => err instanceof UltraTonHttpError && err.statusCode === 302);
        });

        it('rejects a status that is not 2xx, and anything but a 200 text/event-stream, and lets the connection go', async t => {
            const { base, closed } = await server(t, http2);
            const client = clientOf(t, http2);
            await assert.rejects(client.events(`${base}/missing`), (err: unknown) => err instanceof UltraTonHttpError && err.statusCode === 404);
            await assert.rejects(client.events(`${base}/plain`), { name: 'SecureHttpError', code: 'ERR_ULTRATON_EVENT_STREAM' });
            await assert.rejects(client.events(`${base}/empty`), { code: 'ERR_ULTRATON_EVENT_STREAM' });
            assert.ok(await waitFor(() => ['/missing', '/plain', '/empty'].every(p => closed.includes(p))));
            // The media type is matched without case or parameters.
            assert.deepEqual((await all(await client.events(`${base}/charset`))).map(e => e.data), ['yes']);
        });

        it('a server that drips bytes but never ends a line is cut after socketTimeoutMs', { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const stream = await clientOf(t, http2).events(`${base}/trickle`, { socketTimeoutMs: 400 });
            const started = Date.now();
            await assert.rejects(all(stream), (err: unknown) => err instanceof UltraTonNetworkTimeoutError && (err as { code?: string }).code === 'ERR_ULTRATON_SOCKET_TIMEOUT');
            assert.ok(Date.now() - started < 1500, `cut after ${Date.now() - started} ms`);
        });

        it('keep-alive comments keep a quiet stream open', { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const stream = await clientOf(t, http2).events(`${base}/ping`, { socketTimeoutMs: 400 });
            const iterating = all(stream);
            await new Promise(r => setTimeout(r, 1200));
            await stream.cancel();
            assert.deepEqual(await iterating, []);
        });

        it('a consumer slower than socketTimeoutMs is not taken for a stalled server', { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const stream = await clientOf(t, http2).events(`${base}/two-then-ping`, { socketTimeoutMs: 500 });
            const iterator = stream[Symbol.asyncIterator]();
            assert.equal((await iterator.next()).value?.data, '1');
            // Handling the event takes longer than the idle limit; the server kept sending meanwhile.
            await new Promise(r => setTimeout(r, 800));
            assert.equal((await iterator.next()).value?.data, '2');
            await stream.cancel();
        });

        it('maxBodySize bounds the whole stream, and maxEventSize one event', async t => {
            const { base } = await server(t, http2);
            const client = clientOf(t, http2);
            await assert.rejects(all(await client.events(`${base}/flood`, { maxBodySize: 4096 })), UltraTonMemoryError);
            await assert.rejects(all(await client.events(`${base}/big-event`, { maxEventSize: 1024 })), { name: 'UltraTonMemoryError', code: 'ERR_ULTRATON_EVENT_TOO_LARGE' });
            assert.equal((await all(await client.events(`${base}/big-event`)))[0].data.length, 5000);
        });

        it('an abort ends the loop with the signal reason', { timeout: 5000 }, async t => {
            const { base } = await server(t, http2);
            const controller = new AbortController();
            const reason = new Error('stop listening');
            const stream = await clientOf(t, http2).events(`${base}/ping`, { signal: controller.signal });
            setTimeout(() => controller.abort(reason), 200);
            await assert.rejects(all(stream), (err: unknown) => err === reason);
        });
    });
}

describe('client.events() options', () => {
    it('refuses a method, a body and a bad maxEventSize', async t => {
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());
        for (const options of [{ method: 'POST' }, { json: {} }, { body: 'x' }, { form: {} }]) {
            await assert.rejects(client.events('http://127.0.0.1:1/', options as never), TypeError, JSON.stringify(options));
        }
        for (const maxEventSize of [0, -1, 1.5, 'x']) {
            await assert.rejects(client.events('http://127.0.0.1:1/', { maxEventSize } as never), TypeError, String(maxEventSize));
        }
    });
});

describe('client.events() keeps the SSRF checks', () => {
    it('refuses a reserved address, directly or through a redirect, without connecting to it', async t => {
        let hits = 0;
        const srv = http.createServer((_req, res) => { hits++; res.writeHead(302, { location: 'http://169.254.169.254/latest/' }); res.end(); });
        await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
        t.after(() => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()); }));
        const strict = new UltraTonClient();
        const loopbackOnly = new UltraTonClient({ permitReservedIps: ['127.0.0.1'], allowPlainHttp: true });
        t.after(async () => { await strict.close(); await loopbackOnly.close(); });
        await assert.rejects(strict.events('https://169.254.169.254/'), { code: 'ERR_ULTRATON_RESERVED_IP' });
        await assert.rejects(strict.events('http://10.0.0.1/'), { code: 'ERR_ULTRATON_PLAIN_HTTP' });
        await assert.rejects(loopbackOnly.events(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/`, { maxRedirects: 2 }), { code: 'ERR_ULTRATON_RESERVED_IP' });
        assert.equal(hits, 1, 'only the loopback server was reached');
    });
});
