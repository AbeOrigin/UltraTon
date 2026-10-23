/**
 * P2: `headers` as a function on the client. It is called once per call (each method, `stream`, `fetch`, each page of
 * `paginate`), never per retry or redirect hop, and what it returns goes through the same validation as static headers.
 * Real loopback servers on both engines: what the server receives, and how many requests it got, is the contract.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type ServerHttp2Session } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { VERSION } from '../src/constants.ts';
import type { UltraTonClientOptions, UltraTonHeadersContext } from '../src/types/request-options.types.ts';

type Seen = Record<string, string | undefined>;

/**
 * A loopback server (HTTP/1 or h2c) that answers with the request headers as JSON and counts the requests it gets.
 * '/flaky' answers 503 the first time, '/hop' redirects to '/echo' on the same origin, '/page1' links to '/page2'.
 */
async function serve(t: TestContext, http2: boolean) {
    let hits = 0;
    let flaky = 0;
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
        hits++;
        if (req.url === '/flaky' && flaky++ === 0) {
            res.writeHead(503, { 'retry-after': '0' });
            res.end();
            return;
        }
        if (req.url === '/hop') {
            res.writeHead(302, { location: '/echo' });
            res.end();
            return;
        }
        res.writeHead(200, { 'content-type': 'application/json', ...(req.url === '/page1' ? { link: '</page2>; rel="next"' } : {}) });
        res.end(JSON.stringify(req.headers));
    };
    const server = http2 ? createH2Server(handler as never) : http.createServer(handler);
    const sessions = new Set<ServerHttp2Session>();
    if (http2) server.on('session', (s: ServerHttp2Session) => { sessions.add(s); s.on('close', () => sessions.delete(s)); });
    const sockets = new Set<Socket>();
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sessions) s.destroy();
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, hits: () => hits };
}

const clientFor = (t: TestContext, http2: boolean, options: UltraTonClientOptions = {}) => {
    const client = new UltraTonClient({ http2, permitReservedIps: true, timeoutMs: 3000, ...options });
    t.after(() => client.close());
    return client;
};

/** A `headers` function that records every context it gets and returns `make(n)` for its n-th call (from 1). */
function recorder(make: (n: number) => unknown = n => ({ traceparent: String(n) })) {
    const contexts: UltraTonHeadersContext[] = [];
    const fn = (context: UltraTonHeadersContext) => {
        contexts.push(context);
        return make(contexts.length);
    };
    return { fn: fn as never as (context: UltraTonHeadersContext) => Record<string, string>, contexts };
}

for (const http2 of [false, true]) {
    describe(`headers as a function (${http2 ? 'HTTP/2' : 'HTTP/1.1'})`, () => {
        it('is called once per call, with the method and the URL: two calls send two values', async (t) => {
            const { url } = await serve(t, http2);
            const { fn, contexts } = recorder();
            const client = clientFor(t, http2, { headers: fn });
            assert.equal(contexts.length, 0, 'not called by the constructor');
            assert.equal((await client.get(`${url}/echo`)).json<Seen>().traceparent, '1');
            assert.equal((await client.post(`${url}/echo`, { json: {} })).json<Seen>().traceparent, '2');
            assert.deepEqual(contexts.map(c => ({ ...c })), [{ method: 'GET', url: `${url}/echo` }, { method: 'POST', url: `${url}/echo` }]);
            assert.ok(Object.isFrozen(contexts[0]), 'the context is read-only');
        });

        it('sees the URL the call requests: baseUrl and query applied', async (t) => {
            const { url } = await serve(t, http2);
            const { fn, contexts } = recorder();
            const client = clientFor(t, http2, { baseUrl: `${url}/`, headers: fn });
            assert.equal((await client.get('echo', { query: { a: 1 } })).statusCode, 200);
            assert.equal(contexts[0].url, `${url}/echo?a=1`);
        });

        it('a retry and a redirect hop do not call it again', async (t) => {
            const { url, hits } = await serve(t, http2);
            const retried = recorder();
            const retrying = clientFor(t, http2, { headers: retried.fn, retry: 1 });
            const res = await retrying.get(`${url}/flaky`);
            assert.equal(res.statusCode, 200);
            assert.equal(res.json<Seen>().traceparent, '1', 'the retry sends the same value');
            assert.equal(hits(), 2);
            assert.equal(retried.contexts.length, 1);

            const redirected = recorder();
            const following = clientFor(t, http2, { headers: redirected.fn, maxRedirects: 1 });
            const hop = await following.get(`${url}/hop`);
            assert.equal(hop.url, `${url}/echo`);
            assert.equal(hop.json<Seen>().traceparent, '1');
            assert.equal(hits(), 4);
            assert.equal(redirected.contexts.length, 1);
        });

        it('a function that throws rejects the call with that error, without connecting', async (t) => {
            const { url, hits } = await serve(t, http2);
            const boom = new Error('no token');
            const client = clientFor(t, http2, { headers: () => { throw boom; } });
            await assert.rejects(client.get(`${url}/echo`), (err: unknown) => err === boom);
            assert.equal(hits(), 0);
        });

        it('is not called for a URL that fails validation (credentials, bad baseUrl path)', async (t) => {
            const { url, hits } = await serve(t, http2);
            const { fn, contexts } = recorder();
            await assert.rejects(clientFor(t, http2, { headers: fn }).get(url.replace('://', '://u:p@') + '/echo'), /Credentials in URL authority/);
            await assert.rejects(clientFor(t, http2, { baseUrl: `${url}/v1/`, headers: fn }).get('../admin'), /escapes baseUrl/);
            assert.equal(contexts.length, 0);
            assert.equal(hits(), 0);
        });

        it('its result goes through the header firewall: CRLF, pseudo-headers, a Headers and a non-object throw', async (t) => {
            const { url, hits } = await serve(t, http2);
            const rejects = (make: () => unknown, message: RegExp) =>
                assert.rejects(clientFor(t, http2, { headers: make as never }).get(`${url}/echo`), (err: unknown) => err instanceof TypeError && message.test(err.message));
            await rejects(() => ({ 'x-a': 'v\r\nInjected: 1' }), /^UltraTon: Header value for 'x-a' contains invalid CRLF characters\.$/);
            await rejects(() => ({ 'x-a': ['ok', 'v\nInjected: 1'] }), /Header array value for 'x-a' contains invalid CRLF/);
            await rejects(() => ({ 'x\r\na': '1' }), /Header key .* contains invalid CRLF/s);
            await rejects(() => ({ ':path': '/admin' }), /HTTP\/2 pseudo-header and cannot be set/);
            await rejects(() => new Headers({ authorization: 'Bearer t' }), /^UltraTon: Expected 'headers' to be a plain object, received a Headers instance/);
            await rejects(() => 'x-a: 1', /^UltraTon: Expected the 'headers' function to return a plain object, received string\.$/);
            await rejects(() => undefined, /^UltraTon: Expected the 'headers' function to return a plain object, received undefined\.$/);
            await rejects(() => [['x-a', '1']], /^UltraTon: Expected the 'headers' function to return a plain object, received an array\.$/);
            await rejects(async () => ({ 'x-a': '1' }), /^UltraTon: Expected the 'headers' function to return a plain object, received a Promise/);
            assert.equal(hits(), 0);
        });

        it("an own '__proto__' key (from JSON.parse) is dropped, as in static headers", async (t) => {
            const { url } = await serve(t, http2);
            const client = clientFor(t, http2, { headers: () => JSON.parse('{"__proto__": {"x-polluted": "1"}, "x-ok": "1"}') });
            const seen = (await client.get(`${url}/echo`)).json<Seen>();
            assert.equal(seen['x-ok'], '1');
            assert.equal(seen['x-polluted'], undefined);
            assert.equal(({} as Seen)['x-polluted'], undefined);
        });

        it('precedence: request headers beat the function, which beats the default user agent', async (t) => {
            const { url, hits } = await serve(t, http2);
            const client = clientFor(t, http2, { headers: () => ({ 'x-a': 'fn', 'x-b': 'fn' }) });
            const seen = (await client.get(`${url}/echo`, { headers: { 'X-A': 'req' } })).json<Seen>();
            assert.equal(seen['x-a'], 'req');
            assert.equal(seen['x-b'], 'fn');
            assert.equal(seen['user-agent'], `ultraton/${VERSION}`);

            const ownAgent = clientFor(t, http2, { headers: () => ({ 'User-Agent': 'from-fn' }) });
            assert.equal((await ownAgent.get(`${url}/echo`)).json<Seen>()['user-agent'], 'from-fn');

            const before = hits();
            const both = clientFor(t, http2, { userAgent: 'app/1', headers: () => ({ 'user-agent': 'from-fn' }) });
            await assert.rejects(both.get(`${url}/echo`), (err: unknown) => err instanceof TypeError
                && err.message === "UltraTon: Set the user agent with either 'userAgent' or a 'user-agent' header, not both.");
            assert.equal(hits(), before);
            const agentOnly = clientFor(t, http2, { userAgent: 'app/1', headers: () => ({ 'x-a': '1' }) });
            assert.equal((await agentOnly.get(`${url}/echo`)).json<Seen>()['user-agent'], 'app/1');
        });

        it('extend(): a function and an object compose, the variant winning on the keys both set', async (t) => {
            const { url } = await serve(t, http2);
            const base = clientFor(t, http2, { headers: () => ({ traceparent: 't', 'X-Shared': 'base' }) });
            const withObject = base.extend({ headers: { 'x-b': '1', 'x-shared': 'variant' } });
            const withFunction = base.extend({ headers: () => ({ 'X-SHARED': 'variant-fn', 'x-c': '1' }) });
            t.after(async () => { await withObject.close(); await withFunction.close(); });

            const a = (await withObject.get(`${url}/echo`)).json<Seen>();
            assert.deepEqual([a.traceparent, a['x-b'], a['x-shared']], ['t', '1', 'variant']);
            const b = (await withFunction.get(`${url}/echo`)).json<Seen>();
            assert.deepEqual([b.traceparent, b['x-c'], b['x-shared']], ['t', '1', 'variant-fn']);
            const own = (await base.get(`${url}/echo`)).json<Seen>();
            assert.deepEqual([own['x-b'], own['x-c'], own['x-shared']], [undefined, undefined, 'base'], 'the base is unchanged');

            const staticBase = clientFor(t, http2, { headers: { 'x-a': 'base', 'x-b': 'base' } });
            const dynamic = staticBase.extend({ headers: () => ({ 'x-b': 'fn' }) });
            t.after(() => dynamic.close());
            const c = (await dynamic.get(`${url}/echo`)).json<Seen>();
            assert.deepEqual([c['x-a'], c['x-b']], ['base', 'fn']);
        });

        it('extend(): each function still runs once per call, and its result is still validated', async (t) => {
            const { url, hits } = await serve(t, http2);
            const first = recorder();
            const second = recorder(() => ({ 'x-v': 'v\r\nInjected: 1' }));
            const base = clientFor(t, http2, { headers: first.fn });
            const variant = base.extend({ headers: second.fn });
            t.after(() => variant.close());
            await assert.rejects(variant.get(`${url}/echo`), /Header value for 'x-v' contains invalid CRLF/);
            assert.equal(hits(), 0);
            assert.deepEqual([first.contexts.length, second.contexts.length], [1, 1]);
            const notObject = clientFor(t, http2, { headers: () => 'nope' as never }).extend({ headers: { 'x-b': '1' } });
            t.after(() => notObject.close());
            await assert.rejects(notObject.get(`${url}/echo`), /Expected the 'headers' function to return a plain object, received string/);
        });

        it('extend(): the user agent set by the variant wins over the one the other side sets, as with static headers', async (t) => {
            const { url } = await serve(t, http2);
            const fromFunction = clientFor(t, http2, { headers: () => ({ 'user-agent': 'base-fn' }) });
            const withAgent = fromFunction.extend({ userAgent: 'variant/1' });
            const withAgentAndObject = fromFunction.extend({ userAgent: 'variant/2', headers: { 'x-b': '1' } });
            const fromAgent = clientFor(t, http2, { userAgent: 'base/1' });
            const withFunction = fromAgent.extend({ headers: () => ({ 'User-Agent': 'variant-fn' }) });
            const withQuietFunction = fromAgent.extend({ headers: () => ({ 'x-c': '1' }) });
            t.after(async () => { for (const c of [withAgent, withAgentAndObject, withFunction, withQuietFunction]) await c.close(); });
            assert.equal((await withAgent.get(`${url}/echo`)).json<Seen>()['user-agent'], 'variant/1');
            assert.equal((await withAgentAndObject.get(`${url}/echo`)).json<Seen>()['user-agent'], 'variant/2');
            assert.equal((await withFunction.get(`${url}/echo`)).json<Seen>()['user-agent'], 'variant-fn');
            assert.equal((await withQuietFunction.get(`${url}/echo`)).json<Seen>()['user-agent'], 'base/1');
        });

        it('paginate() calls it once per page, and fetch() and stream() go through it', async (t) => {
            const { url } = await serve(t, http2);
            const { fn, contexts } = recorder();
            const client = clientFor(t, http2, { headers: fn });
            const pages: Seen[] = [];
            for await (const page of client.paginate<Seen>(`${url}/page1`)) pages.push(page.json<Seen>());
            assert.deepEqual(pages.map(p => p.traceparent), ['1', '2']);
            assert.deepEqual(contexts.map(c => c.url), [`${url}/page1`, `${url}/page2`]);

            const fetched = await client.fetch(`${url}/echo`, { method: 'PUT', body: 'x' });
            assert.equal(((await fetched.json()) as Seen).traceparent, '3');
            assert.equal(contexts[2].method, 'PUT');
            const streamed = await client.stream(`${url}/echo`);
            assert.equal(JSON.parse(await new Response(streamed.body).text()).traceparent, '4');
        });
    });
}

describe('headers as a function: the constructor', () => {
    it('accepts a function and still rejects any other non-object', () => {
        assert.doesNotThrow(() => new UltraTonClient({ headers: () => ({}) }).close());
        assert.throws(() => new UltraTonClient({ headers: 'x-a: 1' as never }), /Expected 'headers' to be a object, received string/);
    });
});
