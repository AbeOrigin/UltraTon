/**
 * Request headers the engines must fix up before they reach the wire, the same way on both engines: hop-by-hop
 * headers that HTTP/2 forbids (RFC 9113 8.2.2), a caller content-length on a request without a body, and the
 * content-type `json` adds only when neither the request nor the client defaults set one.
 * Real servers on loopback: what the server receives is the contract.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import type { UltraTonClientOptions } from '../src/types/request-options.types.ts';

type Echo = { method: string; headers: Record<string, string | undefined>; body: string };

/** A server of either engine that answers every request with its method, headers and body as JSON. */
async function echoServer(t: TestContext, http2: boolean): Promise<string> {
    const reply = (method: unknown, headers: unknown, body: Buffer) => JSON.stringify({ method, headers, body: body.toString() });
    const server = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => {
            const chunks: Buffer[] = [];
            stream.on('data', (c: Buffer) => chunks.push(c));
            stream.on('end', () => {
                stream.respond({ ':status': 200, 'content-type': 'application/json' });
                stream.end(reply(headers[':method'], headers, Buffer.concat(chunks)));
            });
        })
        : http.createServer((req, res) => {
            const chunks: Buffer[] = [];
            req.on('data', (c: Buffer) => chunks.push(c));
            req.on('end', () => res.end(reply(req.method, req.headers, Buffer.concat(chunks))));
        });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        if (server instanceof http.Server) server.closeAllConnections();
        await new Promise<void>(r => server.close(() => r()));
    });
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const clientFor = (t: TestContext, http2: boolean, options: UltraTonClientOptions = {}) => {
    const client = new UltraTonClient({ http2, permitReservedIps: true, timeoutMs: 3000, socketTimeoutMs: 2000, ...options });
    t.after(() => client.close());
    return client;
};

/** Connection-specific headers HTTP/2 forbids; HTTP/1 callers copy them into configs all the time. */
const HOP_BY_HOP: Array<[string, string]> = [
    ['connection', 'keep-alive'],
    ['keep-alive', 'timeout=5'],
    ['proxy-connection', 'keep-alive'],
    ['transfer-encoding', 'chunked'],
    ['upgrade', 'h2c'],
    ['te', 'gzip'],
];

describe('HTTP/2 strips hop-by-hop request headers instead of failing the request', () => {
    for (const [name, value] of HOP_BY_HOP) {
        it(`'${name}: ${value}' per request and as a client default: 200, and the server never sees it`, async (t) => {
            const base = await echoServer(t, true);
            const perRequest = await clientFor(t, true).get(`${base}/`, { headers: { [name]: value } });
            assert.equal(perRequest.statusCode, 200);
            assert.equal(perRequest.json<Echo>().headers[name], undefined);

            const asDefault = clientFor(t, true, { headers: { [name]: value } });
            const viaDefault = await asDefault.get(`${base}/`);
            assert.equal(viaDefault.statusCode, 200);
            assert.equal(viaDefault.json<Echo>().headers[name], undefined);

            // With a body as well: the stream is opened differently (endStream false).
            const withBody = await asDefault.post(`${base}/`, { json: { a: 1 } });
            assert.equal(withBody.statusCode, 200);
            assert.equal(withBody.json<Echo>().body, '{"a":1}');
        });
    }

    it("'te: trailers', the one value HTTP/2 allows, is kept", async (t) => {
        const base = await echoServer(t, true);
        const res = await clientFor(t, true).get(`${base}/`, { headers: { TE: 'trailers' } });
        assert.equal(res.json<Echo>().headers.te, 'trailers');
    });
});

for (const http2 of [false, true]) {
    const engine = http2 ? 'HTTP/2' : 'HTTP/1';

    describe(`${engine}: a caller content-length on a request without a body is dropped`, () => {
        for (const method of ['get', 'delete'] as const) {
            it(`${method.toUpperCase()} with content-length: 5 and no body answers 200 at once`, async (t) => {
                const base = await echoServer(t, http2);
                const started = Date.now();
                const res = await clientFor(t, http2)[method](`${base}/`, { headers: { 'Content-Length': '5' } });
                assert.equal(res.statusCode, 200);
                const echo = res.json<Echo>();
                assert.equal(echo.body, '');
                assert.ok(echo.headers['content-length'] === undefined || echo.headers['content-length'] === '0', echo.headers['content-length']);
                assert.ok(Date.now() - started < 1500, 'answered without waiting out the idle timeout');
            });
        }

        it('as a client default too', async (t) => {
            const base = await echoServer(t, http2);
            const res = await clientFor(t, http2, { headers: { 'content-length': '5' } }).get(`${base}/`);
            assert.equal(res.statusCode, 200);
        });
    });

    describe(`${engine}: json content-type and the client default headers`, () => {
        it('a client default content-type wins over the one json would add', async (t) => {
            const base = await echoServer(t, http2);
            const client = clientFor(t, http2, { headers: { 'Content-Type': 'application/vnd.api+json' } });
            const echo = (await client.post(`${base}/`, { json: { a: 1 } })).json<Echo>();
            assert.equal(echo.headers['content-type'], 'application/vnd.api+json');
            assert.equal(echo.body, '{"a":1}');
        });

        it('without one, json sends application/json', async (t) => {
            const base = await echoServer(t, http2);
            const echo = (await clientFor(t, http2).post(`${base}/`, { json: { a: 1 } })).json<Echo>();
            assert.equal(echo.headers['content-type'], 'application/json');
        });

        it('a per-request content-type wins over both', async (t) => {
            const base = await echoServer(t, http2);
            const client = clientFor(t, http2, { headers: { 'content-type': 'application/vnd.api+json' } });
            const echo = (await client.post(`${base}/`, { json: { a: 1 }, headers: { 'CONTENT-TYPE': 'text/x-mine' } })).json<Echo>();
            assert.equal(echo.headers['content-type'], 'text/x-mine');
        });

        it('a per-request content-type set to undefined keeps the client default', async (t) => {
            const base = await echoServer(t, http2);
            const client = clientFor(t, http2, { headers: { 'content-type': 'application/vnd.api+json' } });
            const echo = (await client.post(`${base}/`, { json: { a: 1 }, headers: { 'content-type': undefined } })).json<Echo>();
            assert.equal(echo.headers['content-type'], 'application/vnd.api+json');
        });

        it('a plain body still gets no content-type', async (t) => {
            const base = await echoServer(t, http2);
            const echo = (await clientFor(t, http2).post(`${base}/`, { body: 'raw' })).json<Echo>();
            assert.equal(echo.headers['content-type'], undefined);
        });
    });
}
