/**
 * Form bodies: the `form` option, and URLSearchParams, FormData and Blob as `body`. What the server receives is the
 * contract, on both engines; a multipart body is parsed back with the platform's own Request.formData().
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

type Echo = { method: string; headers: Record<string, string | undefined>; body: string };

/** A loopback server of either engine that answers with the method, headers and body (base64) it received. */
async function echoServer(t: TestContext, http2: boolean) {
    const sockets = new Set<Socket>();
    let connections = 0;
    const reply = (method: string, headers: IncomingHttpHeaders, chunks: Buffer[]) =>
        JSON.stringify({ method, headers, body: Buffer.concat(chunks).toString('base64') });
    const server = http2
        ? createH2Server().on('stream', (stream, headers: IncomingHttpHeaders) => {
            const chunks: Buffer[] = [];
            stream.on('data', (c: Buffer) => chunks.push(c));
            stream.on('end', () => {
                stream.respond({ ':status': 200, 'content-type': 'application/json' });
                stream.end(reply(String(headers[':method']), headers, chunks));
            });
        })
        : http.createServer((req, res) => {
            const chunks: Buffer[] = [];
            req.on('data', (c: Buffer) => chunks.push(c));
            req.on('end', () => {
                res.writeHead(200, { 'content-type': 'application/json' });
                res.end(reply(String(req.method), req.headers, chunks));
            });
        });
    server.on('connection', (s: Socket) => { connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/x`, connections: () => connections };
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

const received = (echo: Echo) => Buffer.from(echo.body, 'base64');
const URLENCODED = 'application/x-www-form-urlencoded;charset=UTF-8';

for (const http2 of [false, true]) {
    describe(`form bodies (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('form is urlencoded with the query rules, with its content-type and content-length', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const echo = (await client.post(server.url, { form: { grant_type: 'client_credentials', scope: ['read', 'write'], n: 2, on: true, skip: undefined, q: 'café & té' } })).json<Echo>();
            const expected = 'grant_type=client_credentials&scope=read&scope=write&n=2&on=true&q=caf%C3%A9+%26+t%C3%A9';
            assert.equal(echo.method, 'POST');
            assert.equal(received(echo).toString(), expected);
            assert.equal(echo.headers['content-type'], URLENCODED);
            assert.equal(echo.headers['content-length'], String(expected.length));
        });

        it('form accepts a URLSearchParams, and an empty form is an empty body', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const echo = (await client.put(server.url, { form: new URLSearchParams([['a', '1'], ['a', '2 3']]) })).json<Echo>();
            assert.equal(received(echo).toString(), 'a=1&a=2+3');
            const empty = (await client.post(server.url, { form: {} })).json<Echo>();
            assert.equal(received(empty).toString(), '');
            assert.equal(empty.headers['content-length'], '0');
            assert.equal(empty.headers['content-type'], URLENCODED);
        });

        it('a URLSearchParams body is sent urlencoded', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const echo = (await client.post(server.url, { body: new URLSearchParams({ a: 'b c', d: 'é' }) })).json<Echo>();
            assert.equal(received(echo).toString(), 'a=b+c&d=%C3%A9');
            assert.equal(echo.headers['content-type'], URLENCODED);
        });

        it('a FormData body is sent as multipart with its boundary, fields and files intact', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const fd = new FormData();
            fd.append('name', 'café');
            fd.append('name', 'two');
            fd.append('file', new File([Buffer.from([0, 1, 2, 255])], 'a "b".bin', { type: 'application/octet-stream' }));
            const echo = (await client.post(server.url, { body: fd })).json<Echo>();
            const contentType = echo.headers['content-type']!;
            assert.match(contentType, /^multipart\/form-data; boundary=/);
            const bytes = received(echo);
            assert.equal(echo.headers['content-length'], String(bytes.length));
            const parsed = await new Request('http://parse.invalid/', { method: 'POST', headers: { 'content-type': contentType }, body: bytes }).formData();
            assert.deepEqual(parsed.getAll('name'), ['café', 'two']);
            const file = parsed.get('file') as File;
            assert.equal(file.name, 'a "b".bin');
            assert.equal(file.type, 'application/octet-stream');
            assert.deepEqual(Buffer.from(await file.arrayBuffer()), Buffer.from([0, 1, 2, 255]));
        });

        it('a Blob body is sent as is, with its type as content-type (none without a type)', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const typed = (await client.post(server.url, { body: new Blob(['<a/>'], { type: 'application/xml' }) })).json<Echo>();
            assert.equal(received(typed).toString(), '<a/>');
            assert.equal(typed.headers['content-type'], 'application/xml');
            const bare = (await client.post(server.url, { body: new Blob([Buffer.from([9, 8])]) })).json<Echo>();
            assert.deepEqual(received(bare), Buffer.from([9, 8]));
            assert.equal(bare.headers['content-type'], undefined);
        });

        it("the request's own content-type wins for form, URLSearchParams and Blob", async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const headers = { 'Content-Type': 'text/plain' };
            for (const options of [{ form: { a: '1' } }, { body: new URLSearchParams({ a: '1' }) }, { body: new Blob(['a=1'], { type: 'application/xml' }) }]) {
                const echo = (await client.post(server.url, { ...options, headers })).json<Echo>();
                assert.equal(echo.headers['content-type'], 'text/plain');
                assert.equal(received(echo).toString(), 'a=1');
            }
        });

        it('a FormData with a content-type of its own throws before connecting', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const fd = new FormData();
            fd.append('a', '1');
            for (const key of ['content-type', 'Content-Type']) {
                await assert.rejects(client.post(server.url, { body: fd, headers: { [key]: 'multipart/form-data' } }), {
                    name: 'TypeError',
                    message: "UltraTon: A FormData body sets its own content-type (with the multipart boundary); remove the 'content-type' header.",
                });
            }
            assert.equal(server.connections(), 0);
        });

        it("a client default content-type gives way to the body's, but is kept for json", async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2, { headers: { 'content-type': 'application/vnd.api+json' } });
            const fd = new FormData();
            fd.append('a', '1');
            assert.equal((await client.post(server.url, { form: { a: '1' } })).json<Echo>().headers['content-type'], URLENCODED);
            assert.match((await client.post(server.url, { body: fd })).json<Echo>().headers['content-type']!, /^multipart\/form-data; boundary=/);
            assert.equal((await client.post(server.url, { body: new Blob(['x'], { type: 'image/png' }) })).json<Echo>().headers['content-type'], 'image/png');
            assert.equal((await client.post(server.url, { json: {} })).json<Echo>().headers['content-type'], 'application/vnd.api+json');
            // A Blob without a type implies none: the client default stays, as with a string body.
            assert.equal((await client.post(server.url, { body: new Blob(['x']) })).json<Echo>().headers['content-type'], 'application/vnd.api+json');
        });

        it("a request's own mixed-case Content-Type wins over a client default for form", async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2, { headers: { 'content-type': 'application/json' } });
            const echo = (await client.post(server.url, { form: { a: '1' }, headers: { 'CoNtEnT-TyPe': 'text/plain' } })).json<Echo>();
            assert.equal(echo.headers['content-type'], 'text/plain');
        });

        it('a Blob type with CRLF is rejected by the header firewall before connecting', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            class Sneaky extends Blob { override get type() { return 'text/plain\r\nx-injected: 1'; } }
            await assert.rejects(client.post(server.url, { body: new Sneaky(['x']) }), { name: 'TypeError', message: /CRLF/ });
            assert.equal(server.connections(), 0);
        });

        it('an aborted signal rejects with its reason before a Blob body is read', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            let read = false;
            // new Response(blob) reads its type first: that the getter never ran proves the body was never encoded.
            class Watched extends Blob { override get type() { read = true; return super.type; } }
            const reason = new Error('stop');
            await assert.rejects(client.post(server.url, { body: new Watched(['x']), signal: AbortSignal.abort(reason) }), (err: unknown) => err === reason);
            assert.equal(read, false);
            assert.equal(server.connections(), 0);
        });

        it('a 303 after a form POST drops the body and its content-type', async (t) => {
            const sockets = new Set<Socket>();
            const server = await echoServer(t, http2);
            const redirector = http2
                ? createH2Server().on('stream', (stream) => { stream.resume(); stream.on('end', () => { stream.respond({ ':status': 303, location: server.url }); stream.end(); }); })
                : http.createServer((req, res) => { req.resume(); req.on('end', () => { res.writeHead(303, { location: server.url }); res.end(); }); });
            redirector.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
            await new Promise<void>(r => redirector.listen(0, '127.0.0.1', r));
            t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => redirector.close(() => r())); });
            const client = clientOf(t, http2, { maxRedirects: 1 });
            const echo = (await client.post(`http://127.0.0.1:${(redirector.address() as AddressInfo).port}/`, { form: { a: '1' } })).json<Echo>();
            assert.equal(echo.method, 'GET');
            assert.equal(echo.body, '');
            assert.equal(echo.headers['content-type'], undefined);
        });

        it('stream() sends a form body too', async (t) => {
            const server = await echoServer(t, http2);
            const client = clientOf(t, http2);
            const res = await client.stream(server.url, { method: 'POST', form: { a: '1' } });
            const echo = JSON.parse(await new Response(res.body).text()) as Echo;
            assert.equal(received(echo).toString(), 'a=1');
            assert.equal(echo.headers['content-type'], URLENCODED);
        });
    });
}

describe('form body validation', () => {
    const client = new UltraTonClient();
    const url = 'https://example.com/';
    const ONE_BODY = "UltraTon: Use only one of 'json', 'form' or 'body'.";

    it('form, json and body are mutually exclusive', async () => {
        for (const options of [{ form: {}, json: {} }, { form: {}, body: 'x' }, { json: {}, body: 'x' }, { form: {}, json: 1, body: 'x' }]) {
            await assert.rejects(client.post(url, options as any), { name: 'TypeError', message: ONE_BODY }, Object.keys(options).join('+'));
        }
    });

    it('get and head cannot have a form or a form-like body', async () => {
        for (const verb of ['get', 'head'] as const) {
            for (const options of [{ form: { a: '1' } }, { body: new URLSearchParams() }, { body: new FormData() }, { body: new Blob([]) }]) {
                await assert.rejects(client[verb](url, options as any), { name: 'TypeError', message: 'UltraTon: GET and HEAD requests cannot have a body.' });
            }
        }
    });

    it('rejects a form that is not a plain object or URLSearchParams', async () => {
        for (const form of ['a=1', 42, null, ['a'], new Map([['a', '1']]), new FormData()]) {
            await assert.rejects(client.post(url, { form } as any), (err: Error) => {
                assert.ok(err instanceof TypeError, String(form));
                assert.match(err.message, /^UltraTon: Expected 'form' to be a plain object or URLSearchParams, received /);
                return true;
            });
        }
    });

    it('rejects form values the query option rejects, naming the field', async () => {
        for (const [key, value] of Object.entries({ n: null, o: { a: 1 }, nan: NaN, nested: [['a']] } as Record<string, unknown>)) {
            await assert.rejects(client.post(url, { form: { [key]: value } } as any), (err: Error) => {
                assert.ok(err instanceof TypeError, key);
                assert.match(err.message, new RegExp(`^UltraTon: Expected form field '${key}' to be a string, a finite number or a boolean, received `));
                return true;
            });
        }
    });

    it('still rejects a body of any other type, naming the accepted ones', async () => {
        for (const body of [{ a: 1 }, 42, new ArrayBuffer(2), null]) {
            await assert.rejects(client.post(url, { body } as any), {
                name: 'TypeError',
                message: /^UltraTon: Expected 'body' to be a string, Buffer, Uint8Array, Blob, FormData, URLSearchParams or a stream \(Readable, ReadableStream, async iterable\), received /,
            });
        }
    });

    it('is not inherited from a polluted Object.prototype', async (t) => {
        const server = await echoServer(t, false);
        const local = clientOf(t, false);
        (Object.prototype as any).form = { injected: '1' };
        try {
            const echo = (await local.post(server.url)).json<Echo>();
            assert.equal(echo.body, '');
            assert.equal(echo.headers['content-type'], undefined);
        } finally {
            delete (Object.prototype as any).form;
        }
    });

    it("points 'form' on the constructor at the request, and 'data' at form", async () => {
        assert.throws(() => new UltraTonClient({ form: {} } as any), { message: "UltraTon: Unknown option 'form'. 'form' is a per-request option, not a client option." });
        await assert.rejects(client.post(url, { data: {} } as any), { message: /Unknown option 'data'\..*'form'/ });
    });
});
