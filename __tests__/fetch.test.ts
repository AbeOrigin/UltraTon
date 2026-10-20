import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { createServer as createH2Server, type IncomingHttpHeaders, type ServerHttp2Stream } from 'node:http2';
import net, { type AddressInfo, type Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { SecureHttpError, UltraTonNetworkError, UltraTonRedirectError } from '../src/errors.ts';

type Seen = { method: string; path: string; headers: Record<string, string>; body: string };

/** Echoes what it received as JSON, except: /redir (302 to /echo), /nobody (204), /gzip, /proto, /cookies. */
async function server(t: TestContext, http2: boolean) {
    const answer = (seen: Seen): { status: number; headers: Record<string, string | string[]>; body?: Buffer | string } => {
        switch (seen.path) {
            case '/redir': return { status: 302, headers: { location: '/echo' } };
            case '/nobody': return { status: 204, headers: {} };
            case '/gzip': return { status: 200, headers: { 'content-encoding': 'gzip' }, body: zlib.gzipSync('zipped') };
            case '/proto': return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"__proto__":{"admin":true},"constructor":1,"a":1}' };
            case '/cookies': return { status: 200, headers: { 'set-cookie': ['a=1', 'b=2'] }, body: 'ok' };
            default: return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify(seen) };
        }
    };
    const sockets = new Set<Socket>();
    const srv = http2
        ? createH2Server().on('stream', (stream: ServerHttp2Stream, h: IncomingHttpHeaders) => {
            const chunks: Buffer[] = [];
            stream.on('data', c => chunks.push(c));
            stream.on('error', () => {});
            stream.on('end', () => {
                const headers = Object.fromEntries(Object.entries(h).filter(([k]) => !k.startsWith(':')).map(([k, v]) => [k, String(v)]));
                const r = answer({ method: String(h[':method']), path: String(h[':path']), headers, body: Buffer.concat(chunks).toString('latin1') });
                stream.respond({ ':status': r.status, ...r.headers }, { endStream: r.body === undefined });
                if (r.body !== undefined) stream.end(r.body);
            });
        })
        : http.createServer((req, res) => {
            const chunks: Buffer[] = [];
            req.on('data', c => chunks.push(c));
            req.on('end', () => {
                const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)]));
                const r = answer({ method: req.method ?? '', path: req.url ?? '', headers, body: Buffer.concat(chunks).toString('latin1') });
                res.writeHead(r.status, r.headers);
                res.end(r.body);
            });
        });
    srv.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`client.fetch() (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('returns a standard Response, and works detached from the client', async (t) => {
            const base = await server(t, http2);
            const { fetch } = clientOf(t, http2);
            const res = await fetch(`${base}/echo`);
            assert.ok(res instanceof Response);
            assert.equal(res.status, 200);
            assert.equal(res.ok, true);
            assert.ok(res.headers instanceof Headers);
            assert.equal(res.headers.get('content-type'), 'application/json');
            assert.equal(res.url, `${base}/echo`);
            assert.equal(res.redirected, false);
            assert.equal(((await res.json()) as Seen).method, 'GET');
        });

        it('serializes every standard body type with its content-type', async (t) => {
            const base = await server(t, http2);
            const { fetch } = clientOf(t, http2);
            const send = async (body: BodyInit, headers?: HeadersInit) =>
                (await (await fetch(`${base}/echo`, { method: 'POST', body, headers })).json()) as Seen;

            let seen = await send('héllo');
            assert.equal(seen.headers['content-type'], 'text/plain;charset=UTF-8');
            assert.equal(Buffer.from(seen.body, 'latin1').toString('utf8'), 'héllo');

            seen = await send(JSON.stringify({ a: 1 }), { 'content-type': 'application/json' });
            assert.equal(seen.headers['content-type'], 'application/json');
            assert.equal(seen.body, '{"a":1}');

            seen = await send(new URLSearchParams({ grant_type: 'client_credentials', scope: 'a b' }));
            assert.equal(seen.headers['content-type'], 'application/x-www-form-urlencoded;charset=UTF-8');
            assert.equal(seen.body, 'grant_type=client_credentials&scope=a+b');

            seen = await send(new Blob(['blob!'], { type: 'text/csv' }));
            assert.equal(seen.headers['content-type'], 'text/csv');
            assert.equal(seen.body, 'blob!');

            seen = await send(new Uint8Array([104, 105]));
            assert.equal(seen.body, 'hi');

            const form = new FormData();
            form.append('name', 'Ada');
            form.append('file', new Blob(['contents'], { type: 'text/plain' }), 'a.txt');
            seen = await send(form);
            assert.match(seen.headers['content-type'], /^multipart\/form-data; boundary=/);
            const parsed = await new Request('http://x/', {
                method: 'POST', headers: { 'content-type': seen.headers['content-type'] }, body: Buffer.from(seen.body, 'latin1'),
            }).formData();
            assert.equal(parsed.get('name'), 'Ada');
            assert.equal(await (parsed.get('file') as File).text(), 'contents');
        });

        it('takes headers as Headers, pairs or an object, and a Request as input', async (t) => {
            const base = await server(t, http2);
            const { fetch } = clientOf(t, http2);
            for (const headers of [new Headers({ 'X-A': '1' }), [['X-A', '1']] as [string, string][], { 'X-A': '1' }]) {
                assert.equal(((await (await fetch(`${base}/echo`, { headers })).json()) as Seen).headers['x-a'], '1');
            }
            const request = new Request(`${base}/echo`, { method: 'PUT', headers: { 'x-b': '2' }, body: 'from-request' });
            const seen = (await (await fetch(request)).json()) as Seen;
            assert.equal(seen.method, 'PUT');
            assert.equal(seen.headers['x-b'], '2');
            assert.equal(seen.body, 'from-request');
        });

        it('upper-cases the method', async (t) => {
            const base = await server(t, http2);
            const { fetch } = clientOf(t, http2);
            assert.equal(((await (await fetch(`${base}/echo`, { method: 'patch', body: 'x' })).json()) as Seen).method, 'PATCH');
        });

        it("follows redirects up to the client's maxRedirects, and redirect: manual / error", async (t) => {
            const base = await server(t, http2);
            const following = clientOf(t, http2, { maxRedirects: 1 });
            const res = await following.fetch(`${base}/redir`);
            assert.equal(res.status, 200);
            assert.equal(res.url, `${base}/echo`);
            assert.equal(res.redirected, true);
            await res.body?.cancel();

            const manual = await following.fetch(`${base}/redir`, { redirect: 'manual' });
            assert.equal(manual.status, 302);
            assert.equal(manual.headers.get('location'), '/echo');

            await assert.rejects(following.fetch(`${base}/redir`, { redirect: 'error' }), (err: unknown) =>
                err instanceof TypeError && (err as TypeError).message === 'fetch failed' && (err as any).cause instanceof UltraTonRedirectError);

            // The client default (maxRedirects: 0) returns the 3xx as is.
            assert.equal((await clientOf(t, http2).fetch(`${base}/redir`)).status, 302);
        });

        it('gives a null body to a 204, and decodes gzip', async (t) => {
            const base = await server(t, http2);
            const { fetch } = clientOf(t, http2);
            const empty = await fetch(`${base}/nobody`);
            assert.equal(empty.status, 204);
            assert.equal(empty.body, null);
            assert.equal(await (await fetch(`${base}/gzip`)).text(), 'zipped');
        });

        it('keeps every set-cookie header', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).fetch(`${base}/cookies`);
            assert.deepEqual(res.headers.getSetCookie(), ['a=1', 'b=2']);
        });

        it('json() strips __proto__ and constructor keys, and clone() keeps that, url and redirected', async (t) => {
            const base = await server(t, http2);
            const res = await clientOf(t, http2).fetch(`${base}/proto`);
            const copy = res.clone();
            const parsed = await res.json() as Record<string, unknown>;
            assert.deepEqual(Object.keys(parsed), ['a']);
            assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
            assert.equal(copy.url, `${base}/proto`);
            assert.equal(copy.redirected, false);
            assert.deepEqual(Object.keys(await copy.json() as object), ['a']);
        });

        it('rejects with the signal reason on abort', async (t) => {
            const base = await server(t, http2);
            const reason = new Error('stop');
            await assert.rejects(clientOf(t, http2).fetch(`${base}/echo`, { signal: AbortSignal.abort(reason) }), (err: unknown) => err === reason);
        });
    });
}

describe('client.fetch() errors and init validation', () => {
    it('wraps a network error as TypeError("fetch failed") with the UltraTon error as cause', async (t) => {
        const port = await new Promise<number>(resolve => {
            const probe = net.createServer().listen(0, '127.0.0.1', () => {
                const { port } = probe.address() as AddressInfo;
                probe.close(() => resolve(port));
            });
        });
        const client = clientOf(t, false);
        await assert.rejects(client.fetch(`http://127.0.0.1:${port}/`), (err: unknown) => {
            assert.ok(err instanceof TypeError);
            assert.equal((err as TypeError).message, 'fetch failed');
            assert.ok((err as any).cause instanceof UltraTonNetworkError);
            assert.equal((err as any).cause.code, 'ECONNREFUSED');
            return true;
        });
    });

    it('keeps the SSRF policy: a reserved IP fails before connecting, with the policy error as cause', async () => {
        await assert.rejects(new UltraTonClient().fetch('https://169.254.169.254/latest/meta-data/'), (err: unknown) =>
            err instanceof TypeError && (err as any).cause instanceof SecureHttpError && (err as any).cause.code === 'ERR_ULTRATON_RESERVED_IP');
    });

    it('rejects a streaming request body and options that would change the connection', async () => {
        const client = new UltraTonClient();
        await assert.rejects(client.fetch('https://example.com/', { method: 'POST', body: new ReadableStream(), duplex: 'half' } as any),
            { name: 'TypeError', message: /^UltraTon: Streaming request bodies are not supported/ });
        for (const key of ['dispatcher', 'agent', 'timeout']) {
            await assert.rejects(client.fetch('https://example.com/', { [key]: {} } as any),
                { name: 'TypeError', message: new RegExp(`^UltraTon: Unsupported fetch option '${key}'`) });
        }
    });

    it('validates the redirect mode, and signal: null means no signal', async (t) => {
        const client = new UltraTonClient();
        await assert.rejects(client.fetch('https://example.com/', { redirect: 'Follow' as RequestRedirect }), TypeError);
        const base = await server(t, false);
        const aborted = new Request(`${base}/echo`, { signal: AbortSignal.abort(new Error('request reason')) });
        const res = await clientOf(t, false).fetch(aborted, { signal: null });
        assert.equal(res.status, 200);
        await res.body?.cancel();
    });

    it('accepts and ignores the browser-only RequestInit fields', async (t) => {
        const base = await server(t, false);
        const res = await clientOf(t, false).fetch(`${base}/echo`, {
            mode: 'cors', credentials: 'include', cache: 'no-store', referrer: '', referrerPolicy: 'no-referrer',
            integrity: '', keepalive: false, priority: 'high', window: null,
        } as RequestInit);
        assert.equal(res.status, 200);
        await res.body?.cancel();
    });
});
