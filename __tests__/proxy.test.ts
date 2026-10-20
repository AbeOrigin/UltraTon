/**
 * The `proxy` client option: CONNECT tunnels to the IP UltraTon validated (never a name the proxy could resolve
 * elsewhere), TLS to the target over the tunnel with the hostname checked, credentials only on the CONNECT, SSRF
 * checks before the proxy is contacted, and both engines. The proxy here is a small CONNECT server on node:net.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import fs from 'node:fs';
import https from 'node:https';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import tls from 'node:tls';
import { createSecureServer } from 'node:http2';
import { UltraTonClient } from '../src/http-client.ts';
import { mockDns, RESERVED, v4 } from './fixtures/net-fixtures.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

type Seen = { target: string; headers: string };

/** A CONNECT proxy on loopback that records every request line target and its headers, and tunnels with status 200. */
/** Polls until `check()` holds, for at most 2s. */
async function eventually(check: () => boolean) {
    for (const started = Date.now(); !check(); ) {
        if (Date.now() - started > 2000) assert.fail('condition not met within 2s');
        await new Promise(r => setTimeout(r, 10));
    }
}

/**
 * `unreachable`: target hosts the proxy answers 502 for, as if it could not reach them. `hang`: never answers.
 */
async function connectProxy(t: TestContext, opts: { status?: number; tlsProxy?: boolean; hang?: boolean; unreachable?: string[] } = {}) {
    const seen: Seen[] = [];
    let connections = 0;
    let tunnelsClosed = 0;
    const clients = new Set<net.Socket>();
    const sockets = new Set<net.Socket>();
    const track = (s: net.Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => undefined); };
    const onConnection = (client: net.Socket) => {
        connections++;
        track(client);
        clients.add(client);
        client.on('close', () => clients.delete(client));
        let buffered = Buffer.alloc(0);
        const onData = (chunk: Buffer) => {
            buffered = Buffer.concat([buffered, chunk]);
            const end = buffered.indexOf('\r\n\r\n');
            if (end === -1) return;
            client.off('data', onData);
            const [line, ...headerLines] = buffered.subarray(0, end).toString('latin1').split('\r\n');
            const target = line.split(' ')[1];
            seen.push({ target, headers: headerLines.join('\n').toLowerCase() });
            if (opts.hang) return;
            if (opts.status !== undefined && opts.status !== 200) {
                client.end(`HTTP/1.1 ${opts.status} Refused\r\ncontent-length: 0\r\n\r\n`);
                return;
            }
            const colon = target.lastIndexOf(':');
            const host = target.slice(0, colon).replace(/^\[|\]$/g, '');
            if (opts.unreachable?.includes(host)) {
                client.end('HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n');
                return;
            }
            const upstream = net.connect({ host: host === 'localhost' ? '127.0.0.1' : host, port: Number(target.slice(colon + 1)) });
            track(upstream);
            upstream.once('error', () => { if (!client.destroyed) client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); });
            upstream.once('connect', () => {
                client.write('HTTP/1.1 200 Connection established\r\n\r\n');
                const rest = buffered.subarray(end + 4);
                if (rest.length > 0) upstream.write(rest);
                client.pipe(upstream);
                upstream.pipe(client);
                upstream.on('close', () => client.destroy());
                // The client end of the tunnel closing is what close() must cause.
                client.on('close', () => { tunnelsClosed++; upstream.destroy(); });
            });
        };
        client.on('data', onData);
    };
    const server = opts.tlsProxy ? tls.createServer({ cert: CERT, key: KEY }, onConnection) : net.createServer(onConnection);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    const port = (server.address() as AddressInfo).port;
    return {
        url: `${opts.tlsProxy ? 'https' : 'http'}://127.0.0.1:${port}`,
        seen,
        connections: () => connections,
        tunnelsClosed: () => tunnelsClosed,
        /** Client connections still open to the proxy (a tunnel UltraTon gave up on must not be among them). */
        openClients: () => clients.size,
    };
}

/** An HTTPS (or h2) target for `localhost` that answers with the headers it got; `redirect` makes it a 302 to that URL. */
async function tlsTarget(t: TestContext, http2: boolean, redirect?: string) {
    const handler = (req: http.IncomingMessage | any, res: http.ServerResponse | any) => {
        if (redirect) { res.writeHead(302, { location: redirect }); res.end(); return; }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ headers: req.headers }));
    };
    const server = http2 ? createSecureServer({ cert: CERT, key: KEY }, handler) : https.createServer({ cert: CERT, key: KEY }, handler);
    const sockets = new Set<net.Socket>();
    server.on('secureConnection', (s: net.Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return (server.address() as AddressInfo).port;
}

function proxied(t: TestContext, http2: boolean, proxy: unknown, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, proxy, permitReservedIps: ['127.0.0.0/8'], tls: { ca: CERT }, ...options } as any);
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    describe(`proxy (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('tunnels to the validated IP, never the name, with credentials on the CONNECT only', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await connectProxy(t);
            const port = await tlsTarget(t, http2);
            const client = proxied(t, http2, { url: proxy.url, auth: 'svc:s3cret' });
            const res = await client.get(`https://localhost:${port}/x`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => s.target), [`127.0.0.1:${port}`]);
            assert.match(proxy.seen[0].headers, new RegExp(`proxy-authorization: basic ${Buffer.from('svc:s3cret').toString('base64').toLowerCase()}`));
            const { headers } = res.json<{ headers: Record<string, string> }>();
            assert.equal(headers['proxy-authorization'], undefined);
        });

        it('blocks SSRF before the proxy is ever contacted', async (t) => {
            mockDns(t, { 'internal.example': [v4('10.0.0.1')] });
            const proxy = await connectProxy(t);
            const client = proxied(t, http2, proxy.url, { permitReservedIps: false });
            await assert.rejects(client.get('https://internal.example/'), (err: Error) => RESERVED.test(err.message));
            await assert.rejects(client.get('https://10.0.0.1/'), (err: Error) => RESERVED.test(err.message));
            await assert.rejects(client.get('https://[::1]/'), (err: Error) => RESERVED.test(err.message));
            assert.equal(proxy.connections(), 0);
        });

        it("checks the target's certificate against its hostname through the tunnel", async (t) => {
            mockDns(t, { 'evil.localhost': [v4('127.0.0.1')] });
            const proxy = await connectProxy(t);
            const port = await tlsTarget(t, http2);
            const client = proxied(t, http2, proxy.url);
            await assert.rejects(client.get(`https://evil.localhost:${port}/`), (err: any) => err.name === 'UltraTonNetworkError' && /TLS handshake failed/.test(err.message));
            assert.equal(proxy.seen.length, 1);
        });

        it('a proxy refusal is ERR_ULTRATON_PROXY with the status, never the proxy address', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            for (const status of [407, 403, 502]) {
                const proxy = await connectProxy(t, { status });
                const client = proxied(t, http2, proxy.url);
                await assert.rejects(client.get('https://localhost:9/'), (err: any) => {
                    assert.equal(err.name, 'UltraTonNetworkError');
                    assert.equal(err.code, 'ERR_ULTRATON_PROXY');
                    assert.equal(err.message, `UltraTon: The proxy refused the tunnel (${status}).`);
                    return true;
                });
            }
        });

        it('tries the next validated address when the proxy cannot reach one', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.9'), v4('127.0.0.1')] });
            const proxy = await connectProxy(t, { unreachable: ['127.0.0.9'] });
            const port = await tlsTarget(t, http2);
            const res = await proxied(t, http2, proxy.url).get(`https://localhost:${port}/`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => s.target), [`127.0.0.9:${port}`, `127.0.0.1:${port}`]);
        });

        it("checks an IP-literal target's certificate against the IP, not the proxy's name", async (t) => {
            const proxy = await connectProxy(t);
            // The proxy is reached by name ('localhost'), and the target's certificate is valid for that name only.
            const named = proxy.url.replace('127.0.0.1', 'localhost');
            const cert = { cert: fixture('dns-only-cert.pem'), key: fixture('dns-only-key.pem') };
            const answer = (_req: unknown, res: http.ServerResponse) => res.end('mitm');
            const target = http2 ? createSecureServer(cert, answer as any) : https.createServer(cert, answer);
            await new Promise<void>(r => target.listen(0, '127.0.0.1', r));
            t.after(() => new Promise<void>(r => target.close(() => r())));
            const client = proxied(t, http2, named, { tls: { ca: fixture('dns-only-cert.pem') } });
            await assert.rejects(client.get(`https://127.0.0.1:${(target.address() as AddressInfo).port}/`), /TLS handshake failed/);
            assert.equal(proxy.seen.length, 1);
        });

        it('follows a redirect through the tunnel, validating the new host again', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')], 'internal.example': [v4('10.0.0.1')] });
            const proxy = await connectProxy(t);
            const final = await tlsTarget(t, http2);
            const first = await tlsTarget(t, http2, `https://localhost:${final}/next`);
            const client = proxied(t, http2, proxy.url, { maxRedirects: 2 });
            assert.equal((await client.get(`https://localhost:${first}/`)).statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => s.target), [`127.0.0.1:${first}`, `127.0.0.1:${final}`]);

            const toInternal = await tlsTarget(t, http2, 'https://internal.example/');
            await assert.rejects(client.get(`https://localhost:${toInternal}/`), (err: Error) => RESERVED.test(err.message));
            assert.equal(proxy.seen.length, 3);
        });

        it("resolve: 'proxy' sends the name and resolves nothing locally", async (t) => {
            mockDns(t, {});
            const proxy = await connectProxy(t);
            const port = await tlsTarget(t, http2);
            const client = proxied(t, http2, { url: proxy.url, resolve: 'proxy' });
            assert.equal((await client.get(`https://localhost:${port}/`)).statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => s.target), [`localhost:${port}`]);
            // An IP literal is still judged locally.
            await assert.rejects(client.get('https://10.0.0.1/'), (err: Error) => RESERVED.test(err.message));
            assert.equal(proxy.seen.length, 1);
        });

        it('a proxy that never answers the CONNECT is bounded by timeoutMs and by an abort', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await connectProxy(t, { hang: true });
            const client = proxied(t, http2, proxy.url, { timeoutMs: 300 });
            const started = Date.now();
            await assert.rejects(client.get('https://localhost:9/'), { code: 'ERR_ULTRATON_TIMEOUT' });
            assert.ok(Date.now() - started < 1500, `took ${Date.now() - started}ms`);

            const reason = new Error('stop');
            const controller = new AbortController();
            setTimeout(() => controller.abort(reason), 50);
            const aborted = Date.now();
            await assert.rejects(client.get('https://localhost:9/', { signal: controller.signal, timeoutMs: 0 }), (err: unknown) => err === reason);
            assert.ok(Date.now() - aborted < 1500, `took ${Date.now() - aborted}ms`);
            // Both tunnels the caller gave up on are torn down, not left for the proxy to hold.
            await eventually(() => proxy.openClients() === 0);
        });

        it('close() ends a CONNECT still waiting for the proxy, and one whose DNS is still pending', async (t) => {
            const proxy = await connectProxy(t, { hang: true });
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const waiting = proxied(t, http2, proxy.url, { timeoutMs: 0 });
            const pending = waiting.get('https://localhost:9/');
            await eventually(() => proxy.seen.length === 1);
            const closed = Date.now();
            await waiting.close();
            await assert.rejects(pending, { message: 'UltraTon: Client is closed.' });
            assert.ok(Date.now() - closed < 1500, `took ${Date.now() - closed}ms`);
            await eventually(() => proxy.openClients() === 0);

            t.mock.method(dnsPromises, 'lookup', (async () => {
                await new Promise(r => setTimeout(r, 200));
                return [{ address: '127.0.0.1', family: 4 }];
            }) as any);
            const resolving = proxied(t, http2, proxy.url, { timeoutMs: 0 });
            const inDns = resolving.get('https://localhost:9/');
            await new Promise(r => setTimeout(r, 50));
            await resolving.close();
            await assert.rejects(inDns, { message: 'UltraTon: Client is closed.' });
            await new Promise(r => setTimeout(r, 300));
            assert.equal(proxy.seen.length, 1, 'no CONNECT after close()');
        });

        it('close() closes the tunnels', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await connectProxy(t);
            const port = await tlsTarget(t, http2);
            const client = proxied(t, http2, proxy.url);
            await client.get(`https://localhost:${port}/`);
            await client.close();
            await eventually(() => proxy.tunnelsClosed() === 1);
        });
    });
}

describe('proxy (both engines)', () => {
    it('a plain http loopback target never goes through the proxy', async (t) => {
        const proxy = await connectProxy(t);
        const server = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('direct'); });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        t.after(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()); }));
        const client = proxied(t, false, proxy.url);
        assert.equal((await client.get(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`)).text(), 'direct');
        assert.equal(proxy.connections(), 0);
    });

    it('an https proxy is trusted through proxy.ca, never through the tls.ca meant for targets', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await connectProxy(t, { tlsProxy: true });
        const port = await tlsTarget(t, false);
        await assert.rejects(proxied(t, false, proxy.url).get(`https://localhost:${port}/`), /TLS handshake failed/);
        const res = await proxied(t, false, { url: proxy.url, ca: CERT }).get(`https://localhost:${port}/`);
        assert.equal(res.statusCode, 200);
    });

    it('HTTP/2 through the tunnel to a target without h2 fails instead of hanging', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await connectProxy(t);
        const port = await tlsTarget(t, false);
        const started = Date.now();
        await assert.rejects(proxied(t, true, proxy.url, { timeoutMs: 3000 }).get(`https://localhost:${port}/`), (err: any) => err.name === 'UltraTonNetworkError');
        assert.ok(Date.now() - started < 2000, `took ${Date.now() - started}ms`);
    });

    it('validates the proxy option on the constructor', () => {
        const bad: Array<[unknown, RegExp]> = [
            ['ftp://proxy:21', /^UltraTon: Expected 'proxy' to be an http: or https: URL/],
            ['not a url', /^UltraTon: Expected 'proxy' to be an http: or https: URL/],
            ['http://user:pass@proxy:3128', /^UltraTon: 'proxy' cannot contain credentials; pass them as proxy: \{ url, auth \}\.$/],
            ['http://proxy:3128/path', /^UltraTon: 'proxy' must be an origin only \(no path, query or fragment\)\.$/],
            ['http://proxy:3128/?a=1', /must be an origin only/],
            [{ url: 'http://proxy:3128', resolve: 'remote' }, /^UltraTon: Expected 'proxy\.resolve' to be 'local' or 'proxy', received 'remote'\.$/],
            [{ url: 'http://proxy:3128', auth: 42 }, /^UltraTon: Expected 'proxy\.auth' to be a string/],
            [{ url: 'http://proxy:3128', ca: 42 }, /^UltraTon: Expected 'proxy\.ca' to be a string, Buffer or an array of them/],
            [{ url: 'http://proxy:3128', host: 'x' }, /^UltraTon: Unknown proxy option 'host'\. Valid proxy options: url, auth, ca, resolve\.$/],
            [{ auth: 'a:b' }, /^UltraTon: Expected 'proxy\.url' to be a string/],
            [42, /^UltraTon: Expected 'proxy' to be a URL string or a plain object, received 42\.$/],
        ];
        for (const [proxy, pattern] of bad) {
            assert.throws(() => new UltraTonClient({ proxy } as any), (err: Error) => err instanceof TypeError && pattern.test(err.message), String(JSON.stringify(proxy)));
        }
    });

    it("points 'proxy' on a request at the constructor", async () => {
        await assert.rejects(new UltraTonClient().get('https://example.com/', { proxy: 'http://p:1' } as any), {
            message: "UltraTon: Unknown option 'proxy'. 'proxy' is an option of the client constructor, not of a request.",
        });
    });
});
