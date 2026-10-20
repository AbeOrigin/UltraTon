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
import { ipv6Available, mockDns, RESERVED, v4, v6 } from './fixtures/net-fixtures.ts';
import { ipv6Bytes } from '../src/proxy/tunnel.ts';

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
async function tlsTarget(t: TestContext, http2: boolean, redirect?: string, host = '127.0.0.1') {
    const handler = (req: http.IncomingMessage | any, res: http.ServerResponse | any) => {
        if (redirect) { res.writeHead(302, { location: redirect }); res.end(); return; }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ headers: req.headers }));
    };
    const server = http2 ? createSecureServer({ cert: CERT, key: KEY }, handler) : https.createServer({ cert: CERT, key: KEY }, handler);
    const sockets = new Set<net.Socket>();
    server.on('secureConnection', (s: net.Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, host, r));
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
            ['ftp://proxy:21', /^UltraTon: Expected 'proxy' to be an http:, https:, socks5: or socks5h: URL/],
            ['not a url', /^UltraTon: Expected 'proxy' to be an http:, https:, socks5: or socks5h: URL/],
            ['socks4://proxy:1080', /socks5: or socks5h: URL/],
            ['socks5://user:pass@proxy:1080', /cannot contain credentials/],
            ['socks5://proxy:1080/x', /must be an origin only/],
            [{ url: 'socks5h://proxy:1080', resolve: 'local' }, /^UltraTon: A socks5h: proxy resolves names itself; use socks5: with resolve: 'local', or drop 'resolve'.$/],
            [{ url: 'socks5://proxy:1080', ca: 'x' }, /^UltraTon: 'proxy.ca' only applies to an https: proxy; a SOCKS5 proxy has no TLS of its own.$/],
            [{ url: 'socks5://proxy:1080', auth: 'nopassword' }, /^UltraTon: A SOCKS5 'proxy.auth' must be 'user:password', each part from 1 to 255 bytes.$/],
            [{ url: 'socks5://proxy:1080', auth: `${'u'.repeat(256)}:p` }, /each part from 1 to 255 bytes/],
            [{ url: 'socks5://proxy:1080', auth: ':p' }, /each part from 1 to 255 bytes/],
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

/** The 16 bytes of an IPv6 address in full form (no `::`), as a SOCKS5 request carries it. */
const ipv6Text = (raw: Buffer) => Array.from({ length: 8 }, (_, i) => raw.readUInt16BE(i * 2).toString(16)).join(':');

type SocksSeen = { methods: number[]; user?: string; pass?: string; atyp: number; host: string; port: number };

/**
 * A SOCKS5 proxy (RFC 1928/1929) on loopback that records each request. `auth`: the only accepted `user:password`
 * (method 2 required). `refuse`: target host → reply code. `methodReply`: forces the method answer (0xff: none).
 * `splitReply`: the success reply goes out one byte at a time. `trailing`: a stray byte follows it.
 */
async function socksProxy(t: TestContext, opts: { auth?: string; refuse?: Record<string, number>; methodReply?: number; hang?: boolean; splitReply?: boolean; trailing?: boolean } = {}) {
    const seen: SocksSeen[] = [];
    let connections = 0;
    const clients = new Set<net.Socket>();
    const sockets = new Set<net.Socket>();
    const track = (s: net.Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => undefined); };
    const server = net.createServer(client => {
        connections++;
        track(client);
        clients.add(client);
        client.on('close', () => clients.delete(client));
        let buffered = Buffer.alloc(0);
        let stage: 'greeting' | 'auth' | 'request' = 'greeting';
        const record: Partial<SocksSeen> = {};
        const onData = (chunk: Buffer) => {
            buffered = Buffer.concat([buffered, chunk]);
            for (;;) {
                if (stage === 'greeting') {
                    if (buffered.length < 2 || buffered.length < 2 + buffered[1]) return;
                    record.methods = [...buffered.subarray(2, 2 + buffered[1])];
                    buffered = buffered.subarray(2 + buffered[1]);
                    if (opts.hang) return;
                    const method = opts.methodReply ?? (opts.auth ? 2 : 0);
                    client.write(Buffer.from([5, method]));
                    if (method === 0xff) { client.end(); return; }
                    stage = method === 2 ? 'auth' : 'request';
                    continue;
                }
                if (stage === 'auth') {
                    if (buffered.length < 2) return;
                    const ulen = buffered[1];
                    if (buffered.length < 3 + ulen || buffered.length < 3 + ulen + buffered[2 + ulen]) return;
                    const plen = buffered[2 + ulen];
                    record.user = buffered.subarray(2, 2 + ulen).toString();
                    record.pass = buffered.subarray(3 + ulen, 3 + ulen + plen).toString();
                    buffered = buffered.subarray(3 + ulen + plen);
                    const ok = `${record.user}:${record.pass}` === opts.auth;
                    client.write(Buffer.from([1, ok ? 0 : 1]));
                    if (!ok) { client.end(); return; }
                    stage = 'request';
                    continue;
                }
                if (buffered.length < 5) return;
                const atyp = buffered[3];
                const length = atyp === 1 ? 4 : atyp === 4 ? 16 : 1 + buffered[4];
                if (buffered.length < 4 + length + 2) return;
                const raw = buffered.subarray(4, 4 + length);
                const host = atyp === 1 ? [...raw].join('.') : atyp === 4 ? ipv6Text(raw) : raw.subarray(1).toString();
                const port = buffered.readUInt16BE(4 + length);
                seen.push({ ...record, atyp, host, port } as SocksSeen);
                client.off('data', onData);
                client.pause();
                const code = opts.refuse?.[host];
                if (code !== undefined) { client.end(Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
                const upstream = net.connect({ host: host === 'localhost' ? '127.0.0.1' : host, port });
                track(upstream);
                upstream.once('error', () => { if (!client.destroyed) client.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); });
                upstream.once('connect', () => {
                    // An ATYP 3 bound address, so the reply length depends on it.
                    const reply = Buffer.from([5, 0, 0, 3, 4, ...Buffer.from('bind'), 0, 0, ...(opts.trailing ? [0x16] : [])]);
                    if (opts.splitReply) for (const byte of reply) client.write(Buffer.from([byte]));
                    else client.write(reply);
                    client.pipe(upstream);
                    upstream.pipe(client);
                    upstream.on('close', () => client.destroy());
                    client.on('close', () => upstream.destroy());
                });
                return;
            }
        };
        client.on('data', onData);
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    const port = (server.address() as AddressInfo).port;
    return { port, url: `socks5://127.0.0.1:${port}`, seen, connections: () => connections, openClients: () => clients.size };
}

for (const http2 of [false, true]) {
    describe(`SOCKS5 proxy (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('sends the validated IPv4 address (ATYP 1), never the name, offering no authentication', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await socksProxy(t);
            const port = await tlsTarget(t, http2);
            assert.equal((await proxied(t, http2, proxy.url).get(`https://localhost:${port}/`)).statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => [s.atyp, s.host, s.port, s.methods]), [[1, '127.0.0.1', port, [0]]]);
        });

        it('authenticates with username/password (RFC 1929) when auth is set', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await socksProxy(t, { auth: 'svc:s3cret' });
            const port = await tlsTarget(t, http2);
            const res = await proxied(t, http2, { url: proxy.url, auth: 'svc:s3cret' }).get(`https://localhost:${port}/`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual([proxy.seen[0].methods, proxy.seen[0].user, proxy.seen[0].pass], [[0, 2], 'svc', 's3cret']);
        });

        it('a rejected login, or no acceptable method, is final: no other address is tried', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.9'), v4('127.0.0.1')] });
            const wrong = await socksProxy(t, { auth: 'svc:right' });
            await assert.rejects(proxied(t, http2, { url: wrong.url, auth: 'svc:wrong' }).get('https://localhost:9/'), {
                code: 'ERR_ULTRATON_PROXY', message: 'UltraTon: The SOCKS proxy refused the connection (authentication failed).',
            });
            assert.equal(wrong.connections(), 1);
            const none = await socksProxy(t, { methodReply: 0xff });
            await assert.rejects(proxied(t, http2, none.url).get('https://localhost:9/'), {
                code: 'ERR_ULTRATON_PROXY', message: 'UltraTon: The SOCKS proxy refused the connection (no acceptable authentication method).',
            });
            assert.equal(none.connections(), 1);
        });

        it('tries the next validated address on host unreachable, but not past the ruleset', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.9'), v4('127.0.0.1')] });
            const port = await tlsTarget(t, http2);
            const unreachable = await socksProxy(t, { refuse: { '127.0.0.9': 4 } });
            assert.equal((await proxied(t, http2, unreachable.url).get(`https://localhost:${port}/`)).statusCode, 200);
            assert.deepEqual(unreachable.seen.map(s => s.host), ['127.0.0.9', '127.0.0.1']);

            const ruleset = await socksProxy(t, { refuse: { '127.0.0.9': 2 } });
            await assert.rejects(proxied(t, http2, ruleset.url).get(`https://localhost:${port}/`), {
                code: 'ERR_ULTRATON_PROXY', message: 'UltraTon: The SOCKS proxy refused the connection (connection not allowed by ruleset).',
            });
            assert.equal(ruleset.seen.length, 1);
        });

        it('blocks SSRF before the SOCKS proxy is ever contacted', async (t) => {
            mockDns(t, { 'internal.example': [v4('10.0.0.1')] });
            const proxy = await socksProxy(t);
            const client = proxied(t, http2, proxy.url, { permitReservedIps: false });
            await assert.rejects(client.get('https://internal.example/'), (err: Error) => RESERVED.test(err.message));
            await assert.rejects(client.get('https://10.0.0.1/'), (err: Error) => RESERVED.test(err.message));
            assert.equal(proxy.connections(), 0);
        });

        it('socks5h: sends the name (ATYP 3) and resolves nothing locally', async (t) => {
            mockDns(t, {});
            const proxy = await socksProxy(t);
            const port = await tlsTarget(t, http2);
            const client = proxied(t, http2, `socks5h://127.0.0.1:${proxy.port}`);
            assert.equal((await client.get(`https://localhost:${port}/`)).statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => [s.atyp, s.host]), [[3, 'localhost']]);
        });

        it("checks an IP-literal target's certificate against the IP through a SOCKS proxy reached by name", async (t) => {
            const proxy = await socksProxy(t);
            const cert = { cert: fixture('dns-only-cert.pem'), key: fixture('dns-only-key.pem') };
            const answer = (_req: unknown, res: http.ServerResponse) => res.end('mitm');
            const target = http2 ? createSecureServer(cert, answer as any) : https.createServer(cert, answer);
            await new Promise<void>(r => target.listen(0, '127.0.0.1', r));
            t.after(() => new Promise<void>(r => target.close(() => r())));
            const client = proxied(t, http2, `socks5://localhost:${proxy.port}`, { tls: { ca: fixture('dns-only-cert.pem') } });
            await assert.rejects(client.get(`https://127.0.0.1:${(target.address() as AddressInfo).port}/`), /TLS handshake failed/);
            assert.equal(proxy.seen.length, 1);
        });

        it('a SOCKS proxy that never answers is bounded by timeoutMs, and close() ends it', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const proxy = await socksProxy(t, { hang: true });
            const client = proxied(t, http2, proxy.url, { timeoutMs: 300 });
            const started = Date.now();
            await assert.rejects(client.get('https://localhost:9/'), { code: 'ERR_ULTRATON_TIMEOUT' });
            assert.ok(Date.now() - started < 1500, `took ${Date.now() - started}ms`);
            await eventually(() => proxy.openClients() === 0);

            const waiting = proxied(t, http2, proxy.url, { timeoutMs: 0 });
            const pending = waiting.get('https://localhost:9/');
            await eventually(() => proxy.openClients() === 1);
            await waiting.close();
            await assert.rejects(pending, { message: 'UltraTon: Client is closed.' });
            await eventually(() => proxy.openClients() === 0);
        });

        it('sends a validated IPv6 address as ATYP 4', { skip: !ipv6Available && 'no IPv6 loopback' }, async (t) => {
            mockDns(t, { localhost: [v6('::1')] });
            const proxy = await socksProxy(t);
            const port = await tlsTarget(t, http2, undefined, '::1');
            const res = await proxied(t, http2, proxy.url, { permitReservedIps: ['::1'] }).get(`https://localhost:${port}/`);
            assert.equal(res.statusCode, 200);
            assert.deepEqual(proxy.seen.map(s => [s.atyp, s.host]), [[4, '0:0:0:0:0:0:0:1']]);
        });
    });
}

describe('SOCKS5 proxy (protocol edges)', () => {
    it('reads a reply that arrives one byte at a time, with an ATYP 3 bound address', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await socksProxy(t, { splitReply: true });
        const port = await tlsTarget(t, false);
        assert.equal((await proxied(t, false, proxy.url).get(`https://localhost:${port}/`)).statusCode, 200);
    });

    it('refuses a byte past the reply as malformed', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await socksProxy(t, { trailing: true });
        const port = await tlsTarget(t, false);
        await assert.rejects(proxied(t, false, proxy.url).get(`https://localhost:${port}/`), {
            code: 'ERR_ULTRATON_PROXY', message: 'UltraTon: The proxy sent a malformed response.',
        });
    });

    it('sends no credentials when the proxy picks "no authentication"', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await socksProxy(t, { methodReply: 0 });
        const port = await tlsTarget(t, false);
        assert.equal((await proxied(t, false, { url: proxy.url, auth: 'svc:s3cret' }).get(`https://localhost:${port}/`)).statusCode, 200);
        assert.deepEqual([proxy.seen[0].methods, proxy.seen[0].user], [[0, 2], undefined]);
    });

    it('encodes multibyte credentials by bytes, splitting at the first colon', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await socksProxy(t, { auth: 'üser:pa:ss€' });
        const port = await tlsTarget(t, false);
        assert.equal((await proxied(t, false, { url: proxy.url, auth: 'üser:pa:ss€' }).get(`https://localhost:${port}/`)).statusCode, 200);
        assert.deepEqual([proxy.seen[0].user, proxy.seen[0].pass], ['üser', 'pa:ss€']);
    });

    it('a name too long for SOCKS5 throws before the proxy is contacted', async (t) => {
        const proxy = await socksProxy(t);
        const long = Array.from({ length: 5 }, () => 'a'.repeat(60)).join('.');
        for (const http2 of [false, true]) {
            await assert.rejects(proxied(t, http2, `socks5h://127.0.0.1:${proxy.port}`).get(`https://${long}/`), {
                name: 'TypeError', message: 'UltraTon: The hostname is too long for a SOCKS5 proxy (at most 255 bytes).',
            });
        }
        assert.equal(proxy.connections(), 0);
    });
});

describe('ipv6Bytes', () => {
    it('expands every IPv6 form a resolver can return', () => {
        const hex = (ip: string) => ipv6Bytes(ip).toString('hex');
        assert.equal(hex('::1'), '00000000000000000000000000000001');
        assert.equal(hex('::'), '0'.repeat(32));
        assert.equal(hex('2001:db8::8a2e:370:7334'), '20010db80000000000008a2e03707334');
        assert.equal(hex('1::'), '0001' + '0'.repeat(28));
        assert.equal(hex('::ffff:10.0.0.1'), '00000000000000000000ffff0a000001');
        assert.equal(hex('fe80::1%eth0'), 'fe800000000000000000000000000001');
        assert.equal(hex('1:2:3:4:5:6:7:8'), '00010002000300040005000600070008');
        assert.equal(hex('1:2:3:4:5:6:1.2.3.4'), '00010002000300040005000601020304');
        assert.equal(hex('::FFFF:7F00:1'), '00000000000000000000ffff7f000001');
        assert.throws(() => ipv6Bytes('not-an-ip'), TypeError);
    });
});
