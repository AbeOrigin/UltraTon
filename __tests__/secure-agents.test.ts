/**
 * `createSecureAgents()`: an http/https Agent pair that applies UltraTon's SSRF policy (every address validated and
 * pinned, IP literals judged, plain http only to loopback) to any client that takes an agent. Here: Node's own
 * http.request / https.request; the integration with axios, got and node-fetch is covered in compat/ (D2).
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo, Socket } from 'node:net';
import { createSecureAgents } from '../src/agents.ts';
import { mockDns, PLAIN_HTTP, RESERVED, v4 } from './fixtures/net-fixtures.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

/** A loopback server (TLS with the localhost cert, or plain) that answers 'ok' and counts connections. */
async function server(t: TestContext, secure: boolean) {
    let connections = 0;
    const sockets = new Set<Socket>();
    const handler = (_req: http.IncomingMessage, res: http.ServerResponse) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok'); };
    const srv = secure ? https.createServer({ cert: CERT, key: KEY }, handler) : http.createServer(handler);
    srv.on(secure ? 'secureConnection' : 'connection', (s: Socket) => { connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return { port: (srv.address() as AddressInfo).port, connections: () => connections };
}

/** One request through `agent`; resolves with the body, rejects with the request's error. */
function get(url: string, agent: http.Agent, extra: Record<string, unknown> = {}): Promise<string> {
    return new Promise((resolve, reject) => {
        const request = url.startsWith('https:') ? https.request : http.request;
        const req = request(url, { agent, ...extra } as any, res => {
            const chunks: Buffer[] = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString()));
            res.on('error', reject);
        });
        req.on('error', reject);
        req.end();
    });
}

function agentsOf(t: TestContext, options: Record<string, unknown> = {}) {
    const agents = createSecureAgents(options as any);
    t.after(() => { agents.http.destroy(); agents.https.destroy(); });
    return agents;
}

const reserved = (err: Error) => RESERVED.test(err.message) && (err as any).code === 'ERR_ULTRATON_RESERVED_IP';

describe('createSecureAgents', () => {
    it('connects to an allowed, validated address and verifies TLS against the hostname', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const srv = await server(t, true);
        const agents = agentsOf(t, { permitReservedIps: ['127.0.0.1'], tls: { ca: CERT } });
        assert.equal(await get(`https://localhost:${srv.port}/`, agents.https), 'ok');
    });

    it('blocks a name that resolves to a reserved address, before any socket opens', async (t) => {
        mockDns(t, { 'internal.example': [v4('10.0.0.1')], 'mixed.example': [v4('93.184.216.34'), v4('10.0.0.2')] });
        const agents = agentsOf(t);
        await assert.rejects(get('https://internal.example/', agents.https), reserved);
        // One reserved address in the answer fails the whole lookup.
        await assert.rejects(get('https://mixed.example/', agents.https), reserved);
    });

    it('judges IP literals in every spelling the URL parser normalizes', async (t) => {
        const agents = agentsOf(t);
        for (const url of ['https://10.0.0.1/', 'https://0x7f000001/', 'https://2130706433/', 'https://[::ffff:169.254.169.254]/', 'https://[::1]/']) {
            await assert.rejects(get(url, agents.https), reserved, url);
        }
    });

    it("ignores the caller's own lookup: the agent resolves and validates itself", async (t) => {
        mockDns(t, { 'evil.example': [v4('10.0.0.5')] });
        const agents = agentsOf(t, { permitReservedIps: ['127.0.0.1'] });
        const lying = (_h: string, _o: unknown, cb: (...a: unknown[]) => void) => cb(null, '127.0.0.1', 4);
        await assert.rejects(get('https://evil.example/', agents.https, { lookup: lying }), reserved);
    });

    it("connects to the validated address, never the one the caller's lookup names", async (t) => {
        mockDns(t, { 'svc.internal': [v4('127.0.0.1')] });
        const srv = await server(t, false);
        const agents = agentsOf(t, { allowPlainHttp: true, permitReservedIps: ['127.0.0.1'] });
        // Were this lookup used, the socket would go to 10.0.0.9 (and the test network guard would refuse it).
        const elsewhere = (_h: string, o: { all?: boolean }, cb: (...a: unknown[]) => void) =>
            (o?.all ? cb(null, [{ address: '10.0.0.9', family: 4 }]) : cb(null, '10.0.0.9', 4));
        assert.equal(await get(`http://svc.internal:${srv.port}/`, agents.http, { lookup: elsewhere }), 'ok');
        assert.equal(srv.connections(), 1);
    });

    it('validates DNS again for every new socket (rebinding between connections is blocked)', async (t) => {
        const srv = await server(t, true);
        const answers = ['127.0.0.1', '10.0.0.7'];
        let lookups = 0;
        t.mock.method(dnsPromises, 'lookup', (async (_h: string, o?: { all?: boolean }) => {
            const answer = { address: answers[Math.min(lookups++, 1)], family: 4 };
            return o?.all ? [answer] : answer;
        }) as any);
        const agents = agentsOf(t, { permitReservedIps: ['127.0.0.1'], tls: { ca: CERT } });
        assert.equal(await get(`https://localhost:${srv.port}/`, agents.https, { headers: { connection: 'close' } }), 'ok');
        await assert.rejects(get(`https://localhost:${srv.port}/`, agents.https), reserved);
        assert.equal(srv.connections(), 1);
    });

    it('keeps TLS verification on whatever the request options say', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const srv = await server(t, true);
        // No ca: the self-signed certificate must be refused even with rejectUnauthorized: false on the request.
        const agents = agentsOf(t, { permitReservedIps: ['127.0.0.1'] });
        await assert.rejects(get(`https://localhost:${srv.port}/`, agents.https, { rejectUnauthorized: false, checkServerIdentity: () => undefined }),
            (err: any) => /self[- ]signed|unable to verify|certificate/i.test(`${err.code} ${err.message}`));
        assert.equal(srv.connections(), 0);
    });

    it('allows plain http only to loopback names and addresses by default', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')], 'api.example': [v4('127.0.0.1')], 'rebound.localhost': [v4('10.0.0.3')] });
        const srv = await server(t, false);
        const agents = agentsOf(t, { permitReservedIps: true });
        assert.equal(await get(`http://localhost:${srv.port}/`, agents.http), 'ok');
        assert.equal(await get(`http://127.0.0.1:${srv.port}/`, agents.http), 'ok');
        // A non-loopback name over plain http is refused even when it resolves to loopback...
        await assert.rejects(get(`http://api.example:${srv.port}/`, agents.http), { code: 'ERR_ULTRATON_PLAIN_HTTP' });
        // ...and a loopback name that resolves elsewhere is refused too.
        await assert.rejects(get('http://rebound.localhost/', agents.http), (err: Error) => PLAIN_HTTP.test(err.message));
    });

    it('allowPlainHttp lifts only the scheme rule, never the address policy', async (t) => {
        mockDns(t, { 'svc.internal': [v4('127.0.0.1')], 'db.internal': [v4('10.0.0.9')] });
        const srv = await server(t, false);
        const agents = agentsOf(t, { allowPlainHttp: true, permitReservedIps: ['127.0.0.1'] });
        assert.equal(await get(`http://svc.internal:${srv.port}/`, agents.http), 'ok');
        await assert.rejects(get('http://db.internal/', agents.http), reserved);
    });

    it("refuses forward-proxy requests, whose real target the agent never sees (axios's HTTP_PROXY)", async (t) => {
        // The "proxy" is an allowed loopback address: a library pointing the agent at it must not smuggle a target past it.
        const proxy = await server(t, false);
        const agents = agentsOf(t, { allowPlainHttp: true, permitReservedIps: ['127.0.0.1'] });
        const viaProxy = (options: Record<string, unknown>) => new Promise<void>((resolve, reject) => {
            const req = http.request({ host: '127.0.0.1', port: proxy.port, agent: agents.http, ...options }, () => resolve());
            req.on('error', reject);
            req.end();
        });
        const refused = { name: 'SecureHttpError', code: 'ERR_ULTRATON_AGENT_PROXY' };
        await assert.rejects(viaProxy({ path: 'http://169.254.169.254/latest/meta-data/' }), refused);
        await assert.rejects(viaProxy({ method: 'CONNECT', path: '10.0.0.1:443' }), refused);
        assert.equal(proxy.connections(), 0);
        // The asterisk form (OPTIONS *) is a request to the host itself, not to a proxy.
        await viaProxy({ method: 'OPTIONS', path: '*' });
    });

    it('refuses a socketPath, which would skip every check', async (t) => {
        const agents = agentsOf(t, { permitReservedIps: true });
        await assert.rejects(get('http://localhost/', agents.http, { socketPath: '/tmp/x.sock' }), {
            name: 'TypeError', message: "UltraTon: A secure agent never connects to a socket path ('socketPath').",
        });
    });

    it('never shares sockets between pairs with different policies', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const srv = await server(t, true);
        const open = agentsOf(t, { permitReservedIps: ['127.0.0.1'], tls: { ca: CERT } });
        const strict = agentsOf(t, { tls: { ca: CERT } });
        assert.equal(await get(`https://localhost:${srv.port}/`, open.https), 'ok');
        await assert.rejects(get(`https://localhost:${srv.port}/`, strict.https), reserved);
    });

    it('validates its options like the client does', () => {
        const cases: Array<[unknown, RegExp]> = [
            [{ permitReservedIps: ['not an ip/99'] }, /^UltraTon: Invalid permitReservedIps entry/],
            [{ permitReservedIps: 'yes' }, /^UltraTon: Expected 'permitReservedIps' to be a boolean/],
            [{ tls: { rejectUnauthorized: false } }, /^UltraTon: Unknown tls option 'rejectUnauthorized'/],
            [{ allowPlainHttp: 'true' }, /^UltraTon: Expected 'allowPlainHttp' to be a boolean, received string$/],
            [{ proxy: 'http://p:1' }, /^UltraTon: Unknown option 'proxy'\. A secure agent does not tunnel through a proxy; use the client's 'proxy' option\.$/],
            [{ timeoutMs: 5 }, /^UltraTon: Unknown option 'timeoutMs'\. Valid options: permitReservedIps, tls, allowPlainHttp\./],
            [42, /^UltraTon: Secure agent options must be a plain object\.$/],
        ];
        for (const [options, pattern] of cases) {
            assert.throws(() => createSecureAgents(options as any), (err: Error) => err instanceof TypeError && pattern.test(err.message), JSON.stringify(options));
        }
    });
});
