/**
 * createSecureAgents() with the real clients it is meant for: axios, got and node-fetch, pinned in this workspace.
 * `ultraton` is the packed tarball (see package.json), so this tests what npm users install. Loopback only: the
 * reserved targets are refused before any socket opens, and the network guard refuses anything else.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createSecureServer } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import axios from 'axios';
import got from 'got';
import fetch from 'node-fetch';
import { createSecureAgents } from 'ultraton';
import { mockDns, v4 } from '../__tests__/fixtures/net-fixtures.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`../__tests__/fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

/** An HTTPS server for `localhost` answering 'ok', or a 302 to `redirect`; counts the connections it accepted. */
async function target(t: TestContext, redirect?: string) {
    let connections = 0;
    const sockets = new Set<Socket>();
    const srv = https.createServer({ cert: CERT, key: KEY }, (_req, res) => {
        if (redirect) { res.writeHead(302, { location: redirect }); res.end(); return; }
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('ok');
    });
    srv.on('secureConnection', (s: Socket) => { connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => srv.close(() => r())); });
    return { url: `https://localhost:${(srv.address() as AddressInfo).port}/`, connections: () => connections };
}

function agentsOf(t: TestContext) {
    const agents = createSecureAgents({ permitReservedIps: ['127.0.0.1'], tls: { ca: CERT } });
    t.after(() => { agents.http.destroy(); agents.https.destroy(); });
    return agents;
}

/** The UltraTon code of an error, wherever the library put it (its own `code`, or the original error as `cause`). */
const ultratonCode = (err: unknown): string | undefined => {
    for (let e: any = err; e; e = e.cause) if (typeof e.code === 'string' && e.code.startsWith('ERR_ULTRATON_')) return e.code;
    return undefined;
};

type Client = (agents: ReturnType<typeof createSecureAgents>) => (url: string) => Promise<string>;

/** Each library wired exactly as the README shows, with its own retries off so counts stay exact. */
const CLIENTS: Record<string, Client> = {
    axios: agents => {
        const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false, responseType: 'text' });
        return async url => (await api.get(url)).data;
    },
    got: agents => {
        const api = got.extend({ agent: { http: agents.http, https: agents.https }, retry: { limit: 0 } });
        return async url => (await api.get(url)).body;
    },
    'node-fetch': agents => async url =>
        (await fetch(url, { agent: (u: URL) => (u.protocol === 'http:' ? agents.http : agents.https) })).text(),
};

for (const [name, client] of Object.entries(CLIENTS)) {
    describe(`createSecureAgents with ${name}`, () => {
        it('lets an allowed request through, TLS verified', async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')] });
            const srv = await target(t);
            assert.equal(await client(agentsOf(t))(srv.url), 'ok');
        });

        it('blocks a name that resolves to a reserved address', async (t) => {
            mockDns(t, { 'internal.example': [v4('10.0.0.1')] });
            await assert.rejects(client(agentsOf(t))('https://internal.example/'), (err: unknown) => ultratonCode(err) === 'ERR_ULTRATON_RESERVED_IP');
        });

        it('blocks a reserved IP literal (cloud metadata)', async (t) => {
            // https, so the address policy is what refuses it (over plain http the scheme rule would come first).
            await assert.rejects(client(agentsOf(t))('https://169.254.169.254/latest/meta-data/'), (err: unknown) => ultratonCode(err) === 'ERR_ULTRATON_RESERVED_IP');
        });

        it("blocks a redirect hop the library follows to a reserved address", async (t) => {
            mockDns(t, { localhost: [v4('127.0.0.1')], 'internal.example': [v4('10.0.0.1')] });
            const srv = await target(t, 'https://internal.example/admin');
            await assert.rejects(client(agentsOf(t))(srv.url), (err: unknown) => ultratonCode(err) === 'ERR_ULTRATON_RESERVED_IP');
            assert.equal(srv.connections(), 1);
        });
    });
}

describe('createSecureAgents with axios and HTTP_PROXY', () => {
    /** Sets the proxy variables axios reads (through proxy-from-env) for the duration of the test. */
    function withProxyEnv(t: TestContext, url: string) {
        const names = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy'];
        const saved = Object.fromEntries(names.map(n => [n, process.env[n]]));
        for (const n of names) delete process.env[n];
        process.env.HTTP_PROXY = url;
        process.env.HTTPS_PROXY = url;
        t.after(() => { for (const n of names) { if (saved[n] === undefined) delete process.env[n]; else process.env[n] = saved[n]; } });
    }

    /** A proxy that records what it is asked for (request targets and CONNECTs) and refuses CONNECT with 403. */
    async function proxyServer(t: TestContext) {
        let connections = 0;
        const connects: string[] = [];
        const srv = http.createServer((_req, res) => res.end('proxied'));
        srv.on('connection', () => connections++);
        srv.on('connect', (req: http.IncomingMessage, socket: Socket) => {
            connects.push(String(req.url));
            socket.end('HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n');
        });
        await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
        t.after(() => new Promise<void>(r => { srv.closeAllConnections(); srv.close(() => r()); }));
        return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, connections: () => connections, connects };
    }

    it('refuses the forward-proxy request axios makes for an http: URL', async (t) => {
        const proxy = await proxyServer(t);
        withProxyEnv(t, proxy.url);
        const agents = agentsOf(t);
        const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https });
        await assert.rejects(api.get('http://169.254.169.254/latest/meta-data/'), (err: unknown) => ultratonCode(err) === 'ERR_ULTRATON_AGENT_PROXY');
        assert.equal(proxy.connections(), 0);
    });

    it('LIMIT: for an https: URL axios swaps in its own tunnelling agent, so the secure agents never see the request', async (t) => {
        // This is why the README makes proxy: false mandatory with axios. If axios ever stops replacing a user's
        // httpsAgent, this test fails and the README warning can be relaxed.
        const proxy = await proxyServer(t);
        withProxyEnv(t, proxy.url);
        const agents = agentsOf(t);
        const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https });
        await assert.rejects(api.get('https://10.0.0.1/'), (err: unknown) => ultratonCode(err) === undefined);
        assert.deepEqual(proxy.connects, ['10.0.0.1:443']);
    });

    it('LIMIT: with httpVersion: 2, axios opens its own HTTP/2 connection and the secure agents never see it', async (t) => {
        // Why the README forbids httpVersion: 2 with the agents. The target is loopback and no policy allows it, yet
        // the server still gets a connection. If axios ever routes HTTP/2 through the agents, this test fails.
        let connections = 0;
        const h2 = createSecureServer({ cert: CERT, key: KEY });
        h2.on('connection', () => connections++);
        h2.on('stream', stream => { stream.respond({ ':status': 200 }); stream.end('h2'); });
        await new Promise<void>(r => h2.listen(0, '127.0.0.1', r));
        t.after(() => new Promise<void>(r => h2.close(() => r())));
        const agents = createSecureAgents();
        t.after(() => { agents.http.destroy(); agents.https.destroy(); });
        const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false, httpVersion: 2 } as any);
        await api.get(`https://127.0.0.1:${(h2.address() as AddressInfo).port}/`).catch(() => undefined);
        assert.ok(connections >= 1, 'axios reached the server around the agents');
    });

    it('works with proxy: false, as the README says, whatever the environment', async (t) => {
        mockDns(t, { localhost: [v4('127.0.0.1')] });
        const proxy = await proxyServer(t);
        withProxyEnv(t, proxy.url);
        const srv = await target(t);
        const agents = agentsOf(t);
        const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false, responseType: 'text' });
        assert.equal((await api.get(srv.url)).data, 'ok');
        assert.equal(proxy.connections(), 0);
    });
});
