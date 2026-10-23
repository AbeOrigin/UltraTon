/**
 * TLS 1.2 is the floor of every connection UltraTon opens, set on the connection itself rather than inherited from
 * `tls.DEFAULT_MIN_VERSION`, which `--tls-min-v1.0`, NODE_OPTIONS or any module in the process can lower. Node's https
 * and http2 internals open their sockets through `tls.connect`, so a spy on it sees the options of every handshake:
 * direct HTTP/1.1 and HTTP/2 from the client, and the secure agents whatever the library asks for. The tunnel paths set
 * the same constant (see src/proxy/tunnel.ts and the tunnel branches of both engines).
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { createSecureServer } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { createSecureAgents } from '../src/agents.ts';
import { TLS_MIN_VERSION } from '../src/constants.ts';
import { mockDns, v4 } from './fixtures/net-fixtures.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

/** An HTTPS or h2 server for `localhost` on 127.0.0.1 that answers 200. */
async function serveTls(t: TestContext, http2: boolean) {
    const handler = (_req: unknown, res: { end(body: string): void }) => res.end('ok');
    const server = http2 ? createSecureServer({ cert: CERT, key: KEY }, handler) : https.createServer({ cert: CERT, key: KEY }, handler);
    const sockets = new Set<Socket>();
    server.on('secureConnection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    mockDns(t, { localhost: [v4('127.0.0.1')] });
    return `https://localhost:${(server.address() as AddressInfo).port}/`;
}

/** Records the options of every `tls.connect` call made from now on, and lets the call through. */
function spyTlsConnect(t: TestContext) {
    const seen: tls.ConnectionOptions[] = [];
    const original = tls.connect;
    t.mock.method(tls, 'connect', function (this: unknown, ...args: unknown[]) {
        const options = args.find(a => typeof a === 'object' && a !== null) as tls.ConnectionOptions | undefined;
        if (options) seen.push(options);
        return (original as (...a: unknown[]) => tls.TLSSocket).apply(this, args);
    });
    return seen;
}

for (const http2 of [false, true]) {
    describe(`TLS floor on a direct ${http2 ? 'HTTP/2' : 'HTTP/1.1'} connection`, () => {
        it(`asks for ${TLS_MIN_VERSION} at least on every handshake`, { timeout: 5000 }, async (t) => {
            const url = await serveTls(t, http2);
            const seen = spyTlsConnect(t);
            const client = new UltraTonClient({ http2, permitReservedIps: true, tls: { ca: CERT } });
            t.after(() => client.close());
            assert.equal((await client.get(url)).text(), 'ok');
            assert.ok(seen.length >= 1, 'the handshake went through tls.connect');
            for (const options of seen) assert.equal(options.minVersion, TLS_MIN_VERSION);
        });
    });
}

describe('TLS floor in createSecureAgents()', () => {
    const get = (url: string, agent: http.Agent, options: https.RequestOptions) => new Promise<string>((resolve, reject) => {
        https.get(url, { agent, ...options }, res => {
            const chunks: Buffer[] = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString()));
            res.on('error', reject);
        }).on('error', reject);
    });

    // Node's Agent merges the agent's options over the request's, so the floor holds whatever the library passes.
    for (const asked of ['TLSv1', 'TLSv1.3'] as const) {
        it(`uses ${TLS_MIN_VERSION} when the library asks for ${asked}`, { timeout: 5000 }, async (t) => {
            const url = await serveTls(t, false);
            const seen = spyTlsConnect(t);
            const agents = createSecureAgents({ permitReservedIps: true });
            t.after(() => { agents.http.destroy(); agents.https.destroy(); });
            assert.equal(await get(url, agents.https, { ca: CERT, minVersion: asked }), 'ok');
            assert.equal(seen.length, 1);
            assert.equal(seen[0].minVersion, TLS_MIN_VERSION);
        });
    }
});
