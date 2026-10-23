/**
 * Which of the caller's headers follow a redirect, on both engines with real loopback servers: two servers on 127.0.0.1
 * with different ports are two origins. The default 'all' keeps every header but the credential ones (characterization:
 * an x-api-key does travel, as with fetch, got and axios); 'safe' keeps only content negotiation, the user agent and
 * the body framing; a redirect on the same origin keeps everything in both modes.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type Http2Server, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';

type Engine = 'http1' | 'http2';
type Req = http.IncomingMessage | Http2ServerRequest;
type Res = http.ServerResponse | Http2ServerResponse;

const HEADERS = { 'x-api-key': 'K', 'accept-language': 'es', cookie: 'c=1', authorization: 'Bearer t' };

/** Origin `a` redirects `/cross` to origin `b` and `/same` to itself; both answer `/final` with the request headers as JSON. */
async function twoOrigins(t: TestContext, engine: Engine) {
    const echo = (req: Req, res: Res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(req.headers));
    };
    const listen = async (handler: (req: Req, res: Res) => void) => {
        const server: http.Server | Http2Server = engine === 'http1' ? http.createServer(handler) : createH2Server(handler);
        const sockets = new Set<Socket>();
        server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        t.after(async () => {
            for (const s of sockets) s.destroy();
            await new Promise<void>(r => server.close(() => r()));
        });
        return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    };
    const b = await listen(echo);
    let a = '';
    a = await listen((req, res) => {
        if (req.url === '/final') return echo(req, res);
        res.writeHead(302, { location: `${req.url === '/same' ? a : b}/final` });
        res.end();
    });
    return { a, b };
}

const clientFor = (t: TestContext, engine: Engine, options: Record<string, unknown> = {}) => {
    const client = new UltraTonClient({ http2: engine === 'http2', permitReservedIps: true, maxRedirects: 2, ...options });
    t.after(() => client.close());
    return client;
};

const landed = async (client: UltraTonClient, url: string, options: Record<string, unknown>) =>
    (await client.get(url, options)).json<Record<string, string>>();

for (const engine of ['http1', 'http2'] as Engine[]) {
    describe(`redirectHeaders (${engine})`, () => {
        it("default 'all': the credential headers stay behind on another origin, every other header travels", async (t) => {
            const { a } = await twoOrigins(t, engine);
            const got = await landed(clientFor(t, engine), `${a}/cross`, { headers: HEADERS });
            assert.equal(got['x-api-key'], 'K');
            assert.equal(got['accept-language'], 'es');
            assert.equal(got.cookie, undefined);
            assert.equal(got.authorization, undefined);
        });

        it("'safe': only content negotiation and the user agent follow to another origin", async (t) => {
            const { a } = await twoOrigins(t, engine);
            const got = await landed(clientFor(t, engine), `${a}/cross`, { headers: HEADERS, redirectHeaders: 'safe' });
            assert.equal(got['x-api-key'], undefined);
            assert.equal(got.cookie, undefined);
            assert.equal(got.authorization, undefined);
            assert.equal(got['accept-language'], 'es');
            assert.match(got['user-agent'], /^ultraton\//);
        });

        it("'safe' on the same origin keeps every header", async (t) => {
            const { a } = await twoOrigins(t, engine);
            const got = await landed(clientFor(t, engine), `${a}/same`, { headers: HEADERS, redirectHeaders: 'safe' });
            assert.equal(got['x-api-key'], 'K');
            assert.equal(got.cookie, 'c=1');
            assert.equal(got.authorization, 'Bearer t');
        });

        it('the client default applies to every request and a request can override it', async (t) => {
            const { a } = await twoOrigins(t, engine);
            const client = clientFor(t, engine, { redirectHeaders: 'safe' });
            assert.equal((await landed(client, `${a}/cross`, { headers: HEADERS }))['x-api-key'], undefined);
            assert.equal((await landed(client, `${a}/cross`, { headers: HEADERS, redirectHeaders: 'all' }))['x-api-key'], 'K');
        });
    });
}

describe('redirectHeaders validation', () => {
    it("rejects anything but 'all' or 'safe', before connecting", async () => {
        const client = new UltraTonClient();
        await assert.rejects(
            async () => client.get('https://example.com/', { redirectHeaders: 'none' } as never),
            /UltraTon: Expected 'redirectHeaders' to be 'all' or 'safe', received 'none'\.$/,
        );
        assert.throws(
            () => new UltraTonClient({ redirectHeaders: 1 } as never),
            /UltraTon: Expected 'redirectHeaders' to be 'all' or 'safe', received number\.$/,
        );
    });
});
