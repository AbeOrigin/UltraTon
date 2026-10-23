/**
 * Soak test: a long loop of hostile and flaky server behaviour against loopback servers, then a check that nothing
 * stayed behind. The project promises that memory stays bounded whatever a server sends back; the unit tests prove
 * each behaviour once, this proves that thousands of them in a row do not leak memory, sockets or HTTP/2 sessions.
 *
 * Runs in CI only (.github/workflows/soak.yml, weekly and on demand): it loads the machine for 20 to 60 minutes.
 *
 *   node --expose-gc --import ./__tests__/fixtures/loopback-only.ts scripts/soak.ts
 *
 * SOAK_MINUTES (default 20) is the length of the loop. Locally only SOAK_SMOKE=1 is accepted, with SOAK_SECONDS for
 * a few seconds' check that the harness itself still works.
 *
 * What the loop mixes, on HTTP/1.1 and HTTP/2, directly and through a CONNECT proxy: 200s (small, large, gzip),
 * redirects (same origin, and cross origin to a TLS server on another port), 503s with retries, streams cut by the
 * server, abort via AbortSignal, idle timeouts, body-size overruns on the wire and after decompression, uploads,
 * and a stream the consumer cancels halfway.
 *
 * Measured: baseline after a warm-up, then after the loop and `client.close()`: RSS, heap, the HTTP/2 sessions the
 * clients opened (all must be closed), the server-side sockets still open (none may be), and the TCP/TLS handles in
 * `process.getActiveResourcesInfo()` once the servers are closed too (none may be). Growth over the margins fails.
 *
 * The clients and their reserved-IP policies are a fixed set: the allowlist and agent caches grow by design with
 * distinct policies (marked `ponytail:` in src), so new policies in the loop would measure the design, not a leak.
 */
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import http2, { connect as nativeConnect, type ClientHttp2Session } from 'node:http2';
import net, { type AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import { UltraTonClient } from '../src/http-client.ts';
import { Http2SessionManager } from '../src/engines/http2-session-manager.ts';
import { kSessionManager } from '../src/internal.ts';
import type { ProxyConfig } from '../src/proxy/tunnel.ts';

const SMOKE = process.env.SOAK_SMOKE === '1';
if (!SMOKE && process.env.CI !== 'true') {
    console.error('The soak test runs in CI only. Use SOAK_SMOKE=1 SOAK_SECONDS=5 for a quick local check of the harness.');
    process.exit(2);
}
const DURATION_MS = SMOKE ? Number(process.env.SOAK_SECONDS ?? 5) * 1000 : Number(process.env.SOAK_MINUTES ?? 20) * 60_000;
const WARMUP_MS = Math.min(30_000, DURATION_MS / 5);
const WORKERS = 16;
const RSS_MARGIN = Number(process.env.SOAK_RSS_MARGIN_MIB ?? 64) * 1024 * 1024;
const HEAP_MARGIN = Number(process.env.SOAK_HEAP_MARGIN_MIB ?? 24) * 1024 * 1024;
const MAX_BODY = 1024 * 1024;
const gc = globalThis.gc ?? (() => { throw new Error('run with --expose-gc'); });

const fixture = (name: string) => fs.readFileSync(new URL(`../__tests__/fixtures/${name}`, import.meta.url));
const CERT = fixture('localhost-cert.pem');
const KEY = fixture('localhost-key.pem');

const SMALL = Buffer.from(JSON.stringify({ ok: true, text: 'x'.repeat(200) }));
const LARGE = Buffer.alloc(256 * 1024, 'L');
const GZIP = zlib.gzipSync(LARGE);
const OVER_WIRE = Buffer.alloc(MAX_BODY + 64 * 1024, 'O'); // over maxBodySize on the wire
const OVER_DECODED = zlib.gzipSync(Buffer.alloc(4 * MAX_BODY)); // a few KiB on the wire, 4 MiB decoded

/* ------------------------------------------------------------------ servers */

const serverSockets = new Set<net.Socket>();
const track = (s: net.Socket) => { serverSockets.add(s); s.on('close', () => serverSockets.delete(s)); s.on('error', () => undefined); };
let hits = 0;

type Req = http.IncomingMessage | http2.Http2ServerRequest;
type Res = http.ServerResponse | http2.Http2ServerResponse;

/** One handler for both engines; `crossOrigin` is where /redirect-cross sends the client (TLS, another port). */
const routes = (crossOrigin: () => string) => (req: Req, res: Res) => {
    const path = (req.url ?? '/').split('?')[0];
    res.on('error', () => undefined);
    switch (path) {
        case '/ok': res.writeHead(200, { 'content-type': 'application/json' }); res.end(SMALL); return;
        case '/large': res.writeHead(200); res.end(LARGE); return;
        case '/gzip': res.writeHead(200, { 'content-encoding': 'gzip' }); res.end(GZIP); return;
        case '/over-wire': res.writeHead(200); res.end(OVER_WIRE); return;
        case '/over-decoded': res.writeHead(200, { 'content-encoding': 'gzip' }); res.end(OVER_DECODED); return;
        case '/redirect-same': res.writeHead(302, { location: '/ok' }); res.end(); return;
        case '/redirect-cross': res.writeHead(302, { location: `${crossOrigin()}/ok` }); res.end(); return;
        case '/flaky': // 503 every other hit, retried by the client
            if (hits++ % 2) { res.writeHead(503, { 'retry-after': '0' }); res.end(); } else { res.writeHead(200); res.end(SMALL); }
            return;
        case '/drop': // headers and a chunk, then the server side goes away
            res.writeHead(200); res.write('partial');
            if ('stream' in res) res.stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); else req.socket.destroy();
            return;
        case '/idle': // headers, then silence: the client's socketTimeoutMs ends it
            res.writeHead(200); res.write('partial');
            return;
        case '/hang': // nothing at all: the client aborts
            return;
        case '/echo': { // upload, echoed back in size
            let size = 0;
            req.on('data', (c: Buffer) => { size += c.length; });
            req.on('end', () => { res.writeHead(200); res.end(String(size)); });
            req.on('error', () => undefined);
            return;
        }
        default: res.writeHead(404); res.end();
    }
};

const listen = async (server: net.Server) => {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    return (server.address() as AddressInfo).port;
};

/** A CONNECT proxy on loopback, tunnelling to whatever the client asked for (loopback only, by the guard). */
const connectProxy = () => net.createServer(client => {
    track(client);
    client.once('data', chunk => {
        const head = chunk.toString('latin1');
        const target = head.split(' ')[1] ?? '';
        const colon = target.lastIndexOf(':');
        const upstream = net.connect({ host: target.slice(0, colon), port: Number(target.slice(colon + 1)) });
        track(upstream);
        upstream.once('error', () => client.destroy());
        upstream.once('connect', () => {
            client.write('HTTP/1.1 200 Connection established\r\n\r\n');
            const rest = chunk.subarray(head.indexOf('\r\n\r\n') + 4);
            if (rest.length) upstream.write(rest);
            client.pipe(upstream).pipe(client);
            upstream.on('close', () => client.destroy());
            client.on('close', () => upstream.destroy());
        });
    });
});

async function startServers() {
    let h1Tls = '', h2Tls = '';
    const h1 = http.createServer(routes(() => h1Tls));
    const h1s = https.createServer({ cert: CERT, key: KEY }, routes(() => h1Tls));
    const h2 = http2.createServer(routes(() => h2Tls));
    const h2s = http2.createSecureServer({ cert: CERT, key: KEY }, routes(() => h2Tls));
    const proxy = connectProxy();
    for (const s of [h1, h1s, h2, h2s]) {
        s.on('connection', track);
        s.on('secureConnection', track);
    }
    for (const s of [h2, h2s]) s.on('session', session => session.on('error', () => undefined));
    const [p1, p1s, p2, p2s, pp] = await Promise.all([h1, h1s, h2, h2s, proxy].map(listen));
    h1Tls = `https://127.0.0.1:${p1s}`;
    h2Tls = `https://127.0.0.1:${p2s}`;
    return {
        plain: { http1: `http://127.0.0.1:${p1}`, http2: `http://127.0.0.1:${p2}` },
        tls: { http1: h1Tls, http2: h2Tls },
        proxy: `http://127.0.0.1:${pp}`,
        close: async () => {
            for (const s of serverSockets) s.destroy();
            await Promise.all([h1, h1s, h2, h2s, proxy].map(s => new Promise<void>(r => s.close(() => r()))));
        },
    };
}

/* ------------------------------------------------------------------ clients */

const sessions = new Set<ClientHttp2Session>();
const trackingConnect: typeof nativeConnect = (authority, options, listener) => {
    const session = nativeConnect(authority, options as never, listener as never);
    sessions.add(session);
    session.once('close', () => sessions.delete(session));
    return session;
};

const common = {
    tls: { ca: CERT },
    maxBodySize: MAX_BODY,
    socketTimeoutMs: 10_000,
    timeoutMs: 30_000,
    maxRedirects: 3,
    retry: { limit: 2, maxDelayMs: 5 },
};

/* ------------------------------------------------------------------ the loop */

type Outcome = { status?: number; error?: string };
const outcome = async (p: Promise<{ statusCode: number }>): Promise<Outcome> =>
    p.then(res => ({ status: res.statusCode }), (err: Error & { code?: string }) => ({ error: err.name }));

type Op = { name: string; run: (client: UltraTonClient, base: string) => Promise<Outcome>; expect: (o: Outcome) => boolean };
const ok = (o: Outcome) => o.status === 200;
const errorNamed = (name: string) => (o: Outcome) => o.error === name;

const OPS: Op[] = [
    { name: 'ok', run: (c, b) => outcome(c.get(`${b}/ok`)), expect: ok },
    { name: 'large', run: (c, b) => outcome(c.get(`${b}/large`)), expect: ok },
    { name: 'gzip', run: (c, b) => outcome(c.get(`${b}/gzip`)), expect: ok },
    { name: 'redirect-same', run: (c, b) => outcome(c.get(`${b}/redirect-same`)), expect: ok },
    { name: 'redirect-cross', run: (c, b) => outcome(c.get(`${b}/redirect-cross`)), expect: ok },
    { name: 'flaky-503', run: (c, b) => outcome(c.get(`${b}/flaky`)), expect: o => o.status === 200 || o.status === 503 },
    { name: 'drop', run: (c, b) => outcome(c.get(`${b}/drop`, { retry: 0 })), expect: errorNamed('UltraTonNetworkError') },
    { name: 'idle-timeout', run: (c, b) => outcome(c.get(`${b}/idle`, { socketTimeoutMs: 50, retry: 0 })), expect: errorNamed('UltraTonNetworkTimeoutError') },
    {
        name: 'abort',
        run: async (c, b) => {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 20);
            try { return await outcome(c.get(`${b}/hang`, { signal: controller.signal })); } finally { clearTimeout(timer); }
        },
        expect: errorNamed('AbortError'),
    },
    { name: 'over-wire', run: (c, b) => outcome(c.get(`${b}/over-wire`)), expect: errorNamed('UltraTonMemoryError') },
    { name: 'over-decoded', run: (c, b) => outcome(c.get(`${b}/over-decoded`)), expect: errorNamed('UltraTonMemoryError') },
    { name: 'upload-json', run: (c, b) => outcome(c.post(`${b}/echo`, { json: { blob: 'u'.repeat(4096) } })), expect: ok },
    { name: 'upload-stream', run: (c, b) => outcome(c.post(`${b}/echo`, { body: Readable.from([LARGE.subarray(0, 65_536), LARGE.subarray(0, 65_536)]) })), expect: ok },
    {
        name: 'stream-cancelled',
        run: async (c, b) => {
            try {
                const res = await c.stream(`${b}/large`);
                const reader = res.body.getReader();
                await reader.read();
                await reader.cancel();
                return { status: res.statusCode };
            } catch (err) { return { error: (err as Error).name }; }
        },
        expect: ok,
    },
];

const mib = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MiB`;
const snapshot = () => {
    gc();
    const { rss, heapUsed } = process.memoryUsage();
    return { rss, heapUsed, sessions: sessions.size, serverSockets: serverSockets.size };
};
const fmt = (s: ReturnType<typeof snapshot>) => `rss ${mib(s.rss)}, heap ${mib(s.heapUsed)}, h2 sessions ${s.sessions}, server sockets ${s.serverSockets}`;

async function main() {
    const servers = await startServers();
    const manager = new Http2SessionManager({ ca: CERT }, trackingConnect);
    // An injected manager brings its own TLS and proxy settings, so the proxied one gets the parsed proxy by hand.
    const proxyConfig: ProxyConfig = { url: new URL(servers.proxy), kind: 'connect', resolve: 'local' };
    const proxyManager = new Http2SessionManager({ ca: CERT }, trackingConnect, {}, proxyConfig);
    const direct = [
        { label: 'http1', client: new UltraTonClient({ ...common, permitReservedIps: true }), base: servers.plain.http1 },
        { label: 'http2', client: new UltraTonClient({ ...common, permitReservedIps: true, http2: true, [kSessionManager]: manager } as never), base: servers.plain.http2 },
    ];
    // Through the CONNECT proxy only https targets go (plain http never uses a proxy), so these hit the TLS servers.
    const proxied = [
        { label: 'http1+proxy', client: new UltraTonClient({ ...common, permitReservedIps: ['127.0.0.0/8'], proxy: servers.proxy }), base: servers.tls.http1 },
        { label: 'http2+proxy', client: new UltraTonClient({ ...common, permitReservedIps: ['127.0.0.0/8'], http2: true, [kSessionManager]: proxyManager } as never), base: servers.tls.http2 },
    ];
    const clients = [...direct, ...proxied];

    const counts = new Map<string, number>();
    const unexpected = new Map<string, number>();
    let total = 0;
    const started = Date.now();
    const deadline = started + DURATION_MS;
    let baseline: ReturnType<typeof snapshot> | undefined;

    const worker = async () => {
        while (Date.now() < deadline) {
            const { label, client, base } = clients[Math.floor(Math.random() * clients.length)];
            const op = OPS[Math.floor(Math.random() * OPS.length)];
            const result = await op.run(client, base);
            total++;
            const key = `${label} ${op.name}`;
            counts.set(key, (counts.get(key) ?? 0) + 1);
            if (!op.expect(result)) unexpected.set(`${key} -> ${JSON.stringify(result)}`, (unexpected.get(`${key} -> ${JSON.stringify(result)}`) ?? 0) + 1);
        }
    };

    const ticker = setInterval(() => {
        const s = snapshot();
        if (baseline === undefined && Date.now() - started >= WARMUP_MS) { baseline = s; console.log(`baseline after warm-up: ${fmt(s)}`); }
        console.log(`${Math.round((Date.now() - started) / 1000)}s: ${total} requests, ${fmt(s)}`);
    }, SMOKE ? 1000 : 30_000);
    await Promise.all(Array.from({ length: WORKERS }, worker));
    clearInterval(ticker);
    baseline ??= snapshot(); // a run shorter than the warm-up (smoke) compares against its own end

    await Promise.all(clients.map(c => c.client.close()));
    await new Promise(r => setTimeout(r, 500));
    const afterClose = snapshot();
    await servers.close();
    await new Promise(r => setTimeout(r, 200));
    const handles = process.getActiveResourcesInfo().filter(h => h === 'TCPSocketWrap' || h === 'TLSWrap' || h === 'TCPServerWrap');

    const failures: string[] = [];
    if (afterClose.rss > baseline.rss + RSS_MARGIN) failures.push(`RSS grew by ${mib(afterClose.rss - baseline.rss)} (margin ${mib(RSS_MARGIN)})`);
    if (afterClose.heapUsed > baseline.heapUsed + HEAP_MARGIN) failures.push(`heap grew by ${mib(afterClose.heapUsed - baseline.heapUsed)} (margin ${mib(HEAP_MARGIN)})`);
    if (afterClose.sessions > 0) failures.push(`${afterClose.sessions} HTTP/2 session(s) still open after close()`);
    if (afterClose.serverSockets > 0) failures.push(`${afterClose.serverSockets} connection(s) still open on the servers after close()`);
    if (handles.length > 0) failures.push(`active handles left: ${handles.join(', ')}`);
    if (unexpected.size > 0) failures.push(`${[...unexpected.values()].reduce((a, b) => a + b, 0)} unexpected outcome(s)`);

    const lines = [
        `# Soak: ${total} requests in ${Math.round((Date.now() - started) / 60_000)} min, ${failures.length === 0 ? 'PASS' : 'FAIL'}`,
        '',
        `- baseline: ${fmt(baseline)}`,
        `- after close(): ${fmt(afterClose)}`,
        `- handles after servers closed: ${handles.length === 0 ? 'none' : handles.join(', ')}`,
        ...failures.map(f => `- FAIL: ${f}`),
        '',
        '| operation | count |', '| --- | ---: |',
        ...[...counts].sort().map(([k, v]) => `| ${k} | ${v} |`),
        ...(unexpected.size ? ['', '| unexpected | count |', '| --- | ---: |', ...[...unexpected].sort().map(([k, v]) => `| ${k} | ${v} |`)] : []),
    ];
    console.log(lines.join('\n'));
    if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');
    process.exitCode = failures.length === 0 ? 0 : 1;
}

await main();
