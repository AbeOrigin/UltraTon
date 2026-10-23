/**
 * Q7: the three README recipes (deliver a webhook, preview a link, call an internal service), with the same code the
 * README shows, against loopback servers. If one fails, the recipe is what is wrong, not the package.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonHttpError, UltraTonMemoryError } from '../src/errors.ts';

// The recipes, as the README shows them.

/** Deliver a webhook: POST it, retry what is safe to retry, never follow redirects, keep the reply small. */
async function deliver(client: UltraTonClient, url: string, event: unknown): Promise<void> {
    const res = await client.post(url, { json: event, retry: { limit: 2, methods: ['POST'] }, maxBodySize: 64 * 1024, timeoutMs: 10_000 });
    res.assertOk();
}

/** The <title> of a page, reading at most 64 KiB of it. */
async function previewTitle(client: UltraTonClient, url: string): Promise<string | undefined> {
    const res = await client.stream(url, { maxBodySize: 64 * 1024, timeoutMs: 5_000, maxRedirects: 3, redirectHeaders: 'safe' });
    if (!res.ok) { await res.body.cancel(); return undefined; }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let html = '';
    try {
        while (!html.includes('</head>')) {
            const { done, value } = await reader.read();
            if (done) break;
            html += decoder.decode(value, { stream: true });
        }
    } catch (err) {
        if (!(err instanceof UltraTonMemoryError)) throw err;
    } finally {
        await reader.cancel().catch(() => {});
    }
    return /<title[^>]*>([^<]*)<\/title>/i.exec(html)?.[1].trim();
}

/** The client for one internal service: its address only, no redirects, short timeout. */
function internalClient(baseUrl: string, address: string): UltraTonClient {
    return new UltraTonClient({ baseUrl, permitReservedIps: [address], maxRedirects: 0, timeoutMs: 2_000 });
}

/** A loopback server driven by `handle`, which gets the request, the response and how many bytes it wrote so far. */
async function serve(t: TestContext, handle: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
    const server = http.createServer(handle);
    const sockets = new Set<Socket>();
    server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const clientFor = (t: TestContext, options: Record<string, unknown> = {}) => {
    const client = new UltraTonClient({ permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
};

describe('deliver a webhook', () => {
    it('retries a POST on 503 and succeeds', async (t) => {
        let posts = 0;
        const base = await serve(t, (req, res) => {
            posts++;
            req.resume();
            res.writeHead(posts < 3 ? 503 : 200);
            res.end();
        });
        await deliver(clientFor(t), `${base}/hook`, { id: 1 });
        assert.equal(posts, 3);
    });

    it('gives up on 400 without retrying', async (t) => {
        let posts = 0;
        const base = await serve(t, (req, res) => { posts++; req.resume(); res.writeHead(400); res.end('bad'); });
        await assert.rejects(deliver(clientFor(t), `${base}/hook`, {}), (err: UltraTonHttpError) => err.statusCode === 400);
        assert.equal(posts, 1);
    });

    it('refuses an internal target before connecting', async (t) => {
        await assert.rejects(deliver(clientFor(t, { permitReservedIps: false }), 'https://10.0.0.1/hook', {}), (err: { code?: string }) => err.code === 'ERR_ULTRATON_RESERVED_IP');
    });
});

describe('preview a link', () => {
    const KiB = 1024;
    /** A page: the given head, then `tail` bytes in 16 KiB chunks; records how many bytes were written when the client left. */
    const page = async (t: TestContext, head: string, tail: number) => {
        const written = { atClose: -1, total: 0 };
        const base = await serve(t, (_req, res) => {
            res.writeHead(200, { 'content-type': 'text/html' });
            res.write(head);
            res.on('close', () => { if (written.atClose < 0) written.atClose = written.total; });
            let sent = 0;
            const pump = () => {
                while (sent < tail && !res.destroyed) {
                    const chunk = Buffer.alloc(Math.min(16 * KiB, tail - sent), 'x');
                    sent += chunk.length;
                    written.total = sent;
                    if (!res.write(chunk)) return void res.once('drain', pump);
                }
                if (!res.destroyed) res.end();
            };
            pump();
        });
        return { base, written };
    };

    it('reads the title and cancels the rest', { timeout: 10_000 }, async (t) => {
        const { base, written } = await page(t, '<html><head><title> Hi </title></head>', 1024 * KiB);
        assert.equal(await previewTitle(clientFor(t), `${base}/`), 'Hi');
        await new Promise(r => setTimeout(r, 200));
        assert.ok(written.atClose >= 0 && written.atClose < 1024 * KiB, `the server saw the client leave after ${written.atClose} bytes`);
    });

    it('stops at 64 KiB without a </head>', { timeout: 10_000 }, async (t) => {
        const { base, written } = await page(t, '<html><head><title>Never closed', 1024 * KiB);
        assert.equal(await previewTitle(clientFor(t), `${base}/`), undefined);
        await new Promise(r => setTimeout(r, 200));
        assert.ok(written.atClose >= 0 && written.atClose < 256 * KiB, `the server saw the client leave after ${written.atClose} bytes`);
    });

    it('a non-2xx page has no title and releases its body', async (t) => {
        const base = await serve(t, (_req, res) => { res.writeHead(404); res.end('<title>Not here</title>'); });
        assert.equal(await previewTitle(clientFor(t), `${base}/`), undefined);
    });
});

describe('call an internal service', () => {
    it('reaches its address and follows no redirect', async (t) => {
        const base = await serve(t, (req, res) => {
            if (req.url === '/moved') { res.writeHead(302, { location: `http://127.0.0.2:${new URL(base).port}/` }); return res.end(); }
            res.writeHead(200); res.end('ok');
        });
        const svc = internalClient(`${base}/`, '127.0.0.1');
        t.after(() => svc.close());
        assert.equal((await svc.get('ok')).text(), 'ok');
        assert.equal((await svc.get('moved')).statusCode, 302);
    });

    it('its allowlist admits only its own address', async (t) => {
        const client = clientFor(t, { permitReservedIps: ['127.0.0.1'] });
        await assert.rejects(client.get('http://127.0.0.2:1/'), (err: { code?: string }) => err.code === 'ERR_ULTRATON_RESERVED_IP');
    });
});
