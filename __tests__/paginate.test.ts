import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer as createH2Server, type IncomingHttpHeaders } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { Readable } from 'node:stream';
import { UltraTonClient } from '../src/http-client.ts';
import { nextLink } from '../src/helpers/link-header.ts';

type Answer = { status?: number; link?: string; location?: string; body?: string };

/** A loopback server of either engine that logs each request target and answers with what `route` returns for it. */
async function pagedServer(t: TestContext, http2: boolean, route: (target: string) => Answer) {
    const targets: string[] = [];
    const sockets = new Set<Socket>();
    const answer = (target: string) => {
        targets.push(target);
        const { status = 200, link, location, body = 'ok' } = route(target);
        const extra = { ...(link === undefined ? {} : { link }), ...(location === undefined ? {} : { location }) };
        return { status, headers: { 'content-type': 'text/plain', ...extra }, body };
    };
    const server = http2
        ? createH2Server().on('stream', (stream, headers: IncomingHttpHeaders) => {
            const { status, headers: out, body } = answer(String(headers[':path']));
            stream.respond({ ':status': status, ...out });
            stream.end(body);
        })
        : http.createServer((req, res) => {
            const { status, headers: out, body } = answer(String(req.url));
            res.writeHead(status, out);
            res.end(body);
        });
    server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => server.close(() => r()));
    });
    return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, targets };
}

/** Pages 1 to `last` of /items, each linking to the next with a relative Link. */
const numbered = (last: number) => (target: string): Answer => {
    const page = Number(new URL(target, 'http://x').searchParams.get('page') ?? 1);
    return page < last ? { link: `</items?page=${page + 1}>; rel="next"` } : {};
};

function clientOf(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    const client = new UltraTonClient({ http2, permitReservedIps: true, ...options });
    t.after(() => client.close());
    return client;
}

/** The path and query each page was served from. */
const pathOf = (page: { url: string }) => { const url = new URL(page.url); return url.pathname + url.search; };

async function collect(pages: AsyncIterable<{ url: string }>): Promise<string[]> {
    const paths: string[] = [];
    for await (const page of pages) paths.push(pathOf(page));
    return paths;
}

for (const http2 of [false, true]) {
    describe(`paginate (${http2 ? 'HTTP/2' : 'HTTP/1'})`, () => {
        it('follows rel="next" links until a page has none', async (t) => {
            const { base } = await pagedServer(t, http2, numbered(3));
            const client = clientOf(t, http2);
            assert.deepEqual(await collect(client.paginate(`${base}/items`)), ['/items', '/items?page=2', '/items?page=3']);
        });

        it('takes the next page from a custom next()', async (t) => {
            const { base } = await pagedServer(t, http2, target => ({ body: JSON.stringify({ next: target === '/a' ? '/b' : null }) }));
            const client = clientOf(t, http2);
            const seen: string[] = [];
            for await (const page of client.paginate<{ next: string | null }>(`${base}/a`, { next: p => p.json().next ?? undefined })) {
                seen.push(page.text());
            }
            assert.deepEqual(seen, ['{"next":"/b"}', '{"next":null}']);
        });

        it('applies query to the first page only', async (t) => {
            const { base, targets } = await pagedServer(t, http2, numbered(2));
            const client = clientOf(t, http2);
            await collect(client.paginate(`${base}/items`, { query: { page: 1 }, headers: { 'x-a': '1' } }));
            assert.deepEqual(targets, ['/items?page=1', '/items?page=2']);
        });

        it('rejects a next page on another origin without requesting it', async (t) => {
            const other = await pagedServer(t, http2, () => ({}));
            const { base } = await pagedServer(t, http2, () => ({ link: `<${other.base}/steal>; rel="next"` }));
            const client = clientOf(t, http2);
            await assert.rejects(collect(client.paginate(`${base}/items`)), { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
            assert.deepEqual(other.targets, []);
        });

        it('holds a custom next() to the same origin', async (t) => {
            const { base } = await pagedServer(t, http2, () => ({}));
            const client = clientOf(t, http2);
            const pages = client.paginate(`${base}/items`, { next: () => new URL('https://example.com/') });
            await assert.rejects(collect(pages), { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
        });

        it('stays inside baseUrl', async (t) => {
            const { base, targets } = await pagedServer(t, http2, target =>
                target === '/v1/items' ? { link: '<items?page=2>; rel="next"' }
                    : target === '/v1/items?page=2' ? { link: '</admin>; rel="next"' } : {});
            const client = clientOf(t, http2, { baseUrl: `${base}/v1/` });
            await assert.rejects(collect(client.paginate('/items')), { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
            assert.deepEqual(targets, ['/v1/items', '/v1/items?page=2']);
        });

        it('applies the path checks of baseUrl to a next page inside it', async (t) => {
            const { base, targets } = await pagedServer(t, http2, () => ({ link: '<%252e%252e/admin>; rel="next"' }));
            const client = clientOf(t, http2, { baseUrl: `${base}/v1/` });
            await assert.rejects(collect(client.paginate('items')), TypeError);
            assert.deepEqual(targets, ['/v1/items']);
        });

        it('rejects with ERR_ULTRATON_MAX_PAGES when pages are left, after yielding maxPages', async (t) => {
            const { base, targets } = await pagedServer(t, http2, numbered(5));
            const client = clientOf(t, http2);
            const seen: string[] = [];
            await assert.rejects(async () => { for await (const page of client.paginate(`${base}/items`, { maxPages: 2 })) seen.push(pathOf(page)); },
                { code: 'ERR_ULTRATON_MAX_PAGES' });
            assert.deepEqual(seen, ['/items', '/items?page=2']);
            assert.equal(targets.length, 2);
        });

        it('ends quietly when the last page is exactly maxPages', async (t) => {
            const { base } = await pagedServer(t, http2, numbered(2));
            const client = clientOf(t, http2);
            assert.equal((await collect(client.paginate(`${base}/items`, { maxPages: 2 }))).length, 2);
        });

        it('yields a non-2xx page and stops there', async (t) => {
            const { base, targets } = await pagedServer(t, http2, target =>
                target === '/items' ? { link: '</items?page=2>; rel="next"' } : { status: 503, link: '</items?page=3>; rel="next"' });
            const client = clientOf(t, http2);
            const statuses: number[] = [];
            for await (const page of client.paginate(`${base}/items`)) statuses.push(page.statusCode);
            assert.deepEqual(statuses, [200, 503]);
            assert.equal(targets.length, 2);
        });

        it('rejects a page a redirect served from another origin, before following its link', async (t) => {
            let first = '';
            const other = await pagedServer(t, http2, () => ({ link: `<${first}/v1/admin?all=1>; rel="next"` }));
            const trusted = await pagedServer(t, http2, target => target === '/v1/items' ? { status: 302, location: `${other.base}/x` } : {});
            first = trusted.base;
            const client = clientOf(t, http2, { maxRedirects: 5, headers: { authorization: 'Bearer s' } });
            await assert.rejects(collect(client.paginate(`${trusted.base}/v1/items`)), { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
            assert.deepEqual(trusted.targets, ['/v1/items']);
        });

        it('resolves a relative link against the URL a same-origin redirect landed on', async (t) => {
            const { base, targets } = await pagedServer(t, http2, target =>
                target === '/old/items' ? { status: 301, location: '/new/items' }
                    : target === '/new/items' ? { link: '<items?page=2>; rel="next"' } : {});
            const client = clientOf(t, http2, { maxRedirects: 1 });
            const pages: { url: string; redirected: boolean }[] = [];
            for await (const page of client.paginate(`${base}/old/items`)) pages.push({ url: page.url, redirected: page.redirected });
            assert.deepEqual(targets, ['/old/items', '/new/items', '/new/items?page=2']);
            assert.deepEqual(pages, [{ url: `${base}/new/items`, redirected: true }, { url: `${base}/new/items?page=2`, redirected: false }]);
        });

        it('requests exactly the URL it checked under baseUrl', async (t) => {
            const { base, targets } = await pagedServer(t, http2, target =>
                target === '/v1/items' ? { link: '</v1//dbl>; rel="next"' }
                    : target === '/v1//dbl' ? { link: '</v1/users:search?page=2>; rel="next"' } : {});
            const client = clientOf(t, http2, { baseUrl: `${base}/v1/` });
            await collect(client.paginate('items'));
            assert.deepEqual(targets, ['/v1/items', '/v1//dbl', '/v1/users:search?page=2']);
        });

        it("resolves an empty link against the first page's URL, query included", async (t) => {
            const { base, targets } = await pagedServer(t, http2, () => ({ link: '<>; rel="next"' }));
            const client = clientOf(t, http2);
            await assert.rejects(collect(client.paginate(`${base}/items`, { query: { page: 1 }, maxPages: 2 })), { code: 'ERR_ULTRATON_MAX_PAGES' });
            assert.deepEqual(targets, ['/items?page=1', '/items?page=1']);
        });

        it('reads a next() path as get() does under baseUrl, with or without a leading slash', async (t) => {
            const { base, targets } = await pagedServer(t, http2, () => ({}));
            const client = clientOf(t, http2, { baseUrl: `${base}/v1/` });
            const refs = ['/items?cursor=2', 'items?cursor=3', `${base}/v1/items?cursor=4`, undefined];
            await collect(client.paginate('a/b/start', { next: () => refs.shift() }));
            assert.deepEqual(targets, ['/v1/a/b/start', '/v1/items?cursor=2', '/v1/items?cursor=3', '/v1/items?cursor=4']);
        });

        it('applies the baseUrl path checks to a next() path', async (t) => {
            const { base, targets } = await pagedServer(t, http2, () => ({}));
            const client = clientOf(t, http2, { baseUrl: `${base}/v1/` });
            await assert.rejects(collect(client.paginate('items', { next: () => '../admin' })), TypeError);
            await assert.rejects(collect(client.paginate('items', { next: () => '//evil.example/' })), TypeError);
            await assert.rejects(collect(client.paginate('items', { next: () => `${base}/admin` })), { code: 'ERR_ULTRATON_PAGE_OUT_OF_SCOPE' });
            assert.deepEqual(targets, ['/v1/items', '/v1/items', '/v1/items']);
        });

        it('resolves a next() path against the page without baseUrl', async (t) => {
            const { base, targets } = await pagedServer(t, http2, () => ({}));
            const client = clientOf(t, http2);
            const refs = ['c?cursor=2', undefined];
            await collect(client.paginate(`${base}/a/b`, { next: () => refs.shift() }));
            assert.deepEqual(targets, ['/a/b', '/a/c?cursor=2']);
        });

        it('ends when next() returns null', async (t) => {
            const { base } = await pagedServer(t, http2, () => ({}));
            const client = clientOf(t, http2);
            assert.equal((await collect(client.paginate(`${base}/items`, { next: () => null }))).length, 1);
        });

        it('requests nothing more once the loop breaks', async (t) => {
            const { base, targets } = await pagedServer(t, http2, numbered(5));
            const client = clientOf(t, http2);
            for await (const page of client.paginate(`${base}/items`)) { void page; break; }
            assert.deepEqual(targets, ['/items']);
        });
    });
}

describe('paginate options', () => {
    const client = new UltraTonClient();

    it('refuses a body at the call, releasing a stream one without any iteration', () => {
        assert.throws(() => client.paginate('https://example.com/', { json: {} } as never), TypeError);
        const stream = Readable.from(['x']);
        assert.throws(() => client.paginate('https://example.com/', { body: stream } as never), TypeError);
        assert.equal(stream.destroyed, true);
    });

    it('validates next and maxPages at the call', () => {
        assert.throws(() => client.paginate('https://example.com/', { next: 'x' } as never), /'next'/);
        for (const maxPages of [0, 1.5, -1, '2']) {
            assert.throws(() => client.paginate('https://example.com/', { maxPages } as never), /'maxPages'/);
        }
    });

    it('rejects a next() result that is not a string or a URL', async (t) => {
        const { base } = await pagedServer(t, false, () => ({}));
        const c = clientOf(t, false);
        await assert.rejects(collect(c.paginate(`${base}/`, { next: () => 42 as never })), TypeError);
    });
});

describe('nextLink (RFC 8288)', () => {
    it('finds rel="next" among several links', () => {
        assert.equal(nextLink('<https://a/1>; rel="prev", <https://a/3>; rel="next", <https://a/9>; rel="last"'), 'https://a/3');
    });

    it('reads a rel list, an unquoted rel and any case', () => {
        assert.equal(nextLink('</p2>; rel="prev NEXT"'), '/p2');
        assert.equal(nextLink('</p2>;rel=next'), '/p2');
        assert.equal(nextLink('</p2> ;\tREL = "next"'), '/p2');
    });

    it('is not fooled by commas, semicolons or "next" inside quoted values', () => {
        assert.equal(nextLink('</a>; title="x, </b>; rel=next"; rel="prev", </c>; rel="next"'), '/c');
        assert.equal(nextLink('</a>; title="say \\"rel=next\\""'), undefined);
    });

    it('ignores a second rel parameter and rels that only contain next', () => {
        assert.equal(nextLink('</a>; rel="prev"; rel="next"'), undefined);
        assert.equal(nextLink('</a>; rel="nextpage"'), undefined);
        assert.equal(nextLink('</a>; anchor="next"'), undefined);
    });

    it('skips a malformed link and still finds a later next', () => {
        assert.equal(nextLink('</1>; rel="first"; type=application/json, </2>; rel="next"'), '/2');
        assert.equal(nextLink('</1>; title=Previous Page, </2>; rel="next"'), '/2');
        assert.equal(nextLink('</1>; t="a, b; rel=next" x, </2>; rel="next"'), '/2');
    });

    it('accepts a trailing semicolon and ignores anchored links', () => {
        assert.equal(nextLink('</1>; rel=next;'), '/1');
        assert.equal(nextLink('</1>; rel="next"; anchor="#other", </2>; rel="next"'), '/2');
    });

    it('joins repeated headers', () => {
        assert.equal(nextLink(['</a>; rel="prev"', '</b>; rel="next"']), '/b');
    });

    it('treats malformed input as no next page', () => {
        for (const header of [undefined, '', 'rel="next"', '</a; rel="next"', '</a>; rel="next', '</a> rel="next"', '</a>; ="next"']) {
            assert.equal(nextLink(header), undefined, String(header));
        }
    });

    it('scans a long hostile header in linear time', () => {
        const header = '<'.repeat(4000) + ';'.repeat(4000) + '"'.repeat(4000);
        const start = performance.now();
        nextLink(header);
        nextLink('</a>; t="' + '\\'.repeat(8000));
        assert.ok(performance.now() - start < 200);
    });
});
