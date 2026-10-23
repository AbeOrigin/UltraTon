# UltraTon

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/AbeOrigin/UltraTon/badge)](https://scorecard.dev/viewer/?uri=github.com/AbeOrigin/UltraTon)

> A secure HTTP client for Node.js. The safe choice is the default, and the risky ones are opt-in.

UltraTon is an HTTP/1.1 and HTTP/2 client built only on Node's own modules (`node:https`, `node:http2`, `node:dns`, `node:net`, `node:tls`, `node:zlib`), with **zero runtime dependencies**. It is built for code that sends requests to URLs it does not fully control: webhooks, link previews, integrations, internal service clients. It blocks SSRF (including DNS rebinding), caps memory and time, and never silently ignores a mistake in its options.

It is also a complete everyday client, and every feature keeps the same protections:

- **Requests:** `query` parameters, JSON, `form` fields, `FormData` uploads, and streamed uploads from a file or any stream ([recipes](#recipes)).
- **Responses:** gzip, deflate and brotli decoded with the size limit applied to the decoded bytes, and [`stream()`](#recipes) for large downloads.
- **[`client.fetch()`](#recipes):** a standard `fetch` you can hand to any SDK.
- **[Retries](#retries):** opt-in, idempotent methods only, `Retry-After` respected, one time budget for all attempts.
- **[Proxies](#proxy):** HTTP CONNECT and SOCKS5, tunnelled to the IP UltraTon validated, so the proxy cannot resolve the name elsewhere.

```bash
npm install ultraton
```

Requires Node.js **22.12** or later. Works from ESM (`import`), CommonJS (`require`) and TypeScript.

**Zero dependencies:** `npm install ultraton` installs exactly one package, with no runtime, peer or optional dependencies. The [`compat/`](compat/) folder of this repository holds axios, got and node-fetch only to test [`createSecureAgents()`](#protect-the-client-you-already-use) against them. It is a separate workspace that is never part of the published package, so a dependency scanner reading this repository may list those libraries; they are not dependencies of `ultraton`.

## Quickstart

```ts
import { UltraTonClient } from 'ultraton';

const api = new UltraTonClient({
  baseUrl: 'https://api.example.com/v1/',
  headers: { authorization: `Bearer ${process.env.API_TOKEN}` },
});

const res = await api.get('users/7');
if (res.ok) {
  const user = res.json<{ id: number; name: string }>();
  console.log(user.name);
}

await api.get('users', { query: { page: 2, tags: ['a', 'b'] } }); // users?page=2&tags=a&tags=b
await api.post('users', { json: { name: 'Ada' } });
await api.close(); // when the client is no longer needed
```

- Create **one client and reuse it**. Each client has its own connection pool.
- Every method is `(url, options)`: `get`, `post`, `put`, `patch`, `delete`, `head` and `options`.
- **A non-2xx response resolves.** Check `res.ok` or `res.statusCode`. The promise only rejects when no complete response arrives, or when a policy or a limit stops the request.

## Secure defaults

| Protection | Default | How to change it |
|---|---|---|
| Private, loopback, link-local, cloud-metadata and other reserved IPs | **Blocked**. This covers IP literals in every spelling, DNS answers, and every redirect hop. | `permitReservedIps: true` or an allowlist such as `['10.0.0.0/8']` |
| DNS rebinding | **Blocked**. Every address is validated once and the connection is pinned to it. | — |
| Plain `http:` | Only to loopback hosts, and only if they resolve to loopback addresses. | — (use `https:`) |
| Redirects | **Not followed**. The 3xx comes back as a response. | `maxRedirects` (0–20) |
| https → http redirect | **Rejected**. | — |
| Headers on a cross-origin redirect | `authorization`, `cookie`, `proxy-authorization`, `auth` and `host` are dropped; every other header follows, as with `fetch`. | `redirectHeaders: 'safe'` lets only `accept*`, `user-agent` and the body framing follow |
| Response body size | **2 MB**, then the response is aborted. | `maxBodySize` |
| Compressed responses (gzip, deflate, br) | **Decoded**, with `maxBodySize` applied to the decoded bytes too, so a decompression bomb stops at the limit. At most 2 content-encodings. br only on a Node release with the Brotli fix (see [Security](#security)). | `decompress: false` |
| Total time (DNS + all hops) | **30 s** | `timeoutMs` (`0` = none) |
| Idle connection | **10 s** without bytes | `socketTimeoutMs` (`0` = none) |
| TLS verification | **Always on**. It cannot be disabled. | `tls: { ca, cert, key }` for private CAs and mTLS |
| Header injection (CRLF/NUL), pseudo-headers | **Rejected** before connecting. | — |
| JSON prototype pollution | `__proto__`, `constructor` and `prototype` keys are stripped by `json()`. | — |
| Unknown options or wrong option types | **Throw a `TypeError`**, with a hint for common mistakes. | — |
| Truncated response (`content-length` mismatch, GOAWAY or reset mid-body) | **Rejected**. It never resolves as a short body. | — |
| Retries | **Off**. When on: idempotent methods only, `Retry-After` waited (or the response returned when it asks for too long), and policy, memory and redirect errors never retried. Every attempt is validated again. | `retry` (0–10, or `{ limit, methods, statusCodes, maxDelayMs, onRetry }`) |
| Proxies | **Not used**, and never read from `HTTP_PROXY`/`HTTPS_PROXY`. When set, the proxy gets the validated IP (CONNECT or SOCKS5), never a name, and the target's certificate is still checked. | `proxy` (client option) |

## Choosing a client

UltraTon does not try to be the fastest HTTP client: Node's own `http.request` is about 1.3× faster, and it should be, with no checks to run. UltraTon is the client for code that sends requests to URLs it does not fully control, and for teams that want safe defaults without writing them by hand.

- **The URL is yours and you want maximum throughput:** use `fetch`.
- **The URL comes from outside (webhooks, link previews, integrations, user input), or you want safe defaults:** use UltraTon. It is also 1.4–1.9× faster than axios, got and node-fetch in [our benchmarks](compat/bench/RESULTS.md), and over HTTP/1.1 ahead of `fetch` with 64 KiB bodies (`fetch` leads with 1 KiB ones).
- **You already use axios, got or node-fetch:** keep them and add [`createSecureAgents()`](#protect-the-client-you-already-use). It costs nothing measurable.

How they compare, with each library's defaults (UltraTon 2.x, Node 24's `fetch`, axios 1.20, got 16.1, node-fetch 3.3):

| | UltraTon | `fetch` (undici) | axios | got | node-fetch |
|---|---|---|---|---|---|
| Blocks SSRF (reserved IPs, DNS rebinding, redirects inside) | Yes, all 32 [corpus](compat/ssrf-corpus/RESULTS.md) cases | No | No (yes with `createSecureAgents`) | No (yes with `createSecureAgents`) | No (yes with `createSecureAgents`) |
| Redirects | off by default | followed (up to 20) | followed (up to 21) | followed (up to 10) | followed (up to 20) |
| Response size limit | 2 MB, also on decoded bytes | none | none | none | none |
| Total timeout | 30 s | none (300 s idle) | none | none | none |
| Retries | opt-in, idempotent only | — | — (plugin) | on (2), idempotent | — |
| Proxies | CONNECT and SOCKS5, opt-in, target pinned | `NODE_USE_ENV_PROXY` (recent Node) | from `HTTP_PROXY` by default | through an agent | through an agent |
| HTTP/2 | `http2: true` | not by default | `httpVersion: 2` | `http2: true` | — |
| Hooks / interceptors | `diagnostics_channel` (hooks planned) | — | interceptors | hooks | — |
| Pagination | `paginate()`, same origin only | — | — | Yes | — |
| Cookies, HTTP cache | — | — | — | Yes | — |
| Upload streaming | Yes, with an optional size limit | Yes | Yes | Yes | Yes |
| Runs in browsers, Bun, Deno | — (Node only) | Yes | Yes | — | — |
| Runtime dependencies | 0 | built in | 4 | 10 | 3 |
| Maturity | new (2.x in 2026), one maintainer | Node core team | many years, large community | many years | many years |

**Where UltraTon is not the right choice:**
- **Raw throughput against an API you trust:** Node's own `http.request` is about 1.3× faster. `fetch` is up to 1.4× faster than UltraTon over HTTP/1.1 with small bodies, and needs nothing installed.
- **Other runtimes:** browsers, Bun or Deno.
- **Features it does not have:** request-rewriting interceptors, a cookie jar or HTTP caching. Hooks are planned.

## Options

**Client options** go to `new UltraTonClient(options)`. All of them are optional:

| Option | Type | Notes |
|---|---|---|
| `baseUrl` | `string` | Relative request paths resolve under it and can never escape it (see [baseUrl](#baseurl)). |
| `http2` | `boolean` | Use HTTP/2 (ALPN `h2`, or h2c to loopback). Default `false`. |
| `tls` | `{ ca?, cert?, key? }` | PEM strings or Buffers: a private CA, or a client certificate for mTLS. |
| `userAgent` | `string` | Default `ultraton/<version>`. |
| `proxy` | `string` or `{ url, auth, ca, resolve }` | Outbound HTTP CONNECT or SOCKS5 proxy for `https:` targets, tunnelled to the validated IP (see [Proxy](#proxy)). |
| `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRequestBodySize`, `maxRedirects`, `permitReservedIps`, `retry` | | Defaults for every request. A request that sets the same option wins; headers and `retry` are merged key by key. |

**Request options** are the second argument of every method:

| Option | Type | Default |
|---|---|---|
| `json` | `unknown` | Serialized, and sent with `content-type: application/json` unless you set one. |
| `form` | plain object or `URLSearchParams` | Sent urlencoded, with the same rules as `query`. |
| `body` | `string \| Buffer \| Uint8Array \| Blob \| FormData \| URLSearchParams`, or a stream (`Readable \| ReadableStream \| AsyncIterable`) | A `FormData` goes as multipart with its boundary, a `Blob` with its `type`. A stream is sent as it is read (see [Upload a stream](#recipes)). Only one of `json`, `form` and `body`. GET and HEAD cannot have a body. |
| `headers` | plain object | — |
| `query` | plain object or `URLSearchParams` | Appended to the URL's own query. Arrays repeat the key, `undefined` is skipped, `null` and nested objects throw. |
| `auth` | `'user:password'` | Sent as Basic auth. Dropped on a cross-origin redirect. |
| `signal` | `AbortSignal` | Aborts in any phase. The request rejects with `signal.reason`. |
| `timeoutMs` | integer ms | `30000` |
| `socketTimeoutMs` | integer ms | `10000` |
| `maxBodySize` | integer bytes | `2097152` (2 MB) |
| `maxRequestBodySize` | integer bytes | None. A larger buffered body throws before connecting; a stream is aborted as it goes past it. |
| `decompress` | `boolean` | `true`: sends `accept-encoding` (unless you set one) and decodes the body. `false` leaves `data` as received. |
| `maxRedirects` | integer 0–20 | `0` |
| `redirectHeaders` | `'all' \| 'safe'` | `'all'`: on a redirect to another origin, every header but the credential ones follows. `'safe'`: only `accept`, `accept-encoding`, `accept-language`, `user-agent`, `content-type` and `content-length` do, so an `x-api-key` stays behind. A same-origin redirect keeps every header. |
| `permitReservedIps` | `boolean \| string[]` | `false` |
| `retry` | integer 0–10 or `{ limit, methods, statusCodes, maxDelayMs, onRetry }` | `0` (off). See [Retries](#retries). |

**Response:**

| Field | Type | Notes |
|---|---|---|
| `statusCode` | `number` | — |
| `ok` | `boolean` | `true` for 200–299. |
| `headers` | `IncomingHttpHeaders` | Never contains HTTP/2 pseudo-headers. |
| `url` | `string` | The final URL, after any redirect that was followed. |
| `redirected` | `boolean` | `true` when at least one redirect was followed. |
| `data` | `Buffer` | The raw body. It is never parsed automatically. |
| `json<T>()` | `T` | Parses on each call, whatever the content-type. An empty body gives `{}`. |
| `text()` | `string` | Decodes the body as UTF-8. |

## Errors

Every error the library raises is a `SecureHttpError`, apart from the `TypeError`s for invalid input listed below and an abort, which rejects with your `signal.reason`. Policy errors carry a stable `code`.

| Error | When | `code` |
|---|---|---|
| `TypeError` | Unknown options or wrong option types, a body on GET/HEAD, and with `baseUrl` a request path that is absolute, malformed or escapes it. Thrown before any connection. | — |
| `SecureHttpError` | A malformed URL, a scheme other than http(s), or credentials in the URL (request URL, `baseUrl` or redirect target) | — |
| `SecureHttpError` | A reserved IP not allowed by `permitReservedIps` | `ERR_ULTRATON_RESERVED_IP` |
| `SecureHttpError` | Plain `http:` to a host or address that is not loopback | `ERR_ULTRATON_PLAIN_HTTP` |
| `SecureHttpError` | A redirect from https to http | `ERR_ULTRATON_DOWNGRADE` |
| `SecureHttpError` | `createSecureAgents()`: a library passed a host that is an IPv4 in a non-canonical form (`127.1`, `0x7f.0.0.1`, `2130706433`) | `ERR_ULTRATON_NON_CANONICAL_IP` |
| `SecureHttpError` | `createSecureAgents()`, on a Node.js release without the keep-alive fix (see [SECURITY.md](SECURITY.md)): `keepAlive`, `maxSockets` or `maxTotalSockets` set on an agent. Thrown by the assignment. | `ERR_ULTRATON_AGENT_KEEP_ALIVE` |
| `SecureHttpError` | A request on a closed client | — |
| `UltraTonNetworkTimeoutError` | `timeoutMs` expired (the whole budget, retries included), or no data arrived for `socketTimeoutMs` (the server or the network stalled) | `ERR_ULTRATON_TIMEOUT`, `ERR_ULTRATON_SOCKET_TIMEOUT` |
| `UltraTonNetworkError` | DNS, connect, TLS, reset or truncated response, or a compressed body that is corrupt or cut short | Node's or zlib's code (`ECONNREFUSED`, `ENOTFOUND`, `ECONNRESET`, `Z_DATA_ERROR`, …) |
| `UltraTonNetworkError` | HTTP/2: the server never processed the request (a `REFUSED_STREAM` reset, or above a GOAWAY's last stream). `retry` retries it. | `NGHTTP2_REFUSED_STREAM` |
| `UltraTonNetworkError` | The proxy refused the tunnel (CONNECT status or SOCKS5 reason), or answered outside its protocol | `ERR_ULTRATON_PROXY` |
| `SecureHttpError` | More than 2 content-encodings on a response | `ERR_ULTRATON_CONTENT_ENCODING` |
| `UltraTonMemoryError` | The body exceeded `maxBodySize` | — |
| `UltraTonMemoryError` | The request body exceeded `maxRequestBodySize` | `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE` |
| `SecureHttpError` | A streamed request body yielded more or fewer bytes than its `content-length` | `ERR_ULTRATON_REQUEST_BODY_LENGTH` |
| `UltraTonRedirectError` | More redirects than `maxRedirects` | — |
| `SecureHttpError` | `paginate()`: a next page on another origin, or outside `baseUrl` | `ERR_ULTRATON_PAGE_OUT_OF_SCOPE` |
| `SecureHttpError` | `paginate()`: a next page is left after `maxPages` | `ERR_ULTRATON_MAX_PAGES` |
| `UltraTonParseError` | `json()` on an invalid body. The `SyntaxError` is in `cause`. | — |

`UltraTonNetworkTimeoutError` extends `UltraTonNetworkError`, so test for the timeout first:

```ts
import { UltraTonNetworkTimeoutError, UltraTonNetworkError, SecureHttpError } from 'ultraton';

try {
  await api.get('reports/slow');
} catch (err) {
  if (err instanceof UltraTonNetworkTimeoutError) { /* retry later */ }
  else if (err instanceof UltraTonNetworkError) { /* connection problem, err.code */ }
  else if (err instanceof SecureHttpError && err.code === 'ERR_ULTRATON_RESERVED_IP') { /* blocked target */ }
  else throw err;
}
```

Error messages never contain the IP address or hostname, so they are safe to show to the user who supplied the URL. The original Node error is in `err.cause`, and it does contain them, so do not send `cause` to untrusted sinks.

## Recipes

**Fetch a URL a user gave you (webhooks, link previews).** The defaults are already right. Keep the redirect count small; every hop is still checked against the SSRF policy. With `redirectHeaders: 'safe'`, a server that redirects cannot carry your custom headers (an `x-api-key`) to another origin:

```ts
const client = new UltraTonClient({ maxRedirects: 3, redirectHeaders: 'safe', maxBodySize: 512 * 1024, timeoutMs: 5000 });
const res = await client.get(untrustedUrl);
```

**Call an internal service.** Allow only the ranges you need, never `true`:

```ts
const internal = new UltraTonClient({
  baseUrl: 'https://billing.internal/',
  permitReservedIps: ['10.20.0.0/16'],
  tls: { ca: fs.readFileSync('internal-ca.pem') },
});
```

**Local development against `http://localhost`.** `localhost` usually resolves to both `::1` and `127.0.0.1`, and *every* resolved address must be allowed:

```ts
const dev = new UltraTonClient({ baseUrl: 'http://localhost:3000/', permitReservedIps: ['localhost'] });
// or: permitReservedIps: ['127.0.0.0/8', '::1']
```

**HTTP/2:**

```ts
const h2 = new UltraTonClient({ http2: true, baseUrl: 'https://api.example.com/' });
```

**Mutual TLS:**

```ts
const mtls = new UltraTonClient({ tls: { cert: fs.readFileSync('client.pem'), key: fs.readFileSync('client.key') } });
```

**Cancel a request:**

```ts
const controller = new AbortController();
setTimeout(() => controller.abort(), 1000);
await api.get('search?q=x', { signal: controller.signal }); // rejects with controller.signal.reason
```

**Send a form or upload a file.** `form` sends urlencoded fields (OAuth token endpoints, older APIs). A `FormData` body goes as `multipart/form-data`, with the boundary set for you:

```ts
const token = await client.post(tokenUrl, { form: { grant_type: 'client_credentials', scope: 'read' } });

const fd = new FormData();
fd.append('title', 'Q3 report');
fd.append('file', await fs.openAsBlob('report.pdf', { type: 'application/pdf' }), 'report.pdf');
await client.post(uploadUrl, { body: fd });
```

Your own `content-type` header is kept for `form`, `URLSearchParams` and `Blob`. With a `FormData` it throws, because the header has to carry the boundary of the body. A `content-type` in the client's default headers is replaced by the one the body implies: a form, a `FormData` or a `Blob` with a `type` (for `json`, or a `Blob` without a type, it is kept). These bodies are read into memory before sending: for a large file, stream it instead.

**Upload a stream.** A `Readable`, a `ReadableStream` or any async iterable of bytes (or strings) as `body` is sent as it is read, never held in memory. Set `maxRequestBodySize` to stop a stream that would never end:

```ts
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';

const { size } = await stat('backup.tar');
await client.put(uploadUrl, {
  body: createReadStream('backup.tar'),
  headers: { 'content-type': 'application/x-tar', 'content-length': String(size) },
  maxRequestBodySize: 10 * 1024 ** 3,
});
```

- **Framing:** with your `content-length`, it is sent as is, and the stream must yield exactly that many bytes (`ERR_ULTRATON_REQUEST_BODY_LENGTH` otherwise, never a truncated body). Some servers, such as presigned S3 URLs, require it. Without it, HTTP/1.1 sends the body chunked.
- **Sent once:** a stream can only be read once, so a request with one is never retried, whatever `retry` says, and a 307 or 308 redirect resolves as the 3xx response instead of being followed. 301, 302 and 303 are followed as a GET without a body, as usual.
- **Ending early:** if the request fails, before or during the upload (invalid input, a blocked address, an abort, a timeout, `close()`), the stream is destroyed (a `ReadableStream` is cancelled). So is the rest of it when the server answers before reading it all. An error from your stream rejects the request as is, even if the server already started answering. `socketTimeoutMs` also runs while your stream produces no data.

**Use it as `fetch`, or hand it to a library.** `client.fetch` takes the same arguments as `fetch` and returns a standard `Response`. Every request still goes through the client's SSRF policy and limits. It is bound to the client, so libraries that accept a custom fetch get the protection without code changes:

```ts
const client = new UltraTonClient({ maxRedirects: 3 });
const res = await client.fetch(webhookUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event) });

const sdk = new SomeSdk({ fetch: client.fetch });
```

Differences from the platform's `fetch`:
- **Redirects** follow the client's `maxRedirects`, which defaults to 0. With the default, a 3xx comes back as the `Response`; `redirect: 'manual'` and `'error'` work as usual.
- **Failures:** network and policy failures reject as `TypeError('fetch failed')` with the UltraTon error as `cause`, as undici does. An abort rejects with the signal's reason.
- **`json()`** strips `__proto__`, `constructor` and `prototype` keys.
- **Request bodies:** a `ReadableStream` or async iterable body is streamed, and so is the body of a `Request` input, with the rules of [Upload a stream](#recipes). With a streamed body, a 307 or 308 comes back as the `Response` (the platform's `fetch` would reject).
- **`baseUrl`** applies to string paths. A `Request` or `URL` input is absolute, so on a client with `baseUrl` it is rejected as not relative: use a client without `baseUrl` for libraries.
- **Options:** browser-only options (`mode`, `credentials`, `cache`, …) are ignored. Options that would change the connection (`dispatcher`, `agent`) throw: configure the client instead.

**Stream a large download.** `stream()` resolves on the headers and hands you the body as a `ReadableStream`. Its limits still apply as it is read, and `maxBodySize` may go up to `Number.MAX_SAFE_INTEGER` here:

```ts
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

const res = await client.stream('https://files.example.com/big.csv', { maxBodySize: 500 * 1024 * 1024 });
if (!res.ok) await res.body.cancel();
else await pipeline(Readable.fromWeb(res.body), fs.createWriteStream('big.csv'));
```

`stream(url, { method: 'POST', json, … })` takes the method as an option. The body fails, never ends early, if it is cut short, too large, corrupt, aborted or the client is closed. `socketTimeoutMs` only counts while you are waiting for data, so a slow consumer never times out. `timeoutMs` ends when the headers arrive: a body that keeps moving may take longer than the budget, and only the idle timer guards it. Read the body to the end or `cancel()` it: until then it holds its connection and keeps the process alive.

**Walk a paginated API.** `paginate()` yields one complete response per page, each a full `get()` with every check. By default the next page is the `rel="next"` link of the `Link` header (RFC 8288), as GitHub and many other APIs send it; `next(page)` reads it from somewhere else:

```ts
for await (const page of client.paginate('https://api.example.com/items', { query: { per_page: 100 } })) {
  if (!page.ok) throw new Error(`page failed: ${page.statusCode}`);
  for (const item of page.json<Item[]>()) handle(item);
}

// A cursor in the body: return the next URL, or undefined on the last page.
const pages = api.paginate<{ items: Item[]; cursor?: string }>('items', {
  next: page => { const { cursor } = page.json(); return cursor ? `items?cursor=${encodeURIComponent(cursor)}` : undefined; },
});
```

- **Scope:** the next page must be on the first page's origin and, with `baseUrl`, inside it (its path checks apply). A server cannot steer the walk to another host: that rejects with `ERR_ULTRATON_PAGE_OUT_OF_SCOPE`, and so does a `next()` result. So does a page that a followed redirect served from outside that scope (it is yielded, then the walk rejects before its link is read): otherwise another server would choose the next request on your origin, with your credentials.
- **Bounded:** `maxPages` (default 100). A next page left after it rejects with `ERR_ULTRATON_MAX_PAGES`, after the pages already yielded: a collection is never cut short in silence.
- **Errors:** a non-2xx page is yielded and ends the walk. A relative `Link` resolves against the page's final `url`, as RFC 8288 says. A path from `next()` reads like a `get()` path: under `baseUrl`, `'/items?cursor=x'` and `'items?cursor=x'` are both from the base. An absolute URL from `next()` (a `next_url` field in the body, say) works too, as long as it stays in scope.
- **Options:** `query` applies to the first page only, since a next link carries its own; every other option (headers, `signal`, `retry`, …) to every page. There is no body: every page is a GET.

### Retries

Off by default. `retry: n` retries up to `n` times (at most 10) with these rules:

- **Methods:** GET, PUT, DELETE, HEAD and OPTIONS. POST and PATCH are never retried unless you list them in `methods`, because the server may have already acted on them.
- **Statuses:** 408, 429, 502, 503 and 504. `statusCodes` replaces the list; 500 is not in it by default. When the retries run out, you get the last response, not an error.
- **Network failures:** `ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `EAI_AGAIN`, `EPIPE` and the idle timeout (`ERR_ULTRATON_SOCKET_TIMEOUT`). Policy errors, `maxBodySize`, `maxRedirects`, invalid input, the `timeoutMs` timeout and an abort are never retried.
- **Waits:** exponential backoff with full jitter (300 ms base, at most `maxDelayMs`, default 30 s). A `Retry-After` (seconds or an HTTP date) is waited exactly; if it asks for more than `maxDelayMs` or than what is left of `timeoutMs`, that response is returned instead.
- **Budget:** `timeoutMs` covers every attempt and wait together, and `signal` also cancels a wait.
- **HTTP/2:** a stream the server never processed fails with `NGHTTP2_REFUSED_STREAM` and is retried, on a new connection after a GOAWAY. That covers a `REFUSED_STREAM` reset and a stream above the last one a GOAWAY processed. Any other reset is not retried.

```ts
const api = new UltraTonClient({
  baseUrl: 'https://api.example.com/',
  // error.code, not error: its cause is Node's own error, whose message contains the IP address.
  retry: { limit: 3, onRetry: ({ attempt, delayMs, statusCode, error }) => log.warn({ attempt, delayMs, statusCode, code: (error as Error & { code?: string })?.code }) },
});
await api.get('reports');                                            // up to 3 retries
await api.post('jobs', { json: job, retry: { methods: ['POST'] } }); // opt in for an idempotent POST
await api.get('health', { retry: 0 });                               // off for this request
```

Every attempt is a full request: a new connection resolves and validates DNS again, so a rebinding between attempts is blocked. A request's `retry` merges over the client's field by field. `stream()` retries until the headers arrive. `fetch()` never retries, because libraries that take a fetch bring their own retries. If `onRetry` throws, the request ends with that error.

### Observability

UltraTon publishes [`diagnostics_channel`](https://nodejs.org/api/diagnostics_channel.html) events for every client call (`get`, `post`, …, `stream()`, `fetch()`), so tracing and metrics tools can see requests without wrapping the client. Publishing costs nothing when nobody subscribes.

| Channel | When | Message |
|---|---|---|
| `ultraton:request:start` | The options are valid and the request starts | `{ request }` |
| `ultraton:request:retry` | Before each wait of `retry` | `{ request, attempt, delayMs, statusCode?, error? }` |
| `ultraton:request:response` | A response arrived (for `stream()`: its headers) | `{ request, statusCode, durationMs }` |
| `ultraton:request:error` | The call failed (policy, network, timeout, abort, …) | `{ request, error, durationMs }` |

`request` is `{ method, origin, path }`, frozen, and **the same object** on every event of one call, so it can key a span or a timer. `error` is `{ name, code }`. The events never carry headers, bodies, `auth`, URL credentials, the query string, `;params` (session ids), `error.cause` or resolved IP addresses, because tracing tools ship them off the host.

> **Warning:** **Path segments are published as they are.** If an API puts a secret in the path (a bot token like `/bot<TOKEN>/…`, a webhook URL, a reset token), redact it in your subscriber before it reaches your tracing backend, as the recipe below does.

A call that fails before it starts publishes nothing: options that throw a `TypeError`, a URL that does not parse, or a closed client. A retry event is published once a retry is decided, after your `onRetry` ran; if `onRetry` throws, there is no retry and no retry event, just the error.

An OpenTelemetry span per request, with the `@opentelemetry/api` you already use:

```ts
import diagnosticsChannel from 'node:diagnostics_channel';
import { trace, SpanKind, SpanStatusCode, type Span } from '@opentelemetry/api';
import type { UltraTonDiagnosticsRequest, UltraTonRequestStartMessage, UltraTonRequestResponseMessage, UltraTonRequestErrorMessage } from 'ultraton';

const tracer = trace.getTracer('ultraton');
const spans = new WeakMap<UltraTonDiagnosticsRequest, Span>();
// Your own rule for secrets in paths, for example: /bot123:ABC/sendMessage → /bot{token}/sendMessage
const redact = (path: string) => path.replace(/^\/bot[^/]+/, '/bot{token}');

diagnosticsChannel.subscribe('ultraton:request:start', (message) => {
  const { request } = message as UltraTonRequestStartMessage;
  const url = new URL(request.origin);
  spans.set(request, tracer.startSpan(request.method, {
    kind: SpanKind.CLIENT,
    attributes: {
      'http.request.method': request.method,
      'url.full': request.origin + redact(request.path),
      'server.address': url.hostname,
      'server.port': Number(url.port) || (url.protocol === 'https:' ? 443 : 80),
    },
  }));
});
diagnosticsChannel.subscribe('ultraton:request:response', (message) => {
  const { request, statusCode } = message as UltraTonRequestResponseMessage;
  spans.get(request)?.setAttribute('http.response.status_code', statusCode).end();
});
diagnosticsChannel.subscribe('ultraton:request:error', (message) => {
  const { request, error } = message as UltraTonRequestErrorMessage;
  spans.get(request)
    ?.setAttribute('error.type', error.code ?? error.name)
    .setStatus({ code: SpanStatusCode.ERROR, message: error.code ?? error.name })
    .end();
});
```

Subscribers run synchronously inside the request. As with any `diagnostics_channel` subscriber, one that throws raises an uncaught exception (the request itself is unaffected), so keep them simple. Adding headers to outgoing requests (trace propagation such as `traceparent`) is planned with request hooks. The message types are exported: `UltraTonRequestStartMessage`, `UltraTonRequestRetryMessage`, `UltraTonRequestResponseMessage`, `UltraTonRequestErrorMessage`, `UltraTonDiagnosticsRequest` and `UltraTonDiagnosticsError`.

### Proxy

`proxy` sends every `https:` request through an HTTP CONNECT or a SOCKS5 proxy, on both engines. The SSRF checks run before the proxy is ever contacted, and the proxy cannot point the connection anywhere else:

```ts
const client = new UltraTonClient({
  proxy: { url: 'http://egress.corp:3128', auth: process.env.PROXY_AUTH }, // auth is 'user:password'
});
```

- **Pinning through the proxy.** UltraTon resolves the name and validates every address, then sends `CONNECT <ip>:<port>`: the proxy gets an IP, never a name it could resolve to something else. TLS runs to the target through the tunnel, and its certificate is checked against the hostname as on a direct connection. If the proxy cannot reach one address, the next validated one is tried.
- **Credentials** in `auth` go on the CONNECT only, as `proxy-authorization`, and never reach a target. Credentials in the URL are rejected.
- **An `https:` proxy** (TLS to the proxy itself) is checked against the system CAs, or against `proxy.ca`. The `tls.ca` you set for targets is never trusted for the proxy, and `proxy.ca` is never trusted for targets.
- **Refusals** (407, 403, 502, …) reject with `UltraTonNetworkError` and code `ERR_ULTRATON_PROXY`. The message carries the status and never the proxy address. `retry` does not retry them; a connection to the proxy that drops (`ECONNRESET`, `ETIMEDOUT`) is retried like any other. A proxy that cannot be reached at all fails at once instead of being tried for every address.
- **Plain `http:` targets** (loopback only) never use the proxy. Proxies are never read from `HTTP_PROXY`/`HTTPS_PROXY`. For internal hosts that must not go through the proxy, use a second client without it.

**Proxies that filter by hostname.** Squid ACLs or Smokescreen allowlists reject a CONNECT by IP. `resolve: 'proxy'` sends the name instead:

```ts
new UltraTonClient({ proxy: { url: 'http://smokescreen:4750', resolve: 'proxy' } });
```

> **Warning:** With `resolve: 'proxy'` the proxy resolves the name, so **SSRF protection for hostnames depends on the proxy**. UltraTon still rejects reserved IP literals, bad schemes and credentials in URLs, but it cannot pin DNS. Use it only with a proxy that enforces its own egress policy.

**SOCKS5.** A `socks5:` URL (default port 1080) tunnels the same way: UltraTon resolves and validates the name and sends the IP as the SOCKS5 address (IPv4 or IPv6), never the name. `auth` is SOCKS5 username/password (RFC 1929, each part 1 to 255 bytes). `socks5h:` is the SOCKS5 spelling of `resolve: 'proxy'`: the name is sent and the proxy resolves it, with the same warning as above. `proxy.ca` does not apply, since SOCKS5 has no TLS of its own; TLS to the target runs through the tunnel as with CONNECT.

```ts
new UltraTonClient({ proxy: { url: 'socks5://bastion.corp:1080', auth: 'svc:s3cret' } });
```

A SOCKS5 refusal rejects with `ERR_ULTRATON_PROXY` and the reason (`connection refused`, `host unreachable`, `authentication failed`, …). These are final: a refused login, no acceptable authentication method, the proxy's ruleset and "command not supported". Any other reply (unreachable, refused, general failure, …) moves on to the next validated address. SOCKS4, `BIND` and `UDP ASSOCIATE` are not supported.

> **Warning:** SOCKS5 has no encryption of its own: the username and password in `auth` cross the network to the proxy in cleartext. The request itself is safe (TLS runs end to end through the tunnel), but only use SOCKS5 credentials over a network you trust, or reach the proxy through an SSH tunnel.

### Protect the client you already use

Not ready to switch clients? `createSecureAgents()` gives you an `http.Agent` and an `https.Agent` that apply UltraTon's SSRF policy to any client that takes an agent:

```ts
import { createSecureAgents } from 'ultraton';

const agents = createSecureAgents({ permitReservedIps: ['10.20.0.0/16'] }); // same options as the client: permitReservedIps, tls

// axios
const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false }); // proxy: false, see below
// got
const gotApi = got.extend({ agent: { http: agents.http, https: agents.https } });
// node-fetch
await fetch(url, { agent: (u: URL) => (u.protocol === 'http:' ? agents.http : agents.https) });
// Node's own http.request / https.request
https.get(url, { agent: agents.https }, onResponse);

// when done
agents.http.destroy();
agents.https.destroy();
```

Every new socket resolves its host and validates **every** address, then connects only to those addresses: a DNS rebinding between connections is blocked. Redirects the library follows open their own sockets through the agent, so each hop is checked. IP literals are judged in every spelling, TLS is always verified (a library's `rejectUnauthorized: false` is ignored), and plain `http:` only reaches loopback unless you pass `allowPlainHttp: true`, which lifts the scheme rule but never the address policy. A blocked connection fails with the usual `SecureHttpError` (`ERR_ULTRATON_RESERVED_IP`, `ERR_ULTRATON_PLAIN_HTTP`). axios, got and node-fetch all expose its code as `err.code`; axios and got also keep the original error as `err.cause`. A failure to reach an *allowed* address is Node's own error, and its message may name that address.

> **Warning:** **With axios, `proxy: false` is mandatory, and `httpVersion: 2` is not allowed.** axios reads `HTTP_PROXY`/`HTTPS_PROXY` by default. For an `https:` URL it then **replaces your `httpsAgent`** with its own tunnelling agent, which sends the proxy the hostname: the secure agents never see the request, and no check runs. For an `http:` URL it sends the proxy an absolute URL through your agent, which the agents refuse with `ERR_ULTRATON_AGENT_PROXY`. Always create the instance with `proxy: false`, and never pass `proxy` on a single request (it overrides the instance's). axios with `httpVersion: 2` opens its own HTTP/2 connection without any agent, so never use it with the secure agents. If you need a proxy or HTTP/2, use `UltraTonClient`, whose `proxy` and `http2` keep the target pinned. got and node-fetch do not read proxy variables; got with `http2: true` uses the agent, but not when you also pass `createConnection` or `h2session`. The compat tests in this repository check all three, including this axios behaviour.

The agents protect the **connection**. The rest stays with the library you plug them into:

| Protection | Secure agents | `UltraTonClient` |
|---|---|---|
| Reserved IPs blocked, every address validated, DNS pinned | Yes | Yes |
| Redirect hops checked | Yes (each new socket) | Yes |
| TLS always verified | Yes | Yes |
| Plain http only to loopback | Yes (unless `allowPlainHttp`) | Yes |
| https → http redirect rejected, credentials dropped across origins | No (the library decides) | Yes |
| Body size limit, decompression bombs, truncated bodies | No | Yes |
| Total and idle timeouts | No | Yes |
| Header injection, unknown options, `baseUrl` traversal | No | Yes |
| A library's own proxy (axios reads `HTTP_PROXY`) | Partly: `http:` refused (`ERR_ULTRATON_AGENT_PROXY`); axios bypasses the agents for `https:`, so pass `proxy: false` | — |
| Proxies with the target still pinned (CONNECT, SOCKS5) | No | Yes (`proxy`) |
| Error messages without addresses | Blocked connections only | Yes |

### baseUrl

With `baseUrl` set, request URLs must be relative. `'users/7'` and `'/users/7'` both resolve under the base path. An absolute or protocol-relative URL throws.

A path that would land outside the base throws as well. That includes encoded and look-alike forms that lenient servers decode: `../admin`, `%2e%2e/admin`, `..%2fadmin`, `..;/admin`, `..\admin` and fullwidth dots. Normal paths work, including encoded slashes inside a segment (`group%2Fproject`), `;v=1` parameters and `.well-known/`.

## Limits and things to know

- **Proxies are only used when you set `proxy`.** UltraTon does not read `HTTP_PROXY`/`HTTPS_PROXY`, `NODE_USE_ENV_PROXY` or `http.globalAgent`. Each client uses its own agents so that the SSRF policy cannot be bypassed through a shared pool. HTTP CONNECT and SOCKS5 proxies are supported (no SOCKS4). The proxy handshake for each address gives up after 10 s, or sooner through `timeoutMs`, `signal` or `close()`; `socketTimeoutMs` only starts once the tunnel is up.
- **The allowlist keeps IPv4 and IPv6 apart.** An IPv6 entry never covers an IPv4 address, and an IPv6 address that embeds an IPv4 in its last 32 bits (`::ffff:10.0.0.1`, NAT64) is judged only by your IPv4 entries. A 6to4 (`2002::/16`) or Teredo (`2001:0::/32`) address carrying a reserved IPv4 is blocked, and only an IPv6 entry (`2002:a00::/24`) allows it: `10.0.0.0/8` does not. A broad IPv6 entry such as `::/0` therefore allows them too, whatever IPv4 they carry. A hostname entry trusts whatever that name resolves to, so prefer IPs or CIDRs.
- **Redirects into allowlisted ranges are followed.** A public server can redirect to an address your `permitReservedIps` allows. Keep allowlists narrow, or keep `maxRedirects: 0` on clients that allow private ranges.
- **Redirects are not bound to `baseUrl`.** A followed redirect can go to another host, and every hop is still checked against the SSRF policy. Redirects are off by default.
- **DNS lookups cannot be cancelled.** `timeoutMs` and `signal` reject the request on time, but Node's `getaddrinfo` keeps running in the libuv threadpool until the resolver answers.
- **`close()` does not wait for the sockets to finish closing.** It destroys them and returns, and requests still in flight reject with `UltraTon: Client is closed.`
- **`json()` strips `constructor` and `prototype` keys.** A legitimate field with one of those names disappears. Use `JSON.parse(res.text())` if you need it and trust the source.
- **Decoded bodies keep the wire headers.** With `decompress` on, `data` is decoded but `headers` stay as received: `content-length` is the compressed length and `content-encoding` is still there, as with `fetch`. An encoding UltraTon does not decode (zstd, for now) leaves the body raw. Raw (headerless) deflate from very old servers fails as `Z_DATA_ERROR`. Brotli can use up to 16 MiB of working memory per response whatever `maxBodySize` is. On a Node release without the fix for CVE-2026-111497 (before 22.23.4, 24.22.1 or 26.12.1), br is neither requested nor decoded: a server that sends it anyway gets its body back raw, even when you asked for br in your own `accept-encoding`.
- **The request methods buffer; `stream()` does not.** `get`, `post` and the others read the body into memory up to `maxBodySize` (at most 2 GiB). Use `stream()` for large downloads. A `File` or `Blob` body is read whole into memory first: pass a stream (`createReadStream`) to upload a large file. Over HTTP/2, a `stream()` body you have not read yet can hold up to 1 MiB (the stream's flow-control window) until you read or cancel it.
- **HTTP/2 to an IP literal on Node 22.12–22.13.** Node itself sends the IP as SNI there and prints a `DEP0123` warning once. Node 22.14 and later send no SNI for an IP, as UltraTon asks.
- **Fake-IP DNS setups.** `198.18.0.0/15` is reserved, which affects Clash and sing-box TUN modes. Allow it explicitly if you rely on them.

## Migrating from 1.x

| 1.x | 2.0 |
|---|---|
| `client.post(url, body, options)` | `client.post(url, { json })` or `client.post(url, { body })`. The same applies to `put` and `patch`. |
| `new UltraTonClient()`, then options on every request | `new UltraTonClient({ baseUrl, headers, timeoutMs, … })`. Per-request options still work and win. |
| `timeout` | Removed (it never worked). Use `timeoutMs` (total) or `socketTimeoutMs` (idle). |
| Unknown options ignored | Unknown options throw a `TypeError` with a hint. |
| Out-of-range numbers fell back to the default | They throw a `TypeError` naming the valid range. |
| `statusCode: number \| undefined` | Always a `number`. `ok` and `text()` are new. |
| `json()` on an empty body threw | Returns `{}`. |
| `http://127.0.0.1` (IP literals) worked without a permit | Needs `permitReservedIps` (see the localhost recipe). |
| Shared module-wide connection pool | One pool per client. Reuse the client and call `close()` when done. |
| Network errors were raw Node errors containing the IP | `UltraTonNetworkError` with `code` and `cause`. |
| `UltraTonNetworkTimeoutError` was a separate branch | It extends `UltraTonNetworkError`, so check for it first. |
| No `user-agent` header | `ultraton/<version>` is sent unless you set one. |
| Node ≥ 24.14 | Node ≥ 22.12, and `require('ultraton')` works. |

The full list is in [CHANGELOG.md](CHANGELOG.md).

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a public issue for it.

**Keep Node.js up to date.** Run 22.23.4, 24.22.1, 26.12.1 or later: those releases fix a Brotli decoder flaw that a malicious server could use for remote code execution, and TLS hostname checks fooled by non-canonical IP addresses. On older releases UltraTon stops requesting and decoding `br`; [SECURITY.md](SECURITY.md#nodejs-releases) lists what it covers and what it cannot.

The [SSRF corpus results](compat/ssrf-corpus/RESULTS.md) show, case by case, what `UltraTonClient` and `createSecureAgents()` block next to axios, got, node-fetch and Node's `fetch` on their own: IP spellings, cloud metadata, DNS and redirects. The corpus runs in CI, and a case UltraTon stops blocking fails the build.

[THREAT_MODEL.md](THREAT_MODEL.md) explains what UltraTon defends, against whom, where each defense lives in the code, and the risks it deliberately leaves to you. Releases carry npm provenance, so you can check that a version was built by this repository's CI with `npm audit signatures`.

## Support and contributing

[SUPPORT.md](SUPPORT.md) lists the supported Node.js and UltraTon versions, how long an old major gets security fixes, and what counts as a breaking change. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to set up, test and send a change.

## License

MIT
