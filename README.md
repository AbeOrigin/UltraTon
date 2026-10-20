# UltraTon

> A secure HTTP client for Node.js. The safe choice is the default, and the risky ones are opt-in.

UltraTon is an HTTP/1.1 and HTTP/2 client built only on Node's own `node:https`, `node:http2` and `node:dns`, with **zero runtime dependencies**. It is built for code that sends requests to URLs it does not fully control: webhooks, link previews, integrations, internal service clients. It blocks SSRF (including DNS rebinding), caps memory and time, and never silently ignores a mistake in its options.

```bash
npm install ultraton
```

Requires Node.js **22.12** or later. Works from ESM (`import`), CommonJS (`require`) and TypeScript.

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
| Credentials on a cross-origin redirect | `authorization`, `cookie`, `proxy-authorization`, `auth` and `host` are dropped. | — |
| Response body size | **2 MB**, then the response is aborted. | `maxBodySize` |
| Compressed responses (gzip, deflate, br) | **Decoded**, with `maxBodySize` applied to the decoded bytes too, so a decompression bomb stops at the limit. At most 2 content-encodings. | `decompress: false` |
| Total time (DNS + all hops) | **30 s** | `timeoutMs` (`0` = none) |
| Idle connection | **10 s** without bytes | `socketTimeoutMs` (`0` = none) |
| TLS verification | **Always on**. It cannot be disabled. | `tls: { ca, cert, key }` for private CAs and mTLS |
| Header injection (CRLF/NUL), pseudo-headers | **Rejected** before connecting. | — |
| JSON prototype pollution | `__proto__`, `constructor` and `prototype` keys are stripped by `json()`. | — |
| Unknown options or wrong option types | **Throw a `TypeError`**, with a hint for common mistakes. | — |
| Truncated response (`content-length` mismatch, GOAWAY or reset mid-body) | **Rejected**. It never resolves as a short body. | — |

## Options

**Client options** go to `new UltraTonClient(options)`. All of them are optional:

| Option | Type | Notes |
|---|---|---|
| `baseUrl` | `string` | Relative request paths resolve under it and can never escape it (see [baseUrl](#baseurl)). |
| `http2` | `boolean` | Use HTTP/2 (ALPN `h2`, or h2c to loopback). Default `false`. |
| `tls` | `{ ca?, cert?, key? }` | PEM strings or Buffers: a private CA, or a client certificate for mTLS. |
| `userAgent` | `string` | Default `ultraton/<version>`. |
| `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps` | | Defaults for every request. A request that sets the same option wins; headers are merged key by key. |

**Request options** are the second argument of every method:

| Option | Type | Default |
|---|---|---|
| `json` | `unknown` | Serialized, and sent with `content-type: application/json` unless you set one. |
| `form` | plain object or `URLSearchParams` | Sent urlencoded, with the same rules as `query`. |
| `body` | `string \| Buffer \| Uint8Array \| Blob \| FormData \| URLSearchParams` | A `FormData` goes as multipart with its boundary, a `Blob` with its `type`. Only one of `json`, `form` and `body`. GET and HEAD cannot have a body. |
| `headers` | plain object | — |
| `query` | plain object or `URLSearchParams` | Appended to the URL's own query. Arrays repeat the key, `undefined` is skipped, `null` and nested objects throw. |
| `auth` | `'user:password'` | Sent as Basic auth. Dropped on a cross-origin redirect. |
| `signal` | `AbortSignal` | Aborts in any phase. The request rejects with `signal.reason`. |
| `timeoutMs` | integer ms | `30000` |
| `socketTimeoutMs` | integer ms | `10000` |
| `maxBodySize` | integer bytes | `2097152` (2 MB) |
| `decompress` | `boolean` | `true`: sends `accept-encoding` (unless you set one) and decodes the body. `false` leaves `data` as received. |
| `maxRedirects` | integer 0–20 | `0` |
| `permitReservedIps` | `boolean \| string[]` | `false` |

**Response:**

| Field | Type | Notes |
|---|---|---|
| `statusCode` | `number` | — |
| `ok` | `boolean` | `true` for 200–299. |
| `headers` | `IncomingHttpHeaders` | Never contains HTTP/2 pseudo-headers. |
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
| `SecureHttpError` | A request on a closed client | — |
| `UltraTonNetworkTimeoutError` | `timeoutMs` or `socketTimeoutMs` expired | — |
| `UltraTonNetworkError` | DNS, connect, TLS, reset or truncated response, or a compressed body that is corrupt or cut short | Node's or zlib's code (`ECONNREFUSED`, `ENOTFOUND`, `ECONNRESET`, `Z_DATA_ERROR`, …) |
| `SecureHttpError` | More than 2 content-encodings on a response | `ERR_ULTRATON_CONTENT_ENCODING` |
| `UltraTonMemoryError` | The body exceeded `maxBodySize` | — |
| `UltraTonRedirectError` | More redirects than `maxRedirects` | — |
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

**Fetch a URL a user gave you (webhooks, link previews).** The defaults are already right. Keep the redirect count small; every hop is still checked against the SSRF policy:

```ts
const client = new UltraTonClient({ maxRedirects: 3, maxBodySize: 512 * 1024, timeoutMs: 5000 });
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

Your own `content-type` header is kept for `form`, `URLSearchParams` and `Blob`. With a `FormData` it throws, because the header has to carry the boundary of the body. A `content-type` in the client's default headers is replaced by the one the body implies: a form, a `FormData` or a `Blob` with a `type` (for `json`, or a `Blob` without a type, it is kept). The whole body is read into memory before sending, a large file included.

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
- **Request bodies** are buffered. A `ReadableStream` body in `init` throws, and the body of a `Request` input is read whole.
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

`stream(url, { method: 'POST', json, … })` takes the method as an option. The body fails, never ends early, if it is cut short, too large, corrupt, aborted or the client is closed. `socketTimeoutMs` only counts while you are waiting for data, so a slow consumer never times out. Read the body to the end or `cancel()` it: until then it holds its connection and keeps the process alive.

### baseUrl

With `baseUrl` set, request URLs must be relative. `'users/7'` and `'/users/7'` both resolve under the base path. An absolute or protocol-relative URL throws.

A path that would land outside the base throws as well. That includes encoded and look-alike forms that lenient servers decode: `../admin`, `%2e%2e/admin`, `..%2fadmin`, `..;/admin`, `..\admin` and fullwidth dots. Normal paths work, including encoded slashes inside a segment (`group%2Fproject`), `;v=1` parameters and `.well-known/`.

## Limits and things to know

- **Proxies are not used.** UltraTon does not read `HTTP_PROXY`/`HTTPS_PROXY`, `NODE_USE_ENV_PROXY` or `http.globalAgent`. Each client uses its own agents so that the SSRF policy cannot be bypassed through a shared pool.
- **The allowlist keeps IPv4 and IPv6 apart.** An IPv6 entry never covers an IPv4 address, and an IPv6 address that embeds an IPv4 (`::ffff:10.0.0.1`, NAT64) is judged only by your IPv4 entries. A hostname entry trusts whatever that name resolves to, so prefer IPs or CIDRs.
- **Redirects into allowlisted ranges are followed.** A public server can redirect to an address your `permitReservedIps` allows. Keep allowlists narrow, or keep `maxRedirects: 0` on clients that allow private ranges.
- **Redirects are not bound to `baseUrl`.** A followed redirect can go to another host, and every hop is still checked against the SSRF policy. Redirects are off by default.
- **DNS lookups cannot be cancelled.** `timeoutMs` and `signal` reject the request on time, but Node's `getaddrinfo` keeps running in the libuv threadpool until the resolver answers.
- **`close()` does not wait for the sockets to finish closing.** It destroys them and returns, and requests still in flight reject with `UltraTon: Client is closed.`
- **`json()` strips `constructor` and `prototype` keys.** A legitimate field with one of those names disappears. Use `JSON.parse(res.text())` if you need it and trust the source.
- **Decoded bodies keep the wire headers.** With `decompress` on, `data` is decoded but `headers` stay as received: `content-length` is the compressed length and `content-encoding` is still there, as with `fetch`. An encoding UltraTon does not decode (zstd, for now) leaves the body raw. Raw (headerless) deflate from very old servers fails as `Z_DATA_ERROR`. Brotli can use up to 16 MiB of working memory per response whatever `maxBodySize` is.
- **The request methods buffer; `stream()` does not.** `get`, `post` and the others read the body into memory up to `maxBodySize` (at most 2 GiB). Use `stream()` for large downloads. Request bodies are always buffered (no upload streaming): a `File` or `Blob` body is read whole into memory first.
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

## License

MIT
