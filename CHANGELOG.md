# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Everything below has been merged since 1.0.3 and is not yet published. It includes breaking changes, so the next release needs a semver-major bump.

### Security

- **SSRF via IP-literal URLs.** The reserved-IP check only ran inside the custom DNS `lookup`, which Node never calls for IP-literal hosts. `http://127.0.0.1`, numeric forms (`2130706433`, `0x7f.1`, `127.1`) and IPv6 literals (`[::1]`, `[::ffff:127.0.0.1]`) reached internal services with default options. Every hop, redirect targets included, is now checked before a socket opens (#1).
- **Reserved-range coverage.** `isReservedIp` is rebuilt on `net.BlockList` and also blocks multicast, `240/4`, `198.18/15`, `192.0.0/24`, the TEST-NETs, `::/96`, `fec0::/10`, `ff00::/8`, `2001:db8::/32` and `100::/64`. IPv4 addresses embedded in NAT64 `64:ff9b::/96` are judged by the IPv4 rules, and `64:ff9b:1::/48` is blocked (#1).
- **`auth` option leaked on cross-origin redirects.** It is now cleared whenever the origin changes, like `authorization`, `cookie` and `proxy-authorization` (#1).
- **Keep-alive socket reuse across policies (S1, high).** The shared agent pooled sockets by `host:port` only, so a socket opened with `permitReservedIps: true` could serve a default-deny request. HTTP/1 now uses dedicated keep-alive agents per reserved-IP policy (#4).
- **HTTP/2 DNS hang and pool poisoning (S2, high).** DNS was awaited outside the timeout budget, so a nameserver that never answers hung requests and poisoned the origin in the pending-connection pool. `timeoutMs` now bounds DNS, each caller gets its own `AbortSignal`, and a late DNS answer no longer connects when nobody is waiting (#4).
- **`https` to `http` redirects (S3, medium).** They are rejected in both clients on every hop, so a response can no longer push a permitted client to the plaintext loopback escape hatch (#4).
- **Error messages no longer echo hostnames or IPs (S5, low).** The reserved-IP and DNS-failure errors name the `permitReservedIps` option and contain neither the IP nor the hostname. The phrase `prohibited internal/reserved network IP` is kept (#4).
- **HTTP/2 hardening to HTTP/1 parity.** Options and headers are validated before connecting, including CRLF/NUL, caller-supplied pseudo-headers and a caller `host` header. `parseSafeUrl` runs on every hop. Every pooled session is re-checked against `permitReservedIps`, and the pool key includes that policy. One absolute `timeoutMs` budget is shared across redirect hops. `host` is dropped on cross-origin redirects in both clients (#3).
- **Malformed JSON crashed the process (HTTP/2).** A server answering `application/json` with an invalid body caused an uncaught exception. Responses are no longer parsed at request time at all: the request resolves, and `json()` throws `UltraTonParseError` on invalid JSON (#3).
- **HTTP/2 session races.** A concurrent retry could open sessions that `closeAll()` could not reach, and a pooled session could be overwritten by a concurrent attempt. Both are fixed (#3, #4).

### Added

- **HTTP/2 engine.** Session pooling plus HPACK and memory limits (#3). It is reached through the single client with `new UltraTonClient({ http2: true })` (TLS with ALPN `h2`, or h2c on the `http://localhost` escape hatch); the separate `UltraTonHTTP2` class is gone (see Removed).
- **One client, configured once.** `new UltraTonClient(options)` takes `baseUrl`, `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps`, `http2`, `tls` and `userAgent`. The constructor validates them like the per-request options: an unknown key throws a `TypeError` with a hint (`timeout`, `baseURL`, a top-level `ca`, `rejectUnauthorized`, the per-request `signal`/`auth`/`json`/`body`, and the removed `isolatePool`/`tlsSettings` each get one), and so does a value of the wrong type. A `permitReservedIps` list is copied and frozen, so mutating your array later does not widen the client's policy.
- **Defaults merged per request.** `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects` and `permitReservedIps` given to the constructor apply to every request; a request that sets the same option wins, key by key. Only `undefined` falls back to the client's value: `null` throws the usual type error, as it does without a client default. Headers merge case-insensitively and the request's value wins; a request header set to `undefined` keeps the client's value.
- **`baseUrl`.** Request paths are resolved against it (`'users/7'` and `'/users/7'` both land under the base path) and can never leave it: an absolute URL, a protocol-relative one (`//host`, and the backslash variants `\\host`, `/\host`) throws `TypeError: UltraTon: With baseUrl set, request paths must be relative.`, and a path that resolves outside the base (`../admin`, `%2e%2e/admin`, `..\admin`, a sibling such as `../v1-admin`) throws `TypeError: UltraTon: Request path escapes baseUrl.`. The check runs on the resolved URL, after the WHATWG parser has decoded dot segments and stripped whitespace. The part below the base is then also judged the way lenient servers read it: percent-decoded until it stops changing (at most 5 passes, otherwise refused), NFKC-normalized, split on `/`, `\`, U+2215 and U+29F5, each segment cut at `;` and at a decoded `?` or `#`. A segment that is then `.` or `..`, or only dots plus trailing spaces or control characters, throws the same error, and so does a run of three or more dots followed by a separator. That covers `..%2fadmin`, `%252e%252e%252fadmin`, `..%5cadmin`, `..;/admin`, fullwidth and other lookalike dots and slashes (`．．/admin`, `‥/admin`, `..／admin`), `..%00/admin`, `..%20/admin`, `...%2fadmin` and `..%3f/admin`. An encoded slash inside an ordinary segment (`group%2Fproject/issues`), `a/b/c;v=1`, `.well-known/x`, a trailing `files/...` and `100%25` still work. Malformed percent-encoding in the path throws `TypeError: UltraTon: Request path has malformed percent-encoding.`. `baseUrl` itself must pass `parseSafeUrl` and cannot carry a query string or fragment. Redirects are not bound to it; they follow `maxRedirects` (default 0). Without `baseUrl`, URLs must be absolute as before.
- **`tls: { ca, cert, key }`.** Trust a private CA or present a client certificate, on both engines (the HTTPS agents for HTTP/1, the session connect options for HTTP/2). Each is a PEM `string`, a `Buffer` or an array of them. Any other key throws, in particular `rejectUnauthorized` (certificate verification cannot be disabled), `servername` and `checkServerIdentity`.
- **`user-agent` by default.** Every request sends `user-agent: ultraton/<version>` unless the client sets `userAgent` (or a `user-agent` in its `headers`, but not both) or the request sets its own header.
- **Per-client connection pools and `close()`.** Each client owns its HTTP/1 keep-alive agents (still one pair per `permitReservedIps` policy, 5 s idle timeout) and, with `http2: true`, its own HTTP/2 session manager. Two clients never share a socket or a session, so one client's `permitReservedIps` or `tls` can never serve another's requests. `await client.close()` destroys the client's sockets and sessions and is idempotent. Requests still in flight, and any later request, reject with `SecureHttpError('UltraTon: Client is closed.')` (not a network error).
- **Options are read as own properties only.** Constructor options, `tls` and per-request options ignore anything inherited from `Object.prototype`, so a polluted prototype (`Object.prototype.baseUrl`, `.tls`, `.permitReservedIps`, `.auth`) cannot configure a client or a request. They must be plain objects (prototype `Object.prototype` or `null`): a class instance or `Object.create(proto)` throws `TypeError: UltraTon: Options must be a plain object.` instead of having its getters and inherited values dropped silently.
- **`permitReservedIps` allowlist (S4).** Besides `true`/`false`, it accepts a list of IPs, CIDRs or hostnames, for example `['10.0.0.0/8', 'api.internal']`. An IPv6 CIDR never covers native IPv4, IPv6 addresses that embed an IPv4 (mapped, compatible, NAT64) are judged only by that IPv4, a hostname entry trusts that name's DNS, and redirects into allowlisted ranges are followed (#4).
- **`UltraTonNetworkError`.** Socket, connect and TLS failures (`ECONNREFUSED`, `ECONNRESET`, certificate and handshake errors) reject with it in both engines. It carries `code` (the original `err.code`, or `UNKNOWN`) and `cause` (the original error), and `SecureHttpError` now accepts `{ cause, code }`.
- **Public package entry.** A single `ultraton` entry exports `UltraTonClient`, `SecureHttpError`, `UltraTonNetworkError`, `UltraTonMemoryError`, `UltraTonNetworkTimeoutError`, `UltraTonParseError`, `UltraTonRedirectError` and the types `UltraTonClientOptions`, `UltraTonRequestOptions`, `UltraTonResponse` and `ReservedIpPolicy`. `package.json` `exports` now declares `types` and `default`.
- **`require()` support.** The package can be loaded from CommonJS on Node versions that support `require(esm)`, which is why `engines` starts at 22.12.
- **Package checks.** `npm run test:package` packs the tarball, installs it in a temporary consumer and verifies `import`, `require` and TypeScript resolution. `npm run lint:package` runs `publint` and `@arethetypeswrong/cli`.
- **CI matrix** for Node 22, 24 and 26.
- **`signal` on HTTP/2.** An aborted `signal` closes the stream with `NGHTTP2_CANCEL` (the server sees it cancelled) and rejects the request; a signal that is already aborted rejects before any DNS lookup or connection. The signal also cuts the DNS and pool wait, combined with the `timeoutMs` budget through `AbortSignal.any`, so whichever fires first wins.
- **`socketTimeoutMs` on HTTP/2.** It used to be accepted and ignored. It is now a per-stream idle timeout: no bytes received for that long closes the stream and rejects with `UltraTonNetworkTimeoutError` (`UltraTon: Socket completely idle for <n>ms.`, as in HTTP/1). `0` disables it. The default of 10 s now applies to HTTP/2 requests too. A request body goes out in 64 KiB chunks and each one that gets through resets the timer, so a large upload that keeps moving is not idle; one the server stopped reading still times out.

- **`json` option.** `post(url, { json })` (also `put`, `patch` and the other methods) serializes with `JSON.stringify` and sends `content-type: application/json` unless you already set a `content-type` header.
- **`auth` on HTTP/2.** The HTTP/2 engine never used the `auth` option. It now sends it as a Basic `authorization` header (an explicit `authorization` header wins), and a cross-origin redirect drops it like any other credential.

### Changed

- **`content-length` is always sent.** Every request with a body carries an exact `content-length` in bytes (multibyte strings included) in both engines, so there are no more chunked request bodies. A `content-length` or `transfer-encoding` you set yourself never overrides the real length: the real `content-length` is sent and `transfer-encoding` is dropped, in both engines.
- **Breaking: new response shape.** Responses are now `{ statusCode, ok, headers, data, json<T>(), text() }`:
  - `data` is still a `Buffer`, as in 1.x. There is no auto-parsing: `application/json` bodies are not parsed at request time, so a malformed JSON response resolves and only `json()` throws `UltraTonParseError` (with the original error as `cause`).
  - `json<T>()` is lazy, parses on every call whatever the `content-type` (so `application/problem+json` works), and strips `__proto__`, `constructor` and `prototype` keys at every depth, where 1.0.3's `json()` was a plain `JSON.parse`. A legitimate field named `constructor` or `prototype` silently disappears from the result. An empty body gives `{}`, where 1.0.3's `json()` threw `UltraTonParseError`.
  - New: `text()` (UTF-8) and `ok` (`true` for 200-299).
  - `statusCode` is always a `number`; it used to be typed `number | undefined`.
  - `headers` no longer contains HTTP/2 pseudo-headers such as `:status`.
  - There is no size threshold: a body of any size within `maxBodySize` is available as `data` and parseable with `json()` (#3).
- **Breaking: loopback IP literals need a permit.** `http://127.0.0.1` and its numeric forms (such as `http://2130706433`) now require `permitReservedIps`. They used to work through the URL-parser escape hatch. `http://localhost` was already blocked via DNS before this change (#1, #3).
- **Breaking: uniform `(url, options)` methods.** `post`, `put` and `patch` no longer take the body as a second argument, in either engine. The payload goes in the options: `post(url, { json: { a: 1 } })` or `post(url, { body })`. A string, a `Buffer` or a `Uint8Array` is accepted as `body`; any other type throws a `TypeError` before connecting, and so does passing both `json` and `body`. Passing a body where the options go (`post(url, '{"a":1}')`) throws a `TypeError` that points at `{ json }` / `{ body }`.
- **Breaking: unknown options throw.** The per-request options are a closed list (`headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps`, `signal`, `auth`, `json`, `body`). Any other key, even with the value `undefined`, throws `TypeError: UltraTon: Unknown option '<key>'.` before any connection, where it used to be silently dropped. Common mistakes get a hint: `timeout` points at `timeoutMs`, `baseURL` and `prefixUrl` at `baseUrl`, `data` at `json` or `body`, `params`, `query` and `searchParams` at "put the query string in the URL", and `agent`, `ca` and `rejectUnauthorized` at the `tls` constructor option (`rejectUnauthorized` is not supported), and the constructor options `baseUrl`, `tls`, `http2` and `userAgent` passed to a request point at the constructor. Other keys get the list of valid options. A `method` option is rejected too: the HTTP method is the client method you call. `get` and `head` with `json` or `body` throw `UltraTon: GET and HEAD requests cannot have a body.`; `delete` and `options` may carry one in both engines.
- **Breaking: the constructor takes an options object.** `UltraTonClient` used to take no public arguments; it now takes `UltraTonClientOptions` (see Added). Anything else passed to it throws.
- **Behaviour: a `user-agent` header is always sent** (`ultraton/<version>` unless you set one); Node sends none by default, so servers and logs now see one.
- **Behaviour: no pool sharing between clients.** HTTP/2 clients used to share one module-wide session pool unless `isolatePool` was set, and HTTP/1 clients shared module-wide keep-alive agents. Every client now has its own, so connection reuse happens within a client only: reuse one client instead of creating one per request, and `close()` it when done.
- **Internal: module layout.** The engines moved to `src/engines/` (`http1.ts`, `http2.ts` and `http2-session-manager.ts`, which also fixes the old `http-session-mannager` file name), and `src/http-client.ts` is now the client facade. Not visible through the package entry.
- **Behaviour: network and TLS errors no longer contain the address.** Raw Node errors such as `connect ECONNREFUSED 10.0.0.5:8080` (HTTP/1) and the `UltraTon stream error: ...` / `Failed to establish HTTP/2 connection: ...` wrappers (HTTP/2) are replaced by `UltraTonNetworkError` with the message `UltraTon: Connection failed (<code>).` or `UltraTon: TLS handshake failed (<code>).`. The IP and port are only reachable through `error.cause`, so do not log `cause` to untrusted sinks. `AbortError` and existing `SecureHttpError` subclasses are not wrapped.
- **Behaviour: mid-body failures.** Any failure while reading a response body now surfaces as `SecureHttpError`: socket errors and early ends as `UltraTonNetworkError` (`code` `ECONNRESET` when the stream just ends), a caller abort as the signal's reason (see the abort entry below).
- **HTTP/2 no longer resolves a lost response.** A stream that ends without `:status`, or that closes or is reset before a clean end (destroyed socket, RST_STREAM), rejects with `UltraTonNetworkError` (`ECONNRESET`) instead of resolving with `statusCode: undefined` or a truncated body. A raw `'error'` event could previously leak through (#2).
- **Incomplete responses reject in both engines.** A response whose body has fewer or more bytes than its `content-length` rejects with `UltraTonNetworkError` `UltraTon: Connection failed (ECONNRESET).` (`code` `ECONNRESET`), never a truncated success. HEAD, 1xx, 204 and 304 responses are exempt. On HTTP/2 this replaces the `ERR_HTTP2_STREAM_ERROR` code nghttp2 produced for a short body (the original error is the `cause`).
- **HTTP/2 GOAWAY drains.** A graceful GOAWAY used to destroy the session, which cut off the streams it covered and could resolve one with a truncated body. The session now leaves the pool (the next request opens a new one) and closes gracefully, so in-flight streams finish; `close()` still destroys it.
- **Behaviour: abort rejects with the signal's reason, in both engines.** Whatever the phase (already aborted, while connecting or resolving DNS, waiting for the response, mid-body), the request rejects with `signal.reason`, or with a DOMException `AbortError` when `abort()` was called without one. Before, HTTP/1 rejected a mid-body abort with a plain `SecureHttpError` (`UltraTon: The incoming network stream was closed prematurely.`) and others with Node's own `AbortError` wrapper, so `err === signal.reason` never held. Code that matched that message must check the reason instead.
- **Behaviour: idle HTTP/2 sessions do not hold the process open.** A pooled session with no stream in flight is `unref()`ed and is `ref()`ed only while a request is using it, so a script that makes an HTTP/2 request and never calls `close()` exits when it is done instead of waiting out the 10 s session idle timeout. A request with `timeoutMs: 0` still keeps the process alive until it completes, and aborting or timing out a request whose connection is still being established releases the session at once instead of holding the process until the connect or handshake gives up.
- **Behaviour: keep-alive pools.** HTTP/1 requests use the library's own agents and no longer follow `http.globalAgent` mutations or `NODE_USE_ENV_PROXY` (#4).
- **Behaviour: reserved ranges.** `198.18.0.0/15` is blocked, which affects users behind fake-IP DNS proxies such as Clash or sing-box TUN (#1).
- **Behaviour: HTTP/2 timeout.** `timeoutMs` now also bounds DNS resolution. An abandoned `getaddrinfo` cannot be cancelled and finishes in the threadpool (#4).
- **Internal cleanup.** About 120 lines of source and 7 files removed, with errors consolidated in one module and no change to error messages or defaults. The package is still zero-dependency (#2).
- **Node and tooling.** `engines.node` is now `>=22.12.0` (was `>=24.14.0`). Development uses `@types/node` 22 and TypeScript 5.9.
- **Reproducible build.** `npm run build` removes `dist/` before compiling, and `prepack` runs it, so a tarball can no longer include stale files. `CHANGELOG.md` is now published and tracked.

### Removed

- **Breaking: the `timeout` option.** It never had an effect, because `socketTimeoutMs` always overwrote it. TypeScript callers that pass it get a compile error, and it now throws `UltraTon: Unknown option 'timeout'. Use 'timeoutMs' (milliseconds).` (#2).
- Dead code and the `--experimental-strip-types` flag, which Node 24 no longer needs (#2).
- **Breaking: `UltraTonHTTP2`.** Use `new UltraTonClient({ http2: true, ...options })`. Its `isolatePool` option is gone (every client has its own pool now), and so is `tlsSettings`, which passed any `SecureClientSessionOptions` through (including `rejectUnauthorized`): use `tls: { ca, cert, key }`. The module-wide HTTP/2 session pool is gone too.
- **Breaking: the types `UltraTonOptionsHttp2` and `UltraTonRequestOptionsHttp2`.** Use `UltraTonClientOptions` and `UltraTonRequestOptions` (the per-request options are the same on both engines).

## Historial 1.x

Sprint-style history kept as written by the maintainer.

---

# Changelog: Sprint 1 (Basic Client)

## 🏗️ Core Architecture & Initialization
- **Zero-Dependency Engine:** Initialized the `ultraton` package specifically designed to rely on zero external NPM packages.
- **TypeScript 5.4 Integration:** Configured an explicit `tsconfig.json` favoring `NodeNext` Module Resolution, alongside `"rewriteRelativeImportExtensions": true` for pure Native Node ESM compatibility.
- **Native Node Testing Suite:** Bootstrapped `__tests__` using the new `node:test` framework and native `node:assert`, executable instantaneously via `--experimental-strip-types`.

## ✨ Features Added
- **Asynchronous Protocol Wrapper:** Created `UltraTonClient` to successfully wrap legacy Node HTTP/HTTPS callback streams inside modern `Promise` abstractions.
- **Standard Protocol Support:** Implemented strict class wrappers for all major HTTP verbs (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`).
- **Options & Response Typing:** Mapped `UltraTonRequestOptions` and explicitly forced the `data` payload of `UltraTonResponse` to execute strictly as a binary `Buffer`.

## 🛡️ Security Implementations (Red Team)
- **SSRF Hardening:** Enforced a pre-flight protocol check on `const urlObj = new URL()` to actively throw exceptions on prohibited protocols like `file:` or `ftp:` to prevent internal path traversals.
- **Implicit String Allocation Defense:** Handled all incoming data chunks via manual `chunks.push(chunk)` and native `Buffer.concat()` aggregation instead of implicitly trusting `res.setEncoding('utf8')`.
- **Dangling Socket Traps:** Implemented `res.on('error', reject)` catch logic on incoming socket connections to prevent untrapped V8 Promise hang states and resulting memory leaks.

## 🧪 Testing Validations
- **Mock Service Bootstrapper:** Built a generic local `node:http` mock server that boots dynamically on port 0 to prevent port collisions. 
- **Verbs Verification:** Established end-to-end tests for all 7 standard HTTP methods confirming valid status codes and mock echo payloads.
- **Memory Shield Preparation:** Drafted impending Malicious Mock Server endpoints (`/malicious`) actively dumping infinite chunks to prepare for Sprint 2 `MaxBodySize` socket severing traps.

---

# Changelog: Sprint 2 (Memory Shield)

## 🏗️ Core Architecture & Initialization
- **Dependency Map Injection:** Decoupled `node:https` from the core client via native DI mapping (`this._transport`) to isolate the networking layer. Reconstructed `http-client.test.ts` to execute solely on mocked internal `EventEmitter` instances, guaranteeing offline execution and totally negating self-signed TLS certificate logic.
- **Node Engine Enforcements:** Updated `package.json` and `.github/workflows/ci.yml` strictly forcing CI workflows to execute solely on Node 24.x+ to standardize runtime syntax and execution layers.

## ✨ Features Added
- **Default Bounds:** Engineered strict architectural bounds natively enforcing `maxBodySize: 2097152` (2MB) inside a secure type intersection `UltraTonRequestOptions & { maxBodySize: number }`.

## 🛡️ Security Implementations (Red Team)
- **Protocol Lockdown:** Ripped out the `http:` module entirely. All network traffic is fundamentally enforced to execute strictly over TLS `node:https`. Standard HTTP requests are synchronously rejected before a socket is opened. 
- **The Options Firewall:** Built `buildSafeRequestOptions` locally implementing a completely transparent, zero-dependency "Strict Allowlist" mapping against Node's native `https.RequestOptions`. Drops all hostile socket overrides (`agent`, `createConnection`, `rejectUnauthorized`).
- **Synchronous Primitive Guards:** Appended deep runtime analysis inside the options firewall, verifying correct primitives and natively crashing executions via synchronous `TypeError` payloads if TypeScript is bypassed.
- **The OOM Kill Switch:** Asynchronously parses incoming network streams via `res.on('data')`, tracking mathematical chunk aggregation. Rigorously tears down incoming reads (`res.destroy()`) and outbound socket endpoints (`req.destroy()`) upon breaching payload boundaries, mitigating standard Slowloris dripping memory bombs.
- **Custom Exceptions:** Scaled Sprint 5 early by building `UltraTonMemoryError` to isolate Memory Rejections in the Promise chain.

## 🧪 Testing Validations
- **Unit Test Firewall:** Built isolated `request-options.test.ts` running 5 atomic validations confirming `TypeError` exception trapping, dynamic object extraction, and mitigation mapping.

---

# Changelog: Sprint 3 (Network Control)

## 🏗️ Core Architecture & Initialization
- **Type Airgap Enforcement:** Decoupled chaotic user input (`UltraTonRequestOptions`) from mathematically guaranteed system configuration (`SecureUltraTonRequestOptions`). This negates TypeScript coercion anomalies and mathematically enforces internal boundary conditions at compilation.
- **Mock Interceptor Upgrade:** Refactored the `createMockTransport` test harness. Forced the intercepted request stream to natively emit `req.emit('response')` and support local `.destroy()` invocations, ensuring high-fidelity CI testing matching the underlying Node.js event cycle without stalling the suite.

## ✨ Features Added
- **Native OS Socket Binding:** Bound `timeout: reqOpts.socketTimeoutMs` directly onto the native Node `this._transport` object. Successfully delegates idle connections to the underlying C++ TCP timing layer (default 10s max idle).
- **Absolute Execution Ceiling:** Implemented the non-negotiable `timeoutMs` timer scoping the entire request sequence (default 30s execution ceiling). Ensures "trickle payloads" and deep-level stalling cannot infinitely consume process concurrency.

## 🛡️ Security Implementations (Red Team)
- **TDZ (Temporal Dead Zone) Eradication:** Hoisted request instantiation loops and discarded async callback closures in favor of native `.on('response')` listeners. Prevented an explicit V8 crash vector where timeouts referenced variables caught in closure dead-zones.
- **Type Coercion Safeguards:** Guarded against the infamous Node.js `setTimeout(cb, undefined)` vulnerability where un-typed undefined values coerce into 1ms delays, causing massive DoS cascades.
- **Explicit Garbage Collection:** Injected brutal `req.destroy()` termination markers inside native `error` emitters. This bypasses V8's passive garbage collector and forces immediate tearing down of raw TCP file descriptors if the TLS Handshake or DNS queries encounter hostile environments.

---

# Changelog: Sprint 3.5 (Clean Slate Architecture)

## 🏗️ Core Architecture & Initialization
- **Locality of Behavior:** Maintained logical file structures without over-isolating types, heavily preserving developer navigation latency.
- **Controlled Mutability:** Dropped V8-penalizing `Object.freeze()` wrappers in favor of strict compile-time `readonly` interfaces for `UltraTonRequestOptions`, `SecureUltraTonRequestOptions`, and `UltraTonResponse`.
- **Ecosystem-Native Error Handling:** Abandoned aggressive Go-style Tuples (`[Error, null]`) entirely. Engineered robust Node.js Promise rejection closures, allowing downstream microservices to utilize standard `try/catch` block patterns without logic bypasses.

## 🛡️ Security Implementations (Red Team)
- **Base Exception Hierarchy:** Deployed `SecureHttpError` as the overarching root inheritance layer for memory constraints (`UltraTonMemoryError`) and timing aborts (`UltraTonNetworkTimeoutError`).
- **Piped Stream Integrity:** Hardened all stream emission cascades (`res.on("error")`, `req.on("error")`) mapping them safely into parent `reject()` callbacks, actively neutralizing the risk of Unhandled Promise Rejections silently crashing the parent V8 process.
- **Synchronous Construction Guards:** URL parsing exceptions (e.g., legacy `http:` payloads) are dynamically captured and natively propagated via `Promise.reject(new SecureHttpError(...))`, bridging synchronous failures into asynchronous error handling.

---

# Changelog: Sprint 4 (Anti-SSRF & Redirects)

## 🏗️ Core Architecture & Initialization
- **Config Bound Injection:** Introduced `maxRedirects` to the `UltraTonRequestOptions` boundary with a strict deterministic default-deny integer-checking fallback (safeguarded against `Infinity` loops).
- **Constant Mapping Performance:** Abstracted `HTTP_CODES_REDIRECTS` into a fixed O(1) object literal (`Record<number, boolean>`) to optimize V8 execution against redirect status code validations.

## ✨ Features Added
- **Default-Deny Recursion Engine:** Engineered recursive loopbacks via `this._request` specifically targeting `301, 302, 303, 307, 308` redirect codes strictly when the consumer opts-in via `maxRedirects > 0`.
- **Absolute Timeout Inheritance:** Decoupled `reqOpts.timeoutMs` inside the recursive network engine, dynamically calculating remaining milliseconds explicitly from the original execution's `startTime`. Preserves the overarching timeout ceiling across deep redirect chains.

## 🛡️ Security Implementations (Red Team)
- **Domain Hop Protocol Purism:** Implemented Hostile Header Stripping explicitly targeting cross-origin `URL.origin` hops. Systematically executes case-insensitive enumeration to eradicate forged `Authorization` and `Cookie` tokens, neutralizing SSRF credential leakage.
- **Method Downgrade Safeguards:** Integrated strict detection for `303 See Other` alongside `301`/`302` non-`GET` payloads, forcefully degrading the recursion to a `GET` request. Explicitly drops `content-type` and `content-length` to block upstream proxy smuggling attacks.
- **Immediate GC Severing:** Orchestrated immediate `res.destroy()` and `req.destroy()` inside the redirect interceptor, deliberately detaching `res.on('data')` listening callbacks to permit instant V8 Garbage Collection of unused Socket streams during heavily nested redirect chains.

## 🧪 Testing Validations
- **Chaos QA Factory:** Established `redirect.test.ts` implementing a highly dynamic asynchronous HTTP event emitter mimicking local routing tables. Confirmed the mitigation of Infinite Loops, Tarpit Socket hangs, Domain Hopping authentication loss, and HTTP Method Snuggling behaviors.

---

# Changelog: Sprint 5 (DX & Architecture Refactoring)

## 🏗️ Core Architecture & Initialization
- **Iterative State Machine:** Ripped out the recursive "God-function" redirect implementation inside `_request`. Replaced it with a strictly flattened `while(true)` loop mapped natively across a decoupled `_executeSingleNetworkHop` stream executor. 
- **V8 GC Optimization:** The new iterative engine guarantees that Node's Garbage Collector instantly reclaims defunct `ClientRequest` closures upon a redirect, entirely eliminating nested Promise stacks and memory leaks.
- **Lexical Stream Binding:** Tightly scoped `_consumeResponseBuffer` and network hopping methods securely within `this` class bounds, preventing object deoptimization. 

## ✨ Features Added
- **Synchronous JSON Parsing:** Authored a seamless `.json<T>()` extraction payload inside the final `UltraTonResponse` return object.
- **Dynamic Type Generics:** Augmented `get<T>`, `post<T>`, and all standard protocols to accept `<T>` typescript shapes natively. Converts raw buffered network APIs into perfectly typed data structures synchronously.

## 🛡️ Security Implementations (Red Team)
- **TE.CL Smuggling Mitigation:** Discovered and proactively plugged a critical HTTP Request Smuggling CVE (TE.CL) by strictly parsing and deleting `Transfer-Encoding: chunked` during a 303 `GET` method downgrade.
- **Sandbox Safe Exceptions:** Deployed `UltraTonParseError` explicitly to interdict native C++ `SyntaxError` throws when `JSON.parse` ingests hostile garbled data or HTML walls. Prevented hard crashes from unhanded parse exceptions.

## 🧪 Testing Validations
- **JSON DX Assertions:** Validated deep extraction layers through a fresh `json-parser.test.ts` suite. Simulated hostile malformed payloads natively intercepting bounded custom error types over 20 completely green test runners.

---

# Changelog: Sprint 6 (Post-MVP Security Hardening)

## 🏗️ Core Architecture & Initialization
- **V8 GC Buffer Optimization:** Eliminated redundant double-iteration overheads by injecting mathematical byte bounds (`currentBodySize`) directly into the final `Buffer.concat()` aggregation.

## 🛡️ Security Implementations (Red Team)
- **CRLF & Header Pollution Defenses:** Engineered case-insensitive regex pipelines (`\r\n\0`) targeting all incoming dynamic header keys and array iterations, ruthlessly cutting Request Smuggling logic and native Node Prototype overrides (`__proto__`) before network execution.
- **Timer Overflow Boundary DOS Fix:** Secured absolute Event Loop stability by enforcing strict 32-bit positive integer bounds ( `< 2147483647` and `>= 0`) against dynamic timers to neutralize immediate-execution payload crashing vectors.
- **Resilient Promise Floats:** Handled mute tcp connection drops efficiently. Abrupt `aborted` and socket `close` states are natively hooked into explicit V8 Error mapping closures, saving pending requests from infinite Event Loop leaks.
- **Runtime Sandbox Integrity:** Neutralized public external protocol definitions natively inside the constructor loop, permanently isolating `UltraTon` directly against `node:https`. Any external attempts to modify and intercept traffic will aggressively fail closed.

## 🧪 Testing Validations
- **Isolated Testing Bounds:** Upgraded all underlying mock-transport interceptors (`__tests__`) to bypass internal boundaries securely via `any` assignments, perfectly sustaining over 20 green assertions while upholding ruthless system-wide lockdowns against foreign functions.
