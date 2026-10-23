# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`createSecureAgents()` checks the certificate against the host the socket goes to**, as the client does: never against a `servername` the library set or one Node derived from its `Host` header, and an IP literal is checked as itself with no SNI. Before, a library could connect to `127.0.0.1` with `Host: localhost` and a certificate for `localhost` only was accepted (the CVE-2026-106069 pattern, outside the threat model's adversaries since libraries derive `Host` from the URL, but a gap against what SECURITY.md promised for the client). Found by an adversarial audit of 2.7.0, which found no bypass of any documented defense.
- **Two more reserved ranges**: `192.88.99.0/24` (deprecated 6to4 relay anycast, RFC 7526) and `3fff::/20` (documentation, RFC 9637).

### Fixed

- A header named `__proto__` (from JSON) on the client options no longer makes `extend()` fail: the options copy has no prototype, so the key stays a plain key and is dropped as always.

## [2.7.0] - 2026-10-23

The quality-of-life release, plus what an independent review of 2.6.0 asked for. Security: HTTP/2 server push is refused, TLS 1.2 is the explicit floor of every connection, and `redirectHeaders: 'safe'` keeps custom headers from following a redirect to another origin. For the developer: `client.explain(url)` says what a request would do before connecting, error codes are typed (`UltraTonErrorCode`, `isUltraTonError()`), `res.assertOk()` throws on a non-2xx when you want it to, `await using` closes clients and agents, `client.extend()` makes variants that share the pools, `NODE_DEBUG=ultraton` shows requests without secrets, and the README gains a first-five-minutes section, a troubleshooting table, a migration guide and tested recipes. No breaking changes; the defaults are the same. Nothing published to npm depends on anything but Node.

### Security

- **HTTP/2 server push is refused.** Sessions were opened with Node's default `enablePush: true`, and nothing in UltraTon reads a pushed stream, so a hostile server could park up to 200 pushed streams of 1 MiB each (the window UltraTon advertises) in the process per origin, outside `maxSessionMemory` and the idle timer, until `client.close()`. Every session now sets `enablePush: false`: a `PUSH_PROMISE` is a protocol error that fails the request as a network error. Found in an independent review.
- **TLS 1.2 is the explicit floor of every connection**: direct, through a proxy tunnel, to a TLS proxy, and in the agents of `createSecureAgents()`, where it replaces whatever `minVersion` the library passes. Node's default is already TLS 1.2, but `tls.DEFAULT_MIN_VERSION` can be lowered by `--tls-min-v1.0`, `NODE_OPTIONS` or any module in the process; UltraTon no longer depends on it.

### Changed

- **README for arrival.** "The first five minutes" names the three defaults that surprise on day one and the one-line answer to each; "Troubleshooting by error code" lists every code with what happened and what to change (a test keeps it complete); "Coming from axios, got or fetch" maps the options and the four defaults that change; and the recipes for delivering a webhook, previewing a link and calling an internal service run as tests with the same code the README shows.
- **Limit errors say which option to change.** A body over `maxBodySize` now ends with "Raise maxBodySize" (the same message from `get()` and `stream()`, as the body-parity test requires), a request body over `maxRequestBodySize` with "Raise maxRequestBodySize, or send less"; the first sentence of each message is unchanged, and the HTTP/2 wording now matches HTTP/1.1's. The reserved-address error already named `permitReservedIps`.
- **`maxHeaderListPairs` on HTTP/2 sessions goes from 64 to 128**, Node's default. A legitimate response with many `set-cookie` and CDN headers could exceed 64 and fail with an opaque protocol error; `maxHeaderListSize` (16 KiB) is what bounds the memory and is unchanged.
- Internal: the redirect hop (limit, Location parsing, downgrade refusal, header and method rules), the body framing headers, the time-budget arithmetic and the "client is closed" error were each written twice, once per engine; they are now one helper each, used by both. No behaviour changes: the suite and the public API snapshot are unchanged.
- ROADMAP-HTTP1.md and ROADMAP-HTTP2.md are gone: they were the 1.x sprint plans, and this file is the history. The README no longer announces request hooks (a subscriber of `diagnostics_channel` cannot change a request; headers go in `headers`), CONTRIBUTING says CodeQL runs through GitHub's default setup, and the compat RESULTS files say which release they measure.
- SECURITY.md says that a Node build carrying a security fix under an older version number (a distribution backport) is treated as unfixed, and THREAT_MODEL.md gains rows for server push, the TLS floor and the Node-release gating, plus the error-code oracle (`ERR_ULTRATON_RESERVED_IP` against `ENOTFOUND`) as a residual risk.

### Fixed

- **`text()` and `json()` skip a leading UTF-8 BOM**, as `fetch` does: a JSON body from a server that writes one (common on .NET) no longer fails with `UltraTonParseError`. `data` keeps the raw bytes.

### Added

- **`client.extend(options)`** returns a variant of a client with its options on top (headers merged case-insensitively, `retry` field by field, a `userAgent` replacing the base's), sharing the connection pools unless `http2`, `tls` or `proxy` change; pools stay apart per `permitReservedIps` policy either way. Closing one client leaves the others working; the pools close with the last one.
- **`NODE_DEBUG=ultraton`** writes one line per response, retry and error to stderr (method, origin, status or error code, duration), as a subscriber of the `diagnostics_channel` events; nothing subscribes when it is off. Nothing secret is written. Paths are off by default, since APIs put secrets in them: `ULTRATON_DEBUG_PATHS=1` adds them, and `NODE_DEBUG=*` does not.
- **`res.assertOk()`** for callers who want a non-2xx response to throw: it returns the response when `ok`, and otherwise throws `UltraTonHttpError` (`ERR_ULTRATON_HTTP_STATUS`, with `statusCode` and the response as a non-enumerable property, so logging the error never dumps the body; the message carries the status only). On `stream()` it cancels the body first, so a refused response does not hold its connection. Non-2xx responses still resolve by default; `client.fetch` keeps the standard `Response`.
- **`await using` for the client and the secure agents.** `UltraTonClient` implements `Symbol.asyncDispose` (as `close()`), and the pair from `createSecureAgents()` implements `Symbol.dispose` (destroying both agents).
- **Typed error codes and `isUltraTonError()`.** `UltraTonErrorCode` lists every code UltraTon raises, so `error.code` autocompletes and a misspelled code is a compile error (the type stays open to Node's and zlib's codes); a test keeps the list equal to what the source raises. `isUltraTonError(err, code?)` recognizes UltraTon errors by shape (`name` and `code`), so errors from another copy of the package in `node_modules` count too, and it never throws.
- **`client.explain(url)`** says what a request would do before connecting, without connecting: the URL as it would be sent, the addresses the host resolves to and how the policy judges each one, and the verdict with the code the request would reject with. The same functions decide here and in a request (`judgeAddresses`, now the one place that judges resolved addresses). For the operator configuring `permitReservedIps` or `baseUrl`; the result names addresses, so never return it to whoever supplied the URL.
- **`redirectHeaders` option, `'all'` or `'safe'`, per request and as a client default.** On a redirect to another origin UltraTon drops `authorization`, `cookie`, `proxy-authorization`, `auth` and `host` and lets every other header follow, as `fetch`, got and axios do; the README said "credentials are dropped" without saying that an `x-api-key` or any other custom header is not one of them. `'safe'` lets only `accept`, `accept-encoding`, `accept-language`, `user-agent`, `content-type` and `content-length` cross origins. The default stays `'all'`; `'safe'` is the candidate default for 3.0. Found in an independent review.
- Tests: a server that pushes streams, the TLS floor on every connection, and a Slowloris body (a byte every 50 ms) cut by `timeoutMs` in `get()` and left to the idle timer in `stream()`, on both engines. README and THREAT_MODEL.md now say the latter.
- **A weekly soak test in CI.** `scripts/soak.ts` (workflow `soak.yml`, also on demand with a chosen length) runs 20 to 60 minutes of hostile and flaky server behaviour on loopback, on HTTP/1.1 and HTTP/2, directly and through a CONNECT proxy: redirects across origins, 503s with retries, dropped streams, aborts, idle timeouts, body-size overruns on the wire and after decompression, uploads and cancelled streams. It fails if RSS or heap end above the warm-up baseline by more than a margin, or if an HTTP/2 session, a socket or a handle is still open after `close()`.
- **Signed build provenance on every GitHub release.** `publish.yml` attests the packed tarball with Sigstore (`actions/attest-build-provenance`) and attaches `ultraton-<version>.tgz` and its `.sigstore.json` bundle to the release, so OpenSSF Scorecard's Signed-Releases check no longer scores -1. SECURITY.md shows the `gh attestation verify` command.

## [2.6.0] - 2026-10-23

Closes the last of Node's October 2026 security issues that SECURITY.md still listed as unmitigated: on a Node release without the keep-alive fix (CVE-2026-105481), HTTP/1.1 sockets are no longer reused, so a server cannot slip a response into the next request. Nothing changes on 22.23.4, 24.22.1, 26.12.1 or later; on an earlier release each HTTP/1.1 request opens its own connection. Upgrade Node too: SECURITY.md lists the releases.

### Security

- **HTTP/1.1 keep-alive is turned off on Node releases without the keep-alive fix.** Node fixed a keep-alive socket taking a response a server wrote before the next request was sent (CVE-2026-105481) in 22.23.4, 24.22.1 and 26.12.1. Part of Node's fix needs a native binding a library cannot reach, so on any earlier release UltraTon now builds its HTTP/1.1 agents with `keepAlive: false` instead: a socket serves one request and is then closed, so none ever sits idle in a pool to be poisoned. The cost is a new TCP/TLS connection per request on those releases; upgrade Node to pool again. HTTP/2 is unaffected. SECURITY.md lists the minimum releases.
- **On those releases, the agents of `createSecureAgents()` cannot be switched back to reusing sockets.** Setting `keepAlive` (other than `false`), `maxSockets` or `maxTotalSockets` (other than `Infinity`) on one throws `ERR_ULTRATON_AGENT_KEEP_ALIVE`. `keepAlive` would bring the pool back. With a limit, a request waits in the agent's queue, and when a response ends Node hands it that socket before checking keep-alive, so it could still read bytes the server wrote early; a finite `maxSockets` also makes Node ask for keep-alive whatever the agent says. `UltraTonClient` keeps its agents private and was never exposed.

## [2.5.0] - 2026-10-21

Closes the residual risks UltraTon still listed and narrows exposure to Node's October 2026 security issues: 6to4 and Teredo addresses are judged by the IPv4 they carry, Brotli is off on Node releases without the decoder fix, and a TLS name can no longer come from anything but the URL. `stream()` now reports body limits as `get()` does, and the public API is frozen in CI. Upgrade Node too: SECURITY.md lists the releases.

### Security

- **6to4 and Teredo addresses carrying a reserved IPv4 are blocked.** A 6to4 address (`2002::/16`) holds an IPv4 in bits 16–47, and a Teredo address (`2001:0::/32`) holds a server IPv4 and an inverted client IPv4; a host with a tunnel interface or a relay delivers to them. They used to be judged as public IPv6 (a documented residual risk); now a reserved IPv4 inside one makes the address reserved, `2002:a9fe:a9fe::1` (cloud metadata) and `2001:0:808:808::80ff:fffe` (a Teredo client on 127.0.0.1) included. In an allowlist only an IPv6 entry allows such an address: an IPv4 entry does not cover it. Two new cases in the SSRF corpus (now 32).
- **No Brotli on Node releases without the decoder fix.** Node fixed an out-of-bounds write in its Brotli decoder that a malicious server could use for remote code execution (CVE-2026-111497) in 22.23.4, 24.22.1 and 26.12.1. On any earlier release, UltraTon no longer sends `br` in `accept-encoding` and never feeds a `br` body to the decoder: the body comes back raw, as for any coding the runtime cannot decode. Upgrade Node to get Brotli back. SECURITY.md lists the minimum releases.
- **`createSecureAgents()` refuses a host that is an IPv4 in a non-canonical form** (`127.1`, `0x7f.0.0.1`, `2130706433`), with `ERR_ULTRATON_NON_CANONICAL_IP`. A library may pass one as is, as the host, the `servername` or the Host header Node derives the TLS name from; getaddrinfo can resolve it to that IPv4 while TLS checks it as a DNS name, the confusion behind CVE-2026-106069, -106072 and -105483. An all-numeric single-label host (`123`) is refused too: URL parsers read it as an IPv4.
- **Over HTTP/1.1, the TLS name always comes from the URL.** A caller's `host` header used to become the name Node checked the certificate against: `https://127.0.0.2/` with `headers: { host: 'localhost' }` passed with a certificate for `localhost` only. HTTP/2 already took the name from the URL.

### Fixed

- **`stream()` reports a body limit and a lost connection like `get()`.** On a compressed body over `maxBodySize` (on the wire or decoded), `stream()` and `client.fetch` rejected with `UltraTonNetworkError` "Response body could not be decoded" instead of `UltraTonMemoryError`, and a connection lost mid-body came out as a decoding failure. Buffered and streamed bodies now share one decoding chain, and a test holds them to the same outcome for every body.

### Added

- **The public API is frozen in CI.** `npm run check:api` compares every exported declaration and every `ERR_ULTRATON_*` code with `scripts/public-api.txt`: an API change can only land as a reviewed edit of that file. Property tests now also cover the `Link` header parser, 6to4/Teredo decoding and non-canonical IPv4 hosts.

## [2.4.1] - 2026-10-21

A performance release, with no change to the API: HTTP/2 moves large bodies 1.5× faster, and every request does less work around the same checks. On the CI benchmark, UltraTon over HTTP/1.1 reaches 77% of `node:http`'s throughput (from 62–67%). The site now shows those benchmarks, and how they were measured.

### Changed

- **Faster HTTP/2 bodies.** The receive window is 1 MiB per stream (was Node's 64 KiB) and 16 MiB per connection (was 64 KiB, shared by every stream), so a body no longer waits on WINDOW_UPDATE round trips. The stream window is also the most a `stream()` body left unread can hold; the connection window bounds no memory, because Node acknowledges it as data arrives.
- **Less overhead per request.** HTTP/1.1 response bodies are read with events instead of an async iterator; the client's validated `permitReservedIps` list is reused instead of being validated and copied on every request, and its key is cached; response headers are assigned instead of defined one by one (only `__proto__` is still defined); and a request's options are copied fewer times on their way to the engine, with no promise for a request without a body. No check was removed. On the CI benchmark, UltraTon over HTTP/1.1 went from 62–67% to 77% of `node:http`'s throughput.

### Added

- **A CPU profile of UltraTon in CI.** The Benchmarks workflow now also runs `compat/bench/profile.ts` (`--cpu-prof`, both engines, both body sizes) and uploads a `cpu-profile` artifact: where the time goes, the top functions by self and inclusive time, and the raw `.cpuprofile` files.
- **"Secure, and Built to Be Fast" on the site:** the benchmark chart (requests per second for every client, 1 KiB and 64 KiB bodies) with how it was measured and what it leaves out.

## [2.4.0] - 2026-10-21

Uploads that stream and APIs that paginate: request bodies can be streams, with an optional size limit, `client.paginate()` walks paginated APIs without ever leaving their origin, and every response now says where it came from. All additive.

### Added

- **Streamed uploads.** `body` accepts a `Readable`, a `ReadableStream` or any async iterable of `Uint8Array` or string chunks, on both engines and in `client.fetch` (which no longer rejects them, and also streams a `Request` input's body). The body is sent as it is read, never buffered.
  - **Framing:** the request's own `content-length` is sent as is, and the stream must match it exactly (`ERR_ULTRATON_REQUEST_BODY_LENGTH` otherwise, never a truncated body). Without it, HTTP/1.1 sends chunked.
  - **Sent once:** a request with a streamed body is never retried, whatever `retry` says, and a 307/308 resolves as the 3xx response instead of being followed. 301/302/303 are followed as a GET without a body, as before.
  - **Ending early:** an abort, a timeout or a failure destroys the stream (a `ReadableStream` is cancelled), even while it waits for data. An error from the stream rejects the request as is.
- **`maxRequestBodySize`** (request and client option, no default): a buffered body larger than it throws before connecting, a streamed one is aborted as soon as it goes past it. Both reject with `UltraTonMemoryError`, code `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE`.
- **`url` and `redirected` on every response** (`get`, `post`, …), as `stream()` already had: the final URL after any followed redirect.
- **`client.paginate(url, options)`** walks a paginated API as an async iterator of complete responses, each page a full `get()`. The next page is the `rel="next"` link of the `Link` header (RFC 8288, read without regex) or what a `next(page)` callback returns.
  - **Scope:** it never leaves the first page's origin, nor `baseUrl` when set (whose path checks apply to each page): `SecureHttpError` code `ERR_ULTRATON_PAGE_OUT_OF_SCOPE`. A page that a followed redirect served from outside that scope rejects the same way before its link is read, so another server never picks the next request (credentials attached) on your origin. Links resolve against the page's final URL; a path from `next()` reads like a `get()` path (from `baseUrl` when set).
  - **Bounded:** `maxPages` (default 100); a page left after it rejects with `ERR_ULTRATON_MAX_PAGES` instead of truncating in silence. A non-2xx page is yielded and ends the walk. `query` applies to the first page only.

## [2.3.0] - 2026-10-20

Protection for the clients you already use, and the evidence behind it: `createSecureAgents()` for axios, got and node-fetch, observability through `diagnostics_channel`, a public SSRF corpus, fuzzing and benchmarks run in CI, an honest comparison, and a fix for prototype header keys spelled in another case. All additive.

### Added

- **[SUPPORT.md](SUPPORT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).** The support policy: Node.js lines from 22.12 on that are still maintained upstream, 6 months of security fixes for the previous major, and what counts as a breaking change (error codes and classes yes, messages no; security fixes never wait for a major). The contributing guide covers zero runtime dependencies, test-first, parity between the HTTP/1.1 and HTTP/2 engines, and light, loopback-only tests. Issue forms for bugs and features; a way past a protection goes to a private advisory instead.
- **TSDoc on every public symbol and member,** which is what editors show on hover. A dependency-free CI check (`npm run check:tsdoc`) scans the built `.d.ts` files and fails if a public export, or a member of one, has none. It filled the gaps in the diagnostics payloads, `UltraTonRetryInfo` and `UltraTonSecureAgents`.
- **"Choosing a client" in the README and on the site:** when to use UltraTon, Node's `fetch`, or `createSecureAgents()` with the client you already have, plus a table of each library's defaults (SSRF, redirects, size limits, timeouts, retries, proxies, HTTP/2, dependencies, maturity) that also lists where UltraTon falls short.
- **Reproducible benchmarks** in `compat/bench/`: UltraTon (HTTP/1.1 and HTTP/2, and axios through `createSecureAgents()`) next to Node's `http.request`, Node's `fetch` (undici), axios, got and node-fetch.
  - It reports requests per second, p50/p99 latency, CPU per 1 000 requests and memory, with a 1 KiB and a 64 KiB body.
  - Every client runs in its own process, takes the median of 3 rounds after a warm-up, and gets an IP literal, so DNS is not measured.
  - It runs only in CI, in a `Benchmarks` workflow (by hand, weekly, and on PRs that touch it); results are committed to `compat/bench/RESULTS.md`.
- **Property tests (fuzzing) for the parsers that face hostile input,** with no dependency: a seeded PRNG, generators built from the pieces real bypasses use, and a shrinker, in `__tests__/fuzz/`. They check that:
  - no request path UltraTon accepts escapes `baseUrl` as a lenient server decodes it;
  - IPv6 parsing gives exactly the written address in every spelling;
  - header validation throws if and only if a key or value has CR/LF/NUL or a pseudo-header;
  - against a hostile proxy splitting its answers at random points, a CONNECT or SOCKS5 tunnel opens on a valid answer, never on an invalid one or one followed by bytes in the same write, and never hangs.

  `npm test` runs 200 cases per property with a fixed seed; a nightly workflow runs 5000 with a fresh one.
- **Public SSRF corpus** in `compat/ssrf-corpus/`: 30 cases, each linked to its source (OWASP, PayloadsAllTheThings). They cover IP spellings, IPv6 forms (mapped, compatible, NAT64), `0.0.0.0` and private ranges, cloud metadata, internal DNS answers (including a mixed one and `.nip.io`), `localhost` variants, the userinfo trick, and 302/307/308/protocol-relative redirects. Every case declares the reason UltraTon must block it for, so a case blocked by an unrelated rule cannot hide a regression, and redirect cases check that the allowed first hop happened.
  - It runs against `UltraTonClient`, against axios, got and node-fetch through `createSecureAgents()`, and against those libraries and Node's `fetch` on their own.
  - A CI test fails if UltraTon stops blocking any case.
  - `npm run corpus` regenerates the comparison table in `compat/ssrf-corpus/RESULTS.md`.
- **Observability through `diagnostics_channel`.** Every client call (`get`, …, `stream()`, `fetch()`) publishes `ultraton:request:start`, then `ultraton:request:retry` before each retry wait, and `ultraton:request:response` or `ultraton:request:error`. A subscriber that throws raises an uncaught exception, as with any `diagnostics_channel` subscriber.
  - Each event carries the same frozen `request` (`{ method, origin, path }`, with the query and `;params` left out), plus the status, duration, retry attempt, or the error's `{ name, code }`. It never carries headers, bodies, `auth`, URL credentials, `error.cause` or resolved addresses. Path segments are published as they are: the README shows how to redact a secret kept in a path.
  - It costs nothing without subscribers, and invalid options publish nothing.
  - The README has an OpenTelemetry recipe. New public types for the payloads: `UltraTonDiagnosticsRequest`, `UltraTonDiagnosticsError` and the four `UltraTonRequest*Message` types.
- **Supply-chain and security documentation.**
  - [THREAT_MODEL.md](THREAT_MODEL.md) covers:
    - the assets and adversaries;
    - each defense, with where it lives in the code and which tests cover it;
    - the trust assumptions and the accepted residual risks;
    - a section for auditors.
  - SECURITY.md's scope now covers proxies, retries and the secure agents.
  - An OpenSSF Scorecard workflow (results in the Security tab and a README badge).
  - Dependabot for the actions, the build tooling and `compat/`, with a 14-day cooldown on new versions.
- **`createSecureAgents()`: UltraTon's SSRF policy for the client you already use.** It returns an `http.Agent` and an `https.Agent` for axios (`httpAgent`/`httpsAgent`), got (`agent`), node-fetch (`agent`) and `http.request`.
  - Every new socket resolves its host and validates every address against `permitReservedIps`, then connects only to them. A DNS rebinding between connections is blocked, and so is each redirect hop the library follows, since it opens a new socket.
  - IP literals are judged as themselves. The library's own `lookup` is ignored and a `socketPath` throws.
  - TLS is always verified: a library's `rejectUnauthorized: false` or no-op `checkServerIdentity` is ignored.
  - Plain `http:` only reaches loopback names and addresses unless `allowPlainHttp: true`, which never lifts the address policy.
  - A forward-proxy request through the agents (CONNECT, or an absolute URL as axios sends for `http:` URLs with `HTTP_PROXY`) is refused with `ERR_ULTRATON_AGENT_PROXY`, since the proxy would pick the target unchecked. With axios, `proxy: false` is mandatory (never overridden per request), and `httpVersion: 2` must not be used: for `https:` URLs, axios with a proxy set replaces the `httpsAgent` with its own tunnelling agent, and with `httpVersion: 2` it opens HTTP/2 connections itself. Either way the secure agents are bypassed entirely. Both behaviours are pinned by characterization tests.
  - Integration tests with axios 1.20.0, got 16.1.0 and node-fetch 3.3.2 run against the packed tarball in a separate `compat/` workspace, as their own CI job. Their dependencies are never part of the package.
  - The options are a closed list (`permitReservedIps`, `tls`, `allowPlainHttp`), validated like the client's.
  - New public types `UltraTonSecureAgentOptions` and `UltraTonSecureAgents`. The README lists what the agents cover and what only the full client does (body limits, timeouts, header validation, redirect policy, proxies).

### Security

- **A header key spelling the prototype in another case (`__PROTO__`, `Constructor`) was not dropped.** The check ran before the key was lowercased, so `__PROTO__` set the prototype of the sanitized headers object to its value; an array value then added inherited keys. All case variants are now dropped, like `__proto__`. The fuzzing review found it, and the header property now covers it.

## [2.2.0] - 2026-10-20

Robustness and corporate networks on the same security model, all additive: form bodies, opt-in retries, HTTP CONNECT and SOCKS5 proxies that tunnel to the validated IP, and public codes for timeouts. No breaking changes. Behaviour changes: `UltraTonNetworkTimeoutError` now carries a `code`; an HTTP/2 stream the server never processed fails with `NGHTTP2_REFUSED_STREAM` instead of an `ERR_HTTP2_*` code; and setting more than one of `json`, `form` and `body` throws a reworded `TypeError`.

### Added

- **SOCKS5 proxies.** `proxy` also takes a `socks5:` URL (default port 1080), on both engines, with the same guarantees as an HTTP CONNECT proxy.
  - UltraTon resolves and validates the name and sends the IP as the SOCKS5 address (IPv4 or IPv6), never the name. TLS runs to the target over the tunnel with the certificate checked against it.
  - `auth` is SOCKS5 username/password (RFC 1929, each part 1 to 255 bytes, checked when the client is built).
  - `socks5h:` sends the name instead, as `resolve: 'proxy'`; `socks5h:` with `resolve: 'local'` throws, and so does `proxy.ca` with a SOCKS5 proxy.
  - A refusal rejects with `ERR_ULTRATON_PROXY` and the SOCKS5 reason. A refused login, no acceptable method, the proxy's ruleset and 'command not supported' are final; any other reply moves on to the next validated address. SOCKS5 credentials travel to the proxy in cleartext, as the protocol has no encryption.
  - Not supported: SOCKS4/4a, `BIND`, `UDP ASSOCIATE`, GSSAPI.
- **Outbound proxy: the `proxy` client option**, a URL (`'http://egress.corp:3128'`) or `{ url, auth, ca, resolve }`, on both engines.
  - Every `https:` request is tunnelled with CONNECT **to the IP UltraTon resolved and validated**, never to a name the proxy could resolve elsewhere, so DNS pinning holds through the proxy. If the proxy cannot reach one address, the next validated one is tried. TLS runs to the target over the tunnel, with SNI and the certificate checked against the hostname.
  - SSRF checks run before the proxy is contacted. Redirects go through the tunnel again, validated again.
  - `auth` (`user:password`) is sent as `proxy-authorization` on the CONNECT only, never to a target; credentials in the proxy URL are rejected. The URL must be a bare `http:` or `https:` origin.
  - An `https:` proxy is checked against the system CAs or `proxy.ca`, which is kept apart from the `tls.ca` trusted for targets.
  - A refused CONNECT rejects with `UltraTonNetworkError` code `ERR_ULTRATON_PROXY` and the status in the message, never the proxy address, and is not retried. A malformed or oversized proxy response, or one with bytes past its headers, is refused too.
  - The CONNECT handshake has a 10 s deadline per address, and the request's `timeoutMs`, `signal` and `close()` end it sooner.
  - `resolve: 'proxy'` sends the hostname instead, for proxies that filter by name (Squid, Smokescreen). DNS pinning is then up to the proxy; reserved IP literals are still rejected.
  - Plain `http:` targets (loopback) never use the proxy. Proxies are never read from the environment. `close()` closes the tunnels.
  - New public type `UltraTonProxyOptions`.
- **Retries: the `retry` option**, on the client and per request, off by default.
  - `retry: n` retries up to `n` times (0 to 10). An object sets `limit`, `methods`, `statusCodes`, `maxDelayMs` and `onRetry`, and a request's `retry` merges over the client's field by field.
  - Defaults: the methods GET, PUT, DELETE, HEAD and OPTIONS (never POST or PATCH unless listed) and the statuses 408, 429, 502, 503 and 504. The network failures `ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `EAI_AGAIN` and `EPIPE` are retried, and so is the idle timeout. When the retries run out on a status, the last response is returned.
  - Never retried: policy errors, `UltraTonMemoryError`, `UltraTonRedirectError`, `TypeError`, the `timeoutMs` timeout and an abort.
  - Waits use exponential backoff with full jitter (300 ms base, up to `maxDelayMs`, default 30 s). `Retry-After` (seconds or an HTTP date) is waited exactly; when it asks for more than `maxDelayMs` or than the budget left, the response is returned instead of retried.
  - `timeoutMs` is the budget of every attempt and wait together, and `signal` cancels a wait.
  - Every attempt is a full request, so DNS is validated again on a new connection.
  - `onRetry({ attempt, delayMs, statusCode?, error? })` is called before each wait; if it throws, the request ends with that error.
  - `stream()` retries until the headers arrive. `client.fetch()` never retries.
  - New public types: `UltraTonRetryOptions` and `UltraTonRetryInfo`.
- **HTTP/2 streams the server never processed** fail with `UltraTonNetworkError` code `NGHTTP2_REFUSED_STREAM` (`UltraTon: The server did not process the request (REFUSED_STREAM).`), which `retry` retries, as RFC 9113 allows. This covers a stream reset with REFUSED_STREAM before any answer, and a stream above the last one a GOAWAY processed. Before, the first failed as `ERR_HTTP2_STREAM_ERROR`, and the second as `ERR_HTTP2_SESSION_ERROR` when the GOAWAY carried an error code. Other resets keep their `ERR_HTTP2_*` code and are not retried.
- **Timeout codes.** `UltraTonNetworkTimeoutError` now has a `code`: `ERR_ULTRATON_TIMEOUT` when `timeoutMs` ran out, and `ERR_ULTRATON_SOCKET_TIMEOUT` when the connection sat idle for `socketTimeoutMs`. Before, it had none.
- **Form bodies.**
  - New `form` request option: a plain object or `URLSearchParams`, sent urlencoded (`application/x-www-form-urlencoded;charset=UTF-8`) with the same encoding rules and validation as `query`.
  - `body` now also accepts `URLSearchParams` (sent urlencoded), `FormData` (sent as `multipart/form-data` with its boundary, files included) and `Blob`/`File` (sent with its `type` as content-type). Encoding uses the platform's own `Response`, with no dependencies.
  - The request's own `content-type` header is kept, except with a `FormData` body, where it throws a `TypeError`: the header must carry the body's boundary. A client default `content-type` is replaced by the one the body implies (a form, a `FormData` or a typed `Blob`); for `json` and an untyped `Blob` it is kept.
  - Every body is buffered before sending, a large `File` included.

### Changed

- Setting more than one of `json`, `form` and `body` throws `TypeError("UltraTon: Use only one of 'json', 'form' or 'body'.")`. Before, `json` together with `body` threw `"Use either 'json' or 'body', not both."`.

## [2.1.0] - 2026-10-20

Everyday features on the same security model, all additive: `query`, safe response decompression, `client.stream()` and `client.fetch()`. No breaking changes. One behaviour change: requests now send `accept-encoding: gzip, deflate, br` and decode compressed responses by default (`decompress: false` turns it off).

### Added

- **`client.fetch(input, init)`.** A `fetch()` that goes through the client and returns a standard `Response`. It is bound to the client, so it can be passed to any library that accepts a fetch implementation.
  - It is built on `stream()`, so every UltraTon check applies.
  - Bodies (string, `ArrayBuffer`/views, `Blob`, `URLSearchParams`, `FormData` with its multipart boundary) and headers are normalized by the platform's own `Request`, and a `Request` can be the input.
  - Methods are upper-cased.
  - Redirects follow the client's `maxRedirects` (default 0, so a 3xx comes back as the `Response`). `redirect: 'manual'` returns the 3xx, and `'error'` rejects.
  - Failures follow undici: a non-`TypeError` failure rejects as `TypeError('fetch failed')` with the UltraTon error as `cause`, and an abort rejects with the signal's reason.
  - The `Response` has `url` and `redirected` set and a null body for 204/205/304/HEAD. Its `json()` strips `__proto__`, `constructor` and `prototype` keys.
  - Browser-only init fields are ignored. `dispatcher`, `agent` and any other unknown field throw, and so does a streaming request body.
- **`redirected` on stream responses.** `UltraTonStreamResponse` now says whether a redirect was followed.
- **`client.stream(url, options)`.** Resolves when the response headers arrive, with `{ statusCode, ok, headers, url, body }`, where `body` is a `ReadableStream<Uint8Array>`. The method is an option (`method`, default `'GET'`, one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS). Every check of the other methods applies before the headers (SSRF, redirects followed before resolving, credentials, `timeoutMs`), and the body keeps its limits as it is read:
  - `maxBodySize` on wire and decoded bytes, here up to `Number.MAX_SAFE_INTEGER`;
  - the content-length match and decoding;
  - `signal`, which fails the stream with its reason, and `close()`, which fails it with `Client is closed`.
  
  A truncated, oversized or corrupt body fails the stream instead of ending it. Backpressure reaches the socket or the HTTP/2 flow-control window. `socketTimeoutMs` only runs while the consumer waits for data, so a slow consumer never times out the server. Cancelling the body closes the socket or resets the HTTP/2 stream. New types: `UltraTonStreamOptions`, `UltraTonStreamMethod`, `UltraTonStreamResponse` (and `QueryValue` is now exported).
- **Safe response decompression (`decompress`, default `true`).** Requests send `accept-encoding: gzip, deflate, br` unless they set their own, and both engines decode the body on the fly. `maxBodySize` bounds the bytes on the wire and, separately, the decoded bytes, counted chunk by chunk as zlib produces them, so a decompression bomb stops at the limit with `UltraTonMemoryError`. The content-length check still counts wire bytes. A corrupt or truncated compressed body rejects with `UltraTonNetworkError` carrying zlib's code (`Z_DATA_ERROR`, `Z_BUF_ERROR`), never a partial success. More than 2 content-encodings reject with `ERR_ULTRATON_CONTENT_ENCODING` when there is a body, and an unknown encoding (zstd included: Node's decoder does not report a truncated frame) is left raw. `headers` stay as received. `decompress: false`, per request or as a client default, sends no `accept-encoding` and leaves `data` untouched.
- **`query` option.** `get(url, { query: { q: 'café', page: 2, tags: ['a', 'b'] } })` appends URLSearchParams-encoded pairs to the URL's own query, which is kept byte for byte. An array repeats its key and `undefined` is skipped. `null`, nested objects, non-finite numbers and anything that is not a plain object or `URLSearchParams` throw a `TypeError` before connecting. The query is applied after `baseUrl`'s path check and can never change the path. The `params` and `searchParams` hints now point at `query`, and `query` passed to the constructor says it is a per-request option.

## [2.0.0] - 2026-10-20

The first release since 1.0.3. It is a breaking release: the README has a migration table from 1.x.

### Security

- **Quadratic time on request paths with long control-character runs.** With `baseUrl` set, the leading/trailing whitespace trim used a regex that retried from every position: a 200 000-character path took about 10 s to reject. It is now a linear scan (#6).
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

- **HTTP/2 engine.** Session pooling plus HPACK and memory limits (#3). It is reached through the single client with `new UltraTonClient({ http2: true })` (TLS with ALPN `h2`, or h2c over plain http to a loopback name); the separate `UltraTonHTTP2` class is gone (see Removed).
- **One client, configured once.** `new UltraTonClient(options)` takes `baseUrl`, `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps`, `http2`, `tls` and `userAgent`. The constructor validates them like the per-request options: an unknown key throws a `TypeError` with a hint (`timeout`, `baseURL`, a top-level `ca`, `rejectUnauthorized`, the per-request `signal`/`auth`/`json`/`body`, and the removed `isolatePool`/`tlsSettings` each get one), and so does a value of the wrong type. A `permitReservedIps` list is copied and frozen, so mutating your array later does not widen the client's policy.
- **Defaults merged per request.** `headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects` and `permitReservedIps` given to the constructor apply to every request; a request that sets the same option wins, key by key. Only `undefined` falls back to the client's value: `null` throws the usual type error, as it does without a client default. Headers merge case-insensitively and the request's value wins; a request header set to `undefined` keeps the client's value.
- **`baseUrl`.** Request paths are resolved against it (`'users/7'` and `'/users/7'` both land under the base path) and can never leave it: an absolute URL, a protocol-relative one (`//host`, and the backslash variants `\\host`, `/\host`) throws `TypeError: UltraTon: With baseUrl set, request paths must be relative.`, and a path that resolves outside the base (`../admin`, `%2e%2e/admin`, `..\admin`, a sibling such as `../v1-admin`) throws `TypeError: UltraTon: Request path escapes baseUrl.`. The check runs on the resolved URL, after the WHATWG parser has decoded dot segments and stripped whitespace. The part below the base is then also judged the way lenient servers read it: percent-decoded until it stops changing (at most 5 passes, otherwise refused), NFKC-normalized, split on `/`, `\`, U+2215 and U+29F5, each segment cut at `;` and at a decoded `?` or `#`. A segment that is then `.` or `..`, or only dots plus trailing spaces or control characters, throws the same error, and so does a run of three or more dots followed by a separator. That covers `..%2fadmin`, `%252e%252e%252fadmin`, `..%5cadmin`, `..;/admin`, fullwidth and other lookalike dots and slashes (`．．/admin`, `‥/admin`, `..／admin`), `..%00/admin`, `..%20/admin`, `...%2fadmin` and `..%3f/admin`. An encoded slash inside an ordinary segment (`group%2Fproject/issues`), `a/b/c;v=1`, `.well-known/x`, a trailing `files/...` and `100%25` still work. A later decoding pass whose bytes are not UTF-8 throws the same `escapes baseUrl` error instead of becoming U+FFFD, which covers double-encoded overlong UTF-8 such as `%25c0%25ae%25c0%25ae/admin` (a bare `%` not followed by two hex digits stays literal). Malformed percent-encoding in the path throws `TypeError: UltraTon: Request path has malformed percent-encoding.`. `baseUrl` itself must pass `parseSafeUrl` and cannot carry a query string or fragment. Redirects are not bound to it; they follow `maxRedirects` (default 0). Without `baseUrl`, URLs must be absolute as before.
- **`tls: { ca, cert, key }`.** Trust a private CA or present a client certificate, on both engines (the HTTPS agents for HTTP/1, the session connect options for HTTP/2). Each is a PEM `string`, a `Buffer` or an array of them. Any other key throws, in particular `rejectUnauthorized` (certificate verification cannot be disabled), `servername` and `checkServerIdentity`.
- **`user-agent` by default.** Every request sends `user-agent: ultraton/<version>` unless the client sets `userAgent` (or a `user-agent` in its `headers`, but not both) or the request sets its own header.
- **Per-client connection pools and `close()`.** Each client owns its HTTP/1 keep-alive agents (still one pair per `permitReservedIps` policy, 5 s idle timeout) and, with `http2: true`, its own HTTP/2 session manager. Two clients never share a socket or a session, so one client's `permitReservedIps` or `tls` can never serve another's requests. `await client.close()` destroys the client's sockets and sessions and is idempotent. Requests still in flight, and any later request, reject with `SecureHttpError('UltraTon: Client is closed.')` (not a network error).
- **Options are read as own properties only.** Constructor options, `tls` and per-request options ignore anything inherited from `Object.prototype`, so a polluted prototype (`Object.prototype.baseUrl`, `.tls`, `.permitReservedIps`, `.auth`) cannot configure a client or a request. They must be plain objects (prototype `Object.prototype` or `null`): a class instance or `Object.create(proto)` throws `TypeError: UltraTon: Options must be a plain object.` instead of having its getters and inherited values dropped silently.
- **`permitReservedIps` allowlist (S4).** Besides `true`/`false`, it accepts a list of IPs, CIDRs or hostnames, for example `['10.0.0.0/8', 'api.internal']`. An IPv6 CIDR never covers native IPv4, IPv6 addresses that embed an IPv4 (mapped, compatible, NAT64) are judged only by that IPv4, a hostname entry trusts that name's DNS, and redirects into allowlisted ranges are followed (#4).
- **`UltraTonNetworkError`.** Socket, connect and TLS failures (`ECONNREFUSED`, `ECONNRESET`, certificate and handshake errors) reject with it in both engines. It carries `code` (the original `err.code`, or `UNKNOWN`) and `cause` (the original error), and `SecureHttpError` now accepts `{ cause, code }`.
- **Public package entry.** A single `ultraton` entry exports `UltraTonClient`, `SecureHttpError`, `UltraTonNetworkError`, `UltraTonMemoryError`, `UltraTonNetworkTimeoutError`, `UltraTonParseError`, `UltraTonRedirectError` and the types `UltraTonClientOptions`, `UltraTonRequestOptions`, `UltraTonResponse` and `ReservedIpPolicy`. `package.json` `exports` now declares `types` and `default`.
- **`require()` support.** The package can be loaded from CommonJS on Node versions that support `require(esm)`, which is why `engines` starts at 22.12.
- **Package checks.** `npm run test:package` packs the tarball, installs it in a temporary consumer and verifies `import`, `require` and TypeScript resolution. `npm run lint:package` runs `publint` and `@arethetypeswrong/cli`.
- **CI matrix** for Node 22.12.0 (the minimum, tests run with `--experimental-strip-types`), 22, 24 and 26. CI also runs the strict build, the package smoke test and the package lint, with actions pinned by commit SHA and a read-only token.
- **Release workflow with npm provenance.** `publish.yml` stages a GitHub release through npm trusted publishing (OIDC, no stored token) with `npm stage publish`, so it only reaches npm after a maintainer approves it with 2FA. It refuses a tag that does not match `package.json` and runs the tests and the package smoke test first.
- **Documentation.** A rewritten README (quickstart, secure defaults, options, errors, recipes, limits, migration from 1.x), `SECURITY.md` with private reporting and scope, and TSDoc on the client methods, the response and the error classes.
- **`signal` on HTTP/2.** An aborted `signal` closes the stream with `NGHTTP2_CANCEL` (the server sees it cancelled) and rejects the request; a signal that is already aborted rejects before any DNS lookup or connection. The signal also cuts the DNS and pool wait, combined with the `timeoutMs` budget through `AbortSignal.any`, so whichever fires first wins.
- **`socketTimeoutMs` on HTTP/2.** It used to be accepted and ignored. It is now a per-stream idle timeout: no bytes received for that long closes the stream and rejects with `UltraTonNetworkTimeoutError` (`UltraTon: Socket completely idle for <n>ms.`, as in HTTP/1). `0` disables it. The default of 10 s now applies to HTTP/2 requests too. A request body goes out in 64 KiB chunks and each one that gets through resets the timer, so a large upload that keeps moving is not idle; one the server stopped reading still times out. A stream may wait longer than the session's own 10 s idle timeout: that timeout only reaps a session with no request in flight (it used to destroy the session under a waiting stream and report `ECONNRESET`), so a `socketTimeoutMs` above 10 s, or `0`, is honoured. Instead, a session with a request in flight is checked for liveness: each idle period without a frame sends an HTTP/2 PING, and a PING still unanswered one idle period later means the connection is dead (a peer that vanished without closing it), so the session is destroyed and its requests reject with `UltraTonNetworkError` `ECONNRESET`. A live server that merely takes long to answer acknowledges the PING and is never cut, so a request with both `timeoutMs` and `socketTimeoutMs` at `0` is only cut when the connection is dead. A request given up because of `socketTimeoutMs` or `timeoutMs` also takes its session out of the pool (requests already on it finish, `close()` still destroys it), so the next request opens a fresh connection instead of reusing one that may be dead. A session that is already closing (after a GOAWAY, at the end of its lifespan, or retired that way) is never cut by the PING check: requests still on it finish under their own timeouts, so one request that timed out never resets other healthy streams on its session.

- **`json` option.** `post(url, { json })` (also `put`, `patch` and the other methods) serializes with `JSON.stringify` and sends `content-type: application/json` unless a `content-type` header is already set, by the request or by the client's default `headers` (a client default `application/vnd.api+json` is kept; the request's own header wins over both).
- **Happy Eyeballs over fully validated address sets.** Both engines now resolve every address of a hostname (`dns.lookup` with `all: true`) and let Node race them (`autoSelectFamily`, RFC 8305), so `localhost` resolving to `::1` and `127.0.0.1` reaches a server that only listens on IPv4 instead of failing with `ECONNREFUSED ::1`. Every address is checked against `permitReservedIps` before any connection: if one of them is reserved and not allowed, the whole request is rejected with the usual reserved-IP error (fail closed), so a DNS answer that mixes a public and a private address can never reach the private one. An allowlist must therefore cover all the addresses a name resolves to (`['127.0.0.0/8', '::1']`, or `['localhost']`). An empty DNS answer rejects with `UltraTon: Hostname resolution failed (ENODATA).`. HTTP/2 connects by name through a `lookup` that only returns the validated addresses and never resolves again, and a pooled session re-checks all of them on every reuse.
- **`auth` on HTTP/2.** The HTTP/2 engine never used the `auth` option. It now sends it as a Basic `authorization` header (an explicit `authorization` header wins), and a cross-origin redirect drops it like any other credential.

### Changed

- **`content-length` is always sent.** Every request with a body carries an exact `content-length` in bytes (multibyte strings included) in both engines, so there are no more chunked request bodies. A `content-length` or `transfer-encoding` you set yourself never overrides the real length: the real `content-length` is sent and `transfer-encoding` is dropped, in both engines. A request without a body drops a caller `content-length` too: it promised bytes that never came, so HTTP/1 waited out the socket idle timeout and HTTP/2 failed the stream.
- **Breaking: new response shape.** Responses are now `{ statusCode, ok, headers, data, json<T>(), text() }`:
  - `data` is still a `Buffer`, as in 1.x. There is no auto-parsing: `application/json` bodies are not parsed at request time, so a malformed JSON response resolves and only `json()` throws `UltraTonParseError` (with the original error as `cause`).
  - `json<T>()` is lazy, parses on every call whatever the `content-type` (so `application/problem+json` works), and strips `__proto__`, `constructor` and `prototype` keys at every depth, where 1.0.3's `json()` was a plain `JSON.parse`. A legitimate field named `constructor` or `prototype` silently disappears from the result. An empty body gives `{}`, where 1.0.3's `json()` threw `UltraTonParseError`.
  - New: `text()` (UTF-8) and `ok` (`true` for 200-299).
  - `statusCode` is always a `number`; it used to be typed `number | undefined`.
  - `headers` no longer contains HTTP/2 pseudo-headers such as `:status`. A response header named `__proto__` (HTTP/2 delivers it; Node's HTTP/1 parser drops it) is kept as an own data property instead of being lost or touching the object's prototype.
  - There is no size threshold: a body of any size within `maxBodySize` is available as `data` and parseable with `json()` (#3).
- **Breaking: loopback IP literals need a permit.** `http://127.0.0.1` and its numeric forms (such as `http://2130706433`) now require `permitReservedIps`. They used to work through the URL-parser escape hatch. `http://localhost` was already blocked via DNS before this change (#1, #3).
- **Plain http for every loopback name, and only to loopback addresses.** `parseSafeUrl` accepts `http:` for `localhost`, any `*.localhost` with non-empty labels (case-insensitive; `http://.localhost/` is refused), IPv4 literals in `127.0.0.0/8` and `[::1]`; it used to accept only `localhost` and `127.0.0.1`. A name is resolved like any other, so on every `http:` hop both engines also require every address it resolves to be loopback (`127.0.0.0/8`, `::1` or `::ffff:127.0.0.0/104`). Otherwise the request rejects before connecting with `SecureHttpError` `UltraTon: Plain http is only allowed to loopback addresses.` (no IP or hostname in the message), whatever `permitReservedIps` says, so a resolver that answers `api.localhost` with a public or LAN address never receives a cleartext request. This is on top of the reserved-IP policy: loopback addresses still need `permitReservedIps` to allow every one of them. Redirects from https to http stay rejected.
- **HTTP/2 drops hop-by-hop request headers.** `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, `http2-settings`, and `te` with any value other than `trailers`, have no meaning in HTTP/2 (RFC 9113 8.2.2) and Node refuses to send them, so setting one (per request or as a client default, a common copy from HTTP/1 configs) failed every request with `UltraTonNetworkError` `ERR_HTTP2_INVALID_CONNECTION_HEADERS`. They are now removed before the request is sent, with or without a body.
- **HTTP/2 no longer sends an IP literal as SNI.** The session connects to the origin by name with SNI set to the hostname; for an IP-literal host no `servername` is set (RFC 6066), which also removes Node's `DEP0123` warning. Certificates are still checked against the IP.
- **Breaking: uniform `(url, options)` methods.** `post`, `put` and `patch` no longer take the body as a second argument, in either engine. The payload goes in the options: `post(url, { json: { a: 1 } })` or `post(url, { body })`. A string, a `Buffer` or a `Uint8Array` is accepted as `body`; any other type throws a `TypeError` before connecting, and so does passing both `json` and `body`. Passing a body where the options go (`post(url, '{"a":1}')`) throws a `TypeError` that points at `{ json }` / `{ body }`.
- **Breaking: unknown options throw.** The per-request options are a closed list (`headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps`, `signal`, `auth`, `json`, `body`). Any other key, even with the value `undefined`, throws `TypeError: UltraTon: Unknown option '<key>'.` before any connection, where it used to be silently dropped. Common mistakes get a hint: `timeout` points at `timeoutMs`, `baseURL` and `prefixUrl` at `baseUrl`, `data` at `json` or `body`, `params`, `query` and `searchParams` at "put the query string in the URL", and `agent`, `ca` and `rejectUnauthorized` at the `tls` constructor option (`rejectUnauthorized` is not supported), and the constructor options `baseUrl`, `tls`, `http2` and `userAgent` passed to a request point at the constructor. Other keys get the list of valid options. A `method` option is rejected too: the HTTP method is the client method you call. `get` and `head` with `json` or `body` throw `UltraTon: GET and HEAD requests cannot have a body.`; `delete` and `options` may carry one in both engines.
- **Breaking: the constructor takes an options object.** `UltraTonClient` used to take no public arguments; it now takes `UltraTonClientOptions` (see Added). Anything else passed to it throws.
- **Behaviour: a `user-agent` header is always sent** (`ultraton/<version>` unless you set one); Node sends none by default, so servers and logs now see one.
- **Behaviour: no pool sharing between clients.** HTTP/2 clients used to share one module-wide session pool unless `isolatePool` was set, and HTTP/1 clients shared module-wide keep-alive agents. Every client now has its own, so connection reuse happens within a client only: reuse one client instead of creating one per request, and `close()` it when done.
- **Internal: module layout.** The engines moved to `src/engines/` (`http1.ts`, `http2.ts` and `http2-session-manager.ts`, which also fixes the old `http-session-mannager` file name), and `src/http-client.ts` is now the client facade. Not visible through the package entry.
- **Behaviour: network and TLS errors no longer contain the address.** Raw Node errors such as `connect ECONNREFUSED 10.0.0.5:8080` (HTTP/1) and the `UltraTon stream error: ...` / `Failed to establish HTTP/2 connection: ...` wrappers (HTTP/2) are replaced by `UltraTonNetworkError` with the message `UltraTon: Connection failed (<code>).` or `UltraTon: TLS handshake failed (<code>).`. The IP and port are only reachable through `error.cause`, so do not log `cause` to untrusted sinks. `AbortError` and existing `SecureHttpError` subclasses are not wrapped.
- **Breaking: error classes and codes.** `UltraTonNetworkTimeoutError` now extends `UltraTonNetworkError` (a timeout is a network failure), so a `catch` that tests `instanceof UltraTonNetworkError` before `instanceof UltraTonNetworkTimeoutError` now takes timeouts too: test the timeout first. DNS failures (`ENOTFOUND`, `EAI_AGAIN`, `ENODATA`, `EBADRESP`, ...) reject with `UltraTonNetworkError` (still a `SecureHttpError`) whose `code` is the resolver's code; the message is unchanged (`UltraTon: Hostname resolution failed (<code>).`, no hostname). Policy rejections stay `SecureHttpError` and now carry a stable `code`: `ERR_ULTRATON_RESERVED_IP` (reserved IP not allowed by `permitReservedIps`), `ERR_ULTRATON_PLAIN_HTTP` (plain http to a non-loopback host or address) and `ERR_ULTRATON_DOWNGRADE` (redirect from https to http). `baseUrl` escapes and relative-path errors stay `TypeError`.
- **Plain http to a public host says what to do.** `http://example.com` now throws `SecureHttpError` `UltraTon: Plain http is only allowed for loopback hosts; use https.` (code `ERR_ULTRATON_PLAIN_HTTP`) instead of `UltraTon: Unsupported protocol "http:"`, for request URLs, redirect targets and `baseUrl`. Other schemes (`ftp:`, `file:`, ...) still get `Unsupported protocol`.
- **Breaking: out-of-range numbers throw.** `timeoutMs`, `socketTimeoutMs` and `maxBodySize` must be integers from 0 to 2147483647 and `maxRedirects` an integer from 0 to 20, in the constructor and per request. A negative, fractional or too large value (`timeoutMs: -1`, `maxBodySize: 2 ** 40`, `maxRedirects: 50`) throws `TypeError: UltraTon: Expected '<option>' to be an integer from 0 to <max>, received <value>.` where it used to fall back silently to the default (or, for `maxRedirects`, be capped at 20). `0` keeps its meaning: no timeout for `timeoutMs` and `socketTimeoutMs`, no redirects for `maxRedirects`.
- **Breaking: `headers` must be a plain object.** In the constructor and per request, a `Headers` or `Map` instance (or any class instance) throws `TypeError: UltraTon: Expected 'headers' to be a plain object, received a Headers instance; pass a plain object, e.g. Object.fromEntries(headers).` It used to be sent as no headers at all, silently dropping an `authorization`.
- **Breaking: `signal` must be an `AbortSignal`.** Anything else (`{}`, `null`, a look-alike object) throws `TypeError: UltraTon: Expected 'signal' to be an AbortSignal, received <type>.` before connecting, instead of an unrelated `TypeError` from deep inside the engine.
- **Behaviour: mid-body failures.** Any failure while reading a response body now surfaces as `SecureHttpError`: socket errors and early ends as `UltraTonNetworkError` (`code` `ECONNRESET` when the stream just ends), a caller abort as the signal's reason (see the abort entry below).
- **HTTP/2 no longer resolves a lost response.** A stream that ends without `:status`, or that closes or is reset before a clean end (destroyed socket, RST_STREAM), rejects with `UltraTonNetworkError` (`ECONNRESET`) instead of resolving with `statusCode: undefined` or a truncated body. A raw `'error'` event could previously leak through (#2).
- **3xx responses are the same on both engines.** A redirect that is not followed (`maxRedirects: 0`, the default) resolves like any other response: numeric `statusCode`, `ok: false`, its `Location` in `headers` and its body in `data`, held to `maxBodySize`. HTTP/1 used to return an empty `data` whenever the 3xx carried a `Location`. A redirect that is followed is never read or buffered: HTTP/2 used to buffer it and could fail a followed redirect with `UltraTonMemoryError` when its body exceeded `maxBodySize`; it now ends that stream at once.
- **Incomplete responses reject in both engines.** A response whose body has fewer or more bytes than its `content-length` rejects with `UltraTonNetworkError` `UltraTon: Connection failed (ECONNRESET).` (`code` `ECONNRESET`), never a truncated success. HEAD, 1xx, 204 and 304 responses are exempt. On HTTP/2 this replaces the `ERR_HTTP2_STREAM_ERROR` code nghttp2 produced for a short body (the original error is the `cause`).
- **HTTP/2 GOAWAY drains.** A graceful GOAWAY used to destroy the session, which cut off the streams it covered and could resolve one with a truncated body. The session now leaves the pool (the next request opens a new one) and closes gracefully, so in-flight streams finish; `close()` still destroys it. A session that reaches its 30-minute lifespan is retired the same way; `close()` used to miss such a session, leaving its streams running after the client was closed.
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
