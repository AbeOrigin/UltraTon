# UltraTon threat model

This document says what UltraTon defends, against whom, how, and what it deliberately leaves to you. It is the reference for [SECURITY.md](SECURITY.md) (what counts as a vulnerability) and for anyone auditing the code.

## What UltraTon protects

UltraTon is built for code that sends requests to URLs it does not fully control: webhooks, link previews, integrations, URLs from users. The assets it protects:

1. **The network position of the process.** Internal services, cloud metadata endpoints (`169.254.169.254`), loopback admin ports, and private ranges must not be reachable through a URL an outsider chose, unless the operator allowed them.
2. **The process's resources.** Memory, CPU, sockets and time must stay bounded whatever a server sends back.
3. **Credentials in requests.** `authorization`, `cookie`, `proxy-authorization` and `auth` must not reach a different origin than the one they were meant for.
4. **The integrity of what the caller receives.** A truncated or malformed response must never look like a complete, valid one. A response must never pollute the caller's objects.
5. **Information about the internal network.** Error messages must not reveal internal IPs or hostnames to whoever supplied the URL.

## Adversaries

| | Who | Controls |
|---|---|---|
| **A1** | The author of the URL | The URL itself (scheme, host spelling, path, query); the DNS of a domain they own; the server it points to. |
| **A2** | A hostile or broken server | Every byte of the response: status, headers, redirects, `Retry-After`, body size and encoding, timing (slowloris), HTTP/2 frames (resets, GOAWAY, PING). |
| **A3** | DNS between the client and the target | Answers that change between lookups (rebinding), mixed public and private answers. |
| **A4** | A configured proxy | The tunnel, when `proxy` is set: its responses to CONNECT or SOCKS5, and its own DNS when `resolve: 'proxy'`. |
| **A5** | The supply chain | Dependencies, build and publish pipeline. |

**Trusted:**
- **The developer who configures the client.** Options are configuration, not input, but mistakes in them throw instead of being ignored.
- **The operating system resolver.**
- **Node.js itself** (its TLS stack and CA store, llhttp, nghttp2). On a release that lacks one of Node's own security fixes, the feature that fix covers is narrowed rather than trusted: no Brotli, no HTTP/1.1 keep-alive (see [SECURITY.md](SECURITY.md)).
- **The operator's choice** of `permitReservedIps` and `proxy`.

## Defenses

| Threat | Defense | Where | Tests |
|---|---|---|---|
| A1: a reserved IP in any spelling (decimal, hex, octal, IPv4-mapped and IPv4-compatible IPv6, NAT64, 6to4, Teredo) | WHATWG URL normalization, then `assertAllowedIp` against a `BlockList` of reserved ranges; the IPv6 forms that embed an IPv4 are judged by that IPv4 (a Teredo address by both its server and its client IPv4). In an allowlist, an IPv6 entry never covers an IPv4 address, native or embedded: an IPv4 in the low 32 bits (mapped, compatible, NAT64) is judged only by IPv4 entries, and a 6to4 or Teredo address only by IPv6 entries | `src/helpers/url-parser.ts`, `src/security/dns-pinner.ts` | `dns-pinner`, `http2-security` |
| A1/A3: a name that resolves to a reserved IP, or to a mix | `resolveAndPinAll`: **every** address is validated; one bad address fails the whole lookup | `src/security/dns-pinner.ts` | `dns-pinner`, `happy-eyeballs` |
| A3: DNS rebinding | The socket connects only to the validated addresses (`pinnedLookup`); nothing resolves twice. A pooled HTTP/2 session's pinned addresses are checked again against the caller's policy on every reuse (no new lookup) | `dns-pinner.ts`, `http1.ts`, `http2-session-manager.ts` | `dns-pinner`, `http2-security`, `retry` (rebinding between attempts) |
| A1/A2: redirects to internal targets, downgrade to http | Each hop is parsed and validated again; https→http is rejected; credentials are dropped across origins; redirects are off by default | `src/engines/http1.ts`, `src/engines/http2.ts` | `redirect`, `ssrf-redirect-integration` |
| A1: plain http to the outside | `http:` only to loopback names that resolve to loopback addresses | `url-parser.ts`, `dns-pinner.ts` | `loopback-http` |
| A1: escaping `baseUrl` with the request path | The resolved path is judged the way lenient servers read it (repeated percent-decoding, NFKC, `..;/`, backslashes, fullwidth dots). Followed redirects are not bound to `baseUrl` (see residual risks) | `src/http-client.ts` | `client-facade` |
| A1: header injection | CRLF/NUL and HTTP/2 pseudo-headers in headers throw before connecting | `src/helpers/request-options.ts` | `request-headers` |
| A2: memory exhaustion, decompression bombs | `maxBodySize` on the wire and on decoded bytes; at most 2 content-encodings (Brotli's own working memory is a residual risk) | `src/helpers/body-reader.ts` | `decompress`, `http2-memory-shield` |
| A2: HTTP/2 server push | `enablePush: false` on every session: a `PUSH_PROMISE` is a protocol error that fails the request, so a server cannot park streams nobody reads (up to 200 × the 1 MiB window) in the process | `src/engines/http2-session-manager.ts` | `http2-security`, `http2-session-limits` |
| A2: TLS downgrade | TLS 1.2 is the floor of every connection UltraTon opens (direct, through a tunnel, to a TLS proxy, and in the secure agents whatever the library asks), set per connection, not inherited from `tls.DEFAULT_MIN_VERSION` or `--tls-min-v1.0` | engines, `src/proxy/tunnel.ts`, `src/agents.ts` | `tls-min-version`, `http2-session-limits` |
| A2 through Node: a release without one of Node's own security fixes | The feature the fix covers is turned off below the first fixed release of the line: `br` is neither requested nor decoded, HTTP/1.1 sockets are not reused; a prerelease or an unknown version counts as unfixed | `src/helpers/node-release.ts`, `body-reader.ts`, `keep-alive.ts` | `decompress`, `keep-alive`, `keepalive-guard` |
| A2: hangs, slowloris | `timeoutMs` (one budget for DNS, every hop, every retry and a buffered body, however slowly it drips), `socketTimeoutMs` idle timer, HTTP/2 PING liveness. The body of `stream()` is guarded by the idle timer alone: it may legitimately outlive the budget | engines, `src/helpers/retry.ts` | `abort-and-idle`, `http2-session-lifetime`, `retry` |
| A2: truncated or malformed responses | content-length checked against wire bytes; a reset, GOAWAY or abort mid-body is an error, never a short success | engines, `src/helpers/response.ts` | `response-shape`, `http2-parsing-fix` |
| A2: prototype pollution | `json()` strips `__proto__`, `constructor`, `prototype`; options are read as own properties only | `src/helpers/response.ts`, `request-options.ts` | `json-parsing-fix`, pollution tests in several files |
| A2: retry abuse (`Retry-After` loops, 503 floods) | Retries off by default; at most 10; a `Retry-After` above `maxDelayMs` or the budget is not waited; only idempotent methods unless the caller lists others in `retry.methods` | `src/helpers/retry.ts` | `retry` |
| A4: a proxy redirecting the connection | CONNECT/SOCKS5 to the **validated IP**, never the name (`resolve: 'local'`); TLS to the target through the tunnel with the certificate checked against the target (its IP for an IP literal, never the proxy's name); strict, bounded parsing of the proxy's answers (16 KiB, 10 s per address) | `src/proxy/tunnel.ts` (handshakes), `src/engines/http1.ts` and `http2-session-manager.ts` (TLS over the tunnel) | `proxy` |
| A1 via third-party clients | `createSecureAgents()` validates and pins every new socket, refuses forward-proxy requests, ignores the library's `lookup`, forces TLS verification | `src/agents.ts` | `secure-agents`, `compat/` |
| A1: information leaks | Error messages carry codes, never IPs or hostnames; the original error is in `cause` | `src/errors.ts` | assertions across the suite |
| A5: supply chain | Zero runtime dependencies; actions pinned by SHA; npm trusted publishing (OIDC, no token) with provenance and staged publishing approved with 2FA; Dependabot with a 14-day cooldown; OpenSSF Scorecard | `.github/`, `package.json` | CI |

## Residual risks and non-goals

These are accepted and documented. Reports about them are not vulnerabilities (see SECURITY.md):

- **What the operator allows is reachable.** `permitReservedIps: true`, broad CIDRs, and hostname entries (which trust whatever that name resolves to) all mean what they say. Redirects into allowed ranges are followed.
- **Redirects are not bound to `baseUrl`.** A followed redirect may go to another host or path (every hop is still checked against the SSRF policy). Redirects are off by default.
- **Brotli can use up to 16 MiB of working memory per layer**, whatever `maxBodySize` is (zlib has no setting to lower it). The decoded output is still capped by `maxBodySize`.
- **`resolve: 'proxy'` and `socks5h:` hand name resolution to the proxy.** SSRF protection for hostnames then depends on the proxy. Reserved IP literals are still rejected.
- **SOCKS5 credentials travel in cleartext to the proxy**, as the protocol has no encryption.
- **DNS lookups cannot be cancelled.** A timeout rejects the request on time, but `getaddrinfo` keeps a threadpool thread until the resolver answers.
- **`error.cause` keeps Node's original error**, which may contain addresses: do not send it to untrusted sinks.
- **Error codes tell a blocked name from an unknown one.** A name that resolves to a reserved address fails with `ERR_ULTRATON_RESERVED_IP`, one that does not resolve with `ENOTFOUND`. Whoever chose the URL and sees the code learns that an internal name exists, never what it resolves to. Any client that validates has this oracle; map both to one message for end users.
- **The secure agents protect the connection only.** Body limits, timeouts and header validation stay with the library using them. Some library modes skip any agent: axios with a proxy for `https:` URLs, axios with `httpVersion: 2`, got with `createConnection` or `h2session`. The README makes `proxy: false` mandatory and forbids those modes. A failure to reach an *allowed* address surfaces Node's own error, which may name it.
- **Request bodies have no size limit by default.** The caller controls what it sends: `maxRequestBodySize` caps it when the body comes from somewhere else (a stream that might not end). A `File` or `Blob` body is read whole into memory; a stream body is not. A stream body is never retried and never replayed on a 307/308, because it can only be read once.
- **`json()` drops legitimate fields** named `__proto__`, `constructor` or `prototype`.
- **Environment proxies (`HTTP_PROXY`) are never used.** That is a choice, not a gap: a shared, environment-driven proxy could bypass the per-client policy.

## For auditors

**Highest-value targets, in order:**
1. `src/security/dns-pinner.ts`: the reserved-range list, allowlist compilation (IPv4/IPv6 separation, embedded IPv4), `resolveAndPinAll`.
2. `src/http-client.ts`: `resolveAgainstBase` and `assertNoDecodedTraversal` (`baseUrl` escapes).
3. `src/proxy/tunnel.ts`: the CONNECT and SOCKS5 parsers against a hostile proxy, and `ipv6Bytes`, which must encode exactly the address that was validated.
4. `src/agents.ts`: every way a calling library can make the agent connect somewhere unvalidated.
5. `src/engines/http2-session-manager.ts` and `src/engines/http2.ts`: session pooling and reuse across policies, GOAWAY and refused streams, PING liveness.
6. `src/helpers/body-reader.ts`: the limits on decoded bytes, truncation detection.

**Running the tests:** `npm ci && npm test` (Node ≥ 22.12). The property tests in `__tests__/fuzz/` cover the `baseUrl` check, IPv6 parsing, header validation and both proxy handshakes; run more cases with `FUZZ_RUNS=5000` and another seed with `FUZZ_SEED=<n>`. The suite preloads a guard that refuses any connection outside loopback, so nothing leaves the machine. `compat/` has the third-party client tests (see its README).

**Reporting:** privately, as described in [SECURITY.md](SECURITY.md).
