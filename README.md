# UltraTon

> Ultra safe HTTP client for critical environments in Node.js

UltraTon is an enterprise-grade, highly secure HTTP client for Node.js written in TypeScript. It is built strictly on top of `node:https` with a core focus on absolute security for high-risk environments. It has **zero external dependencies** and is designed to mitigate Server-Side Request Forgery (SSRF), Out-Of-Memory (OOM) attacks, and hanging connections (e.g., Slowloris).

## Features

- **Zero Dependencies**: Built entirely on native Node.js APIs (`node:https`). Assures a reduced attack surface.
- **Strict Protocol Enforcement**: Only connects to secure endpoints (HTTPS).
- **Memory Shield**: Implements strict constraints on response payload sizes, providing native protection against memory exhaustion attacks. Optimized using V8 zero-GC allocation controls.
- **Network Control**: Absolute, safe-integer bounded timeouts on connections that explicitly reject floating promises, completely neutralizing Slowloris and TCP hung-socket attacks.
- **Protocol Purism (CRLF & Pollution Defense)**: Actively downcases and filters headers at the pipeline boundary against `\r\n\0`, rendering HTTP request smuggling and prototype pollution void.
- **Anti-SSRF & DNS Rebinding Mitigation**: Deep Dual-Stack (IPv4 & IPv6) IP validation neutralizing localhost SSRF, internal metadata attacks, and split-second DNS Rebinding using a zero-dependency native resolver interceptor. Combined with default-deny redirect policies and secure credential stripping.
- **Sandbox Isolation**: Locked constructor implementations physically enforce inner requests to remain native, neutralizing rogue transport injection and monkey-patching.
- **First-class TypeScript Support**: Written in TypeScript with strict typings and security-focused interfaces.

## Installation

Since UltraTon is designed for enterprise usage and has zero dependencies, you can install it seamlessly:

```bash
npm install ultraton
```

*(Note: Requires Node.js >= 24.14.0)*

## Usage

```typescript
import { UltraTonClient } from 'ultraton';

const client = new UltraTonClient();

async function run() {
    try {
        const response = await client.get<{ items: string[] }>('https://example.com/api/data', {
            headers: {
                'Accept': 'application/json'
            }
        });

        console.log(`Status: ${response.statusCode} (ok: ${response.ok})`);
        // `data` is always the raw Buffer. `json()` and `text()` decode it on demand.
        const { items } = response.json();
        console.log(items, response.text().length, response.data.length);
    } catch (error) {
        console.error('Request failed:', error);
    }
}

run();
```

## Breaking changes (unreleased)

- **Response shape.** Responses expose `statusCode: number` (never `undefined`), `ok` (200-299), `headers` (no HTTP/2 pseudo-headers), `data: Buffer` (as in 1.x, never auto-parsed), `json<T>()` and `text()`. `json()` parses lazily on every call regardless of content-type, strips `__proto__`, `constructor` and `prototype` keys at every depth, returns `{}` for an empty body (1.0.3 threw) and throws `UltraTonParseError` (with `cause`) on invalid JSON. A malformed JSON response no longer rejects the request itself.
- **The `timeout` option is removed.** It never had any effect, and it now throws. Use `timeoutMs` (absolute time budget) or `socketTimeoutMs` (socket idle time).
- **Methods are `(url, options)`.** Send a payload with `post(url, { json: { a: 1 } })` or `post(url, { body })` (`string`, `Buffer` or `Uint8Array`), never both. Bodies always go out with a `content-length`, never chunked.
- **Unknown options throw.** An option outside the documented list (`headers`, `timeoutMs`, `socketTimeoutMs`, `maxBodySize`, `maxRedirects`, `permitReservedIps`, `signal`, `auth`, `json`, `body`) throws a `TypeError`, with a hint for the usual suspects (`timeout`, `params`, `data`, `rejectUnauthorized`...), instead of being silently ignored.
- **Loopback names need `permitReservedIps`.** Plain HTTP is accepted for every loopback name (`localhost`, `*.localhost`, `127.0.0.0/8` literals and `[::1]`) and only ever reaches loopback addresses: if such a name resolves to anything else, the request is rejected (`UltraTon: Plain http is only allowed to loopback addresses.`). Loopback addresses are reserved, so the SSRF guard also rejects them unless you opt in. `localhost` usually resolves to both `::1` and `127.0.0.1`, and every address must be allowed: use `true`, `['localhost']`, or a list covering both, such as `['127.0.0.0/8', '::1']`.

## Security Goals & Roadmap

UltraTon is developed in methodical security-focused sprints:

1. **Core Engine**: Asynchronous wrapper for `node:https` and manual buffer management.
2. **Memory Shield**: Strict `MaxBodySize` limits and immediate socket destruction upon overflow.
3. **Network Control**: Absolute timeouts for connection and total read time (Slowloris protection).
4. **Anti-SSRF**: Default-deny redirect policies and sensitive header stripping across domain hops.
5. **DX & Tooling**: Strict TypeScript generics, secure error handling, and final package structuring.
6. **Hardening**: CRLF Injection defenses, strict integer boundary verification, floating promise execution prevention, and zero GC allocation buffering.
7. **DX & Composability**: Advanced generics, robust Promise-based rejection interfaces, and structural modularity.
8. **Rebinding & Deep SSRF Prevention**: Native `node:dns` interception to block IPv4, IPv6, and IPv4-Mapped internal IP addresses with resilient Dual-Stack resolution mapping.

## License

MIT
