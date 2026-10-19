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

        console.log(`Status: ${response.statusCode}`);
        // application/json responses arrive already parsed; any other content type is a Buffer.
        console.log(response.body);
    } catch (error) {
        console.error('Request failed:', error);
    }
}

run();
```

## Breaking changes (unreleased)

- **`data` is now `body`.** Responses expose `body: T | Buffer` instead of `data`, which no longer exists. A response with an `application/json` content type is parsed automatically (`__proto__`, `constructor` and `prototype` keys are stripped), and an invalid JSON payload with that content type rejects with `UltraTonParseError`. Any other content type, and any JSON payload over 5MB, is returned as a raw `Buffer`.
- **The `timeout` option is removed.** It never had any effect. Use `timeoutMs` (absolute time budget) or `socketTimeoutMs` (socket idle time).
- **`http://127.0.0.1` and `http://localhost` now need `permitReservedIps: true`.** Plain HTTP is still accepted for them, but they are reserved addresses, so the SSRF guard rejects them unless you opt in.

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
