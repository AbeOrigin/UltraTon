# UltraTon

> Ultra safe HTTP client for critical environments in Node.js

UltraTon is an enterprise-grade, highly secure HTTP client for Node.js written in TypeScript. It is built strictly on top of `node:https` with a core focus on absolute security for high-risk environments. It has **zero external dependencies** and is designed to mitigate Server-Side Request Forgery (SSRF), Out-Of-Memory (OOM) attacks, and hanging connections (e.g., Slowloris).

## Features

- **Zero Dependencies**: Built entirely on native Node.js APIs (`node:https`). Assures a reduced attack surface.
- **Strict Protocol Enforcement**: Only connects to secure endpoints (HTTPS).
- **Memory Shield**: Implements strict constraints on response payload sizes, providing native protection against memory exhaustion attacks. Optimized using V8 zero-GC allocation controls.
- **Network Control**: Absolute, safe-integer bounded timeouts on connections that explicitly reject floating promises, completely neutralizing Slowloris and TCP hung-socket attacks.
- **Protocol Purism (CRLF & Pollution Defense)**: Actively downcases and filters headers at the pipeline boundary against `\r\n\0`, rendering HTTP request smuggling and prototype pollution void.
- **Anti-SSRF**: Default-deny redirect policies and secure credential stripping.
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
        const response = await client.get('https://example.com/api/data', {
            headers: {
                'Accept': 'application/json'
            }
        });
        
        console.log(`Status: ${response.statusCode}`);
        console.log(response.data.toString());
    } catch (error) {
        console.error('Request failed:', error);
    }
}

run();
```

## Security Goals & Roadmap

UltraTon is developed in methodical security-focused sprints:

1. **Core Engine**: Asynchronous wrapper for `node:https` and manual buffer management.
2. **Memory Shield**: Strict `MaxBodySize` limits and immediate socket destruction upon overflow.
3. **Network Control**: Absolute timeouts for connection and total read time (Slowloris protection).
4. **Anti-SSRF**: Default-deny redirect policies and sensitive header stripping across domain hops.
5. **DX & Tooling**: Strict TypeScript generics, secure error handling, and final package structuring.
6. **Hardening**: CRLF Injection defenses, strict integer boundary verification, floating promise execution prevention, and zero GC allocation buffering.

## License

MIT
