# 🗺️ Architecture Roadmap: UltraTon2 (HTTP/2)

This roadmap details the implementation of the native HTTP/2 engine for UltraTon, prioritizing Developer Experience (DX) through a hidden connection manager, and applying strict network defenses against vulnerabilities like SSRF, TOCTOU, and L7 OOM.

---

## 🏗️ Phase 1: The Engine and the Hidden Pool
*Objective: Build the core of the client guaranteeing efficient multiplexing without exposing state management to the user.*

### Sprint 1: The Session Manager (Connection Pool)
- [x] Create the abstract `Http2SessionManager` class.
- [x] Implement an in-memory dictionary (`Map<string, ClientHttp2Session>`) indexed by `hostname`.
- [x] Routing logic: Resolve `http2.connect()` if the session does not exist, or return the active session if it is already in the pool.

### Sprint 2: Transmission and Pseudo-Headers (The Core)
- [x] Implement the main entry point `UltraTon2.request(url, options)`.
- [x] Develop the adapter from traditional headers to Pseudo-Headers (`:method`, `:path`, `:authority`).
- [x] Execute `session.request()`, collect chunks via `stream.on('data')`, and resolve the response in a format compatible with UltraTon 1.0.

### Sprint 3: The "Garbage Collector" (Preventing Memory Leaks)
- [x] Implement **Idle Timeout** (e.g., 10 seconds) per session.
- [x] Purge logic: Execute `session.destroy()` and clear the `Map` if the session registers no active streams within the idle period.
- [x] Native event handling: Automatically purge sessions upon receiving `goaway` or `error` events from the server.

### Sprint 4: Cross-Domain SSRF (Secure Redirects)
- [x] Implement strict tracking of 301/302/307 status codes.
- [x] Execute security sanitization upon detecting a domain hop (strip `authorization`, `cookie`, `proxy-authorization`).
- [x] Reconnection logic: Request a new tunnel to the destination domain from the Session Manager before opening the new stream.

---

## 🛡️ Phase 2: Defenses and Attack Vectors (Red Team)
*Objective: Shield the HTTP/2 engine against denial-of-service attacks, state manipulation, and resource exhaustion.*

### Sprint 5: Zero-Cache Atomic DNS Pinning
*Mitigation: DNS Rebinding (TOCTOU)*
- [ ] Inject the custom `lookup` function (from `dns-pinner.ts`) into the `http2.connect()` options.
- [ ] Implement **Forced Rotation (Max Connection Life)**: Set an absolute lifespan limit per session (e.g., 30 minutes).
- [ ] Upon Max Life expiration, block new streams, allow active ones to drain, and destroy the socket to force a new DNS validation on the next request.

### Sprint 6: Surgical Memory Shield
*Mitigation: L7 OOM (Infinite Payloads)*
- [ ] Migrate the `maxBodySize` logic to the streams environment.
- [ ] Implement the surgical "kill switch": If the sum of chunks exceeds the limit, isolate and kill only the affected stream using `stream.close(http2.constants.NGHTTP2_CANCEL)`.
- [ ] Ensure the global socket (`session`) survives to avoid interrupting the rest of the multiplexed streams.

### Sprint 7: Native Configuration Hardening
*Mitigation: HPACK Bombs and Ping/Settings Floods*
- [ ] Enforce paranoid limits during session initialization (`http2.connect`).
- [ ] Limit the size and quantity of headers (`maxHeaderListSize`, `maxHeaderListPairs`) to prevent RAM exhaustion when decompressing HPACK.
- [ ] Limit the global memory footprint per tunnel (`maxSessionMemory`).

### Sprint 8: App-Level Backpressure
*Mitigation: Concurrency Denial (Inverted Rapid Reset)*
- [ ] Dynamically read the remote server's configurations (`session.remoteSettings.maxConcurrentStreams`).
- [ ] Implement an internal queuing system: If user requests exceed the server's concurrency limit, hold local promises in a queue and release them sequentially as streams finish.