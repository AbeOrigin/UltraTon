# UltraTon Roadmap

This document meticulously tracks our progress and architectural goals. We strictly enforce a ticket-by-ticket sequence. Do not proceed to the next sprint until the current sprint passes security review.

## 🟩 Sprint 1: Core Engine (Completed)
- [x] Abstract asynchronous wrapper for `node:https`.
- [x] Manual buffer chunk accumulation.
- [x] Native TypeScript typings and `.test.ts` suite via Node `--experimental-strip-types`.
- [x] GitHub Actions CI automated pipeline.

## 🟦 Sprint 2: Memory Shield (Completed)
- [x] **Objective:** Mitigate Out-of-Memory (OOM) attacks from infinite payloads.
- [x] **Protocol Lockdown:** Strip all plain text (`node:http`) references.
- [x] **The Kill Switch:** Implement `maxBodySize` parameter (default: 2MB).
- [x] **Resource Release:** Actively call `res.destroy()` and reject the promise upon memory overflow.
- [x] **Firewall:** Implement strict runtime type validation whitelist (`buildSafeRequestOptions`) to prevent socket injection and property poisoning.

## 🟨 Sprint 3: Network Control (Completed)
- [x] **Objective:** Absolute Slowloris and connection-drop protection.
- [x] Implement strict socket timeouts (`socketTimeoutMs`).
- [x] Enforce an execution timeout ceiling (`timeoutMs`) across the entire request sequence.
- [x] Guarantee file descriptor and listener cleanup on request abort.

## 🟧 Sprint 3.5: Clean Slate Architecture (Completed)
- [x] **Objective:** Refactor error handling, types, and mutability to strictly meet `ts-coding-standards.md`.
- [x] Apply deep `readonly` locks to API boundaries instead of `Object.freeze()`.
- [x] Refactor unhandled stream errors to pipe directly into the native Promise `reject()`.
- [x] Replace unstructured `.catch()` traps by extending the new root `SecureHttpError` layer.
- [x] Retain V8 logging efficiency by maintaining standard `private` context modifiers over stringy `#` closures.

## 🟪 Sprint 4: Anti-SSRF (Completed)
- [x] **Objective:** Prevent Server-Side Request Forgery logic bypasses.
- [x] Safe default-deny redirect handling (`maxRedirects`).
- [x] Strip sensitive headers (Cookies, Authorization tokens) upon domain-hopping redirects.

## 🟩 Sprint 5: DX & Architecture Refactoring (Completed)
- [x] **Objective:** Developer Experience tooling, strict TypeScript, and Engine Modularization.
- [x] Refactor `_request` to reduce cyclomatic complexity and abstract stream buffering (Iterative Loop).
- [x] Lexically bind helper methods (`_executeSingleNetworkHop`, `_consumeResponseBuffer`) to avoid `this` loss.
- [x] Secure error subclasses (e.g., `UltraTonMemoryError`, `UltraTonNetworkError`).
- [x] Advanced generic injections for JSON response parsing.

## ✅ Sprint 6: Post-MVP Security Hardening
- [x] **Objective:** Address edge-case vulnerabilities and engine optimizations identified during MVP red-teaming.
- [x] Implement strict header key/value validation to prevent CRLF injection and Prototype Pollution.
- [x] Enforce safe integer boundaries (`Number.isInteger`, `>= 0`, `< 2147483647`) to prevent 32-bit `setTimeout` overflow bugs.
- [x] Optimize `Buffer.concat(chunks, currentBodySize)` to eliminate V8 double-iteration memory and GC overhead.
- [x] Handle mute stream events (e.g., `'aborted'`, `'close'`) to guarantee floating promises are resolved/rejected.
- [x] Lock down the class constructor to prevent untrusted `node:https` transport injections.

## 🚧 Sprint 7: Advanced Engine Resiliency
- [ ] **Objective:** Address fundamental Node.js boundaries requiring complex mitigation strategies.
- [ ] **DNS Rebinding Prevention:** Investigate custom caching resolver to lock host IPs across the request lifecycle to neutralize split-second SSRF DNS rebinding.