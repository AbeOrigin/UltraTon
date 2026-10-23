# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.x | No. Upgrade to 2.x: 1.x has known SSRF bypasses. |

### Node.js releases

Run UltraTon on a Node.js release with the October 2026 security fixes: **22.23.4, 24.22.1, 26.12.1 or later**. Node's own fixes are what protect you; UltraTon only narrows the exposure on older releases:

- **CVE-2026-111497, Brotli decoder out-of-bounds write (remote code execution):** a client decoding responses from servers it does not control is exposed. On an unpatched release, UltraTon neither requests nor decodes `br`, and a `br` body comes back raw.
- **CVE-2026-106069, -106072, -105483, TLS hostname checks with non-canonical IP addresses:** the client checks the certificate against the host of the URL, which the URL parser canonicalizes, and never against a `host` header. `createSecureAgents()` refuses a host or TLS name given as an IPv4 in a non-canonical form (`ERR_ULTRATON_NON_CANONICAL_IP`).
- **CVE-2026-105481, a keep-alive socket can take a response written before the request:** on an unpatched release UltraTon turns HTTP/1.1 keep-alive off, so a socket serves one request and is then closed and never sits idle in a pool to be poisoned (a new TCP/TLS connection per request until you upgrade Node). The agents of `createSecureAgents()` also refuse to have `keepAlive` turned back on, or a `maxSockets` or `maxTotalSockets` limit set, there (`ERR_ULTRATON_AGENT_KEEP_ALIVE`): with a limit, Node hands a waiting request the socket a response just ended on, keep-alive or not. Pools are per origin, so only the server you are talking to could have done it.
- **The eMudhra intermediate CA compromise:** fixed by the CA store of the patched releases, which UltraTon uses unless you pass your own `tls.ca`.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
[Report a vulnerability](https://github.com/AbeOrigin/UltraTon/security/advisories/new) (the Security tab → "Report a vulnerability").

Include the UltraTon and Node.js versions, the options you used, and a minimal reproduction. A local server is ideal, never a third-party host.

You can expect an acknowledgement within 7 days. A fix and an advisory follow once the issue is confirmed, with credit to you unless you prefer otherwise.

## Scope

UltraTon's job is to keep a request from reaching somewhere it should not, and to keep a response from exhausting the process. These count as vulnerabilities:

- **Reaching a reserved address with the default policy, or outside an allowlist.** This covers IP-literal spellings, DNS answers, rebinding and redirects.
- **Plain `http:` reaching a non-loopback address**, or a redirect from https to http being followed.
- **A credential (`authorization`, `cookie`, `proxy-authorization`, `auth`) sent to another origin** after a redirect.
- **A request path escaping `baseUrl`.**
- **Header injection**, meaning CRLF/NUL or pseudo-headers reaching the wire.
- **Resource exhaustion**: memory beyond `maxBodySize`, a hang beyond `timeoutMs`/`socketTimeoutMs`, or superlinear CPU on attacker-controlled input.
- **A truncated response resolving as if it were complete.**
- **An error message that leaks the target's IP or hostname.**
- **Prototype pollution through options, headers or `json()`.**
- **A proxy receiving a hostname, or an unvalidated address,** with `resolve: 'local'` (the default), or the target's certificate checked against anything but the target.
- **Proxy credentials (`proxy.auth`) reaching a target**, or retries going past `retry.limit`, the `timeoutMs` budget, or onto a non-idempotent method that was not opted in.
- **`createSecureAgents()` connecting to an address it did not validate**, when used as the README describes (with axios: `proxy: false`, no `httpVersion: 2`).

These are out of scope, because they are documented behaviour (see the README section "Limits and things to know" and [THREAT_MODEL.md](THREAT_MODEL.md)):

- what a client configured with `permitReservedIps: true`, or a broad allowlist, can reach;
- redirects into allowlisted ranges;
- environment proxies being ignored;
- Brotli's working memory (up to 16 MiB per layer) beyond `maxBodySize`; the decoded output is still capped;
- redirects not being bound to `baseUrl`;
- name resolution by the proxy with `resolve: 'proxy'` or `socks5h:` (SSRF protection for hostnames is then the proxy's), and SOCKS5 credentials travelling in cleartext;
- library modes that skip any agent (axios with a proxy for `https:` or `httpVersion: 2`, got with `createConnection` or `h2session`), and the limits the secure agents leave to the library (body size, timeouts, headers);
- DNS lookups that keep running after a timeout;
- the contents of `error.cause`.

## Release integrity

Releases are built and staged by GitHub Actions with npm provenance, and only reach npm once a maintainer approves them with 2FA (npm staged publishing). No npm token exists. Check a downloaded version with:

```bash
npm audit signatures
```
