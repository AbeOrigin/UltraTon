# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | Yes |
| 1.x | No. Upgrade to 2.x: 1.x has known SSRF bypasses. |

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
- 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses, which are not reserved (see THREAT_MODEL.md);
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
