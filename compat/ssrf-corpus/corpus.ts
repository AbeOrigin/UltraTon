/**
 * A public SSRF corpus: each case is a URL an attacker could hand to an HTTP client, and the harness checks, for
 * several clients, whether the request was refused or got to an internal address. Everything runs on loopback:
 * "canary" servers on 127.0.0.1 (http and https) and ::1 record every request and every TCP connection, DNS is mocked,
 * and the test network guard refuses any other address. Clients run one at a time, so connection counts are exact.
 *
 * Each case names the mechanism UltraTon must block it with (`expect`), so a case blocked for an unrelated reason
 * cannot hide a regression in the check it is about. Sources: PayloadsAllTheThings and the OWASP SSRF Prevention Cheat
 * Sheet (linked per case).
 */
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo, Socket } from 'node:net';
import axios from 'axios';
import got from 'got';
import nodeFetch from 'node-fetch';
import { UltraTonClient, createSecureAgents } from 'ultraton';

/** How UltraTon is expected to refuse a case. */
export type BlockReason = 'reserved-ip' | 'plain-http' | 'credentials';
/** reached: hit a canary or opened a TCP connection to one. attempted: tried to connect to a non-loopback internal address (the sandbox refused it). */
export type Outcome = 'blocked' | 'reached' | 'attempted' | 'error';

const PATT = 'https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery';
const OWASP = 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html';

export interface Ports { http4: number; https4: number; http6?: number; redirector: number }

export interface CorpusCase {
    readonly id: string;
    readonly category: string;
    readonly description: string;
    readonly source: string;
    /** The block reasons that count for UltraTon (the client and the secure agents). */
    readonly expect: readonly BlockReason[];
    /** Needs an IPv6 loopback (::1). */
    readonly ipv6?: boolean;
    /** Only meaningful for validating clients (it is about how an answer is judged, not about where it leads). */
    readonly protectedOnly?: boolean;
    readonly dns?: Record<string, string[]>;
    /** The URL; `path` is unique per case and client. */
    url(ports: Ports, path: string): string;
    /** When set, the request goes to the redirector first, which answers `status` with this Location. */
    readonly redirect?: { status: number; location(ports: Ports, path: string): string };
}

const reserved: BlockReason[] = ['reserved-ip'];

export const CASES: readonly CorpusCase[] = [
    // IP literals that are loopback by name, so plain http is allowed and the address policy must catch them.
    { id: 'loopback-literal', category: 'IP literal', description: 'Loopback IPv4 literal', source: OWASP, expect: reserved, url: (p, path) => `http://127.0.0.1:${p.http4}${path}` },
    { id: 'loopback-decimal', category: 'IP literal', description: 'Loopback as one decimal number (2130706433)', source: PATT, expect: reserved, url: (p, path) => `http://2130706433:${p.http4}${path}` },
    { id: 'loopback-hex', category: 'IP literal', description: 'Loopback in hexadecimal (0x7f000001)', source: PATT, expect: reserved, url: (p, path) => `http://0x7f000001:${p.http4}${path}` },
    { id: 'loopback-hex-dotted', category: 'IP literal', description: 'Loopback with a hexadecimal first octet (0x7f.0.0.1)', source: PATT, expect: reserved, url: (p, path) => `http://0x7f.0.0.1:${p.http4}${path}` },
    { id: 'loopback-octal', category: 'IP literal', description: 'Loopback in octal (0177.0.0.1)', source: PATT, expect: reserved, url: (p, path) => `http://0177.0.0.1:${p.http4}${path}` },
    { id: 'loopback-short', category: 'IP literal', description: 'Loopback short form (127.1)', source: PATT, expect: reserved, url: (p, path) => `http://127.1:${p.http4}${path}` },
    { id: 'loopback-ipv6', category: 'IP literal', description: 'IPv6 loopback ([::1])', source: PATT, expect: reserved, ipv6: true, url: (p, path) => `http://[::1]:${p.http6}${path}` },
    // Over https, so the address policy is what refuses them (no plain-http shortcut).
    { id: 'loopback-mapped', category: 'IPv6 forms', description: 'IPv4-mapped IPv6 ([::ffff:127.0.0.1]), https', source: PATT, expect: reserved, url: (p, path) => `https://[::ffff:127.0.0.1]:${p.https4}${path}` },
    { id: 'loopback-mapped-hex', category: 'IPv6 forms', description: 'IPv4-mapped IPv6 in hex ([::ffff:7f00:1]), https', source: PATT, expect: reserved, url: (p, path) => `https://[::ffff:7f00:1]:${p.https4}${path}` },
    { id: 'loopback-compatible', category: 'IPv6 forms', description: 'IPv4-compatible IPv6 ([::127.0.0.1]), https', source: PATT, expect: reserved, url: (p, path) => `https://[::127.0.0.1]:${p.https4}${path}` },
    { id: 'loopback-nat64', category: 'IPv6 forms', description: 'NAT64 form of loopback ([64:ff9b::7f00:1]), https', source: PATT, expect: reserved, url: (p, path) => `https://[64:ff9b::7f00:1]:${p.https4}${path}` },
    // Tunnelled IPv4 outside the low 32 bits: 6to4 (RFC 3056) in bits 16-47, a Teredo client (RFC 4380) inverted in the low 32.
    { id: '6to4-metadata', category: 'IPv6 forms', description: 'A 6to4 address carrying the cloud metadata IPv4 ([2002:a9fe:a9fe::1]), https', source: 'https://www.rfc-editor.org/rfc/rfc3056', expect: reserved, url: (_p, path) => `https://[2002:a9fe:a9fe::1]${path}` },
    { id: 'teredo-loopback-client', category: 'IPv6 forms', description: 'A Teredo address whose client is 127.0.0.1 ([2001:0:808:808::80ff:fffe]), https', source: 'https://www.rfc-editor.org/rfc/rfc4380', expect: reserved, url: (_p, path) => `https://[2001:0:808:808::80ff:fffe]${path}` },
    { id: 'zero-address', category: 'IP literal', description: '0.0.0.0, which reaches the local host on Linux, https', source: PATT, expect: reserved, url: (p, path) => `https://0.0.0.0:${p.https4}${path}` },
    { id: 'private-ula', category: 'IP literal', description: 'IPv6 unique local address ([fd00::1]), https', source: OWASP, expect: reserved, url: (_p, path) => `https://[fd00::1]${path}` },
    { id: 'private-cgnat', category: 'IP literal', description: 'Carrier-grade NAT (100.64.0.1), https', source: OWASP, expect: reserved, url: (_p, path) => `https://100.64.0.1${path}` },
    { id: 'metadata-literal', category: 'Cloud metadata', description: 'Cloud metadata endpoint (169.254.169.254), https', source: OWASP, expect: reserved, url: (_p, path) => `https://169.254.169.254${path}` },
    { id: 'metadata-decimal', category: 'Cloud metadata', description: 'Cloud metadata as a decimal number (2852039166), https', source: PATT, expect: reserved, url: (_p, path) => `https://2852039166${path}` },
    { id: 'metadata-hex', category: 'Cloud metadata', description: 'Cloud metadata in hexadecimal (0xA9FEA9FE), https', source: PATT, expect: reserved, url: (_p, path) => `https://0xA9FEA9FE${path}` },
    // Names: DNS (mocked) answers with an internal address.
    { id: 'name-to-loopback', category: 'DNS', description: 'A public-looking name that resolves to 127.0.0.1, https', source: OWASP, expect: reserved, dns: { 'internal.example': ['127.0.0.1'] }, url: (p, path) => `https://internal.example:${p.https4}${path}` },
    { id: 'name-to-metadata', category: 'DNS', description: 'A name that resolves to the cloud metadata address, https', source: OWASP, expect: reserved, dns: { 'metadata.example': ['169.254.169.254'] }, url: (_p, path) => `https://metadata.example${path}` },
    { id: 'name-nip-io', category: 'DNS', description: 'A wildcard-DNS name embedding the address (127.0.0.1.nip.io), https', source: PATT, expect: reserved, dns: { '127.0.0.1.nip.io': ['127.0.0.1'] }, url: (p, path) => `https://127.0.0.1.nip.io:${p.https4}${path}` },
    { id: 'name-mixed-answer', category: 'DNS', description: 'A name whose answer mixes a public and an internal address, https', source: OWASP, expect: reserved, protectedOnly: true, dns: { 'mixed.example': ['93.184.216.34', '127.0.0.1'] }, url: (p, path) => `https://mixed.example:${p.https4}${path}` },
    { id: 'localhost-name', category: 'DNS', description: 'localhost', source: OWASP, expect: reserved, dns: { localhost: ['127.0.0.1'] }, url: (p, path) => `http://localhost:${p.http4}${path}` },
    { id: 'localhost-upper', category: 'DNS', description: 'LOCALHOST in capitals', source: PATT, expect: reserved, dns: { localhost: ['127.0.0.1'] }, url: (p, path) => `http://LOCALHOST:${p.http4}${path}` },
    { id: 'localhost-trailing-dot', category: 'DNS', description: 'localhost. with a trailing dot, https', source: PATT, expect: reserved, dns: { 'localhost.': ['127.0.0.1'] }, url: (p, path) => `https://localhost.:${p.https4}${path}` },
    // URL parsing tricks.
    { id: 'userinfo-trick', category: 'URL parsing', description: 'A trusted-looking name as userinfo (http://example.com@127.0.0.1)', source: PATT, expect: ['reserved-ip', 'credentials'], url: (p, path) => `http://example.com@127.0.0.1:${p.http4}${path}` },
    // Redirects: the first hop goes to an allowed host (the redirector), which sends the client inside.
    { id: 'redirect-302-loopback', category: 'Redirect', description: 'An allowed host that redirects (302) to 127.0.0.1', source: OWASP, expect: reserved, url: (p, path) => `http://redirector.localhost:${p.redirector}${path}`, redirect: { status: 302, location: (p, path) => `http://127.0.0.1:${p.http4}${path}` } },
    { id: 'redirect-307-loopback', category: 'Redirect', description: 'The same with a 307', source: OWASP, expect: reserved, url: (p, path) => `http://redirector.localhost:${p.redirector}${path}`, redirect: { status: 307, location: (p, path) => `http://127.0.0.1:${p.http4}${path}` } },
    { id: 'redirect-308-loopback', category: 'Redirect', description: 'The same with a 308', source: OWASP, expect: reserved, url: (p, path) => `http://redirector.localhost:${p.redirector}${path}`, redirect: { status: 308, location: (p, path) => `http://127.0.0.1:${p.http4}${path}` } },
    { id: 'redirect-protocol-relative', category: 'Redirect', description: 'A protocol-relative redirect (Location: //127.0.0.1)', source: PATT, expect: reserved, url: (p, path) => `http://redirector.localhost:${p.redirector}${path}`, redirect: { status: 302, location: (p, path) => `//127.0.0.1:${p.http4}${path}` } },
    { id: 'redirect-metadata', category: 'Redirect', description: 'An allowed host that redirects to cloud metadata (https)', source: OWASP, expect: reserved, url: (p, path) => `http://redirector.localhost:${p.redirector}${path}`, redirect: { status: 302, location: (_p, path) => `https://169.254.169.254${path}` } },
];

/** The one host the protected clients allow: the redirector's name, so a redirect's first hop is legitimate. */
const POLICY = ['redirector.localhost'];
const TIMEOUT_MS = 3000;

export interface Client {
    readonly name: string;
    /** Protected clients must block every case with the expected reason; the others are shown for comparison. */
    readonly protected: boolean;
    get(url: string): Promise<unknown>;
    close(): Promise<void> | void;
}

/**
 * Every client of the comparison. The unprotected ones keep their defaults, with three changes so the run is
 * deterministic: no proxy from the environment (axios), no retries (got), and a 3 s timeout.
 */
export function clients(): Client[] {
    const ultraton = new UltraTonClient({ permitReservedIps: POLICY, maxRedirects: 5, retry: 0, timeoutMs: TIMEOUT_MS });
    const agents = createSecureAgents({ permitReservedIps: POLICY });
    const fetchAgent = (u: URL) => (u.protocol === 'http:' ? agents.http : agents.https);
    const axiosSecure = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false, timeout: TIMEOUT_MS });
    const gotSecure = got.extend({ agent: { http: agents.http, https: agents.https }, retry: { limit: 0 }, timeout: { request: TIMEOUT_MS } });
    const axiosPlain = axios.create({ proxy: false, timeout: TIMEOUT_MS });
    const gotPlain = got.extend({ retry: { limit: 0 }, timeout: { request: TIMEOUT_MS } });
    return [
        { name: 'UltraTonClient', protected: true, get: url => ultraton.get(url), close: () => ultraton.close() },
        { name: 'axios + createSecureAgents', protected: true, get: url => axiosSecure.get(url), close: () => undefined },
        { name: 'got + createSecureAgents', protected: true, get: url => gotSecure.get(url), close: () => undefined },
        { name: 'node-fetch + createSecureAgents', protected: true, get: url => nodeFetch(url, { agent: fetchAgent, signal: AbortSignal.timeout(TIMEOUT_MS) }), close: () => { agents.http.destroy(); agents.https.destroy(); } },
        { name: 'axios', protected: false, get: url => axiosPlain.get(url), close: () => undefined },
        { name: 'got', protected: false, get: url => gotPlain.get(url), close: () => undefined },
        { name: 'node-fetch', protected: false, get: url => nodeFetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) }), close: () => undefined },
        { name: 'fetch (Node built-in)', protected: false, get: url => fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) }), close: () => undefined },
    ];
}

/** Walks an error's cause chain (and AggregateError members), as libraries wrap errors differently. */
function* chain(err: unknown, depth = 0): Generator<any> {
    if (!err || depth > 6) return;
    yield err;
    const e = err as any;
    if (Array.isArray(e.errors)) for (const inner of e.errors) yield* chain(inner, depth + 1);
    yield* chain(e.cause, depth + 1);
}

/** The policy reason UltraTon refused with. Only these count as blocked: a timeout or a network error never does. */
function blockReason(err: unknown): BlockReason | undefined {
    for (const e of chain(err)) {
        if (e?.code === 'ERR_ULTRATON_RESERVED_IP') return 'reserved-ip';
        if (e?.code === 'ERR_ULTRATON_PLAIN_HTTP') return 'plain-http';
        if (e?.name === 'SecureHttpError' && typeof e.message === 'string' && e.message.startsWith('UltraTon: Credentials in URL authority')) return 'credentials';
        // node-fetch and Node's fetch refuse a URL with userinfo themselves, before any agent is involved.
        if (e instanceof TypeError && /credentials/i.test(e.message)) return 'credentials';
    }
    return undefined;
}

const sandboxRefused = (err: unknown) => [...chain(err)].some(e => e?.code === 'ETESTNONLOOPBACK');

interface Servers {
    ports: Ports;
    /** Request paths seen by the canaries and the redirector. */
    canaryHits: Set<string>;
    redirectorHits: Set<string>;
    /** TCP connections accepted by the canaries so far (a client that fails TLS still connected). */
    canaryConnections(): number;
    redirect: { current?: CorpusCase['redirect'] };
    close(): Promise<void>;
}

/** Canaries (http and https on 127.0.0.1, http on ::1 when available) and the redirector, all on loopback. */
export async function startServers(ipv6: boolean): Promise<Servers> {
    const cert = fs.readFileSync(new URL('../../__tests__/fixtures/localhost-cert.pem', import.meta.url));
    const key = fs.readFileSync(new URL('../../__tests__/fixtures/localhost-key.pem', import.meta.url));
    const canaryHits = new Set<string>();
    const redirectorHits = new Set<string>();
    const sockets = new Set<Socket>();
    let connections = 0;
    const redirect: Servers['redirect'] = {};
    const canary = (req: http.IncomingMessage, res: http.ServerResponse) => {
        canaryHits.add(req.url ?? '');
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('canary');
    };
    const servers: http.Server[] = [];
    const listen = async (srv: http.Server, host: string, isCanary: boolean) => {
        servers.push(srv);
        srv.on('connection', (s: Socket) => { if (isCanary) connections++; sockets.add(s); s.on('close', () => sockets.delete(s)); });
        await new Promise<void>((resolve, reject) => { srv.once('error', reject); srv.listen(0, host, resolve); });
        return (srv.address() as AddressInfo).port;
    };
    let ports!: Ports;
    const redirector = http.createServer((req, res) => {
        redirectorHits.add(req.url ?? '');
        res.writeHead(redirect.current?.status ?? 404, { location: redirect.current?.location(ports, req.url ?? '/') ?? '/' });
        res.end();
    });
    ports = {
        http4: await listen(http.createServer(canary), '127.0.0.1', true),
        https4: await listen(https.createServer({ cert, key }, canary), '127.0.0.1', true),
        http6: ipv6 ? await listen(http.createServer(canary), '::1', true) : undefined,
        redirector: await listen(redirector, '127.0.0.1', false),
    };
    return {
        ports, canaryHits, redirectorHits, redirect,
        canaryConnections: () => connections,
        async close() {
            for (const s of sockets) s.destroy();
            await Promise.all(servers.map(srv => new Promise<void>(r => srv.close(() => r()))));
        },
    };
}

/**
 * Points both DNS APIs (dns.lookup, used by Node's sockets, and dns/promises, used by UltraTon) at `table`; returns the
 * undo. Unknown names fail as ENOTFOUND.
 */
export function mockDns(table: Record<string, string[]>): () => void {
    const answer = (host: string) => (table[host] ?? []).map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
    const realLookup = dns.lookup;
    const realPromise = dnsPromises.lookup;
    const notFound = () => Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    (dns as any).lookup = (host: string, options: any, callback?: any) => {
        const cb = typeof options === 'function' ? options : callback;
        const all = typeof options === 'object' && options?.all;
        const list = answer(host);
        process.nextTick(() => (list.length === 0 ? cb(notFound()) : all ? cb(null, list) : cb(null, list[0].address, list[0].family)));
    };
    (dnsPromises as any).lookup = async (host: string, options?: any) => {
        const list = answer(host);
        if (list.length === 0) throw notFound();
        return options?.all ? list : list[0];
    };
    return () => { (dns as any).lookup = realLookup; (dnsPromises as any).lookup = realPromise; };
}

export interface Result {
    caseId: string;
    client: string;
    outcome: Outcome;
    /** For blocked: the reason. Otherwise a short note. */
    detail: string;
    /** Redirect cases: whether the first, allowed hop reached the redirector. */
    firstHop?: boolean;
}

/** Runs every case against every client, one at a time, and classifies each outcome. */
export async function runCorpus(ipv6: boolean): Promise<Result[]> {
    const servers = await startServers(ipv6);
    const all = clients();
    const results: Result[] = [];
    try {
        for (const c of CASES) {
            if (c.ipv6 && !ipv6) continue;
            const undo = mockDns({ 'redirector.localhost': ['127.0.0.1'], ...c.dns });
            servers.redirect.current = c.redirect;
            try {
                for (const client of all) {
                    if (c.protectedOnly && !client.protected) continue;
                    const path = `/canary/${c.id}/${encodeURIComponent(client.name)}`;
                    const before = servers.canaryConnections();
                    let error: unknown;
                    try {
                        await client.get(c.url(servers.ports, path));
                    } catch (err: unknown) {
                        error = err;
                    }
                    const connected = servers.canaryHits.has(path) || servers.canaryConnections() > before;
                    const reason = error === undefined ? undefined : blockReason(error);
                    let outcome: Outcome;
                    let detail: string;
                    if (connected) {
                        outcome = 'reached';
                        detail = servers.canaryHits.has(path) ? 'request served' : 'TCP connection opened';
                    } else if (error !== undefined && sandboxRefused(error)) {
                        outcome = 'attempted';
                        detail = 'tried to connect; only the test sandbox refused it';
                    } else if (reason) {
                        outcome = 'blocked';
                        detail = reason;
                    } else {
                        outcome = 'error';
                        detail = String((error as any)?.code ?? (error as Error)?.message ?? 'resolved without reaching the canary');
                    }
                    results.push({ caseId: c.id, client: client.name, outcome, detail, firstHop: c.redirect ? servers.redirectorHits.has(path) : undefined });
                }
            } finally {
                undo();
            }
        }
    } finally {
        for (const client of all) await client.close();
        await servers.close();
    }
    return results;
}
