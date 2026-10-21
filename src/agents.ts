import * as http from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { SecureHttpError } from './errors.ts';
import { resolveSecureAgentOptions } from './helpers/request-options.ts';
import { isLoopbackHost } from './helpers/url-parser.ts';
import { pinnedLookup, resolveAndPinAll, type ReservedIpPolicy } from './security/dns-pinner.ts';
import type { TlsMaterial } from './types/request-options.types.ts';

/** The options of {@link createSecureAgents}. All optional; the defaults are the client's. */
export interface UltraTonSecureAgentOptions {
    /** As the client's `permitReservedIps`: `false` by default, `true`, or an allowlist of IPs, CIDRs and hostnames. */
    readonly permitReservedIps?: ReservedIpPolicy;
    /** As the client's `tls`: extra CAs (`ca`) and a client certificate (`cert`, `key`). Verification cannot be turned off. */
    readonly tls?: { readonly ca?: TlsMaterial; readonly cert?: TlsMaterial; readonly key?: TlsMaterial };
    /**
     * Plain `http:` is only allowed to loopback names and addresses by default, as in the client. `true` lifts that
     * scheme rule for the `http` agent, for internal services without TLS; the address policy still applies in full.
     */
    readonly allowPlainHttp?: boolean;
}

/** An `http.Agent` and an `https.Agent` that only ever connect to addresses UltraTon validated. */
export interface UltraTonSecureAgents {
    /** For `http:` URLs: loopback only, unless `allowPlainHttp` is set. */
    readonly http: http.Agent;
    /** For `https:` URLs, with TLS always verified. */
    readonly https: https.Agent;
}

// Idle pooled sockets are reaped after 5s, as in the client's own agents.
const IDLE_SOCKET_TIMEOUT_MS = 5000;

type Connect = (options: any) => Duplex;
type Callback = (err: Error | null, socket: Duplex) => void;
/** Node ignores the socket argument when there is an error. */
const noSocket = undefined as unknown as Duplex;

/**
 * Refuses a forward-proxy request: a CONNECT, or a request line with an absolute URL (`GET http://target/`). The agent
 * only sees, and validates, the proxy's address; the proxy would pick the real target, unchecked. axios does this by
 * default when HTTP_PROXY is set. The asterisk form (`OPTIONS *`) is a request to the host itself, so it passes.
 * Reported the way Node's own agent reports a socket it could not create.
 * @returns `true` when the request was refused.
 */
function refuseForwardProxy(req: http.ClientRequest): boolean {
    if (req.method !== 'CONNECT' && (req.path.startsWith('/') || req.path === '*')) return false;
    const err = new SecureHttpError(
        "UltraTon: A secure agent refuses forward-proxy requests (CONNECT or an absolute URL): the proxy, not the agent, would pick the target. Turn the library's proxy off (axios: proxy: false), or use UltraTonClient's 'proxy' option.",
        { code: 'ERR_ULTRATON_AGENT_PROXY' },
    );
    (req as unknown as { onSocket(socket: null, err: Error): void }).onSocket(null, err);
    return true;
}

/**
 * A host Node does not take for an IP but a URL parser reads as an IPv4: `127.1`, `0x7f.0.0.1`, `0177.0.0.1`,
 * `2130706433`, fullwidth digits. The client never sees one (its URL parser canonicalizes the host first), but a library
 * may hand one to the agent as is. getaddrinfo may resolve it to that IPv4 while TLS checks it as a DNS name: the
 * confusion behind CVE-2026-106069, -106072 and -105483 in unpatched Node releases.
 */
function isLooseIpv4(host: string): boolean {
    if (isIP(host) !== 0) return false;
    try {
        return isIP(new URL(`http://${host}/`).hostname) === 4;
    } catch {
        return false;
    }
}

/**
 * Resolves and validates the target, then opens the socket through `connect` (the agent's own net/tls connect) with a
 * lookup pinned to the validated addresses. Everything the calling library passed that could point the socket
 * elsewhere is overridden: its `lookup` is replaced, a `socket`/`fd`/`handle` to reuse is dropped, and a
 * `socketPath` is refused.
 */
function secureConnect(connect: Connect, options: any, callback: Callback, policy: ReservedIpPolicy, plainHttp: boolean): void {
    if (options.socketPath !== undefined && options.socketPath !== null) {
        return callback(new TypeError("UltraTon: A secure agent never connects to a socket path ('socketPath')."), noSocket);
    }
    // Node hands the agent the bare host (no brackets around an IPv6 literal); the loopback name check expects them.
    const host = String(options.host ?? 'localhost').replace(/^\[|\]$/g, '').toLowerCase();
    if (isLooseIpv4(host)) {
        return callback(new SecureHttpError('UltraTon: A secure agent refuses an IP address in a non-canonical form; write it as a dotted-decimal IPv4.', { code: 'ERR_ULTRATON_NON_CANONICAL_IP' }), noSocket);
    }
    if (plainHttp && !isLoopbackHost(isIP(host) === 6 ? `[${host}]` : host)) {
        return callback(new SecureHttpError('UltraTon: Plain http is only allowed for loopback hosts; use https.', { code: 'ERR_ULTRATON_PLAIN_HTTP' }), noSocket);
    }
    resolveAndPinAll(host, policy, plainHttp).then(addresses => {
        let socket: Duplex;
        try {
            const { socket: _socket, fd: _fd, handle: _handle, ...own } = options;
            socket = connect({ ...own, lookup: pinnedLookup(addresses) });
        } catch (err: unknown) {
            return callback(err as Error, noSocket);
        }
        callback(null, socket);
    }, (err: Error) => callback(err, noSocket));
}

/**
 * An `http.Agent` and an `https.Agent` that apply UltraTon's SSRF policy to any client that takes an agent: axios
 * (`httpAgent`/`httpsAgent`), got (`agent: { http, https }`), node-fetch (`agent`) and Node's `http.request`.
 *
 * Every new socket resolves its host and validates **every** address against `permitReservedIps`, then connects only
 * to those (DNS rebinding blocked); IP literals are judged as themselves; plain `http:` reaches loopback only unless
 * `allowPlainHttp`; TLS is always verified, whatever the request options say. Redirects the library follows open their
 * own sockets through the agent, so each hop is checked too. Each pair has its own keep-alive pool.
 *
 * The agents protect the connection only. Body size, timeouts, header validation, `baseUrl` and decompression limits
 * stay with the library using them; `UltraTonClient` covers all of it. A library's own proxy is refused
 * (`ERR_ULTRATON_AGENT_PROXY`), since the proxy would pick the target: turn it off (axios: `proxy: false`). Connection
 * failures to an allowed address are Node's own errors and may name that address. Call `destroy()` on both agents
 * when done.
 * @throws {TypeError} On an unknown option or a value of the wrong type, as the client constructor does.
 */
export function createSecureAgents(options?: UltraTonSecureAgentOptions): UltraTonSecureAgents {
    const { permitReservedIps: policy, tls: tlsMaterial, allowPlainHttp } = resolveSecureAgentOptions(options);

    class SecureHttpAgent extends http.Agent {
        addRequest(req: http.ClientRequest, requestOptions: unknown): void {
            if (refuseForwardProxy(req)) return;
            (http.Agent.prototype as unknown as { addRequest(r: unknown, o: unknown): void }).addRequest.call(this, req, requestOptions);
        }

        override createConnection(connectOptions: any, callback?: Callback): undefined {
            const connect: Connect = opts => super.createConnection(opts) as Duplex;
            secureConnect(connect, connectOptions, callback!, policy, !allowPlainHttp);
            return undefined;
        }
    }

    class SecureHttpsAgent extends https.Agent {
        addRequest(req: http.ClientRequest, requestOptions: unknown): void {
            if (refuseForwardProxy(req)) return;
            (https.Agent.prototype as unknown as { addRequest(r: unknown, o: unknown): void }).addRequest.call(this, req, requestOptions);
        }

        override createConnection(connectOptions: any, callback?: Callback): undefined {
            // Certificate checks stay on: a library's rejectUnauthorized: false or no-op checkServerIdentity is ignored.
            const connect: Connect = opts => super.createConnection({ ...opts, rejectUnauthorized: true, checkServerIdentity: tls.checkServerIdentity }) as Duplex;
            secureConnect(connect, connectOptions, callback!, policy, false);
            return undefined;
        }
    }

    return Object.freeze({
        http: new SecureHttpAgent({ keepAlive: true, timeout: IDLE_SOCKET_TIMEOUT_MS }),
        https: new SecureHttpsAgent({ keepAlive: true, timeout: IDLE_SOCKET_TIMEOUT_MS, ...tlsMaterial }),
    });
}
