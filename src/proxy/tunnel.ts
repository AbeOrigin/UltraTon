import net, { isIP } from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { UltraTonNetworkError, toNetworkError } from '../errors.ts';
import type { TlsMaterial } from '../types/request-options.types.ts';
import { ipv6Groups } from '../security/dns-pinner.ts';
import { TLS_MIN_VERSION } from '../constants.ts';
import { incompleteResponse } from '../helpers/response.ts';

/** `proxy` once validated (see proxyOption). */
export interface ProxyConfig {
    /** `http:`, `https:`, `socks5:` or `socks5h:`, origin only. */
    readonly url: URL;
    /** `'connect'`: an HTTP CONNECT proxy (`http:`/`https:`). `'socks5'`: a SOCKS5 proxy (RFC 1928). */
    readonly kind: 'connect' | 'socks5';
    /** `user:password`: Basic `proxy-authorization` on the CONNECT, or SOCKS5 username/password (RFC 1929). */
    readonly auth?: string;
    /** CAs trusted for an `https:` proxy's own certificate, apart from the `tls.ca` trusted for targets. */
    readonly ca?: TlsMaterial;
    /** `'local'`: tunnel to the IP UltraTon resolved and validated. `'proxy'`: send the name; the proxy resolves it. */
    readonly resolve: 'local' | 'proxy';
}

/** The most a proxy may send before its handshake answer is complete. */
const MAX_PROXY_RESPONSE_BYTES = 16 * 1024;
// ponytail: one fixed deadline for the whole handshake, however the proxy drips its bytes. The request's own
// timeoutMs and signal end it sooner (kTunnelSignal on HTTP/1, the attempt's waiters on HTTP/2). Make it configurable
// if a proxy ever needs more.
const PROXY_HANDSHAKE_TIMEOUT_MS = 10_000;
/** Statuses that say the proxy itself refuses (credentials, policy): the same for every address, so none is tried next. */
const FINAL_PROXY_STATUSES = new Set([401, 403, 407]);

/**
 * Set by the HTTP/1 engine on each request's options to the signal of that hop (aborted by the caller's signal, its
 * timeouts and close()), so a tunnel still being set up for a request nobody waits for is torn down at once.
 */
export const kTunnelSignal = Symbol('ultraton.tunnelSignal');

/** Proxy refusals that no other address can fix (see FINAL_PROXY_STATUSES and the SOCKS5 replies). */
const finalRefusals = new WeakSet<Error>();

const refusal = (message: string, final: boolean) => {
    const err = new UltraTonNetworkError(message, { code: 'ERR_ULTRATON_PROXY' });
    if (final) finalRefusals.add(err);
    return err;
};

const proxyError = (status: number) =>
    refusal(`UltraTon: The proxy refused the tunnel (${status}).`, FINAL_PROXY_STATUSES.has(status));

/** The proxy's answer did not follow its protocol, was too large, or carried bytes past the handshake. */
const malformedResponse = () => refusal('UltraTon: The proxy sent a malformed response.', false);

/**
 * One proxy protocol's side of the handshake: what to send first, then a judge of what the proxy sent so far.
 * `read` gets every byte not consumed yet and answers `undefined` to wait for more, an Error to fail, or the bytes it
 * consumed plus either more to send or `done` once the tunnel is up.
 */
interface Handshake {
    readonly greeting: string | Buffer;
    read(received: Buffer): undefined | Error | { consumed: number; write?: Buffer; done?: true };
}

/** The status of an `HTTP/1.0` or `HTTP/1.1` status line: three digits, then a space or the end. No regex: proxy input. */
function statusOf(line: string): number | undefined {
    if (!(line.startsWith('HTTP/1.1 ') || line.startsWith('HTTP/1.0 '))) return undefined;
    const digits = line.slice(9, 12);
    if (digits.length !== 3 || ![...digits].every(c => c >= '0' && c <= '9')) return undefined;
    return line.length === 12 || line.charAt(12) === ' ' ? Number(digits) : undefined;
}

/** `host:port` for a CONNECT request target and its Host header, brackets around an IPv6 literal. */
const authority = (host: string, port: number) => `${isIP(host) === 6 ? `[${host}]` : host}:${port}`;

/** HTTP CONNECT: one request, one response whose status says whether the tunnel is up. */
function connectHandshake(proxy: ProxyConfig, host: string, port: number): Handshake {
    const target = authority(host, port);
    const auth = proxy.auth === undefined ? '' : `proxy-authorization: Basic ${Buffer.from(proxy.auth).toString('base64')}\r\n`;
    return {
        greeting: `CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n${auth}\r\n`,
        read(received) {
            const end = received.indexOf('\r\n\r\n');
            if (end === -1) return undefined;
            // "HTTP/1.1 200 Connection established": only the status code is read, never echoed.
            const status = statusOf(received.subarray(0, received.indexOf('\r\n')).toString('latin1'));
            if (status === undefined) return malformedResponse();
            if (status < 200 || status > 299) return proxyError(status);
            return { consumed: end + 4, done: true };
        },
    };
}

/**
 * The 16 bytes of an IPv6 address (an embedded IPv4 and `::` included; a zone dropped), read by the same parser that
 * validated it (dns-pinner's ipv6Groups): the address sent to the proxy can never differ from the one judged.
 */
export function ipv6Bytes(ip: string): Buffer {
    const groups = ipv6Groups(ip);
    if (groups === undefined) throw new TypeError('UltraTon: Not an IPv6 address.');
    const bytes = Buffer.alloc(16);
    groups.forEach((group, i) => bytes.writeUInt16BE(group, i * 2));
    return bytes;
}

/**
 * Throws, before anything is opened, for a target the proxy protocol cannot carry: with a SOCKS5 proxy that resolves
 * names (socks5h), a name over the 255 bytes a SOCKS5 domain field holds. The HTTP/1 engine calls it per hop, since an
 * error raised inside its agent would surface as a network failure; socksHandshake checks it again.
 * @throws {TypeError}
 */
export function assertTunnelable(proxy: ProxyConfig, host: string): void {
    if (proxy.kind === 'socks5' && proxy.resolve === 'proxy' && isIP(host) === 0 && Buffer.byteLength(host) > 255) {
        throw new TypeError('UltraTon: The hostname is too long for a SOCKS5 proxy (at most 255 bytes).');
    }
}

/** SOCKS5 reply codes (RFC 1928 section 6) as readable reasons; the index is the code. */
const SOCKS_REPLIES = ['succeeded', 'general failure', 'connection not allowed by ruleset', 'network unreachable',
    'host unreachable', 'connection refused', 'TTL expired', 'command not supported', 'address type not supported'];
/** Replies no other address can change: the proxy's rules, or a command it does not do. */
const FINAL_SOCKS_REPLIES = new Set([2, 7]);

const socksRefusal = (reason: string, final: boolean) =>
    refusal(`UltraTon: The SOCKS proxy refused the connection (${reason}).`, final);

/**
 * SOCKS5 (RFC 1928) CONNECT: method negotiation, username/password (RFC 1929) when `auth` is set, then the request.
 * The target goes as ATYP IPv4/IPv6 for a validated IP, or as a domain name with `resolve: 'proxy'` (socks5h).
 * @throws {TypeError} For a name longer than the 255 bytes a SOCKS5 domain can hold.
 */
function socksHandshake(proxy: ProxyConfig, host: string, port: number): Handshake {
    const family = isIP(host);
    let address: Buffer;
    if (family === 4) {
        address = Buffer.from([1, ...host.split('.').map(Number)]);
    } else if (family === 6) {
        address = Buffer.concat([Buffer.from([4]), ipv6Bytes(host)]);
    } else {
        // Only with resolve: 'proxy' (socks5h) may a name leave; anything else would quietly drop the DNS pinning.
        if (proxy.resolve !== 'proxy') throw new TypeError('UltraTon: A SOCKS5 target must be a validated IP unless the proxy resolves names.');
        const name = Buffer.from(host);
        if (name.length > 255) throw new TypeError('UltraTon: The hostname is too long for a SOCKS5 proxy (at most 255 bytes).');
        address = Buffer.concat([Buffer.from([3, name.length]), name]);
    }
    const portBytes = Buffer.alloc(2);
    portBytes.writeUInt16BE(port);
    const request = Buffer.concat([Buffer.from([5, 1, 0]), address, portBytes]);

    let stage: 'method' | 'auth' | 'reply' = 'method';
    return {
        // Version 5, then the methods offered: "no authentication", plus username/password when there is `auth`.
        greeting: Buffer.from(proxy.auth === undefined ? [5, 1, 0] : [5, 2, 0, 2]),
        read(r) {
            if (stage === 'method') {
                if (r.length < 2) return undefined;
                if (r[0] !== 5) return malformedResponse();
                if (r[1] === 0) {
                    stage = 'reply';
                    return { consumed: 2, write: request };
                }
                if (r[1] === 2 && proxy.auth !== undefined) {
                    stage = 'auth';
                    const colon = proxy.auth.indexOf(':');
                    const user = Buffer.from(proxy.auth.slice(0, colon));
                    const password = Buffer.from(proxy.auth.slice(colon + 1));
                    return { consumed: 2, write: Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([password.length]), password]) };
                }
                return socksRefusal('no acceptable authentication method', true);
            }
            if (stage === 'auth') {
                if (r.length < 2) return undefined;
                // RFC 1929 says version 1; some servers answer 5. Anything else here is final all the same: the
                // credentials must not be sent again to a proxy that answers them oddly, once per address.
                if (r[0] !== 1 && r[0] !== 5) return socksRefusal('malformed authentication answer', true);
                if (r[1] !== 0) return socksRefusal('authentication failed', true);
                stage = 'reply';
                return { consumed: 2, write: request };
            }
            // VER REP RSV ATYP BND.ADDR BND.PORT: the bound address only tells how long the reply is.
            if (r.length < 2) return undefined;
            if (r[0] !== 5) return malformedResponse();
            if (r[1] !== 0) return socksRefusal(SOCKS_REPLIES.at(r[1]) ?? `reply ${r[1]}`, FINAL_SOCKS_REPLIES.has(r[1]));
            if (r.length < 5) return undefined;
            if (r[2] !== 0) return malformedResponse();
            const addressLength = r[3] === 1 ? 4 : r[3] === 4 ? 16 : r[3] === 3 ? 1 + r[4] : -1;
            if (addressLength === -1) return malformedResponse();
            const total = 4 + addressLength + 2;
            if (r.length < total) return undefined;
            return { consumed: total, done: true };
        },
    };
}

const DEFAULT_PORTS: Record<ProxyConfig['kind'], number> = { connect: 80, socks5: 1080 };

/**
 * Opens a tunnel through the proxy to `host:port` and resolves with the raw socket, paused, once the proxy says it is
 * up. `host` is sent as is: an IP UltraTon already validated, or with `resolve: 'proxy'` the name. The TLS client
 * speaks first over the tunnel, so a proxy that sends anything past its handshake is refused.
 * @throws {UltraTonNetworkError} `ERR_ULTRATON_PROXY` when the proxy refuses or answers outside its protocol; the
 *   usual network mapping (no address in the message) when the proxy cannot be reached.
 */
function openTunnel(proxy: ProxyConfig, host: string, port: number, signal: AbortSignal | undefined): Promise<Duplex> {
    return new Promise((resolve, reject) => {
        signal?.throwIfAborted();
        const handshake = proxy.kind === 'socks5' ? socksHandshake(proxy, host, port) : connectHandshake(proxy, host, port);
        const proxyHost = proxy.url.hostname.replace(/^\[|\]$/g, '');
        const secure = proxy.url.protocol === 'https:';
        const proxyPort = Number(proxy.url.port) || (secure ? 443 : DEFAULT_PORTS[proxy.kind]);
        const socket: net.Socket = secure
            ? tls.connect({
                host: proxyHost,
                port: proxyPort,
                ...(isIP(proxyHost) === 0 ? { servername: proxyHost } : {}),
                ...(proxy.ca !== undefined ? { ca: proxy.ca } : {}),
                minVersion: TLS_MIN_VERSION,
                ALPNProtocols: ['http/1.1'],
            })
            : net.connect({ host: proxyHost, port: proxyPort });

        let received = Buffer.alloc(0);
        const finish = (err: unknown) => {
            socket.off('data', onData);
            socket.off('error', onError);
            socket.off('close', onClose);
            clearTimeout(deadline);
            signal?.removeEventListener('abort', onAbort);
            if (err !== undefined) {
                socket.destroy();
                reject(err);
            }
        };
        // Failing to reach the proxy itself (refused, TLS to it) is the same for every address: final, not retried.
        let reached = false;
        socket.once(secure ? 'secureConnect' : 'connect', () => { reached = true; });
        const onError = (err: Error) => {
            const mapped = toNetworkError(err);
            if (!reached && mapped instanceof Error) finalRefusals.add(mapped);
            finish(mapped);
        };
        const onClose = () => finish(incompleteResponse());
        const onAbort = () => finish(signal!.reason);
        const onTimeout = () => {
            const err = new UltraTonNetworkError('UltraTon: Connection failed (ETIMEDOUT).', { code: 'ETIMEDOUT' });
            // The proxy itself never answered the connect (blackholed): no other address will do better.
            if (!reached) finalRefusals.add(err);
            finish(err);
        };
        const onData = (chunk: Buffer) => {
            received = Buffer.concat([received, chunk]);
            for (;;) {
                const step = handshake.read(received);
                if (step === undefined) {
                    if (received.length > MAX_PROXY_RESPONSE_BYTES) finish(malformedResponse());
                    return;
                }
                if (step instanceof Error) return finish(step);
                received = received.subarray(step.consumed);
                if (step.write) {
                    socket.write(step.write);
                    continue;
                }
                if (received.length > 0) return finish(malformedResponse());
                finish(undefined);
                // Nothing reads it until TLS takes over: no byte may be emitted to nobody in between.
                socket.pause();
                return resolve(socket);
            }
        };

        socket.on('error', onError);
        socket.on('close', onClose);
        socket.on('data', onData);
        const deadline = setTimeout(onTimeout, PROXY_HANDSHAKE_TIMEOUT_MS);
        signal?.addEventListener('abort', onAbort, { once: true });
        socket.write(handshake.greeting);
    });
}

/**
 * A tunnel to the first of `hosts` the proxy connects to, tried in order (Happy Eyeballs through the proxy, one at a
 * time): every one of them was validated already, or with `resolve: 'proxy'` there is just the name. A refusal by the
 * proxy itself (credentials, its rules) is final, and so is an abort.
 */
export async function tunnelTo(proxy: ProxyConfig, hosts: readonly string[], port: number, signal?: AbortSignal): Promise<Duplex> {
    let last: unknown;
    for (const host of hosts) {
        try {
            return await openTunnel(proxy, host, port, signal);
        } catch (err: unknown) {
            if (signal?.aborted || (err instanceof Error && finalRefusals.has(err)) || err instanceof TypeError) throw err;
            last = err;
        }
    }
    throw last;
}
