import net, { isIP } from 'node:net';
import tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { UltraTonNetworkError, toNetworkError } from '../errors.ts';
import type { TlsMaterial } from '../types/request-options.types.ts';

/** `proxy` once validated (see proxyOption). */
export interface ProxyConfig {
    /** `http:` or `https:`, origin only. */
    readonly url: URL;
    /** `user:password`, sent as Basic `proxy-authorization` on the CONNECT only. */
    readonly auth?: string;
    /** CAs trusted for an `https:` proxy's own certificate, apart from the `tls.ca` trusted for targets. */
    readonly ca?: TlsMaterial;
    /** `'local'`: CONNECT to the IP UltraTon resolved and validated. `'proxy'`: CONNECT by name; the proxy resolves it. */
    readonly resolve: 'local' | 'proxy';
}

/** The most a proxy may send before the end of its CONNECT response headers. */
const MAX_PROXY_RESPONSE_BYTES = 16 * 1024;
// ponytail: one fixed deadline for the whole CONNECT handshake, however the proxy drips its bytes. The request's own
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

/** Proxy refusals that no other address can fix (see FINAL_PROXY_STATUSES). */
const finalRefusals = new WeakSet<Error>();

const proxyError = (status: number) => {
    const err = new UltraTonNetworkError(`UltraTon: The proxy refused the tunnel (${status}).`, { code: 'ERR_ULTRATON_PROXY' });
    if (FINAL_PROXY_STATUSES.has(status)) finalRefusals.add(err);
    return err;
};

/** The proxy's answer was not an HTTP/1.x status line plus headers, was too large, or carried bytes past the headers. */
const malformedResponse = () =>
    new UltraTonNetworkError('UltraTon: The proxy sent a malformed response.', { code: 'ERR_ULTRATON_PROXY' });

/** The status of an `HTTP/1.0` or `HTTP/1.1` status line: three digits, then a space or the end. No regex: proxy input. */
function statusOf(line: string): number | undefined {
    if (!(line.startsWith('HTTP/1.1 ') || line.startsWith('HTTP/1.0 '))) return undefined;
    const digits = line.slice(9, 12);
    if (digits.length !== 3 || ![...digits].every(c => c >= '0' && c <= '9')) return undefined;
    return line.length === 12 || line.charAt(12) === ' ' ? Number(digits) : undefined;
}

/** `host:port` for a CONNECT request target and its Host header, brackets around an IPv6 literal. */
const authority = (host: string, port: number) => `${isIP(host) === 6 ? `[${host}]` : host}:${port}`;

/**
 * Opens a CONNECT tunnel through the proxy to `host:port` and resolves with the raw socket, paused, once the proxy
 * answers 2xx. `host` is sent as is: an IP UltraTon already validated, or with `resolve: 'proxy'` the name. The TLS
 * client speaks first over the tunnel, so a proxy that sends anything past its response headers is refused.
 * @throws {UltraTonNetworkError} `ERR_ULTRATON_PROXY` when the proxy answers anything but 2xx, or a malformed or
 *   oversized response; the usual network mapping (no address in the message) when the proxy cannot be reached.
 */
function openTunnel(proxy: ProxyConfig, host: string, port: number, signal: AbortSignal | undefined): Promise<Duplex> {
    return new Promise((resolve, reject) => {
        signal?.throwIfAborted();
        const proxyHost = proxy.url.hostname.replace(/^\[|\]$/g, '');
        const proxyPort = Number(proxy.url.port) || (proxy.url.protocol === 'https:' ? 443 : 80);
        const socket: net.Socket = proxy.url.protocol === 'https:'
            ? tls.connect({
                host: proxyHost,
                port: proxyPort,
                ...(isIP(proxyHost) === 0 ? { servername: proxyHost } : {}),
                ...(proxy.ca !== undefined ? { ca: proxy.ca } : {}),
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
        socket.once(proxy.url.protocol === 'https:' ? 'secureConnect' : 'connect', () => { reached = true; });
        const onError = (err: Error) => {
            const mapped = toNetworkError(err);
            if (!reached && mapped instanceof Error) finalRefusals.add(mapped);
            finish(mapped);
        };
        const onClose = () => finish(new UltraTonNetworkError('UltraTon: Connection failed (ECONNRESET).', { code: 'ECONNRESET' }));
        const onAbort = () => finish(signal!.reason);
        const onTimeout = () => {
            const err = new UltraTonNetworkError('UltraTon: Connection failed (ETIMEDOUT).', { code: 'ETIMEDOUT' });
            // The proxy itself never answered the connect (blackholed): no other address will do better.
            if (!reached) finalRefusals.add(err);
            finish(err);
        };
        const onData = (chunk: Buffer) => {
            received = Buffer.concat([received, chunk]);
            const end = received.indexOf('\r\n\r\n');
            if (end === -1) {
                if (received.length > MAX_PROXY_RESPONSE_BYTES) finish(malformedResponse());
                return;
            }
            // "HTTP/1.1 200 Connection established": only the status code is read, never echoed.
            const status = statusOf(received.subarray(0, received.indexOf('\r\n')).toString('latin1'));
            if (status === undefined || received.length > end + 4) return finish(malformedResponse());
            if (status < 200 || status > 299) return finish(proxyError(status));
            finish(undefined);
            // Nothing reads it until TLS takes over: no byte may be emitted to nobody in between.
            socket.pause();
            resolve(socket);
        };

        socket.on('error', onError);
        socket.on('close', onClose);
        socket.on('data', onData);
        const deadline = setTimeout(onTimeout, PROXY_HANDSHAKE_TIMEOUT_MS);
        signal?.addEventListener('abort', onAbort, { once: true });

        const target = authority(host, port);
        const auth = proxy.auth === undefined ? '' : `proxy-authorization: Basic ${Buffer.from(proxy.auth).toString('base64')}\r\n`;
        socket.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n${auth}\r\n`);
    });
}

/**
 * A tunnel to the first of `hosts` the proxy connects to, tried in order (Happy Eyeballs through the proxy, one at a
 * time): every one of them was validated already, or with `resolve: 'proxy'` there is just the name. A refusal by the
 * proxy itself (401, 403, 407) is final, and so is an abort.
 */
export async function tunnelTo(proxy: ProxyConfig, hosts: readonly string[], port: number, signal?: AbortSignal): Promise<Duplex> {
    let last: unknown;
    for (const host of hosts) {
        try {
            return await openTunnel(proxy, host, port, signal);
        } catch (err: unknown) {
            if (signal?.aborted || (err instanceof Error && finalRefusals.has(err))) throw err;
            last = err;
        }
    }
    throw last;
}
