import { IncomingMessage, ClientRequest } from "node:http";
import { absoluteTimeout, bodyTooLarge, clientClosed, idleTimeout, remainingBudget, toNetworkError } from "../errors.ts";
import { buildSafeRequestOptions } from "../helpers/request-options.ts";
import { parseSafeUrl } from "../helpers/url-parser.ts";
import type { ResolvedRequestOptions, SecureUltraTonRequestOptions, TlsOptions } from "../types/request-options.types.ts";
import type { UltraTonRedirect, UltraTonResponse, UltraTonStreamResponse } from "../types/request-response.ts";
import { assertAllowedIp, policyKey, resolveAndPinAll } from "../security/dns-pinner.ts";
import type { ReservedIpPolicy } from "../security/dns-pinner.ts";
import * as http from 'node:http';
import * as https from 'node:https';
import type { LookupOptions, LookupAddress } from 'node:dns';
import { promisify } from 'node:util';
import { HTTP_CODES_REDIRECTS, IDLE_SOCKET_TIMEOUT_MS, TLS_MIN_VERSION } from '../constants.ts';
import { followRedirect } from '../helpers/redirect-headers.ts';
import { createResponse, createStreamResponse, declaredBodyLength, incompleteResponse, NO_REDIRECTS } from '../helpers/response.ts';
import { BodyReader, createBodyStream } from '../helpers/body-reader.ts';
import { KEEP_ALIVE } from '../helpers/keep-alive.ts';
import { frameBody, isSinkClosed, limitRequestBody, StreamedBody } from '../helpers/request-body.ts';
import { assertTunnelable, kTunnelSignal, tunnelTo, type ProxyConfig } from '../proxy/tunnel.ts';
import { isIP } from 'node:net';
import tls from 'node:tls';
import { finished, type Duplex } from 'node:stream';
import type { HopTimings, TimingsCollector } from '../helpers/diagnostics.ts';

// Node only runs the custom `lookup` (the SSRF check) when it opens a NEW socket, and its default agent pools sockets by
// host:port alone, so a socket opened under one reserved-IP policy would be reused by a request under another and skip the check.
// Hence one keep-alive agent pair per policy: sockets are never shared across policies. The map belongs to one engine (one
// client), so two clients never share a socket either, whatever their policies or TLS settings.
// Idle pooled sockets are reaped after IDLE_SOCKET_TIMEOUT_MS, as with Node's global agent: without it a hostile server
// reached through N hostnames could pin N file descriptors for as long as it keeps them open.
// ponytail: one agent pair per distinct policy, never evicted, so the map grows with distinct allowlists; the ceiling is the
// number of policies an app uses. Same upgrade path as the compiled-allowlist cache: bound it if lists ever come from request-time input.

/**
 * An HTTPS agent whose sockets are TLS over a CONNECT tunnel through the proxy. The tunnel goes to an address the
 * request's own `lookup` resolved and validated (all of them, tried in order), or with `resolve: 'proxy'` to the name;
 * TLS then runs to the target with its SNI and certificate check on the hostname, exactly as on a direct socket. Keep-alive
 * pools the tunnelled sockets like any others, per policy (one agent per policy, see Http1Engine).
 */
class TunnelAgent extends https.Agent {
    readonly #proxy: ProxyConfig;
    readonly #signal: AbortSignal;

    constructor(options: https.AgentOptions, proxy: ProxyConfig, signal: AbortSignal) {
        super(options);
        this.#proxy = proxy;
        this.#signal = signal;
    }

    override createConnection(options: any, callback: (err: Error | null, socket?: Duplex) => void): undefined {
        const host = String(options.host);
        const port = Number(options.port) || 443;
        // An IP literal was judged by request() already, and has nothing to resolve.
        // Every validated address of the host, through the request's own pinning `lookup` (see _executeSingleNetworkHop).
        const hosts: Promise<string[]> = this.#proxy.resolve === 'proxy' || isIP(host) !== 0
            ? Promise.resolve([host])
            : promisify(options.lookup)(host, { all: true }).then((all: LookupAddress[]) => all.map(a => a.address));
        // close() or this request giving up (abort, timeout) tears down a tunnel still being set up.
        const hop: unknown = options[kTunnelSignal];
        const signal = hop instanceof AbortSignal ? AbortSignal.any([this.#signal, hop]) : this.#signal;
        hosts
            .then(list => tunnelTo(this.#proxy, list, port, signal))
            .then(raw => {
                // Only TLS material and the target: nothing from the request options can point the socket elsewhere.
                // `host` is what the certificate is checked against when there is no SNI (an IP literal): without it
                // Node would fall back to the name of the socket it wraps, the proxy's, and accept the proxy's own cert.
                // ponytail: no TLS session resumption through the proxy (https.Agent's session cache lives in the
                // createConnection this replaces); a full handshake per new tunnel, add the cache if that ever costs.
                const { ca, cert, key, servername } = options;
                callback(null, tls.connect({ socket: raw, host, ca, cert, key, servername, minVersion: TLS_MIN_VERSION, ALPNProtocols: ['http/1.1'] }));
            }, (err: Error) => callback(err));
        return undefined;
    }
}

/** The HTTP/1.1 engine behind `UltraTonClient`. Not public: the client validates and merges the options it receives. */
export class Http1Engine {
    readonly #agentsByPolicy = new Map<string, { http: http.Agent; https: https.Agent }>();
    readonly #tls: TlsOptions;
    // Internal testing interceptor (kTransport)
    readonly #transport?: typeof https.request | typeof http.request;
    readonly #proxy?: ProxyConfig;
    /** The client's `allowPlainHttp`: plain http to any host, not only loopback. */
    readonly #allowPlainHttp: boolean;
    /** Aborted by close(): a tunnel still being set up through the proxy is torn down with it. */
    readonly #closing = new AbortController();
    #closed = false;

    /**
     * @param tls - The client's validated `ca`/`cert`/`key`, applied to its HTTPS agents.
     * @param transport - Replacement for `http.request`/`https.request`, used strictly for internal testing.
     * @param proxy - The client's validated `proxy`: every `https:` request is tunnelled through it.
     * @param allowPlainHttp - The client's `allowPlainHttp` (never with a proxy, which plain http would bypass).
     */
    constructor(tls: TlsOptions = {}, transport?: typeof https.request | typeof http.request, proxy?: ProxyConfig, allowPlainHttp = false) {
        this.#tls = tls;
        this.#transport = transport;
        this.#proxy = proxy;
        this.#allowPlainHttp = allowPlainHttp;
    }

    /** Destroys every pooled socket (in-flight requests on them fail) and refuses any later request. */
    public close(): void {
        this.#closed = true;
        this.#closing.abort(clientClosed());
        for (const agents of this.#agentsByPolicy.values()) {
            agents.http.destroy();
            agents.https.destroy();
        }
        this.#agentsByPolicy.clear();
    }

    #agentFor(policy: ReservedIpPolicy, protocol: string): http.Agent {
        const key = policyKey(policy);
        let agents = this.#agentsByPolicy.get(key);
        if (!agents) {
            agents = {
                // keepAlive is off on a Node whose pooled-socket reuse is unsafe (CVE-2026-105481): see KEEP_ALIVE.
                http: new http.Agent({ keepAlive: KEEP_ALIVE, timeout: IDLE_SOCKET_TIMEOUT_MS }),
                https: this.#proxy
                    ? new TunnelAgent({ keepAlive: KEEP_ALIVE, timeout: IDLE_SOCKET_TIMEOUT_MS, minVersion: TLS_MIN_VERSION, ...this.#tls }, this.#proxy, this.#closing.signal)
                    : new https.Agent({ keepAlive: KEEP_ALIVE, timeout: IDLE_SOCKET_TIMEOUT_MS, minVersion: TLS_MIN_VERSION, ...this.#tls }),
            };
            this.#agentsByPolicy.set(key, agents);
        }
        return protocol === 'http:' ? agents.http : agents.https;
    }

    private async _consumeResponseBuffer(
        res: IncomingMessage,
        req: ClientRequest,
        reqOpts: SecureUltraTonRequestOptions,
        executionTimer: NodeJS.Timeout | undefined
    ): Promise<{ data: Buffer, wireBytes: number }> {
        // A decoding failure or a decoded overflow surfaces asynchronously: destroying the request ends the loop below.
        const reader = new BodyReader({
            maxBodySize: reqOpts.maxBodySize,
            contentEncoding: res.headers['content-encoding'],
            decompress: reqOpts.decompress,
            tooLarge: () => bodyTooLarge(reqOpts.maxBodySize),
            onError: () => req.destroy(),
        });

        try {
            // Events, not `for await`: the async iterator costs a promise and a microtask turn per chunk. finished()
            // rejects as the iterator did: a socket error, or a close before 'end' (ERR_STREAM_PREMATURE_CLOSE).
            // A write that throws (maxBodySize, a decoding error) destroys `res` with it, as leaving the loop did.
            await new Promise<void>((resolve, reject) => {
                res.on('data', (chunk: Buffer) => {
                    try {
                        reader.write(chunk);
                    } catch (err: unknown) {
                        res.destroy(err as Error);
                    }
                });
                finished(res, err => (err ? reject(err) : resolve()));
            });
        } catch (err: unknown) {
            clearTimeout(executionTimer);
            if (reader.error) {
                req.destroy();
                throw reader.error;
            }
            reader.destroy();
            // A caller abort is not a network fault: it surfaces as the signal's own reason, like before the body started.
            if (reqOpts.signal?.aborted) throw reqOpts.signal.reason;
            // close() destroyed the socket mid-body: say so instead of reporting a reset connection.
            if (this.#closed) throw clientClosed();
            const code = (err as NodeJS.ErrnoException | undefined)?.code;
            // A socket error with a code (ECONNRESET, ERR_STREAM_PREMATURE_CLOSE, ...) maps like any other network error;
            // a stream that just ends early has none, which is a reset connection as far as the caller is concerned.
            if (typeof code === 'string') throw toNetworkError(err);
            throw incompleteResponse(err);
        }

        // The absolute timeout still runs while the queued compressed bytes finish decoding.
        try {
            const data = await reader.end();
            // close() or an abort during that last stretch wins over the decoded body, as it would mid-body.
            if (reqOpts.signal?.aborted) throw reqOpts.signal.reason;
            if (this.#closed) throw clientClosed();
            return { data, wireBytes: reader.wireBytes };
        } finally {
            clearTimeout(executionTimer);
        }
    }

    private _executeSingleNetworkHop(
        urlObj: URL,
        reqOpts: SecureUltraTonRequestOptions,
        body: Buffer | StreamedBody | undefined,
        currentTimeoutMs: number,
        followRedirects: boolean,
        stream?: { maxBodySize: number },
        phases?: HopTimings
    ): Promise<{ statusCode: number, headers: import('node:http').IncomingHttpHeaders, data: Buffer, isRedirect: boolean, body?: ReadableStream<Uint8Array> }> {
        return new Promise((resolve, reject) => {
            let executionTimer: NodeJS.Timeout | undefined;

            const transport = this.#transport || (urlObj.protocol === 'http:' ? http.request : https.request);
            
            // The body dictates the framing (see frameBody); chunked is set here so Node frames it that way for every method.
            const headers = { ...reqOpts.headers };
            frameBody(headers, body, true);
            // A streamed body cannot be sent again: a 307/308 is returned to the caller instead of being followed.
            const canFollow = (status: number) => followRedirects && !(body instanceof StreamedBody && (status === 307 || status === 308));
            // The streamed body's own failure (its stream, a limit, the length): what the request reports, mid-response too.
            let bodyError: unknown;
            // The response is complete while the upload is still open (the server answered early): the socket cannot be
            // reused, and a stalled or endless source must not hold it, so the request is ended here.
            const stopUpload = () => {
                if (body instanceof StreamedBody && !req.writableFinished) req.destroy();
            };

            // Ends a proxy tunnel still being set up for this hop when the hop gives up: abort, timeout (see TunnelAgent).
            const hop = new AbortController();
            const tunnelSignal = this.#proxy && reqOpts.signal ? AbortSignal.any([hop.signal, reqOpts.signal]) : hop.signal;

            // The TLS name comes from the URL, which WHATWG canonicalized, never from a caller's Host header: Node's agent
            // would otherwise take it from there, and a non-canonical IP (`127.1`) checked as a DNS name is the confusion
            // behind CVE-2026-106069/-106072. An IP literal gets '': no SNI, and the certificate is checked against the IP.
            const bareHostname = urlObj.hostname.replace(/^\[|\]$/g, '');
            // Before the request: creating it is what opens a new socket and starts its lookup.
            phases?.mark('start');
            const req = transport(urlObj, {
                ...reqOpts,
                ...(this.#proxy ? { [kTunnelSignal]: tunnelSignal } : {}),
                servername: isIP(bareHostname) === 0 ? bareHostname : '',
                headers,
                timeout: reqOpts.socketTimeoutMs,
                agent: this.#agentFor(reqOpts.permitReservedIps, urlObj.protocol),
                lookup: (lookupHostname: string, lookupOptions: LookupOptions, callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void) => {
                    // Over plain http every address must also be loopback: a `*.localhost` name can resolve anywhere.
                    // `allowPlainHttp` lifts that rule; the policy still judges every address.
                    resolveAndPinAll(lookupHostname, reqOpts.permitReservedIps, urlObj.protocol === 'http:' && !this.#allowPlainHttp)
                        .then(addresses => {
                            // Only a new socket (or a tunnel, see TunnelAgent) looks up, and never an IP literal.
                            phases?.mark('lookup');
                            // close() ran while DNS was pending: a socket opened now would outlive it, unpooled and unreachable.
                            if (this.#closed) throw clientClosed();
                            // With autoSelectFamily (Node's default) the socket asks for every address and races them
                            // (Happy Eyeballs). Each one was validated, so whichever connects is allowed.
                            if (lookupOptions.all) callback(null, addresses);
                            else callback(null, addresses[0].address, addresses[0].family);
                        })
                        .catch(err => {
                            // Passing the error back into the Node HTTP machinery so it emits an 'error' event on req
                            callback(err as NodeJS.ErrnoException, '', 4);
                        });
                }
            });

            if (currentTimeoutMs > 0) {
                executionTimer = setTimeout(() => {
                    hop.abort();
                    req.destroy();
                    reject(absoluteTimeout(reqOpts.timeoutMs));
                }, currentTimeoutMs);
            }

            // Only while someone listens to the diagnostics events (see observeRequest): otherwise no listener is added.
            if (phases) {
                req.once('socket', socket => {
                    // A pooled socket had no lookup nor connect of its own.
                    if (req.reusedSocket) return phases.reused();
                    // The lookup is marked by `lookup` below: it can answer before this event.
                    if (socket.connecting) {
                        socket.once('connect', () => phases.mark('connect'));
                    } else {
                        // A tunnel through the proxy, handed over once up: its lookup ran inside TunnelAgent.
                        phases.mark('connect');
                    }
                    if (socket instanceof tls.TLSSocket) socket.once('secureConnect', () => phases.mark('secure'));
                });
                // The request and its body were flushed to the socket, which is up by then.
                req.once('finish', () => phases.mark('sent'));
            }

            req.on('response', (res: IncomingMessage) => {
                phases?.mark('response');
                const isRedirect = res.statusCode !== undefined && HTTP_CODES_REDIRECTS.has(res.statusCode);
                const location = res.headers.location;

                // Only a redirect that will be followed skips its body (never buffered, so never held to maxBodySize);
                // one that will not be followed is an ordinary response, body included, as on HTTP/2.
                if (isRedirect && location && canFollow(res.statusCode as number)) {
                    res.destroy(); // Dump incoming V8 buffers natively before recurse
                    req.destroy(); // Kill socket cleanly
                    clearTimeout(executionTimer);
                    return resolve({
                        statusCode: res.statusCode as number,
                        headers: res.headers,
                        data: Buffer.alloc(0),
                        isRedirect: true
                    });
                }

                // A stream hands the body over with the headers. timeoutMs covered the wait for them; from here the
                // socket's own idle timer must stop (a paused socket is idle whenever the consumer is slow) and the
                // body stream's timer, which only runs while the consumer waits for data, takes over.
                if (stream) {
                    clearTimeout(executionTimer);
                    req.setTimeout(0);
                    req.off('timeout', onSocketTimeout);
                    return resolve({
                        statusCode: res.statusCode as number,
                        headers: res.headers,
                        data: Buffer.alloc(0),
                        isRedirect: false,
                        body: createBodyStream({
                            source: res,
                            contentEncoding: res.headers['content-encoding'],
                            decompress: reqOpts.decompress,
                            maxBodySize: stream.maxBodySize,
                            declaredLength: declaredBodyLength(reqOpts.method, res.statusCode as number, res.headers),
                            socketTimeoutMs: reqOpts.socketTimeoutMs,
                            signal: reqOpts.signal,
                            tooLarge: () => bodyTooLarge(stream.maxBodySize),
                            idle: () => idleTimeout(reqOpts.socketTimeoutMs),
                            mapError: err => bodyError ?? (this.#closed ? clientClosed() : toNetworkError(err)),
                            onSourceEnd: stopUpload,
                        }),
                    });
                }

                this._consumeResponseBuffer(res, req as ClientRequest, reqOpts, executionTimer)
                    .then(({ data, wireBytes }) => {
                        // llhttp already fails a body cut short of its content-length; checked here too so both
                        // engines share one rule and a truncated body can never resolve as a success. The
                        // content-length counts the bytes on the wire, before any content-encoding is undone.
                        const declared = declaredBodyLength(reqOpts.method, res.statusCode as number, res.headers);
                        if (declared !== undefined && wireBytes !== declared) return reject(incompleteResponse());
                        resolve({
                            statusCode: res.statusCode as number,
                            headers: res.headers,
                            data,
                            isRedirect: false
                        });
                        stopUpload();
                    })
                    .catch(reject);
            });

            const onSocketTimeout = () => {
                hop.abort();
                req.destroy();
                clearTimeout(executionTimer);
                reject(idleTimeout(reqOpts.socketTimeoutMs));
            };
            req.on('timeout', onSocketTimeout);

            req.on('error', (err: Error) => {
                req.destroy();
                clearTimeout(executionTimer);
                // close() destroyed the socket: that is the reason, not the reset it causes.
                // Node's socket/TLS messages embed the resolved IP and port: map them to a code-only error.
                // A caller abort is reported as the signal's reason (Node's own AbortError only wraps it).
                reject(bodyError ?? (reqOpts.signal?.aborted ? reqOpts.signal.reason : this.#closed ? clientClosed() : toNetworkError(err)));
            });

            if (!(body instanceof StreamedBody)) {
                req.end(body);
                return;
            }
            // Each chunk is read only once the previous one reached the socket. The request ending first (answered,
            // aborted, timed out) reports its own outcome. The body's own failure ends the exchange with that error, even
            // once the server started answering: the response cannot complete without the body. A response already read
            // in full has resolved and keeps its result.
            body.pump(req).then(() => req.end(), (err: unknown) => {
                if (isSinkClosed(err)) return;
                bodyError = err;
                clearTimeout(executionTimer);
                hop.abort();
                reject(err);
                req.destroy();
            });
        });
    }

    /**
     * @param options - Already validated, serialized (`json`) and merged with the client defaults by `UltraTonClient`.
     * @param timings - Where each hop records its phases; only while someone listens to the diagnostics events.
     */
    public async request<T = unknown>(url: string, options: ResolvedRequestOptions, stream?: undefined, timings?: TimingsCollector): Promise<UltraTonResponse<T>>;
    public async request(url: string, options: ResolvedRequestOptions, stream: { maxBodySize?: number }, timings?: TimingsCollector): Promise<UltraTonStreamResponse>;
    public async request<T = unknown>(url: string, options: ResolvedRequestOptions, stream?: { maxBodySize?: number }, timings?: TimingsCollector): Promise<UltraTonResponse<T> | UltraTonStreamResponse> {
        const startTime = Date.now();
        // The hops followed so far, as the response reports them.
        const redirects: UltraTonRedirect[] = [];
        let currentUrl = url;
        let currentOptions: ResolvedRequestOptions = options;

        let reqOpts: SecureUltraTonRequestOptions = buildSafeRequestOptions(currentOptions);
        // Before connecting: a buffered body over maxRequestBodySize throws here, a streamed one as it is read.
        limitRequestBody(currentOptions.body, reqOpts.maxRequestBodySize);

        while (true) {
            if (this.#closed) throw clientClosed();
            // Before anything is resolved or opened; throws the signal's reason (an AbortError when it had none).
            reqOpts.signal?.throwIfAborted();
            const urlObj: URL = parseSafeUrl(currentUrl, undefined, this.#allowPlainHttp);

            // Node never calls `lookup` for IP-literal hosts, so the DNS pinner cannot guard them.
            // URL.hostname keeps the brackets on IPv6 literals; strip them so they parse as IPs. Hostnames pass through.
            // For a literal the "hostname" is the literal itself, which no hostname entry of an allowlist can match.
            const bareHostname = urlObj.hostname.replace(/^\[|\]$/g, '');
            assertAllowedIp(bareHostname, reqOpts.permitReservedIps, bareHostname);
            if (this.#proxy && urlObj.protocol === 'https:') assertTunnelable(this.#proxy, bareHostname);

            const currentTimeoutMs = remainingBudget(reqOpts.timeoutMs, startTime);

            const hop = await this._executeSingleNetworkHop(urlObj, reqOpts, currentOptions.body, currentTimeoutMs, reqOpts.maxRedirects > 0,
                stream && { maxBodySize: stream.maxBodySize ?? reqOpts.maxBodySize }, timings?.hop());

            if (hop.isRedirect && hop.headers.location && reqOpts.maxRedirects > 0) {
                const next = followRedirect(hop.statusCode, hop.headers.location, urlObj, currentOptions, reqOpts, redirects.length, this.#allowPlainHttp);
                redirects.push(Object.freeze({ url: currentUrl, statusCode: hop.statusCode }));
                currentUrl = next.url;
                currentOptions = next.options;
                reqOpts = buildSafeRequestOptions(currentOptions);
                continue;
            }

            const followed = redirects.length > 0 ? Object.freeze(redirects) : NO_REDIRECTS;
            if (hop.body) return createStreamResponse(hop.statusCode, hop.headers, hop.body, currentUrl, followed);
            return createResponse<T>(hop.statusCode, hop.headers, hop.data, currentUrl, followed);
        }
    }
}