import { IncomingMessage, ClientRequest } from "node:http";
import { SecureHttpError, UltraTonMemoryError, UltraTonNetworkError, UltraTonNetworkTimeoutError, UltraTonRedirectError, toNetworkError } from "../errors.ts";
import { buildSafeRequestOptions } from "../helpers/request-options.ts";
import { parseSafeUrl } from "../helpers/url-parser.ts";
import type { ResolvedRequestOptions, SecureUltraTonRequestOptions, TlsOptions } from "../types/request-options.types.ts";
import type { UltraTonResponse } from "../types/request-response.ts";
import { assertAllowedIp, policyKey, resolveAndPinAll } from "../security/dns-pinner.ts";
import type { ReservedIpPolicy } from "../security/dns-pinner.ts";
import * as http from 'node:http';
import * as https from 'node:https';
import type { LookupOptions, LookupAddress } from 'node:dns';
import { HTTP_CODES_REDIRECTS } from '../constants.ts';
import { createResponse, declaredBodyLength, incompleteResponse } from '../helpers/response.ts';
import { BodyReader } from '../helpers/body-reader.ts';

// Node only runs the custom `lookup` (the SSRF check) when it opens a NEW socket, and its default agent pools sockets by
// host:port alone, so a socket opened under one reserved-IP policy would be reused by a request under another and skip the check.
// Hence one keep-alive agent pair per policy: sockets are never shared across policies. The map belongs to one engine (one
// client), so two clients never share a socket either, whatever their policies or TLS settings.
// Idle pooled sockets are reaped after 5s, as with Node's global agent: without it a hostile server reached through N hostnames
// could pin N file descriptors for as long as it keeps them open.
// ponytail: one agent pair per distinct policy, never evicted, so the map grows with distinct allowlists; the ceiling is the
// number of policies an app uses. Same upgrade path as the compiled-allowlist cache: bound it if lists ever come from request-time input.
const IDLE_SOCKET_TIMEOUT_MS = 5000;

const clientClosed = () => new SecureHttpError('UltraTon: Client is closed.');

/** The HTTP/1.1 engine behind `UltraTonClient`. Not public: the client validates and merges the options it receives. */
export class Http1Engine {
    readonly #agentsByPolicy = new Map<string, { http: http.Agent; https: https.Agent }>();
    readonly #tls: TlsOptions;
    // Internal testing interceptor (kTransport)
    readonly #transport?: typeof https.request | typeof http.request;
    #closed = false;

    /**
     * @param tls - The client's validated `ca`/`cert`/`key`, applied to its HTTPS agents.
     * @param transport - Replacement for `http.request`/`https.request`, used strictly for internal testing.
     */
    constructor(tls: TlsOptions = {}, transport?: typeof https.request | typeof http.request) {
        this.#tls = tls;
        this.#transport = transport;
    }

    /** Destroys every pooled socket (in-flight requests on them fail) and refuses any later request. */
    public close(): void {
        this.#closed = true;
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
                http: new http.Agent({ keepAlive: true, timeout: IDLE_SOCKET_TIMEOUT_MS }),
                https: new https.Agent({ keepAlive: true, timeout: IDLE_SOCKET_TIMEOUT_MS, ...this.#tls }),
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
            tooLarge: () => new UltraTonMemoryError(`UltraTon: Body size exceeded the maximum allowed size of ${reqOpts.maxBodySize} bytes`),
            onError: () => req.destroy(),
        });

        try {
            // Leaving the loop early (throw) destroys `res`; a premature close or socket error throws here.
            for await (const chunk of res) reader.write(chunk);
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
            throw new UltraTonNetworkError('UltraTon: Connection failed (ECONNRESET).', { cause: err, code: 'ECONNRESET' });
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
        body: Buffer | undefined,
        currentTimeoutMs: number,
        followRedirects: boolean
    ): Promise<{ statusCode: number, headers: import('node:http').IncomingHttpHeaders, data: Buffer, isRedirect: boolean }> {
        return new Promise((resolve, reject) => {
            let executionTimer: NodeJS.Timeout | undefined;

            const transport = this.#transport || (urlObj.protocol === 'http:' ? http.request : https.request);
            
            // The body always goes out with its exact length, never chunked: a caller-supplied content-length or
            // transfer-encoding must not disagree with the bytes actually written. Without a body a caller
            // content-length would promise bytes that never come and the server would wait for them: drop it.
            const headers = { ...reqOpts.headers };
            if (body !== undefined) {
                headers['content-length'] = String(body.length);
                delete headers['transfer-encoding'];
            } else {
                delete headers['content-length'];
            }

            const req = transport(urlObj, {
                ...reqOpts,
                headers,
                timeout: reqOpts.socketTimeoutMs,
                agent: this.#agentFor(reqOpts.permitReservedIps, urlObj.protocol),
                lookup: (lookupHostname: string, lookupOptions: LookupOptions, callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void) => {
                    // Over plain http every address must also be loopback: a `*.localhost` name can resolve anywhere.
                    resolveAndPinAll(lookupHostname, reqOpts.permitReservedIps, urlObj.protocol === 'http:')
                        .then(addresses => {
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
                    req.destroy();
                    reject(new UltraTonNetworkTimeoutError(`UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`));
                }, currentTimeoutMs);
            }

            req.on('response', (res: IncomingMessage) => {
                const isRedirect = res.statusCode !== undefined && HTTP_CODES_REDIRECTS.has(res.statusCode);
                const location = res.headers.location;

                // Only a redirect that will be followed skips its body (never buffered, so never held to maxBodySize);
                // one that will not be followed is an ordinary response, body included, as on HTTP/2.
                if (isRedirect && location && followRedirects) {
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
                    })
                    .catch(reject);
            });

            req.on('timeout', () => {
                req.destroy();
                clearTimeout(executionTimer);
                reject(new UltraTonNetworkTimeoutError(`UltraTon: Socket completely idle for ${reqOpts.socketTimeoutMs}ms.`));
            });

            req.on('error', (err: Error) => {
                req.destroy();
                clearTimeout(executionTimer);
                // close() destroyed the socket: that is the reason, not the reset it causes.
                // Node's socket/TLS messages embed the resolved IP and port: map them to a code-only error.
                // A caller abort is reported as the signal's reason (Node's own AbortError only wraps it).
                reject(reqOpts.signal?.aborted ? reqOpts.signal.reason : this.#closed ? clientClosed() : toNetworkError(err));
            });

            req.end(body);
        });
    }

    /**
     * @param options - Already validated, serialized (`json`) and merged with the client defaults by `UltraTonClient`.
     */
    public async request<T = unknown>(url: string, options: ResolvedRequestOptions): Promise<UltraTonResponse<T>> {
        const startTime = Date.now();
        let redirectCount = 0;
        let currentUrl = url;
        let currentOptions: ResolvedRequestOptions = options;

        let reqOpts: SecureUltraTonRequestOptions = buildSafeRequestOptions(currentOptions);

        while (true) {
            if (this.#closed) throw clientClosed();
            // Before anything is resolved or opened; throws the signal's reason (an AbortError when it had none).
            reqOpts.signal?.throwIfAborted();
            const urlObj: URL = parseSafeUrl(currentUrl);

            // Node never calls `lookup` for IP-literal hosts, so the DNS pinner cannot guard them.
            // URL.hostname keeps the brackets on IPv6 literals; strip them so they parse as IPs. Hostnames pass through.
            // For a literal the "hostname" is the literal itself, which no hostname entry of an allowlist can match.
            const bareHostname = urlObj.hostname.replace(/^\[|\]$/g, '');
            assertAllowedIp(bareHostname, reqOpts.permitReservedIps, bareHostname);

            let currentTimeoutMs = reqOpts.timeoutMs;
            if (reqOpts.timeoutMs > 0) {
                const elapsed = Date.now() - startTime;
                currentTimeoutMs = Math.max(0, reqOpts.timeoutMs - elapsed);
                if (currentTimeoutMs === 0) {
                    throw new UltraTonNetworkTimeoutError(`UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`);
                }
            }

            const hop = await this._executeSingleNetworkHop(urlObj, reqOpts, currentOptions.body, currentTimeoutMs, reqOpts.maxRedirects > 0);

            if (hop.isRedirect && hop.headers.location && reqOpts.maxRedirects > 0) {
                if (redirectCount >= reqOpts.maxRedirects) {
                    throw new UltraTonRedirectError(`UltraTon: Max redirects (${reqOpts.maxRedirects}) exceeded.`);
                }

                redirectCount++;

                const nextUrlObj: URL = parseSafeUrl(hop.headers.location, currentUrl);

                // A response fetched over TLS must never steer the request onto plaintext (e.g. the http loopback escape hatch).
                if (urlObj.protocol === 'https:' && nextUrlObj.protocol === 'http:') {
                    throw new SecureHttpError('UltraTon: Redirect from https to http is not allowed.', { code: 'ERR_ULTRATON_DOWNGRADE' });
                }

                // sanitizeHeaders already lowercased every key
                const nextHeaders = { ...reqOpts.headers } as Record<string, string | string[] | undefined>;

                if (urlObj.origin !== nextUrlObj.origin) {
                    currentOptions = { ...currentOptions, auth: undefined };
                    delete nextHeaders['authorization'];
                    delete nextHeaders['cookie'];
                    delete nextHeaders['proxy-authorization'];
                    delete nextHeaders['host'];
                }

                let nextMethod = reqOpts.method;
                let nextBody = currentOptions.body;

                if (hop.statusCode === 303 || ((hop.statusCode === 301 || hop.statusCode === 302) && nextMethod !== 'GET' && nextMethod !== 'HEAD')) {
                    nextMethod = 'GET';
                    nextBody = undefined;
                    delete nextHeaders['content-length'];
                    delete nextHeaders['content-type'];
                    delete nextHeaders['transfer-encoding'];
                }

                currentUrl = nextUrlObj.href;
                currentOptions = { ...currentOptions, method: nextMethod, headers: nextHeaders, body: nextBody };
                reqOpts = buildSafeRequestOptions(currentOptions);

                continue;
            }

            return createResponse<T>(hop.statusCode, hop.headers, hop.data);
        }
    }
}