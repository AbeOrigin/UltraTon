import { IncomingMessage, ClientRequest } from "node:http";
import { SecureHttpError, UltraTonMemoryError, UltraTonNetworkTimeoutError, UltraTonParseError, UltraTonRedirectError } from "./errors.ts";
import { buildSafeRequestOptions } from "./helpers/request-options.ts";
import { parseSafeUrl } from "./helpers/url-parser.ts";
import type { SecureUltraTonRequestOptions, UltraTonRequestOptions } from "./types/request-options.types.ts";
import type { UltraTonResponse } from "./types/request-response.ts";
import { assertAllowedIp, resolveAndPinHost } from "./security/dns-pinner.ts";
import * as http from 'node:http';
import * as https from 'node:https';
import type { LookupOptions, LookupAddress } from 'node:dns';

const HTTP_CODES_REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);


export class UltraTonClient {
    // Internal testing interceptor
    #transport?: typeof https.request | typeof http.request;

    /**
     * @param transportInterceptor - Optional transport layer interceptor used strictly for internal testing.
     */
    constructor(transportInterceptor?: typeof https.request | typeof http.request) {
        this.#transport = transportInterceptor;
    }

    public async get<T = unknown>(url: string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'GET' });
    }

    public async post<T = unknown>(url: string, body: Buffer | string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'POST', body });
    }

    public async put<T = unknown>(url: string, body: Buffer | string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'PUT', body });
    }

    public async patch<T = unknown>(url: string, body: Buffer | string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'PATCH', body });
    }

    public async delete<T = unknown>(url: string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'DELETE' });
    }

    public async head<T = unknown>(url: string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'HEAD' });
    }

    public async options<T = unknown>(url: string, options?: Omit<UltraTonRequestOptions, 'method' | 'body'>): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'OPTIONS' });
    }

    private async _consumeResponseBuffer(
        res: IncomingMessage,
        req: ClientRequest,
        reqOpts: SecureUltraTonRequestOptions,
        executionTimer: NodeJS.Timeout | undefined
    ): Promise<Buffer> {
        const chunks: Buffer[] = [];
        let currentBodySize = 0;

        try {
            // Leaving the loop early (throw) destroys `res`; a premature close or socket error throws here.
            for await (const chunk of res) {
                currentBodySize += chunk.length;
                if (currentBodySize > reqOpts.maxBodySize) {
                    req.destroy();
                    throw new UltraTonMemoryError(`UltraTon: Body size exceeded the maximum allowed size of ${reqOpts.maxBodySize} bytes`);
                }
                chunks.push(chunk);
            }
        } catch (err: unknown) {
            if (err instanceof UltraTonMemoryError) throw err;
            throw new SecureHttpError('UltraTon: The incoming network stream was closed prematurely.');
        } finally {
            clearTimeout(executionTimer);
        }

        return Buffer.concat(chunks, currentBodySize);
    }

    private _executeSingleNetworkHop(
        urlObj: URL,
        reqOpts: SecureUltraTonRequestOptions,
        options: UltraTonRequestOptions,
        currentTimeoutMs: number
    ): Promise<{ statusCode: number, headers: import('node:http').IncomingHttpHeaders, data: Buffer, isRedirect: boolean }> {
        return new Promise((resolve, reject) => {
            let executionTimer: NodeJS.Timeout | undefined;

            const transport = this.#transport || (urlObj.protocol === 'http:' ? http.request : https.request);
            
            const req = transport(urlObj, {
                ...reqOpts,
                timeout: reqOpts.socketTimeoutMs,
                lookup: (lookupHostname: string, lookupOptions: LookupOptions, callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family: number) => void) => {
                    resolveAndPinHost(lookupHostname, reqOpts.permitReservedIps)
                        .then(ip => {
                            const family = ip.includes(':') ? 6 : 4;
                            const result = lookupOptions.all ? [{ address: ip, family }] : ip;
                            callback(null, result, family);
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

                if (isRedirect && location) {
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
                    .then(data => {
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
                reject(err);
            });

            if (options.body) req.write(options.body);

            req.end();
        });
    }

    private async _request<T = unknown>(url: string, options: UltraTonRequestOptions): Promise<UltraTonResponse<T>> {
        const startTime = Date.now();
        let redirectCount = 0;
        let currentUrl = url;
        let currentOptions = { ...options };

        let reqOpts: SecureUltraTonRequestOptions = buildSafeRequestOptions(currentOptions);

        while (true) {
            const urlObj: URL = parseSafeUrl(currentUrl);

            // Node never calls `lookup` for IP-literal hosts, so the DNS pinner cannot guard them.
            // URL.hostname keeps the brackets on IPv6 literals; strip them so they parse as IPs. Hostnames pass through.
            assertAllowedIp(urlObj.hostname.replace(/^\[|\]$/g, ''), reqOpts.permitReservedIps);

            let currentTimeoutMs = reqOpts.timeoutMs;
            if (reqOpts.timeoutMs > 0) {
                const elapsed = Date.now() - startTime;
                currentTimeoutMs = Math.max(0, reqOpts.timeoutMs - elapsed);
                if (currentTimeoutMs === 0) {
                    throw new UltraTonNetworkTimeoutError(`UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`);
                }
            }

            const hop = await this._executeSingleNetworkHop(urlObj, reqOpts, currentOptions, currentTimeoutMs);

            if (hop.isRedirect && hop.headers.location && reqOpts.maxRedirects > 0) {
                if (redirectCount >= reqOpts.maxRedirects) {
                    throw new UltraTonRedirectError(`UltraTon: Max redirects (${reqOpts.maxRedirects}) exceeded.`);
                }

                redirectCount++;

                const nextUrlObj: URL = parseSafeUrl(hop.headers.location, currentUrl);
                // sanitizeHeaders already lowercased every key
                const nextHeaders = { ...reqOpts.headers } as Record<string, string | string[] | undefined>;

                if (urlObj.origin !== nextUrlObj.origin) {
                    currentOptions = { ...currentOptions, auth: undefined };
                    delete nextHeaders['authorization'];
                    delete nextHeaders['cookie'];
                    delete nextHeaders['proxy-authorization'];
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

            return {
                statusCode: hop.statusCode,
                headers: hop.headers,
                data: hop.data,
                json(): T {
                    try {
                        return JSON.parse(hop.data.toString('utf-8')) as T;
                    } catch (e: unknown) {
                        throw new UltraTonParseError(`UltraTon: Failed to parse JSON response payload.`);
                    }
                }
            };
        }
    }
}