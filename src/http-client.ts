import { IncomingMessage, ClientRequest } from "node:http";
import { UltraTonNetworkTimeoutError } from "./exceptions/network-timeout.error.ts";
import { UltraTonMemoryError } from "./exceptions/out-of-memory.error.ts";
import { SecureHttpError } from "./exceptions/secure-http.error.ts";
import { UltraTonRedirectError } from "./exceptions/redirect.error.ts";
import { UltraTonParseError } from "./exceptions/parse.error.ts";
import { buildSafeRequestOptions } from "./helpers/request-options.ts";
import { parseSafeUrl } from "./helpers/url-parser.ts";
import type { SecureUltraTonRequestOptions, UltraTonRequestOptions } from "./types/request-options.types.ts";
import type { UltraTonResponse } from "./types/request-response.ts";
import * as http from 'node:http';
import * as https from 'node:https';
import { HTTP_CODES_REDIRECTS } from "./constants/http-codes-redirects.ts";


export class UltraTonClient {

    constructor() {
        // Transport dynamically assigned per network hop to support localhost HTTP escape hatch
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

    private _consumeResponseBuffer(
        res: IncomingMessage,
        req: ClientRequest,
        reqOpts: SecureUltraTonRequestOptions,
        executionTimer: NodeJS.Timeout | undefined
    ): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            let settled = false;
            let currentBodySize = 0;
            const chunks: Buffer[] = [];

            res.on('data', (chunk: Buffer) => {
                if (settled) return;
                currentBodySize += chunk.length;
                if (currentBodySize > reqOpts.maxBodySize) {
                    settled = true;
                    res.destroy();
                    req.destroy();
                    chunks.length = 0;
                    clearTimeout(executionTimer);
                    reject(new UltraTonMemoryError(`UltraTon: Body size exceeded the maximum allowed size of ${reqOpts.maxBodySize} bytes`));
                    return;
                }
                chunks.push(chunk);
            });

            res.on('aborted', () => {
                if (settled) return;
                settled = true;
                clearTimeout(executionTimer);
                reject(new SecureHttpError('UltraTon: The connection was abruptly aborted by the server.'));
            });

            res.on('close', () => {
                if (settled) return;
                settled = true;
                clearTimeout(executionTimer);
                reject(new SecureHttpError('UltraTon: The incoming network stream was closed prematurely.'));
            });

            res.on('error', (err: Error) => {
                if (settled) return;
                settled = true;
                clearTimeout(executionTimer);
                reject(err);
            });

            res.on('end', () => {
                if (settled) return;
                settled = true;
                clearTimeout(executionTimer);
                resolve(Buffer.concat(chunks, currentBodySize));
            });
        });
    }

    private _executeSingleNetworkHop(
        urlObj: URL,
        reqOpts: SecureUltraTonRequestOptions,
        options: UltraTonRequestOptions,
        currentTimeoutMs: number
    ): Promise<{ statusCode: number, headers: import('node:http').IncomingHttpHeaders, data: Buffer, isRedirect: boolean }> {
        return new Promise((resolve, reject) => {
            let executionTimer: NodeJS.Timeout | undefined;

            const transport = urlObj.protocol === 'http:' ? http.request : https.request;
            
            const req = transport(urlObj, {
                ...reqOpts,
                timeout: reqOpts.socketTimeoutMs,
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

        let reqOpts: SecureUltraTonRequestOptions = buildSafeRequestOptions({
            method: currentOptions.method || 'GET',
            headers: currentOptions.headers || {},
            ...currentOptions
        });

        while (true) {
            const urlObj: URL = parseSafeUrl(currentUrl);

            let currentTimeoutMs = reqOpts.timeoutMs;
            if (reqOpts.timeoutMs > 0) {
                const elapsed = Date.now() - startTime;
                currentTimeoutMs = Math.max(0, reqOpts.timeoutMs - elapsed);
                if (currentTimeoutMs === 0) {
                    throw new UltraTonNetworkTimeoutError(`UltraTon: Absolute execution time of ${reqOpts.timeoutMs}ms exceeded.`);
                }
            }

            const hop = await this._executeSingleNetworkHop(urlObj, reqOpts, currentOptions, currentTimeoutMs);

            if (hop.isRedirect && hop.headers.location && typeof hop.headers.location === 'string') {
                if (reqOpts.maxRedirects > 0) {
                    if (redirectCount >= reqOpts.maxRedirects) {
                        throw new UltraTonRedirectError(`UltraTon: Max redirects (${reqOpts.maxRedirects}) exceeded.`);
                    }

                    redirectCount++;
                    const location = hop.headers.location;

                    const nextUrlObj: URL = parseSafeUrl(location, currentUrl);
                    const originalUrlObj = urlObj;
                    const nextHeaders = { ...reqOpts.headers } as Record<string, string | string[] | undefined>;

                    if (originalUrlObj.origin !== nextUrlObj.origin) {
                        for (const key of Object.keys(nextHeaders)) {
                            const lowerKey = key.toLowerCase();
                            if (lowerKey === 'authorization' || lowerKey === 'cookie') {
                                delete nextHeaders[key];
                            }
                        }
                    }

                    let nextMethod = reqOpts.method;
                    let nextBody = currentOptions.body;

                    if (hop.statusCode === 303 || ((hop.statusCode === 301 || hop.statusCode === 302) && nextMethod !== 'GET' && nextMethod !== 'HEAD')) {
                        nextMethod = 'GET';
                        nextBody = undefined;

                        for (const key of Object.keys(nextHeaders)) {
                            const lowerKey = key.toLowerCase();
                            if (lowerKey === 'content-length' || lowerKey === 'content-type' || lowerKey === 'transfer-encoding') {
                                delete nextHeaders[key];
                            }
                        }
                    }

                    currentUrl = nextUrlObj.href;
                    currentOptions = { ...currentOptions, method: nextMethod, headers: nextHeaders, body: nextBody };
                    reqOpts = buildSafeRequestOptions({
                        ...currentOptions,
                        headers: nextHeaders,
                        method: nextMethod
                    });

                    continue;
                }
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