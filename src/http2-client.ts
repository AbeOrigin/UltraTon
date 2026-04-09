import { Buffer } from "node:buffer";
import type { ClientHttp2Session, ClientHttp2Stream, IncomingHttpHeaders, OutgoingHttpHeaders } from "node:http2";
import type { UltraTonResponse } from "./types/request-response.ts";
import { Http2SessionManager } from "./classes/http-session-mannager.ts";
import type { UltraTonOptionsHttp2, UltraTonRequestOptionsHttp2 } from "./types/request-options.types.ts";
import { SecureHttpError } from "./exceptions/secure-http.error.ts";
import { UltraTonParseError } from "./exceptions/parse.error.ts";
import { UltraTonRedirectError } from "./exceptions/redirect.error.ts";
import { UltraTonMemoryError } from "./exceptions/out-of-memory.error.ts";
import { HTTP_CODES_REDIRECTS } from "./constants/http-codes-redirects.ts";
import { MAX_REDIRECTS_CEILING } from "./constants/limits.ts";
import { parseSecurePayload } from "./helpers/payload-parser.ts";

const globalPool = new Http2SessionManager();

export class UltraTonHTTP2 {

    readonly #sessionManager: Http2SessionManager;
    readonly #globalOptions: UltraTonOptionsHttp2;

    constructor(options: UltraTonOptionsHttp2 = {}) {
        this.#globalOptions = options;
        if (options.isolatePool) {
            this.#sessionManager = new Http2SessionManager(options.tlsSettings);
            return;
        }
        this.#sessionManager = globalPool;
    }

    public async get<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'GET' });
    }

    public async post<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'POST' });
    }

    public async put<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'PUT', });
    }

    public async patch<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'PATCH' });
    }

    public async delete<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'DELETE' });
    }

    public async head<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'HEAD' });
    }

    public async options<T = unknown>(url: string, options?: UltraTonRequestOptionsHttp2): Promise<UltraTonResponse<T>> {
        return this._request<T>(url, { ...options, method: 'OPTIONS' });
    }

    private async _request<T = unknown>(targetUrl: string, options: UltraTonRequestOptionsHttp2 = {}): Promise<UltraTonResponse<T>> {
        let currentUrl = targetUrl;
        let currentOptions = { ...options };
        let redirectCount = 0;
        const maxRedirects = Math.min(currentOptions.maxRedirects ?? this.#globalOptions.maxRedirects ?? 0, MAX_REDIRECTS_CEILING);

        while (true) {
            const parsedUrl = new URL(currentUrl);
            const origin = parsedUrl.origin;
            const path = parsedUrl.pathname + parsedUrl.search;

            const session = await this.#sessionManager.getSession(origin);

            const safeHeaders = this.#sanitizeHeaders(currentOptions.headers || {});

            if (currentOptions.body) {
                safeHeaders['content-length'] = Buffer.byteLength(currentOptions.body).toString();
            }

            const method = (currentOptions.method || 'GET').toUpperCase();

            const pseudoHeaders: OutgoingHttpHeaders = {
                ':method': method,
                ':path': path,
                ':authority': parsedUrl.host,
                ...safeHeaders
            };

            const streamTimeoutMs = currentOptions.timeoutMs ?? this.#globalOptions.timeoutMs ?? 30_000;
            const maxBodySize = currentOptions.maxBodySize ?? this.#globalOptions.maxBodySize ?? 2_097_152;

            const response = await this.#executeStream<T>(session, pseudoHeaders, currentOptions.body, streamTimeoutMs, maxBodySize);

            const statusCode = response.statusCode;
            const location = response.headers.location;

            if (statusCode && HTTP_CODES_REDIRECTS.has(statusCode) && location && typeof location === 'string') {
                if (maxRedirects > 0) {
                    if (redirectCount >= maxRedirects) {
                        throw new UltraTonRedirectError(`UltraTon: Max redirects (${maxRedirects}) exceeded.`);
                    }

                    redirectCount++;

                    const nextUrl = new URL(location, currentUrl);
                    const nextHeaders = { ...currentOptions.headers } as Record<string, string | string[] | undefined>;

                    if (parsedUrl.origin !== nextUrl.origin) {
                        for (const key of Object.keys(nextHeaders)) {
                            const lowerKey = key.toLowerCase();
                            if (lowerKey === 'authorization' || lowerKey === 'cookie' || lowerKey === 'proxy-authorization') {
                                delete nextHeaders[key];
                            }
                        }
                    }

                    let nextMethod = method;
                    let nextBody = currentOptions.body;

                    if (statusCode === 303 || ((statusCode === 301 || statusCode === 302) && nextMethod !== 'GET' && nextMethod !== 'HEAD')) {
                        nextMethod = 'GET';
                        nextBody = undefined;

                        for (const key of Object.keys(nextHeaders)) {
                            const lowerKey = key.toLowerCase();
                            if (lowerKey === 'content-length' || lowerKey === 'content-type' || lowerKey === 'transfer-encoding') {
                                delete nextHeaders[key];
                            }
                        }
                    }

                    currentUrl = nextUrl.href;
                    currentOptions = { ...currentOptions, method: nextMethod, headers: nextHeaders, body: nextBody };

                    continue;
                }
            }

            return response;
        }
    }

    #sanitizeHeaders(headers: UltraTonRequestOptionsHttp2['headers']): Record<string, string | string[] | undefined> {
        const clean: Record<string, string | string[] | undefined> = {};
        for (const [key, value] of Object.entries(headers || {})) {
            clean[key.toLowerCase()] = value;
        }
        return clean;
    }

    #executeStream<T = unknown>(session: ClientHttp2Session, pseudoHeaders: any, body: Buffer | string | undefined, streamTimeoutMs: number, maxBodySize: number): Promise<UltraTonResponse<T>> {
        return new Promise((resolve, reject) => {
            let settled = false;
            let statusCode: number | undefined;
            let responseHeaders: IncomingHttpHeaders = {};
            const chunks: Buffer[] = [];

            let stream: ClientHttp2Stream;

            try {
                stream = session.request(pseudoHeaders);
            } catch (err: unknown) {
                return reject(new SecureHttpError(`UltraTon: Failed to initialize HTTP/2 stream: ${err instanceof Error ? err.message : String(err)}`));
            }

            const streamTimer = streamTimeoutMs > 0
                ? setTimeout(() => {
                    if (settled) return;
                    settled = true;
                    stream.close();
                    reject(new SecureHttpError('UltraTon: HTTP/2 stream execution timeout exceeded.'));
                }, streamTimeoutMs)
                : undefined;

            stream.on('response', (headers) => {
                if (settled) return;
                statusCode = Number(headers[':status']);
                responseHeaders = headers;

                if (pseudoHeaders[':method'] === 'HEAD') {
                    settled = true;
                    clearTimeout(streamTimer);
                    stream.close();

                    return resolve({
                        statusCode,
                        headers: responseHeaders,
                        body: Buffer.alloc(0),
                        json: (): T => ({} as T)
                    });
                }
            });

            let totalBytes = 0;
            stream.on('data', (chunk: Buffer) => {
                if (settled) return;
                totalBytes += chunk.length;
                if (totalBytes > maxBodySize) {
                    settled = true;
                    clearTimeout(streamTimer);
                    stream.close();
                    reject(new UltraTonMemoryError(`UltraTon: HTTP/2 response body exceeded the maximum allowed size of ${maxBodySize} bytes.`));
                    return;
                }
                chunks.push(chunk);
            });

            stream.on('end', () => {
                if (settled) return;
                settled = true;
                clearTimeout(streamTimer);

                const data = Buffer.concat(chunks);

                resolve({
                    statusCode,
                    headers: responseHeaders,
                    body: parseSecurePayload<T>(data, responseHeaders['content-type']),
                    json: (): T => {
                        try {
                            if (data.length === 0) return {} as T;
                            return JSON.parse(data.toString('utf-8')) as T;
                        } catch (e: unknown) {
                            throw new UltraTonParseError(`UltraTon: Failed to parse JSON response payload.`);
                        }
                    }
                });
            });

            stream.on('error', (err: Error) => {
                if (settled) return;
                settled = true;
                clearTimeout(streamTimer);
                reject(new SecureHttpError(`UltraTon stream error: ${err.message}`));
            });

            if (body) {
                stream.write(body);
            }

            stream.end();
        });
    }
}