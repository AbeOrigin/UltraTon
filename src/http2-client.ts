import { Buffer } from "node:buffer";
import { ClientHttp2Session, ClientHttp2Stream, IncomingHttpHeaders } from "node:http2";
import { UltraTonResponse } from "./types/request-response.ts";
import { Http2SessionManager } from "./classes/http-session-mannager.ts";
import { UltraTonOptionsHttp2, UltraTonRequestOptionsHttp2 } from "./types/request-options.types.ts";
import { SecureHttpError } from "./exceptions/secure-http.error.ts";
import { UltraTonParseError } from "./exceptions/parse.error.ts";

const globalPool = new Http2SessionManager();

export class UltraTonHTTP2 {

    readonly #sessionManager: Http2SessionManager;

    constructor(options: UltraTonOptionsHttp2 = {}) {
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
        const parsedUrl = new URL(targetUrl);
        const origin = parsedUrl.origin;
        const path = parsedUrl.pathname + parsedUrl.search;

        const session = this.#sessionManager.getSession(origin);

        const safeHeaders = this.#sanitizeHeaders(options.headers || {});

        if (options.body) {
            safeHeaders['content-length'] = Buffer.byteLength(options.body).toString();
        }

        const method = (options.method || 'GET').toUpperCase();

        const pseudoHeaders = {
            ':method': method,
            ':path': path,
            ':authority': parsedUrl.host,
            ...safeHeaders
        };

        return this.#executeStream<T>(session, pseudoHeaders, options.body, method);
    }

    #sanitizeHeaders(headers: UltraTonRequestOptionsHttp2['headers']): Record<string, string | string[] | undefined> {
        const clean: Record<string, string | string[] | undefined> = {};
        for (const [key, value] of Object.entries(headers || {})) {
            clean[key.toLowerCase()] = value;
        }
        return clean;
    }

    #executeStream<T = unknown>(session: ClientHttp2Session, pseudoHeaders: any, body?: Buffer | string, method?: string): Promise<UltraTonResponse<T>> {
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

            stream.on('response', (headers) => {
                if (settled) return;
                statusCode = headers[':status'];
                responseHeaders = headers as import('node:http').IncomingHttpHeaders;
            });

            stream.on('data', (chunk: Buffer) => {
                if (settled) return;
                chunks.push(chunk);
            });

            stream.on('end', () => {
                if (settled) return;
                settled = true;

                const data = Buffer.concat(chunks);

                resolve({
                    statusCode,
                    headers: responseHeaders,
                    data,
                    json: (): T => {
                        try {
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

                // Protect V8 from floating socket errors by instantly rejecting
                reject(new SecureHttpError(`UltraTon stream error: ${err.message}`));
            });

            if (body) {
                stream.write(body);
            }

            stream.end();
        });
    }
}