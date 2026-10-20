import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { UltraTonClient } from '../src/engines/http1.ts';
import { SecureHttpError, UltraTonNetworkTimeoutError, UltraTonRedirectError } from '../src/errors.ts';
import https from 'node:https';

describe('UltraTonClient - Sprint 4 Anti-SSRF & Redirects', () => {

    const createSmartMockTransport = () => {
        return (urlObj: URL, options: any, callback?: any) => {
            const req = new EventEmitter();
            const reqBody: Buffer[] = [];
            
            (req as any).write = (chunk: any) => {
                reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            };
            
            (req as any).destroy = () => {};
            
            (req as any).end = (chunk?: any) => {
                if (chunk) reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
                const res = Readable.from([Buffer.from(JSON.stringify({}))]);

                // MOCK ROUTING TABLE
                if (urlObj.pathname === '/default-deny') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'https://example.com/target' };
                } 
                else if (urlObj.pathname === '/tarpit-step1') {
                    (res as any).statusCode = 301;
                    (res as any).headers = { location: 'https://example.com/tarpit-step2' };
                }
                else if (urlObj.pathname === '/tarpit-step2') {
                    // Tarpit: Never emits 'response', simulating a hung socket after redirect,
                    // allowing the executionTimer to eventually kill it.
                    return; 
                }
                else if (urlObj.pathname === '/infinite') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'https://example.com/infinite' };
                }
                else if (urlObj.host.toLowerCase() === 'domaina.com' && urlObj.pathname === '/hop') {
                    (res as any).statusCode = 307;
                    (res as any).headers = { location: 'https://evil-domain.com/steal' };
                }
                else if (urlObj.host.toLowerCase() === 'evil-domain.com' && urlObj.pathname === '/steal') {
                    (res as any).statusCode = 200;
                    // Lowercase the options headers to match node core request behavior for assertions
                    const echoedHeaders: any = {};
                    if (options.headers) {
                        for (const k of Object.keys(options.headers)) {
                            echoedHeaders[k.toLowerCase()] = options.headers[k];
                        }
                    }
                    (res as any).headers = echoedHeaders; 
                }
                else if (urlObj.pathname === '/to-metadata') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'https://169.254.169.254/latest/meta-data' };
                }
                else if (urlObj.pathname === '/downgrade') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'http://127.0.0.1:1/x' };
                }
                else if (urlObj.pathname === '/start') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'https://example.com/mid' };
                }
                else if (urlObj.pathname === '/mid') {
                    (res as any).statusCode = 302;
                    (res as any).headers = { location: 'http://127.0.0.1:1/end' };
                }
                else if (urlObj.pathname === '/smuggle-start') {
                    (res as any).statusCode = 303;
                    (res as any).headers = { location: 'https://example.com/smuggle-end' };
                }
                else if (urlObj.pathname === '/smuggle-end') {
                    (res as any).statusCode = 200;
                    
                    const hasContentType = options.headers ? Object.keys(options.headers).some(k => k.toLowerCase() === 'content-type') : false;
                    const hasContentLength = options.headers ? Object.keys(options.headers).some(k => k.toLowerCase() === 'content-length') : false;

                    (res as any).headers = { 
                        'x-received-method': options.method,
                        'x-received-body-length': Buffer.concat(reqBody).length.toString(),
                        'x-has-content-type': String(hasContentType),
                        'x-has-content-length': String(hasContentLength)
                    };
                }
                else {
                    (res as any).statusCode = 404;
                    (res as any).headers = {};
                }

                if (callback) callback(res);
                req.emit('response', res);
            };
            return req as any;
        };
    };

    it('Should cleanly return 3xx when maxRedirects is 0 (Default Deny)', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        const res = await client.get('https://example.com/default-deny'); // Implicitly maxRedirects: 0
        assert.strictEqual(res.statusCode, 302);
        assert.strictEqual(res.headers.location, 'https://example.com/target');
    });

    it('Should throw UltraTonNetworkTimeoutError if absolute timeout is hit during a tarpit redirect', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        await assert.rejects(
            client.get('https://example.com/tarpit-step1', { maxRedirects: 5, timeoutMs: 50 }),
            (err: any) => err instanceof UltraTonNetworkTimeoutError && err.message.includes('exceeded')
        );
    });

    it('Should throw UltraTonRedirectError on infinite local loopback', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        await assert.rejects(
            client.get('https://example.com/infinite', { maxRedirects: 3 }),
            (err: any) => err instanceof UltraTonRedirectError && err.message.includes('Max redirects (3) exceeded')
        );
    });

    it('Should case-insensitively strip credentials upon domain hopping', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        const res = await client.get('https://domaina.com/hop', {
            maxRedirects: 1,
            headers: {
                'aUthorizAtion': 'Bearer secret',
                'cOOkie': 'session=victim',
                'pRoXy-AuThoriZatIon': 'Basic secret_proxy_token',
                'X-Safe-Header': 'keep-me'
            }
        });
        assert.strictEqual(res.statusCode, 200);
        // Ensure sensitive headers were dropped
        assert.strictEqual(res.headers['authorization'], undefined);
        assert.strictEqual(res.headers['cookie'], undefined);
        assert.strictEqual(res.headers['proxy-authorization'], undefined);
        // Ensure safe headers were kept
        assert.strictEqual(res.headers['x-safe-header'], 'keep-me');
    });

    it('Should block a redirect hop to a reserved IP literal', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        await assert.rejects(
            client.get('https://example.com/to-metadata', { maxRedirects: 1 }),
            (err: any) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
        );
    });

    it('Should reject an https to http redirect downgrade even with permitReservedIps, before connecting to the target', async () => {
        const inner = createSmartMockTransport();
        const hostsReached: string[] = [];
        const client = new UltraTonClient(((urlObj: URL, options: any, callback?: any) => {
            hostsReached.push(urlObj.host);
            return inner(urlObj, options, callback);
        }) as any);

        await assert.rejects(
            client.get('https://example.com/downgrade', { permitReservedIps: true, maxRedirects: 1 }),
            (err: any) => err instanceof SecureHttpError && /Redirect from https to http is not allowed/.test(err.message)
        );
        // Only the original https hop was ever attempted: the http://127.0.0.1 target never got a connection.
        assert.deepStrictEqual(hostsReached, ['example.com']);
    });

    it('Should reject an https to http downgrade in the middle of a chain that started on http', async () => {
        const inner = createSmartMockTransport();
        const reached: string[] = [];
        const client = new UltraTonClient(((urlObj: URL, options: any, callback?: any) => {
            reached.push(urlObj.href);
            return inner(urlObj, options, callback);
        }) as any);

        // http://127.0.0.1:1/start -> https://example.com/mid -> http://127.0.0.1:1/end
        await assert.rejects(
            client.get('http://127.0.0.1:1/start', { permitReservedIps: true, maxRedirects: 5 }),
            (err: any) => err instanceof SecureHttpError && /Redirect from https to http is not allowed/.test(err.message)
        );
        // The check applies to every hop, not only to a chain that started on https: /end was never contacted.
        assert.deepStrictEqual(reached, ['http://127.0.0.1:1/start', 'https://example.com/mid']);
    });

    it('Should still follow a redirect that upgrades from http to https', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        // /default-deny redirects to https://example.com/target, which the mock answers with its 404 fallback.
        const res = await client.get('http://127.0.0.1:1/default-deny', { permitReservedIps: true, maxRedirects: 1 });
        assert.strictEqual(res.statusCode, 404);
    });

    it('Should block a NAT64 literal embedding a private IPv4', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        await assert.rejects(
            client.get('https://[64:ff9b::a00:5]/'),
            (err: any) => err instanceof SecureHttpError && /prohibited internal\/reserved/.test(err.message)
        );
    });

    it('Should not block a public IP literal', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        const res = await client.get('https://8.8.8.8/anything');
        assert.strictEqual(res.statusCode, 404); // mock fallback route: reached the transport
    });

    it('Should downgrade POST to GET on 303 and strip smuggling headers and body', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        const res = await client.post('https://example.com/smuggle-start', {
            body: 'massive-payload',
            maxRedirects: 1,
            headers: {
                'Content-Type': 'text/plain',
                'Content-Length': '15'
            }
        });
        
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.headers['x-received-method'], 'GET');
        assert.strictEqual(res.headers['x-received-body-length'], '0'); // Body was dropped
        assert.strictEqual(res.headers['x-has-content-type'], 'false');
        assert.strictEqual(res.headers['x-has-content-length'], 'false');
    });
});
