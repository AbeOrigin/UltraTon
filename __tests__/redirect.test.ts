import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonRedirectError } from '../src/exceptions/redirect.error.ts';
import { UltraTonNetworkTimeoutError } from '../src/exceptions/network-timeout.error.ts';

describe('UltraTonClient - Sprint 4 Anti-SSRF & Redirects', () => {

    const createSmartMockTransport = () => {
        return (urlObj: URL, options: any, callback?: any) => {
            const req = new EventEmitter();
            const reqBody: Buffer[] = [];
            
            (req as any).write = (chunk: any) => {
                reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            };
            
            (req as any).destroy = () => {};
            
            (req as any).end = () => {
                const res = new EventEmitter();
                (res as any).destroy = () => {};
                
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
                
                if (urlObj.pathname !== '/tarpit-step2') {
                    setImmediate(() => {
                        res.emit('data', Buffer.from(JSON.stringify({})));
                        res.emit('end');
                    });
                }
            };
            return req as any;
        };
    };

    it('Should cleanly return 3xx when maxRedirects is 0 (Default Deny)', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        const res = await client.get('https://example.com/default-deny'); // Implicitly maxRedirects: 0
        assert.strictEqual(res.statusCode, 302);
        assert.strictEqual(res.headers.location, 'https://example.com/target');
    });

    it('Should throw UltraTonNetworkTimeoutError if absolute timeout is hit during a tarpit redirect', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        await assert.rejects(
            client.get('https://example.com/tarpit-step1', { maxRedirects: 5, timeoutMs: 50 }),
            (err: any) => err instanceof UltraTonNetworkTimeoutError && err.message.includes('exceeded')
        );
    });

    it('Should throw UltraTonRedirectError on infinite local loopback', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        await assert.rejects(
            client.get('https://example.com/infinite', { maxRedirects: 3 }),
            (err: any) => err instanceof UltraTonRedirectError && err.message.includes('Max redirects (3) exceeded')
        );
    });

    it('Should case-insensitively strip credentials upon domain hopping', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        const res = await client.get('https://domaina.com/hop', {
            maxRedirects: 1,
            headers: {
                'aUthorizAtion': 'Bearer secret',
                'cOOkie': 'session=victim',
                'X-Safe-Header': 'keep-me'
            }
        });
        assert.strictEqual(res.statusCode, 200);
        // Ensure sensitive headers were dropped
        assert.strictEqual(res.headers['authorization'], undefined);
        assert.strictEqual(res.headers['cookie'], undefined);
        // Ensure safe headers were kept
        assert.strictEqual(res.headers['x-safe-header'], 'keep-me');
    });

    it('Should downgrade POST to GET on 303 and strip smuggling headers and body', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        const res = await client.post('https://example.com/smuggle-start', 'massive-payload', {
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
