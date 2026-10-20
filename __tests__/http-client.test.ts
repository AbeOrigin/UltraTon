import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { UltraTonClient } from '../src/http-client.ts';
import { kTransport } from '../src/internal.ts';
import https from 'node:https';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { SecureHttpError, UltraTonMemoryError, UltraTonNetworkError } from '../src/errors.ts';

describe('UltraTonClient - Sprint 1 & 2 Protocol Lockdown', () => {

    // Helper to generate a fake https.request implementation
    const createMockTransport = (mockResponseData: any, expectedMethod: string, statusCode = 200) => {
        return (urlObj: any, options: any, callback?: any) => {
            const req = new EventEmitter();
            const reqBody: Buffer[] = [];
            
            (req as any).write = (chunk: any) => {
                reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            };
            
            (req as any).destroy = () => {};
            
            (req as any).end = (chunk?: any) => {
                if (chunk) reqBody.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
                if (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH') {
                    // Echo the body back structurally if needed
                    mockResponseData = Buffer.concat(reqBody);
                }

                const dataBuffer = Buffer.isBuffer(mockResponseData) ? mockResponseData : Buffer.from(JSON.stringify(mockResponseData));
                const res = Object.assign(Readable.from(dataBuffer.length > 0 ? [dataBuffer] : []), {
                    statusCode,
                    headers: { 'x-method-used': options.method }
                });

                if (callback) callback(res);
                req.emit('response', res);
            };
            return req as any;
        };
    };

    it('Should completely block http:// URLs and reject synchronously', async () => {
        const client = new UltraTonClient();
        await assert.rejects(
            client.get(`http://example.com/json`),
            { message: 'UltraTon: Unsupported protocol "http:"' }
        );
    });

    it('Should successfully perform a basic GET request (https)', async () => {
        const fakeTransport = createMockTransport({ success: true }, 'GET');
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.get(`https://localhost/json`);
        assert.strictEqual(response.statusCode, 200);
        
        const parsedData = JSON.parse(response.text());
        assert.strictEqual(parsedData.success, true);
    });

    it('Should successfully perform a POST request', async () => {
        const fakeTransport = createMockTransport({}, 'POST', 201);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.post(`https://localhost/echo`, { json: { test: 'post' } });
        assert.strictEqual(response.statusCode, 201);
        assert.strictEqual(response.headers['x-method-used'], 'POST');
        assert.deepStrictEqual(JSON.parse(response.text()), { test: 'post' });
    });

    it('Should successfully perform a PUT request', async () => {
        const fakeTransport = createMockTransport({}, 'PUT', 201);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);

        const response = await client.put(`https://localhost/echo`, { json: { test: 'put' } });
        assert.strictEqual(response.headers['x-method-used'], 'PUT');
        assert.deepStrictEqual(JSON.parse(response.text()), { test: 'put' });
    });;

    it('Should successfully perform a PATCH request', async () => {
        const fakeTransport = createMockTransport({}, 'PATCH', 201);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.patch(`https://localhost/echo`, { json: { test: 'patch' } });
        assert.strictEqual(response.headers['x-method-used'], 'PATCH');
        assert.deepStrictEqual(JSON.parse(response.text()), { test: 'patch' });
    });

    it('Should successfully perform a DELETE request', async () => {
        // empty body response
        const fakeTransport = createMockTransport('', 'DELETE', 204);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.delete(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'DELETE');
        assert.strictEqual(response.statusCode, 204);
    });

    it('Should successfully perform an OPTIONS request', async () => {
        const fakeTransport = createMockTransport('', 'OPTIONS', 204);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.options(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'OPTIONS');
    });

    it('Should successfully perform a HEAD request', async () => {
        const fakeTransport = createMockTransport('', 'HEAD', 204);
        const client = new UltraTonClient({ [kTransport]: fakeTransport } as any);
        
        const response = await client.head(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'HEAD');
    });

});

// Real sockets: pins the body-consumption contract (size cap, truncated bodies) before any refactor of it.
describe('UltraTonClient - response body consumption (real sockets)', () => {
    let server: http.Server;
    let base = '';

    before(async () => {
        server = http.createServer((req, res) => {
            if (req.url === '/two-kb') {
                res.write(Buffer.alloc(1024));
                res.end(Buffer.alloc(1024));
            } else if (req.url === '/truncated') {
                res.writeHead(200, { 'content-length': '100' });
                res.write(Buffer.alloc(10), () => res.socket!.destroy());
            }
        });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    after(() => server.close());

    it('Accepts a body exactly at maxBodySize', async () => {
        const res = await new UltraTonClient().get(`${base}/two-kb`, { maxBodySize: 2048, permitReservedIps: true });
        assert.strictEqual(res.data.length, 2048);
    });

    it('Rejects with UltraTonMemoryError once the body exceeds maxBodySize', async () => {
        await assert.rejects(
            new UltraTonClient().get(`${base}/two-kb`, { maxBodySize: 1500, permitReservedIps: true }),
            (err: unknown) => err instanceof UltraTonMemoryError
        );
    });

    it('Rejects with UltraTonNetworkError when the server cuts the body short', async () => {
        await assert.rejects(
            new UltraTonClient().get(`${base}/truncated`, { permitReservedIps: true }),
            (err: unknown) => err instanceof UltraTonNetworkError && !(err instanceof UltraTonMemoryError)
        );
    });
});
