import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { UltraTonClient } from '../src/http-client.ts';
import https from 'node:https';

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
            
            (req as any).end = () => {
                const res = new EventEmitter();
                (res as any).statusCode = statusCode;
                (res as any).headers = { 'x-method-used': options.method };

                if (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH') {
                    // Echo the body back structurally if needed
                    mockResponseData = Buffer.concat(reqBody);
                }

                if (callback) callback(res);
                req.emit('response', res);
                
                setImmediate(() => {
                    const dataBuffer = Buffer.isBuffer(mockResponseData) ? mockResponseData : Buffer.from(JSON.stringify(mockResponseData));
                    if (dataBuffer.length > 0) res.emit('data', dataBuffer);
                    res.emit('end');
                });
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
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.get(`https://localhost/json`);
        assert.strictEqual(response.statusCode, 200);
        
        const parsedData = JSON.parse(response.body.toString());
        assert.strictEqual(parsedData.success, true);
    });

    it('Should successfully perform a POST request', async () => {
        const fakeTransport = createMockTransport({}, 'POST', 201);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.post(`https://localhost/echo`, JSON.stringify({ test: 'post' }));
        assert.strictEqual(response.statusCode, 201);
        assert.strictEqual(response.headers['x-method-used'], 'POST');
        assert.deepStrictEqual(JSON.parse(response.body.toString()), { test: 'post' });
    });

    it('Should successfully perform a PUT request', async () => {
        const fakeTransport = createMockTransport({}, 'PUT', 201);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.put(`https://localhost/echo`, JSON.stringify({ test: 'put' }));
        assert.strictEqual(response.headers['x-method-used'], 'PUT');
        assert.deepStrictEqual(JSON.parse(response.body.toString()), { test: 'put' });
    });

    it('Should successfully perform a PATCH request', async () => {
        const fakeTransport = createMockTransport({}, 'PATCH', 201);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.patch(`https://localhost/echo`, JSON.stringify({ test: 'patch' }));
        assert.strictEqual(response.headers['x-method-used'], 'PATCH');
        assert.deepStrictEqual(JSON.parse(response.body.toString()), { test: 'patch' });
    });

    it('Should successfully perform a DELETE request', async () => {
        // empty body response
        const fakeTransport = createMockTransport('', 'DELETE', 204);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.delete(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'DELETE');
        assert.strictEqual(response.statusCode, 204);
    });

    it('Should successfully perform an OPTIONS request', async () => {
        const fakeTransport = createMockTransport('', 'OPTIONS', 204);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.options(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'OPTIONS');
    });

    it('Should successfully perform a HEAD request', async () => {
        const fakeTransport = createMockTransport('', 'HEAD', 204);
        const client = new UltraTonClient(fakeTransport as any);
        
        const response = await client.head(`https://localhost/empty`);
        assert.strictEqual(response.headers['x-method-used'], 'HEAD');
    });

});
