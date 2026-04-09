import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonParseError } from '../src/exceptions/parse.error.ts';

describe('UltraTonClient - generic JSON Parsing (Sprint 5)', () => {

    const createSmartMockTransport = () => {
        return (urlObj: URL, options: any, callback?: any) => {
            const req = new EventEmitter();
            
            (req as any).write = () => {};
            (req as any).destroy = () => {};
            
            (req as any).end = () => {
                const res = new EventEmitter();
                (res as any).destroy = () => {};
                (res as any).statusCode = 200;
                (res as any).headers = { 'content-type': 'application/json' };

                if (callback) callback(res);
                req.emit('response', res);
                
                setImmediate(() => {
                    if (urlObj.pathname === '/valid-json') {
                        res.emit('data', Buffer.from(JSON.stringify({ user: 'abe', role: 'architect' })));
                    } else if (urlObj.pathname === '/invalid-json') {
                        res.emit('data', Buffer.from('<html>Sorry, Bad Gateway</html>'));
                    }
                    res.emit('end');
                });
            };
            return req as any;
        };
    };

    it('Should cleanly parse JSON and explicitly map it to the requested interface synchronously', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        
        interface UserShape {
            user: string;
            role: string;
        }

        const res = await client.get<UserShape>('https://example.com/valid-json');
        
        // Assert native response shape is unharmed
        assert.strictEqual(res.statusCode, 200);
        assert.ok(!Buffer.isBuffer(res.body)); // Auto parsing kicked in
        
        // Assert the parsed data extraction works inline
        const jsonBody = res.body as UserShape;
        assert.strictEqual(jsonBody.user, 'abe');
        assert.strictEqual(jsonBody.role, 'architect');
    });

    it('Should cleanly trap native SyntaxError and throw UltraTonParseError upon malformed payload during request', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        
        await assert.rejects(
            client.get('https://example.com/invalid-json'),
            (err: any) => err instanceof UltraTonParseError && err.message.includes('Failed to parse JSON')
        );
    });

});
