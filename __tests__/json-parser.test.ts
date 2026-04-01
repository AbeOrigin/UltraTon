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
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        
        interface UserShape {
            user: string;
            role: string;
        }

        const res = await client.get<UserShape>('https://example.com/valid-json');
        
        // Assert native response shape is unharmed
        assert.strictEqual(res.statusCode, 200);
        assert.ok(Buffer.isBuffer(res.data)); // Core security buffer mechanism is intact
        
        // Assert the parsed data extraction works synchronously
        const json = res.json();
        assert.strictEqual(json.user, 'abe');
        assert.strictEqual(json.role, 'architect');
    });

    it('Should cleanly trap native SyntaxError and throw UltraTonParseError upon malformed payload', async () => {
        const client = new UltraTonClient();
        (client as any)._transport = createSmartMockTransport();
        const res = await client.get('https://example.com/invalid-json');
        
        assert.throws(
            () => { res.json() },
            (err: any) => err instanceof UltraTonParseError && err.message.includes('Failed to parse JSON')
        );
    });

});
