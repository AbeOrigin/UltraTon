import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import { UltraTonClient } from '../src/engines/http1.ts';
import { UltraTonParseError } from '../src/errors.ts';

describe('UltraTonClient - generic JSON Parsing (Sprint 5)', () => {

    const createSmartMockTransport = () => {
        return (urlObj: URL, options: any, callback?: any) => {
            const req = new EventEmitter();
            
            (req as any).write = () => {};
            (req as any).destroy = () => {};
            
            (req as any).end = () => {
                const body = urlObj.pathname === '/valid-json' ? [Buffer.from(JSON.stringify({ user: 'abe', role: 'architect' }))]
                    : urlObj.pathname === '/invalid-json' ? [Buffer.from('<html>Sorry, Bad Gateway</html>')]
                    : [];
                const res = Object.assign(Readable.from(body), { statusCode: 200, headers: { 'content-type': 'application/json' } });

                if (callback) callback(res);
                req.emit('response', res);
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
        assert.ok(Buffer.isBuffer(res.data)); // No auto-parsing: data stays the raw Buffer
        
        // Assert the lazy, typed extraction works
        const jsonBody: UserShape = res.json();
        assert.strictEqual(jsonBody.user, 'abe');
        assert.strictEqual(jsonBody.role, 'architect');
    });

    it('Should cleanly trap native SyntaxError and throw UltraTonParseError upon malformed payload from json()', async () => {
        const client = new UltraTonClient(createSmartMockTransport() as any);
        
        // The request itself resolves: parsing is lazy
        const res = await client.get('https://example.com/invalid-json');
        assert.strictEqual(res.statusCode, 200);
        assert.throws(
            () => res.json(),
            (err: any) => err instanceof UltraTonParseError && err.message.includes('Failed to parse JSON') && err.cause instanceof SyntaxError
        );
    });

});
