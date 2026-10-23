/**
 * Q2: the client implements `Symbol.asyncDispose` (as `close()`) and the secure-agents pair `Symbol.dispose`
 * (destroying both agents), so `await using` / `using` free them when a block ends. The `using` syntax itself needs a
 * compiler or Node 24+, so the methods are called directly here.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { UltraTonClient } from '../src/http-client.ts';
import { createSecureAgents } from '../src/agents.ts';

describe('Symbol.asyncDispose on the client', () => {
    it('closes the client', async () => {
        const client = new UltraTonClient();
        await client[Symbol.asyncDispose]();
        await assert.rejects(client.get('https://example.com/'), /UltraTon: Client is closed\.$/);
    });

    it('twice, or after close(), does nothing more', async () => {
        const client = new UltraTonClient();
        await client.close();
        await client[Symbol.asyncDispose]();
        await client[Symbol.asyncDispose]();
    });
});

describe('Symbol.dispose on the secure agents', () => {
    it('destroys both agents and leaves the pair frozen', (t) => {
        const agents = createSecureAgents();
        const http = t.mock.method(agents.http, 'destroy');
        const https = t.mock.method(agents.https, 'destroy');
        agents[Symbol.dispose]();
        assert.equal(http.mock.callCount(), 1);
        assert.equal(https.mock.callCount(), 1);
        assert.equal(Object.isFrozen(agents), true);
    });

    it('twice does not throw', () => {
        const agents = createSecureAgents();
        agents[Symbol.dispose]();
        agents[Symbol.dispose]();
    });
});
