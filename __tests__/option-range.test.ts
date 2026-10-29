/**
 * A number option outside its range throws a TypeError with code ERR_ULTRATON_OPTION_RANGE and the option's name and
 * bounds, so a caller can explain it in its own words (and translate it); a wrong type keeps its plain TypeError.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { UltraTonClient } from '../src/http-client.ts';

const INT32_MAX = 2 ** 31 - 1;
const range = (option: string, min: number, max: number) => (err: unknown) => {
    assert.ok(err instanceof TypeError);
    assert.deepEqual({ ...(err as object) }, { code: 'ERR_ULTRATON_OPTION_RANGE', option, min, max });
    return true;
};

describe('ERR_ULTRATON_OPTION_RANGE', () => {
    const client = new UltraTonClient();

    it('on a request: timeoutMs and maxBodySize above 2^31-1, and the other integer options', async () => {
        const url = 'https://example.com/';
        await assert.rejects(client.get(url, { timeoutMs: INT32_MAX + 1 }), range('timeoutMs', 0, INT32_MAX));
        await assert.rejects(client.get(url, { maxBodySize: 3e9 }), range('maxBodySize', 0, INT32_MAX));
        await assert.rejects(client.get(url, { socketTimeoutMs: -1 }), range('socketTimeoutMs', 0, INT32_MAX));
        await assert.rejects(client.get(url, { maxRedirects: 21 }), range('maxRedirects', 0, 20));
        await assert.rejects(client.get(url, { timeoutMs: 1.5 }), range('timeoutMs', 0, INT32_MAX));
        await assert.rejects(client.get(url, { retry: { limit: 11 } }), range('retry.limit', 0, 10));
        await assert.rejects(client.stream(url, { maxBodySize: 2 ** 53 }), range('maxBodySize', 0, Number.MAX_SAFE_INTEGER));
        // paginate() validates when called, not on the first iteration.
        assert.throws(() => client.paginate(url, { maxPages: 0 }), range('maxPages', 1, Number.MAX_SAFE_INTEGER));
    });

    it('on the client: the same error, thrown by the constructor', () => {
        assert.throws(() => new UltraTonClient({ timeoutMs: 2 ** 32 }), range('timeoutMs', 0, INT32_MAX));
        assert.throws(() => new UltraTonClient({ maxConcurrency: 0 }), range('maxConcurrency', 1, INT32_MAX));
    });

    it('not for a wrong type, which is a plain TypeError without a code', async () => {
        await assert.rejects(client.get('https://example.com/', { timeoutMs: '100' as any }), (err: unknown) =>
            err instanceof TypeError && (err as { code?: string }).code === undefined);
    });
});
