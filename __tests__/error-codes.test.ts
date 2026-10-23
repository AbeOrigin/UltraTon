/**
 * Q3: `UltraTonErrorCode` is exactly the set of codes `src` raises (the same scan as the API gate), and
 * `isUltraTonError()` recognizes UltraTon errors by shape, so that errors from another copy of the package in
 * node_modules count too, and never throws on anything else.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { apiSnapshot } from '../scripts/check-api.mjs';
import { ERROR_CODES, SecureHttpError, UltraTonNetworkTimeoutError, isUltraTonError } from '../src/errors.ts';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('ERROR_CODES', () => {
    it('is exactly the set of codes src raises, sorted', () => {
        // The snapshot's declarations need a dist; an empty index.d.ts gives none, and the codes come from src.
        const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'ultraton-codes-'));
        fs.writeFileSync(path.join(dist, 'index.d.ts'), '');
        const snapshot: string = apiSnapshot(dist, path.join(root, 'src'));
        fs.rmSync(dist, { recursive: true, force: true });
        const codes = snapshot.slice(snapshot.indexOf('## error codes')).split('\n').slice(1).filter(Boolean);
        assert.deepEqual([...ERROR_CODES], codes);
        assert.deepEqual([...ERROR_CODES], [...ERROR_CODES].sort());
    });
});

describe('isUltraTonError', () => {
    it('recognizes UltraTon errors by shape, this copy or another', () => {
        assert.equal(isUltraTonError(new SecureHttpError('x', { code: 'ERR_ULTRATON_RESERVED_IP' })), true);
        assert.equal(isUltraTonError(new UltraTonNetworkTimeoutError('x')), true);
        assert.equal(isUltraTonError({ name: 'UltraTonNetworkError', code: 'ECONNRESET', message: 'x' }), true);
    });

    it('with a code matches only that code', () => {
        const err = new SecureHttpError('x', { code: 'ERR_ULTRATON_RESERVED_IP' });
        assert.equal(isUltraTonError(err, 'ERR_ULTRATON_RESERVED_IP'), true);
        assert.equal(isUltraTonError(err, 'ERR_ULTRATON_PLAIN_HTTP'), false);
        assert.equal(isUltraTonError(new SecureHttpError('x'), 'ERR_ULTRATON_PLAIN_HTTP'), false);
    });

    it('rejects everything else without throwing', () => {
        for (const value of [null, undefined, 'ERR_ULTRATON_RESERVED_IP', 42, new TypeError('x'), { name: 'TypeError' }]) {
            assert.equal(isUltraTonError(value), false);
        }
        // A plain Error wearing one of our codes is not ours: its name says Error.
        assert.equal(isUltraTonError(Object.assign(new Error('x'), { code: 'ERR_ULTRATON_RESERVED_IP' })), false);
        const hostile = { get name(): string { throw new Error('no'); } };
        assert.equal(isUltraTonError(hostile), false);
    });
});
