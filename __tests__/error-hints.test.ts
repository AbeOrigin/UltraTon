/**
 * Q10: the errors a developer meets first name the option that resolves them. The first sentence of each message is
 * what the rest of the suite matches; this file holds the hint sentence. The engines' use of bodyTooLarge is covered
 * by the maxBodySize tests (decompress, http2-memory-shield, stream).
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { bodyTooLarge, requestBodyTooLarge } from '../src/errors.ts';
import { assertAllowedIp } from '../src/security/dns-pinner.ts';

describe('errors name the option to change', () => {
    it('a body over maxBodySize names that option, with one message for get() and stream()', () => {
        const { message } = bodyTooLarge(1024);
        assert.match(message, /^UltraTon: Body size exceeded the maximum allowed size of 1024 bytes\. Raise maxBodySize\.$/);
    });

    it('a request body over maxRequestBodySize names that option', () => {
        const err = requestBodyTooLarge(5);
        assert.equal(err.code, 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE');
        assert.match(err.message, / Raise maxRequestBodySize, or send less\.$/);
    });

    it('a reserved address names permitReservedIps and never the address', () => {
        assert.throws(() => assertAllowedIp('10.0.0.5', false, 'internal.example'), (err: Error) => {
            assert.match(err.message, /permitReservedIps/);
            assert.doesNotMatch(err.message, /10\.0\.0\.5|internal\.example/);
            return true;
        });
    });
});
