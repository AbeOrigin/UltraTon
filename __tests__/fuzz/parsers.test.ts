/**
 * Property tests (no dependencies, see fuzz.ts) for the pure parsers: IPv6 parsing, which must yield exactly the
 * address that was validated (the SOCKS5 tunnel sends what ipv6Bytes produces), and header validation.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { ipv6Groups } from '../../src/security/dns-pinner.ts';
import { ipv6Bytes } from '../../src/proxy/tunnel.ts';
import { buildSafeRequestOptions } from '../../src/helpers/request-options.ts';
import { forAll, type Rand } from './fuzz.ts';
import { spellIpv6 } from './generators.ts';

/** An IPv6 address as its 8 groups (the ground truth), and one of its many valid spellings. */
function ipv6(r: Rand): { groups: number[]; text: string } {
    const groups = Array.from({ length: 8 }, () => (r.chance(0.4) ? 0 : r.chance(0.3) ? r.int(16) : r.int(65536)));
    return { groups, text: spellIpv6(r, groups) };
}

describe('fuzz: IPv6 parsing', () => {
    it('ipv6Groups and ipv6Bytes give exactly the address that was written, in every spelling', async () => {
        await forAll(ipv6, ({ groups, text }) => {
            assert.equal(isIP(text), 6, `generator produced an invalid address: ${text}`);
            assert.deepEqual(ipv6Groups(text), groups, text);
            const expected = Buffer.alloc(16);
            groups.forEach((g, i) => expected.writeUInt16BE(g, i * 2));
            assert.deepEqual(ipv6Bytes(text), expected, text);
        });
    });
});

const VALUE_PIECES = ['ok', 'a', ' ', '\t', ';', ':', '=', 'é', '∑', '\r', '\n', '\r\n', '\0', 'Host: x', '%0d%0a'];
const KEY_PIECES = ['x', 'auth', '-', 'a', ':', 'Host', '\r', '\n', '\0', ' ', 'é', '__proto__', '__PROTO__', 'constructor', 'Constructor', 'PROTOTYPE'];

describe('fuzz: header validation', () => {
    it('a header value (alone or in an array) throws if and only if it contains CR, LF or NUL', async () => {
        await forAll(r => r.array(1, 6, () => r.pick(VALUE_PIECES)), pieces => {
            const value = pieces.join('');
            const forbidden = /[\r\n\0]/.test(value);
            // Both forms reach the wire: the value alone, and inside an array.
            const asArray = pieces.length % 2 === 0;
            let threw: unknown;
            try { buildSafeRequestOptions({ headers: { 'x-test': asArray ? ['ok', value] : value } }); } catch (err) { threw = err; }
            if (forbidden) assert.match(String((threw as Error)?.message), /contains invalid CRLF characters/, JSON.stringify(value));
            else assert.equal(threw, undefined, JSON.stringify(value));
        });
    });

    it('a header key throws for CR/LF/NUL or a pseudo-header, is otherwise kept or (prototype keys, any case) dropped, and never changes the prototype', async () => {
        await forAll(r => r.array(1, 4, () => r.pick(KEY_PIECES)), pieces => {
            const key = pieces.join('');
            let threw: unknown;
            let result: Record<string, unknown> | undefined;
            // An array value: assigned as the prototype, it would add inherited keys ('0').
            try { result = buildSafeRequestOptions({ headers: { [key]: ['evil: 1'] } as any }).headers as Record<string, unknown>; } catch (err) { threw = err; }
            if (/[\r\n\0]/.test(key)) {
                assert.match(String((threw as Error)?.message), /contains invalid CRLF characters/, JSON.stringify(key));
            } else if (key.startsWith(':')) {
                assert.match(String((threw as Error)?.message), /pseudo-header/, JSON.stringify(key));
            } else {
                assert.equal(threw, undefined, JSON.stringify(key));
                const dropped = ['__proto__', 'constructor', 'prototype'].includes(key.toLowerCase());
                assert.equal(Object.getPrototypeOf(result), Object.prototype, `${JSON.stringify(key)} changed the prototype`);
                assert.equal(Object.hasOwn(result!, key.toLowerCase()), !dropped, JSON.stringify(key));
            }
        });
    });
});
