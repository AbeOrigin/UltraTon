/**
 * Property tests (no dependencies, see fuzz.ts) for addresses that carry another address: 6to4 and Teredo IPv6 forms,
 * judged by the IPv4 they carry, in every spelling the IPv6 parser accepts.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isReservedIp } from '../../src/security/dns-pinner.ts';
import { forAll, type Rand } from './fuzz.ts';
import { spellIpv6 } from './generators.ts';

const RESERVED_V4 = ['127.0.0.1', '10.1.2.3', '169.254.169.254', '192.168.0.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255'];
const PUBLIC_V4 = ['8.8.8.8', '1.1.1.1', '93.184.216.34'];

/** An IPv4 as its two 16-bit halves: from the reserved or the public list, or any address at all. */
function ipv4(r: Rand): { text: string; high: number; low: number } {
    const text = r.chance(0.4) ? r.pick(RESERVED_V4) : r.chance(0.5) ? r.pick(PUBLIC_V4) : Array.from({ length: 4 }, () => r.int(256)).join('.');
    const [a, b, c, d] = text.split('.').map(Number);
    return { text, high: (a << 8) | b, low: (c << 8) | d };
}

/** A 6to4 or Teredo address (or, now and then, a 2001:x:: one that only looks like Teredo) and what it must judge as. */
function tunnelled(r: Rand): { text: string; expected: boolean } {
    const rest = () => r.int(65536);
    if (r.chance(0.5)) {
        const v4 = ipv4(r);
        const groups = [0x2002, v4.high, v4.low, rest(), rest(), rest(), rest(), rest()];
        return { text: spellIpv6(r, groups), expected: isReservedIp(v4.text) };
    }
    const server = ipv4(r);
    const client = ipv4(r);
    // Group 1 is 0 for Teredo; any other value is plain global unicast, judged as itself, except 0xdb8:
    // 2001:db8::/32 is the documentation range, reserved on its own.
    const notTeredo = r.chance(0.2);
    const other = 1 + r.int(65534);
    const groups = [0x2001, notTeredo ? (other >= 0xdb8 ? other + 1 : other) : 0, server.high, server.low, rest(), rest(), ~client.high & 0xffff, ~client.low & 0xffff];
    return { text: spellIpv6(r, groups), expected: !notTeredo && (isReservedIp(server.text) || isReservedIp(client.text)) };
}

describe('fuzz: 6to4 and Teredo', () => {
    it('a 6to4 or Teredo address is reserved exactly when an IPv4 it carries is', async () => {
        await forAll(tunnelled, ({ text, expected }) => {
            assert.equal(isReservedIp(text), expected, text);
        });
    });
});
