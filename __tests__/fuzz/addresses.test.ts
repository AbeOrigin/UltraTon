/**
 * Property tests (no dependencies, see fuzz.ts) for addresses that carry another address: 6to4 and Teredo IPv6 forms,
 * judged by the IPv4 they carry, in every spelling the IPv6 parser accepts; and IPv4 addresses written the loose ways a
 * URL parser still reads as IPv4 (127.1, 0x7f.0.0.1, 2130706433), which the secure agents refuse.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isReservedIp } from '../../src/security/dns-pinner.ts';
import { isLooseIpv4 } from '../../src/agents.ts';
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

/**
 * An IPv4 written as a URL parser reads one: 1 to 4 parts, the last holding all the remaining bytes, each part in
 * decimal, octal (leading 0) or hex (0x), sometimes with a trailing dot. Canonical: 4 decimal parts, no leading zero, no dot.
 */
function ipv4Spelling(r: Rand): { text: string; canonical: boolean } {
    const value = r.int(2 ** 32);
    const parts = 1 + r.int(4);
    const bytes = [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
    // The first parts - 1 parts are one byte each; the last one takes the rest.
    const numbers = [...bytes.slice(0, parts - 1), bytes.slice(parts - 1).reduce((n, b) => n * 256 + b, 0)];
    let allDecimal = true;
    const written = numbers.map(n => {
        const base = r.int(3);
        if (base === 0) return String(n);
        allDecimal = false;
        if (base === 1) return `0${n.toString(8)}`;
        const digits = n.toString(16);
        return `${r.pick(['0x', '0X'])}${r.chance(0.5) ? digits.toUpperCase() : digits}`;
    });
    const dot = r.chance(0.1);
    return { text: written.join('.') + (dot ? '.' : ''), canonical: parts === 4 && allDecimal && !dot };
}

const LABELS = ['a', 'api', 'x1', '1a', 'nip', 'io', 'xn--bcher-kva', 'b-c'];

/** A domain name: 1 to 4 labels, sometimes behind an IPv4-looking prefix, always ending in a non-numeric label. */
function domain(r: Rand): string {
    const name = r.array(1, 4, () => r.pick(LABELS)).join('.');
    return r.chance(0.3) ? `1.2.3.4.${name}` : name;
}

describe('fuzz: loose IPv4 hosts', () => {
    it('every non-canonical spelling of an IPv4 is loose, the canonical one is not', async () => {
        await forAll(ipv4Spelling, ({ text, canonical }) => {
            assert.equal(isLooseIpv4(text), !canonical, text);
        });
    });

    it('a domain name is never loose', async () => {
        await forAll(domain, name => {
            assert.equal(isLooseIpv4(name), false, name);
        });
    });
});
