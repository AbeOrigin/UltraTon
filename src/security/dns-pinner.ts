import dnsPromises from 'node:dns/promises';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { SecureHttpError, UltraTonNetworkError } from '../errors.ts';

const reservedIps = new BlockList();

const reservedIpv4Ranges = [
    ['0.0.0.0', 8],        // "This" network
    ['10.0.0.0', 8],       // Private
    ['100.64.0.0', 10],    // Carrier-grade NAT
    ['127.0.0.0', 8],      // Loopback
    ['169.254.0.0', 16],   // Link-local / cloud metadata
    ['172.16.0.0', 12],    // Private
    ['192.0.0.0', 24],     // IETF protocol assignments
    ['192.0.2.0', 24],     // TEST-NET-1
    ['192.168.0.0', 16],   // Private
    ['198.18.0.0', 15],    // Benchmarking
    ['198.51.100.0', 24],  // TEST-NET-2
    ['203.0.113.0', 24],   // TEST-NET-3
    ['224.0.0.0', 4],      // Multicast
    ['240.0.0.0', 4]       // Reserved + limited broadcast (255.255.255.255)
] as const;

for (const [network, prefix] of reservedIpv4Ranges) {
    // BlockList also matches IPv4 rules against IPv4-mapped IPv6 forms (::ffff:a.b.c.d and ::ffff:hhhh:hhhh).
    reservedIps.addSubnet(network, prefix, 'ipv4');
    // NAT64 well-known prefix (RFC 6052) carries the IPv4 address in its low 32 bits, so every reserved IPv4 range maps
    // to the IPv6 range 64:ff9b::<network>/(96 + prefix). Public embedded IPv4 (64:ff9b::8.8.8.8) stays allowed.
    reservedIps.addSubnet(`64:ff9b::${network}`, 96 + prefix, 'ipv6');
}

// 6to4 (2002::/16) and Teredo (2001:0::/32) embed an IPv4 elsewhere than the low 32 bits, so no prefix can express
// "reserved IPv4 inside": isReservedIp decodes them instead (see tunnelledIpv4s).
for (const [network, prefix] of [
    ['::', 96],            // Unspecified, loopback and IPv4-compatible (::7f00:1)
    ['64:ff9b:1::', 48],   // Local-use NAT64 (RFC 8215): targets non-global IPv4 by definition
    ['100::', 64],         // Discard-only
    ['2001:db8::', 32],    // Documentation
    ['fc00::', 7],         // Unique local
    ['fe80::', 10],        // Link-local
    ['fec0::', 10],        // Deprecated site-local
    ['ff00::', 8]          // Multicast
] as const) {
    reservedIps.addSubnet(network, prefix, 'ipv6');
}

export function isReservedIp(ip: string): boolean {
    const family = isIP(ip);
    if (family === 0) return false;
    if (family === 4) return reservedIps.check(ip, 'ipv4');
    return reservedIps.check(ip, 'ipv6') || tunnelledIpv4s(ip).some(v4 => reservedIps.check(v4, 'ipv4'));
}

/**
 * The IPv4 addresses a 6to4 or Teredo address carries, which a host with a tunnel interface (or a relay) delivers to.
 * 6to4 (2002::/16, RFC 3056) holds one in bits 16-47. Teredo (2001:0::/32, RFC 4380) holds the server's in bits 32-63
 * and the client's, every bit inverted, in the low 32. Packets go to the client, through a relay; the server's is
 * returned too, so that a reserved one fails closed rather than relying on how the host's relay routes.
 * Empty for any other address. The NAT64 and IPv4-mapped forms are covered by prefixes above.
 */
function tunnelledIpv4s(ip: string): string[] {
    // Every spelling of these prefixes starts with the first group: a cheap filter before parsing.
    if (!/^200[12]:/i.test(ip)) return [];
    const groups = ipv6Groups(ip);
    if (groups === undefined) return [];
    const ipv4 = (high: number, low: number) => `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`;
    if (groups[0] === 0x2002) return [ipv4(groups[1], groups[2])];
    if (groups[0] === 0x2001 && groups[1] === 0) return [ipv4(groups[2], groups[3]), ipv4(groups[6] ^ 0xffff, groups[7] ^ 0xffff)];
    return [];
}

// What plain http may reach: 127.0.0.0/8 (BlockList also matches it against the IPv4-mapped ::ffff:127.0.0.0/104
// forms) and ::1. Deliberately not the other IPv4 embeddings (::7f00:1, 64:ff9b::7f00:1): they are not loopback.
const loopbackIps = new BlockList();
loopbackIps.addSubnet('127.0.0.0', 8, 'ipv4');
loopbackIps.addAddress('::1', 'ipv6');

export function isLoopbackIp(ip: string): boolean {
    const family = isIP(ip);
    if (family === 0) return false;

    return loopbackIps.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

/**
 * Throws unless `ip` is a loopback address. Plain http is accepted only for loopback names, but a name such as
 * `api.localhost` is resolved like any other and a resolver may answer it with any address: without this check a
 * spoofed or forwarded answer would receive the request, credentials included, in cleartext. Names neither the IP
 * nor the hostname. It does not replace the reserved-IP policy: loopback still needs `permitReservedIps`.
 */
export function assertLoopbackIp(ip: string): void {
    if (!isLoopbackIp(ip)) {
        throw new SecureHttpError('UltraTon: Plain http is only allowed to loopback addresses.', { code: 'ERR_ULTRATON_PLAIN_HTTP' });
    }
}

/**
 * What a caller may reach among the reserved addresses: `true` allows all of them, `false` (or `[]`) none, and a list
 * allows only the IPs/CIDRs it names, plus any address reached through a hostname it names (exact, no wildcards).
 */
export type ReservedIpPolicy = boolean | readonly string[];

// The key of each frozen list, by identity: a frozen array never changes, so neither does its key. The client's
// validated allowlist is one such list, used by every request (agent lookup, IP checks, the HTTP/2 pool key).
const keysOfFrozenLists = new WeakMap<readonly string[], string>();

/** Stable identity of a policy: equal for lists that differ only in order or case. Also keys the compiled cache and the HTTP/2 pool. */
export function policyKey(policy: ReservedIpPolicy): string {
    if (typeof policy === 'boolean') return policy ? 'all' : 'deny';
    if (policy.length === 0) return 'deny';
    const frozen = Object.isFrozen(policy);
    let key = frozen ? keysOfFrozenLists.get(policy) : undefined;
    if (key === undefined) {
        key = 'list:' + policy.map(entry => entry.toLowerCase()).sort().join(',');
        if (frozen) keysOfFrozenLists.set(policy, key);
    }
    return key;
}

// IPv4 and IPv6 rules live in separate lists on purpose, and no address is ever judged by both. BlockList checks a
// native IPv4 address against IPv6 rules as ::ffff:a.b.c.d, so one shared list would let any IPv6 rule containing
// ::ffff:0:0/96 (::/0 .. ::/80, or that prefix itself) allow every IPv4 address. See `coveredByAllowlist`.
interface CompiledAllowlist {
    ipv4: BlockList;
    ipv6: BlockList;
    hostnames: Set<string>;
}

// ponytail: one entry per distinct allowlist ever used, never evicted. Fine while allowlists come from static config
// (a handful per process). Upgrade path: bound it with a small LRU if lists are ever built from request-time input.
const compiledAllowlists = new Map<string, CompiledAllowlist>();

function compileAllowlist(entries: readonly string[], key: string): CompiledAllowlist {
    let compiled = compiledAllowlists.get(key);
    if (compiled) return compiled;

    compiled = { ipv4: new BlockList(), ipv6: new BlockList(), hostnames: new Set() };
    for (const entry of entries) {
        const lower = entry.toLowerCase();
        const slash = lower.indexOf('/');
        if (slash !== -1) {
            const network = lower.slice(0, slash);
            if (isIP(network) === 4) compiled.ipv4.addSubnet(network, Number(lower.slice(slash + 1)), 'ipv4');
            else compiled.ipv6.addSubnet(network, Number(lower.slice(slash + 1)), 'ipv6');
        } else if (isIP(lower) === 4) {
            compiled.ipv4.addAddress(lower, 'ipv4');
        } else if (isIP(lower) === 6) {
            compiled.ipv6.addAddress(lower, 'ipv6');
        } else {
            compiled.hostnames.add(lower);
        }
    }
    compiledAllowlists.set(key, compiled);
    return compiled;
}

/** The 8 groups of an IPv6 address in any spelling (compressed, expanded, dotted tail); `undefined` if it does not parse. */
export function ipv6Groups(ip: string): number[] | undefined {
    let text = ip.split('%')[0];
    const tail4 = /\d+\.\d+\.\d+\.\d+$/.exec(text)?.[0];
    if (tail4 !== undefined) {
        const [a, b, c, d] = tail4.split('.').map(Number);
        if (isIP(tail4) !== 4) return undefined;
        text = `${text.slice(0, -tail4.length)}${(a << 8 | b).toString(16)}:${(c << 8 | d).toString(16)}`;
    }
    const halves = text.split('::');
    if (halves.length > 2) return undefined;
    const head = halves[0] ? halves[0].split(':') : [];
    const rest = halves[1] ? halves[1].split(':') : [];
    const gap = 8 - head.length - rest.length;
    if (halves.length === 2 ? gap < 1 : gap !== 0) return undefined;
    const groups = [...head, ...Array<string>(halves.length === 2 ? gap : 0).fill('0'), ...rest]
        .map(group => /^[0-9a-f]{1,4}$/i.test(group) ? parseInt(group, 16) : NaN);
    return groups.some(Number.isNaN) ? undefined : groups;
}

/**
 * The IPv4 an IPv6 address carries in its low 32 bits, for the four embedding forms: IPv4-mapped (::ffff:0:0/96),
 * IPv4-compatible (::/96), NAT64 (64:ff9b::/96) and local-use NAT64 (64:ff9b:1::/48). `undefined` for any other IPv6.
 * `::` and `::1` are the unspecified and loopback addresses, not IPv4-compatible ones, so they stay native IPv6.
 */
function embeddedIpv4(groups: number[]): string | undefined {
    const zeros = (from: number, to: number) => groups.slice(from, to).every(group => group === 0);
    const embeds =
        (zeros(0, 5) && groups[5] === 0xffff) ||
        (zeros(0, 6) && !(groups[6] === 0 && groups[7] <= 1)) ||
        (groups[0] === 0x64 && groups[1] === 0xff9b && (zeros(2, 6) || groups[2] === 1));
    return embeds ? `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.${groups[7] & 255}` : undefined;
}

/**
 * An address is judged by exactly one family, so a rule of one family never widens into the other: native IPv4 by the
 * IPv4 rules, an IPv6 address that embeds an IPv4 only by that IPv4 against the IPv4 rules (an IPv6 rule such as
 * `::/0` or `::ffff:0:0/96` does not cover it), and any other IPv6 address by the IPv6 rules. An unparsable address is
 * never covered.
 */
function coveredByAllowlist(ip: string, { ipv4, ipv6 }: CompiledAllowlist): boolean {
    if (isIP(ip) === 4) return ipv4.check(ip, 'ipv4');
    const groups = ipv6Groups(ip);
    if (groups === undefined) return false;
    const embedded = embeddedIpv4(groups);
    return embedded === undefined ? ipv6.check(ip, 'ipv6') : ipv4.check(embedded, 'ipv4');
}

/**
 * Throws when `ip` is reserved and `policy` does not allow it. `hostname` is the name the caller asked for (the
 * literal itself for an IP-literal URL); only a hostname entry of the list can match it.
 * The message names neither the IP nor the hostname, so it cannot be used to probe the internal network.
 */
export function assertAllowedIp(ip: string, policy: ReservedIpPolicy, hostname?: string): void {
    if (policy === true || !isReservedIp(ip)) return;

    if (typeof policy !== 'boolean' && policy.length > 0) {
        const compiled = compileAllowlist(policy, policyKey(policy));
        if (coveredByAllowlist(ip, compiled)) return;
        if (hostname !== undefined && compiled.hostnames.has(hostname.toLowerCase().replace(/^\[|\]$/g, ''))) return;
    }

    throw new SecureHttpError(
        'UltraTon: Target resolves to a prohibited internal/reserved network IP. ' +
        'To allow internal targets set permitReservedIps (true or an allowlist of IPs, CIDRs or hostnames).',
        { code: 'ERR_ULTRATON_RESERVED_IP' }
    );
}

/** One validated address, in the shape `dns.lookup(..., { all: true })` and a socket `lookup` callback use. */
export interface PinnedAddress {
    address: string;
    family: 4 | 6;
}

/**
 * A socket `lookup` that answers only with `addresses`, already validated, and never asks DNS again: whichever address
 * Node connects to, Happy Eyeballs included, is one of them. Answers on the next tick, as a real lookup would.
 */
export const pinnedLookup = (addresses: readonly PinnedAddress[]): LookupFunction => (_hostname, options, callback) => {
    process.nextTick(() => {
        if (options.all) callback(null, addresses.map(a => ({ ...a })));
        else callback(null, addresses[0].address, addresses[0].family);
    });
};

// The code only: the hostname is already known to the caller and must not be echoed into a message that may be relayed.
// A network error like a refused connect: the name could not be reached, whatever the reason the resolver gave.
const resolutionFailed = (code: string) =>
    new UltraTonNetworkError(`UltraTon: Hostname resolution failed (${code}).`, { code });

/** One address of a host as the policy judges it; `error` is what a request would reject with. Not public. */
export interface JudgedAddress extends PinnedAddress {
    allowed: boolean;
    error?: SecureHttpError;
}

/**
 * Every address `hostname` resolves to, each one judged by `policy` and, with `plainHttp` (the hop is `http:`), by the
 * loopback rule first (see `assertLoopbackIp`). The one place that decides: resolveAndPinAll enforces it and
 * `client.explain()` reports it. An IP literal is judged as itself and never resolved, like Node itself never resolves
 * one. An empty answer, or an entry that is not an IP address, is a resolution failure and throws.
 */
export async function judgeAddresses(hostname: string, policy: ReservedIpPolicy = false, plainHttp = false): Promise<JudgedAddress[]> {
    const literal = isIP(hostname);
    let pinned: PinnedAddress[];
    if (literal !== 0) {
        pinned = [{ address: hostname, family: literal as 4 | 6 }];
    } else {
        const answer: unknown = await dnsPromises.lookup(hostname, { all: true }).catch((err: NodeJS.ErrnoException) => {
            throw resolutionFailed(err.code || 'UNKNOWN_DNS_ERROR');
        });
        if (!Array.isArray(answer) || answer.length === 0) throw resolutionFailed('ENODATA');
        pinned = [];
        for (const entry of answer) {
            const address = (entry as { address?: unknown } | null)?.address;
            // isReservedIp() calls a non-IP "not reserved": never let one through as if it were a public address.
            const family = typeof address === 'string' ? isIP(address) : 0;
            if (family === 0) throw resolutionFailed('EBADRESP');
            pinned.push({ address: address as string, family: family as 4 | 6 });
        }
    }
    // Only once the whole answer is known to be well formed.
    return pinned.map(entry => {
        try {
            if (plainHttp) assertLoopbackIp(entry.address);
            assertAllowedIp(entry.address, policy, hostname);
            return { ...entry, allowed: true };
        } catch (err) {
            return { ...entry, allowed: false, error: err as SecureHttpError };
        }
    });
}

/**
 * Every address `hostname` resolves to, validated (see judgeAddresses). If any of them is refused, the whole lookup is
 * rejected (fail closed), so a caller that lets Node pick any address of the result (Happy Eyeballs) can only ever
 * reach validated ones: all of it, or nothing. The loopback rule wins over the whole answer: a non-loopback address
 * over http is refused as such, whatever the policy says about another address.
 */
export async function resolveAndPinAll(hostname: string, policy: ReservedIpPolicy = false, plainHttp = false): Promise<PinnedAddress[]> {
    const judged = await judgeAddresses(hostname, policy, plainHttp);
    const refused = judged.find(a => a.error?.code === 'ERR_ULTRATON_PLAIN_HTTP') ?? judged.find(a => !a.allowed);
    if (refused) throw refused.error;
    return judged.map(({ address, family }) => ({ address, family }));
}
