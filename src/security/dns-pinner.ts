import dnsPromises from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { SecureHttpError } from '../errors.ts';

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

// ponytail: 6to4 (2002::/16) and Teredo (2001::/32) are not blocked because they legitimately embed public IPv4
// addresses and need host tunnel interfaces to be reachable. Upgrade path: decode the embedded IPv4 like NAT64 above.
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

    return reservedIps.check(ip, family === 4 ? 'ipv4' : 'ipv6');
}

/**
 * What a caller may reach among the reserved addresses: `true` allows all of them, `false` (or `[]`) none, and a list
 * allows only the IPs/CIDRs it names, plus any address reached through a hostname it names (exact, no wildcards).
 */
export type ReservedIpPolicy = boolean | readonly string[];

/** Stable identity of a policy: equal for lists that differ only in order or case. Also keys the compiled cache and the HTTP/2 pool. */
export function policyKey(policy: ReservedIpPolicy): string {
    if (typeof policy === 'boolean') return policy ? 'all' : 'deny';
    if (policy.length === 0) return 'deny';
    return 'list:' + policy.map(entry => entry.toLowerCase()).sort().join(',');
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
function ipv6Groups(ip: string): number[] | undefined {
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
        'To allow internal targets set permitReservedIps (true or an allowlist of IPs, CIDRs or hostnames).'
    );
}

export async function resolveAndPinHost(hostname: string, policy: ReservedIpPolicy = false): Promise<string> {
    // { family: 0 } instructs getaddrinfo to return the OS-preferred address type (Dual-Stack)
    const { address } = await dnsPromises.lookup(hostname, { family: 0 }).catch((err: NodeJS.ErrnoException) => {
        // The code only: the hostname is already known to the caller and must not be echoed into a message that may be relayed.
        throw new SecureHttpError(`UltraTon: Hostname resolution failed (${err.code || 'UNKNOWN_DNS_ERROR'}).`);
    });

    assertAllowedIp(address, policy, hostname);
    return address;
}
