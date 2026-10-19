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

interface CompiledAllowlist {
    allowed: BlockList;
    hostnames: Set<string>;
}

// ponytail: one entry per distinct allowlist ever used, never evicted. Fine while allowlists come from static config
// (a handful per process). Upgrade path: bound it with a small LRU if lists are ever built from request-time input.
const compiledAllowlists = new Map<string, CompiledAllowlist>();

function compileAllowlist(entries: readonly string[], key: string): CompiledAllowlist {
    let compiled = compiledAllowlists.get(key);
    if (compiled) return compiled;

    compiled = { allowed: new BlockList(), hostnames: new Set() };
    for (const entry of entries) {
        const lower = entry.toLowerCase();
        const slash = lower.indexOf('/');
        if (slash !== -1) {
            const network = lower.slice(0, slash);
            compiled.allowed.addSubnet(network, Number(lower.slice(slash + 1)), isIP(network) === 4 ? 'ipv4' : 'ipv6');
        } else if (isIP(lower) !== 0) {
            compiled.allowed.addAddress(lower, isIP(lower) === 4 ? 'ipv4' : 'ipv6');
        } else {
            compiled.hostnames.add(lower);
        }
    }
    compiledAllowlists.set(key, compiled);
    return compiled;
}

/**
 * Throws when `ip` is reserved and `policy` does not allow it. `hostname` is the name the caller asked for (the
 * literal itself for an IP-literal URL); only a hostname entry of the list can match it.
 * The message names neither the IP nor the hostname, so it cannot be used to probe the internal network.
 */
export function assertAllowedIp(ip: string, policy: ReservedIpPolicy, hostname?: string): void {
    if (policy === true || !isReservedIp(ip)) return;

    if (typeof policy !== 'boolean' && policy.length > 0) {
        const { allowed, hostnames } = compileAllowlist(policy, policyKey(policy));
        if (allowed.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6')) return;
        if (hostname !== undefined && hostnames.has(hostname.toLowerCase().replace(/^\[|\]$/g, ''))) return;
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
