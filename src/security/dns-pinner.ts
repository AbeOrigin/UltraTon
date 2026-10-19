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

export function assertAllowedIp(ip: string, permitReservedIps: boolean): void {
    if (!permitReservedIps && isReservedIp(ip)) {
        throw new SecureHttpError(
            'UltraTon: Target resolved to a strictly prohibited internal/reserved network IP.'
        );
    }
}

export async function resolveAndPinHost(hostname: string, permitReservedIps: boolean = false): Promise<string> {
    // { family: 0 } instructs getaddrinfo to return the OS-preferred address type (Dual-Stack)
    const { address } = await dnsPromises.lookup(hostname, { family: 0 }).catch((err: NodeJS.ErrnoException) => {
        throw new SecureHttpError(`UltraTon: Hostname resolution failed for ${hostname} with code ${err.code || 'UNKNOWN_DNS_ERROR'}.`);
    });

    assertAllowedIp(address, permitReservedIps);
    return address;
}
