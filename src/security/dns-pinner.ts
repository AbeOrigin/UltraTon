import dnsPromises from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { SecureHttpError } from '../exceptions/secure-http.error.ts';

const reservedIps = new BlockList();

// BlockList also matches IPv4 rules against IPv4-mapped IPv6 forms (::ffff:a.b.c.d and ::ffff:hhhh:hhhh).
for (const [network, prefix] of [
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
] as const) {
    reservedIps.addSubnet(network, prefix, 'ipv4');
}

// ponytail: NAT64 (64:ff9b::/96), 6to4 (2002::/16) and Teredo (2001::/32) are not blocked because they legitimately
// embed public IPv4 addresses. Upgrade path: decode the embedded IPv4 and validate it against the IPv4 rules above.
for (const [network, prefix] of [
    ['::', 96],            // Unspecified, loopback and IPv4-compatible (::7f00:1)
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
    try {
        // { family: 0 } instructs getaddrinfo to return the OS-preferred address type (Dual-Stack)
        const result = await dnsPromises.lookup(hostname, { family: 0 });

        assertAllowedIp(result.address, permitReservedIps);

        return result.address;
    } catch (err: unknown) {
        if (err instanceof SecureHttpError) {
            throw err;
        }

        const standardError = err as NodeJS.ErrnoException;
        const code = standardError.code || 'UNKNOWN_DNS_ERROR';

        throw new SecureHttpError(
            `UltraTon: Hostname resolution failed for ${hostname} with code ${code}.`
        );
    }
}
