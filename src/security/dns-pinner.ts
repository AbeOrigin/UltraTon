import dnsPromises from 'node:dns/promises';
import { SecureHttpError } from '../exceptions/secure-http.error.ts';

export function isReservedIp(ip: string): boolean {
    const lowerIp = ip.toLowerCase();
    
    // IPv4-Mapped IPv6 bypass handling
    if (lowerIp.startsWith('::ffff:')) {
        return isReservedIp(lowerIp.substring(7));
    }

    if (lowerIp.includes('.')) {
        // Fast, strictly numeric IPv4 boundary checking
        const parts = lowerIp.split('.').map(p => parseInt(p, 10));
        if (parts.length !== 4 || parts.some(isNaN)) return false;

        const [p0, p1] = parts;

        if (p0 === 127) return true; // 127.0.0.0/8 (Localhost)
        if (p0 === 10) return true;  // 10.0.0.0/8 (Private)
        if (p0 === 172 && p1 >= 16 && p1 <= 31) return true; // 172.16.0.0/12 (Private)
        if (p0 === 192 && p1 === 168) return true; // 192.168.0.0/16 (Private)
        if (p0 === 169 && p1 === 254) return true; // 169.254.0.0/16 (Link-Local / AWS Metadata)
        if (p0 === 0) return true; // 0.0.0.0/8 (Soft Localhost / Any)
        if (p0 === 100 && p1 >= 64 && p1 <= 127) return true; // 100.64.0.0/10 (Carrier-grade NAT)

        return false;
    }

    if (lowerIp.includes(':')) {
        // Exact checks for standard IPv6 Unspecified and Localhost bindings
        if (lowerIp === '::' || lowerIp === '::1') return true;

        const parts = lowerIp.split(':');
        const firstSegment = parts[0] ? parts[0] : '0';
        const firstHextet = parseInt(firstSegment, 16);

        if (isNaN(firstHextet)) return false;

        // Unique Local Addresses (fc00::/7) -> Ranges from fc00 to fdff
        if (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) return true;

        // Link-Local Address Space (fe80::/10) -> Ranges from fe80 to febf
        if (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) return true;

        // Fallback catch for fully unwound IPv6 structures like 0:0:0:0:0:0:0:1
        if (firstHextet === 0) {
            if (parts.every(p => p === '' || p === '0')) return true; // Unspecified
            if (parts[parts.length - 1] === '1' && parts.slice(0, -1).every(p => p === '' || p === '0')) return true; // Localhost
        }

        return false;
    }

    return false;
}

export async function resolveAndPinHost(hostname: string, permitReservedIps: boolean = false): Promise<string> {
    try {
        // { family: 0 } instructs getaddrinfo to return the OS-preferred address type (Dual-Stack)
        const result = await dnsPromises.lookup(hostname, { family: 0 });

        if (!permitReservedIps && isReservedIp(result.address)) {
            throw new SecureHttpError(
                'UltraTon: Target resolved to a strictly prohibited internal/reserved network IP.'
            );
        }

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
