/**
 * Test-suite network guard, preloaded by `npm test` (`node --import`): no socket opened by a test may reach anything
 * but loopback. Several tests mock DNS with public-looking answers (93.184.216.34, 8.8.8.8) to prove the library
 * refuses them; if the library (or a deliberate mutant during review) ever let one through, the connection would
 * otherwise leave the machine. Here it fails instead, with code ETESTNONLOOPBACK and a line on stderr.
 * Unix-socket paths and loopback addresses (127.0.0.0/8, ::1, ::ffff:127.0.0.0/104) pass through untouched.
 */
import dns from 'node:dns';
import net from 'node:net';

const loopback = new net.BlockList();
loopback.addSubnet('127.0.0.0', 8, 'ipv4');
loopback.addAddress('::1', 'ipv6');

const isLoopback = (ip: string): boolean => {
    const family = net.isIP(ip);
    return family !== 0 && loopback.check(ip, family === 4 ? 'ipv4' : 'ipv6');
};

const refused = (ip: string) => {
    console.error(`[loopback-only] refused a test connection to a non-loopback address (${ip})`);
    return Object.assign(new Error('Test network guard: connection to a non-loopback address refused.'), { code: 'ETESTNONLOOPBACK' });
};

type Lookup = (host: string, options: dns.LookupOptions, callback: (...args: any[]) => void) => void;

/** A lookup that answers like `inner`, unless any address it gives is not loopback. */
const guardedLookup = (inner: Lookup): Lookup => (host, options, callback) =>
    inner(host, options, (err: unknown, address: unknown, family: unknown) => {
        if (err) return callback(err, address, family);
        const list = Array.isArray(address) ? address.map((a: { address: string }) => a.address) : [address as string];
        const outside = list.find(ip => !isLoopback(ip));
        if (outside !== undefined) return callback(refused(outside));
        callback(null, address, family);
    });

const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (this: net.Socket, ...args: any[]) {
    // net.connect() passes [options, cb] already normalized (an array); a direct call passes options or (port, host).
    const first = args[0];
    let options: any = Array.isArray(first) ? first[0] : typeof first === 'object' && first !== null ? first : undefined;
    if (options === undefined && (typeof first === 'number' || typeof first === 'string') && !Number.isNaN(Number(first))) {
        options = { port: first, host: typeof args[1] === 'string' ? args[1] : undefined };
        args = [options, ...args.slice(typeof args[1] === 'string' ? 2 : 1)];
    }
    if (options && typeof options.path !== 'string') {
        const host: string = options.host ?? 'localhost';
        if (net.isIP(host) !== 0) {
            if (!isLoopback(host)) throw refused(host);
        } else {
            options.lookup = guardedLookup(options.lookup ?? (dns.lookup as unknown as Lookup));
        }
    }
    return (connect as (...a: any[]) => net.Socket).apply(this, args);
} as typeof net.Socket.prototype.connect;
