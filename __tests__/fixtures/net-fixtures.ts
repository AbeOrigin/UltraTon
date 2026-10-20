/**
 * Shared by happy-eyeballs.test.ts and loopback-http.test.ts: DNS mocked with `t.mock.method(dnsPromises, 'lookup')`
 * (honouring `{ all: true }` like the real one), real loopback servers, and clients of either engine that count the
 * connections they opened: for HTTP/1 the addresses the client's `lookup` handed to Node (a failed lookup hands none, so
 * no socket can connect), for HTTP/2 the calls to a spy around `http2.connect`.
 */
import type { TestContext } from 'node:test';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net, { type AddressInfo } from 'node:net';
import { connect as nativeConnect, createServer as createH2Server } from 'node:http2';
import { UltraTonClient } from '../../src/http-client.ts';
import { Http2SessionManager } from '../../src/engines/http2-session-manager.ts';
import { kSessionManager, kTransport } from '../../src/internal.ts';
export type Answer = { address: string; family: number };
export const v4 = (address: string): Answer => ({ address, family: 4 });
export const v6 = (address: string): Answer => ({ address, family: 6 });

export const RESERVED = /prohibited internal\/reserved network IP/;
export const PLAIN_HTTP = /^UltraTon: Plain http is only allowed to loopback addresses\.$/;

/** `table[host]` is what the nameserver answers; `{ all: true }` gets the list, anything else its first entry. */
export const mockDns = (t: TestContext, table: Record<string, Answer[]>) =>
    t.mock.method(dnsPromises, 'lookup', (async (host: string, options?: { all?: boolean }) => {
        const answer = table[host];
        if (!answer) throw Object.assign(new Error('no resolver in tests'), { code: 'ENOTFOUND' });
        return options?.all ? answer : answer[0];
    }) as any);

/** A server on `host` that answers 200 with the peer address (HTTP/1 or h2c), and counts the connections it accepted. */
export async function serve(t: TestContext, http2: boolean, host = '127.0.0.1') {
    let accepted = 0;
    const server = http2
        ? createH2Server((req, res) => res.end(`peer ${req.socket.remoteAddress}`))
        : http.createServer((req, res) => res.end(`peer ${req.socket.remoteAddress}`));
    const sockets = new Set<net.Socket>();
    server.on('connection', (socket: net.Socket) => {
        accepted++;
        sockets.add(socket);
    });
    await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, host, resolve);
    });
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
    });
    return { port: (server.address() as AddressInfo).port, accepted: () => accepted };
}

/** A TCP server that accepts and drops: counts connection attempts that got through, whatever the protocol. */
export async function tcpCounter(t: TestContext) {
    let accepted = 0;
    const server = net.createServer(socket => {
        accepted++;
        socket.destroy();
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
    return { port: (server.address() as AddressInfo).port, accepted: () => accepted };
}

/**
 * A client of either engine plus the number of connections it opened. HTTP/1 runs over the real `http`/`https`
 * request with the engine's own `lookup`, wrapped only to record the addresses it handed to Node.
 */
export function clientFor(t: TestContext, http2: boolean, options: Record<string, unknown> = {}) {
    if (http2) {
        const connect = t.mock.fn(nativeConnect);
        const manager = new Http2SessionManager({}, connect);
        const client = new UltraTonClient({ http2: true, ...options, [kSessionManager]: manager } as any);
        t.after(() => client.close());
        return { client, opened: () => connect.mock.callCount() };
    }
    const handed: unknown[] = [];
    const transport = (url: URL, requestOptions: any) => {
        const lookup = requestOptions.lookup;
        return (url.protocol === 'http:' ? http.request : https.request)(url, {
            ...requestOptions,
            lookup: (host: string, lookupOptions: object, callback: (...args: unknown[]) => void) =>
                lookup(host, lookupOptions, (err: unknown, address: unknown, family: unknown) => {
                    if (!err) handed.push(address);
                    callback(err, address, family);
                }),
        });
    };
    const client = new UltraTonClient({ ...options, [kTransport]: transport } as any);
    t.after(() => client.close());
    return { client, opened: () => handed.length };
}

export const ipv6Available = await new Promise<boolean>(resolve => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '::1', () => probe.close(() => resolve(true)));
});
