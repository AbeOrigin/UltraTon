/**
 * Mitigation for CVE-2026-105481: on a Node whose keep-alive pool reuse is unsafe, UltraTon's HTTP/1.1 agents run with
 * keepAlive off, so no socket sits idle in a pool to take a response a server wrote before the next request went out.
 * The version gate is unit-tested against the same release train as Brotli; the behaviour is checked end to end by
 * counting the TCP connections a loopback server accepts for two sequential requests (reused when safe, one each when
 * not). Preloaded loopback guard (fixtures/loopback-only.ts) keeps every socket here on 127.0.0.1.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { createSecureAgents } from '../src/agents.ts';
import { SecureHttpError } from '../src/errors.ts';
import { hasSafeKeepAlive, KEEP_ALIVE } from '../src/helpers/keep-alive.ts';

describe('hasSafeKeepAlive (CVE-2026-105481)', () => {
    it('is true on the fixed releases and anything newer on their line, and on later lines', () => {
        for (const v of ['22.23.4', '22.24.0', '24.22.1', '24.23.0', '26.12.1', '26.13.0', '27.0.0', '28.1.0']) {
            assert.equal(hasSafeKeepAlive(v), true, v);
        }
    });

    it('is false on earlier patches, end-of-life lines, prereleases and unparseable versions', () => {
        for (const v of ['22.12.0', '22.23.3', '24.14.1', '24.22.0', '26.12.0', '23.11.0', '25.9.0', '20.19.0', 'x', '26.12.1-pre', '27.0.0-rc.1', '28.0.0-nightly20261020abc']) {
            assert.equal(hasSafeKeepAlive(v), false, v);
        }
    });

    it('KEEP_ALIVE reflects the Node actually running the test', () => {
        assert.equal(KEEP_ALIVE, hasSafeKeepAlive(process.versions.node));
    });
});

/** A loopback HTTP/1.1 server that answers 200 and counts the TCP connections it accepts. */
async function serveCounting(t: TestContext) {
    let accepted = 0;
    const sockets = new Set<Socket>();
    const server = http.createServer((_req, res) => res.end('ok'));
    server.on('connection', socket => {
        accepted++;
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>(resolve => server.close(() => resolve()));
    });
    return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/`, accepted: () => accepted };
}

describe('HTTP/1.1 keep-alive is off on an unsafe Node', () => {
    it('reuses one socket when safe, opens a fresh one per request when not', async (t) => {
        const server = await serveCounting(t);
        const client = new UltraTonClient({ permitReservedIps: true });
        t.after(() => client.close());

        const first = await client.get(server.url, { timeoutMs: 5000 });
        const second = await client.get(server.url, { timeoutMs: 5000 });

        assert.equal(first.statusCode, 200);
        assert.equal(second.statusCode, 200);
        // Safe Node: the pool reuses the idle socket, so the server sees one connection. Unsafe Node (keepAlive off):
        // each request opens and closes its own, so the server sees two and nothing is ever left idle to be poisoned.
        assert.equal(server.accepted(), KEEP_ALIVE ? 1 : 2);
    });
});

// keepAlive off alone left a gap: createSecureAgents() returns agents a caller can change. keepAlive set back to true
// brings the pool back; with a socket limit, Node queues a request and hands it the socket a response just ended on,
// before it checks keepAlive (and a finite maxSockets also turns keep-alive back on). On an unsafe Node they refuse all three.
describe('createSecureAgents() cannot be switched back to socket reuse (CVE-2026-105481)', () => {
    const refused = (err: unknown) =>
        err instanceof SecureHttpError && err.code === 'ERR_ULTRATON_AGENT_KEEP_ALIVE' && /CVE-2026-105481/.test(err.message);
    const settings = [['keepAlive', false, true], ['maxSockets', Infinity, 4], ['maxTotalSockets', Infinity, 1]] as const;

    it(KEEP_ALIVE ? 'leaves keepAlive and the limits settable on a fixed Node' : 'refuses keepAlive, maxSockets and maxTotalSockets on an unsafe Node', () => {
        const agents = createSecureAgents();
        for (const agent of [agents.http, agents.https]) {
            const settable = agent as unknown as Record<string, unknown>;
            for (const [key, pinned, other] of settings) {
                if (KEEP_ALIVE) {
                    settable[key] = other;
                    assert.equal(settable[key], other, key);
                } else {
                    assert.throws(() => { settable[key] = other; }, refused, key);
                    assert.equal(settable[key], pinned, key);
                    settable[key] = pinned; // the value it already has: accepted
                    assert.throws(() => Object.defineProperty(agent, key, { value: other }), TypeError, `${key} cannot be redefined`);
                }
            }
            agent.destroy();
        }
    });

    it('a caller Connection: keep-alive header does not bring socket reuse back', async (t) => {
        const server = await serveCounting(t);
        const { http: agent } = createSecureAgents({ permitReservedIps: true });
        t.after(() => agent.destroy());
        const get = () => new Promise<number | undefined>((resolve, reject) => {
            http.get(server.url, { agent, headers: { connection: 'keep-alive' } }, res => {
                res.resume();
                res.on('end', () => resolve(res.statusCode));
            }).on('error', reject);
        });

        assert.equal(await get(), 200);
        assert.equal(await get(), 200);
        assert.equal(server.accepted(), KEEP_ALIVE ? 1 : 2);
    });
});
