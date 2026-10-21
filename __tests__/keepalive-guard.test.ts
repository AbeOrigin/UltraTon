/**
 * Regression tests for CVE-2026-105481: a keep-alive socket back in the pool must never hand a request bytes the server
 * wrote before that request was sent. UltraTon has no guard of its own (see SECURITY.md): on the Node releases CI runs,
 * Node destroys a socket whose server glues a second response to the first, and drops bytes reaching an idle pooled
 * socket. These tests hold that on every release line, for the client and for the secure agents. A raw TCP server
 * controls exactly when each byte is written.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net, { type AddressInfo, type Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { createSecureAgents } from '../src/agents.ts';

const EVIL = 'HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: keep-alive\r\n\r\nEVIL';
const reply = (body: string) => `HTTP/1.1 200 OK\r\ncontent-length: ${body.length}\r\nconnection: keep-alive\r\n\r\n${body}`;

type Mode = 'well-behaved' | 'glued' | 'idle';

/**
 * Answers the n-th request it receives (across connections) with 'one', 'two', ... After the first answer, 'glued'
 * writes an extra response in the same write, and 'idle' writes it 50 ms later, while the socket sits in the pool.
 */
async function server(t: TestContext, mode: Mode) {
    let requests = 0;
    let connections = 0;
    const sockets = new Set<Socket>();
    const srv = net.createServer(socket => {
        connections++;
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        socket.on('error', () => {});
        let buffered = '';
        socket.on('data', chunk => {
            buffered += chunk.toString('latin1');
            for (let end = buffered.indexOf('\r\n\r\n'); end !== -1; end = buffered.indexOf('\r\n\r\n')) {
                buffered = buffered.slice(end + 4);
                requests++;
                const body = ['one', 'two', 'three'][requests - 1] ?? 'more';
                if (requests === 1 && mode === 'glued') socket.write(reply(body) + EVIL);
                else socket.write(reply(body));
                if (requests === 1 && mode === 'idle') setTimeout(() => { if (!socket.destroyed) socket.write(EVIL); }, 50);
            }
        });
    });
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
    t.after(async () => {
        for (const s of sockets) s.destroy();
        await new Promise<void>(r => srv.close(() => r()));
    });
    return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}/`, connections: () => connections };
}

const pause = (ms: number) => new Promise(r => setTimeout(r, ms));

/** What the second request ended with: its body, or the error it failed with. Anything but 'EVIL' is acceptable. */
async function secondOutcome(first: () => Promise<string>, second: () => Promise<string>): Promise<string> {
    assert.equal(await first(), 'one');
    await pause(100);
    try {
        return await second();
    } catch (err) {
        return `error: ${(err as Error).name}`;
    }
}

function viaClient(t: TestContext, url: string) {
    const client = new UltraTonClient({ permitReservedIps: true });
    t.after(() => client.close());
    return () => client.get(url).then(res => res.text());
}

function viaAgents(t: TestContext, url: string) {
    const agents = createSecureAgents({ permitReservedIps: true });
    t.after(() => { agents.http.destroy(); agents.https.destroy(); });
    return () => new Promise<string>((resolve, reject) => {
        http.get(url, { agent: agents.http }, res => {
            const chunks: Buffer[] = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks).toString()));
            res.on('error', reject);
        }).on('error', reject);
    });
}

for (const [label, make] of [['UltraTonClient', viaClient], ['createSecureAgents', viaAgents]] as const) {
    describe(`stale bytes on a pooled keep-alive socket (${label})`, () => {
        it('bytes glued to the end of a response are never taken as the next one', async (t) => {
            const { url } = await server(t, 'glued');
            const get = make(t, url);
            assert.notEqual(await secondOutcome(get, get), 'EVIL');
        });

        it('bytes written while the socket is idle are never taken as the next one', async (t) => {
            const { url } = await server(t, 'idle');
            const get = make(t, url);
            assert.notEqual(await secondOutcome(get, get), 'EVIL');
        });

        it('a well-behaved server keeps one socket for both requests', async (t) => {
            const { url, connections } = await server(t, 'well-behaved');
            const get = make(t, url);
            assert.equal(await secondOutcome(get, get), 'two');
            assert.equal(connections(), 1);
        });
    });
}
