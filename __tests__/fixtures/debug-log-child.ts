/**
 * Child process of debug-log.test.ts: one request with every kind of secret (URL credentials, a query string, a
 * `;param`, an authorization header, `auth`) against a loopback server, then exit. What it writes to stderr is what
 * NODE_DEBUG=ultraton would show a user.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../../src/http-client.ts';

const server = http.createServer((_req, res) => res.end('ok'));
await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
const { port } = server.address() as AddressInfo;
const client = new UltraTonClient({ permitReservedIps: true });
try {
    await client.get(`http://127.0.0.1:${port}/a;jsessionid=s3cret/b?token=s3cret`, { auth: 'u:s3cret', headers: { authorization: 'Bearer s3cret' } });
    await client.get(`http://127.0.0.1:1/down`, { timeoutMs: 2000 }).catch(() => {});
} finally {
    await client.close();
    server.close();
}
