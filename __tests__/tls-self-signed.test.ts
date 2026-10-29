/**
 * A development server with a self-signed certificate is reached by trusting that certificate in `tls.ca`, on both
 * engines; verification itself never turns off. Covers a self-signed CA certificate (`CA:TRUE`, what `openssl req
 * -x509` makes) and a self-signed leaf (`CA:FALSE`, what Vite's and ASP.NET's dev certificates are).
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import { createSecureServer } from 'node:http2';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { UltraTonNetworkError } from '../src/errors.ts';

const fixture = (name: string) => fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const CERTS = {
    'self-signed CA certificate': { cert: fixture('localhost-cert.pem'), key: fixture('localhost-key.pem') },
    'self-signed leaf certificate': { cert: fixture('self-signed-leaf-cert.pem'), key: fixture('self-signed-leaf-key.pem') },
};

async function devServer(t: TestContext, http2: boolean, material: { cert: Buffer; key: Buffer }) {
    const handler = (_req: unknown, res: any) => res.end('dev');
    const server = http2 ? createSecureServer(material, handler) : https.createServer(material, handler);
    const sockets = new Set<Socket>();
    server.on('secureConnection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => server.close(() => r())); });
    return `https://localhost:${(server.address() as AddressInfo).port}/`;
}

function clientOf(t: TestContext, options: Record<string, unknown>) {
    const client = new UltraTonClient({ permitReservedIps: ['localhost'], ...options });
    t.after(() => client.close());
    return client;
}

for (const http2 of [false, true]) {
    for (const [kind, material] of Object.entries(CERTS)) {
        describe(`${http2 ? 'HTTP/2' : 'HTTP/1.1'}, ${kind}`, () => {
            it('is refused by default, as a TLS error with a code', async (t) => {
                const url = await devServer(t, http2, material);
                await assert.rejects(clientOf(t, { http2 }).get(url), (err: unknown) => {
                    assert.ok(err instanceof UltraTonNetworkError);
                    assert.match(err.message, /^UltraTon: TLS handshake failed \(/);
                    assert.ok(typeof err.code === 'string' && err.code !== 'UNKNOWN', String(err.code));
                    return true;
                });
            });

            it('is reached once tls.ca trusts that certificate', async (t) => {
                const url = await devServer(t, http2, material);
                const res = await clientOf(t, { http2, tls: { ca: material.cert } }).get(url);
                assert.equal(res.text(), 'dev');
            });

            it('is reached with the system roots plus that certificate, from a variant of a client', async (t) => {
                const url = await devServer(t, http2, material);
                const base = clientOf(t, { http2 });
                const dev = base.extend({ tls: { ca: [...tls.rootCertificates, material.cert] } });
                t.after(() => dev.close());
                assert.equal((await dev.get(url)).text(), 'dev');
                await assert.rejects(base.get(url), UltraTonNetworkError);
            });
        });
    }
}

describe('certificate verification cannot be turned off', () => {
    it('rejectUnauthorized is refused with a pointer to tls.ca, on the client and on a request', async (t) => {
        assert.throws(() => new UltraTonClient({ rejectUnauthorized: false } as any), { name: 'TypeError', message: /tls: \{ ca \}/ });
        const client = clientOf(t, {});
        await assert.rejects(client.get('https://localhost/', { rejectUnauthorized: false } as any), { name: 'TypeError', message: /Disabling certificate verification is not supported/ });
    });
});
