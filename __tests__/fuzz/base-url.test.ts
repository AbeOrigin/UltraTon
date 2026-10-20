/**
 * Property test (no dependencies, see fuzz.ts) for baseUrl containment: no request path UltraTon accepts may land
 * outside the base path, as the most lenient server reads it. Paths are assembled from the pieces traversal bypasses
 * use (encoded, double-encoded and overlong dots and slashes, backslashes, fullwidth and look-alike characters,
 * ;params). The path is judged as a loopback server actually receives it, byte for byte.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { UltraTonClient } from '../../src/http-client.ts';
import { forAll } from './fuzz.ts';

const PIECES = [
    '..', '.', '...', 'a', 'users', '7', '/', '\\', ';', ';x=1', '?', '#', ' ', '\t',
    '%2e', '%2E', '%2e%2e', '%252e', '%25252e', '%2f', '%2F', '%252f', '%5c', '%5C', '%255c', '%3b', '%3f', '%23',
    '%00', '%20', '%c0%ae', '%c0%af', '%e0%80%ae', '%u002e', '%c2%a0', '%e2%88%95', '∕', '⧵', '．', '／',
    '%ef%bc%8e', '‥', '%e2%80%a5',
];

/**
 * Whether `path` (absolute, as sent) escapes `/v1/` for a lenient server: percent-decoded until stable (a run that is
 * not UTF-8 counts as an escape: such a server may read it as anything), NFKC, every slash look-alike a separator,
 * each segment cut at ';', '?' or '#', and a segment of only dots and trailing junk read as '..' (IIS trims trailing
 * dots and spaces). A last segment of three or more dots is a file name, as UltraTon deliberately allows.
 */
function escapesBase(path: string): boolean {
    // The query is not part of the path: a server splits it off at the raw '?' before decoding anything.
    let text = path.split('?', 1)[0];
    for (let pass = 0; pass < 8; pass++) {
        let next: string;
        try {
            next = text.replace(/(?:%[0-9A-Fa-f]{2})+/g, run => new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(run.replace(/%/g, ''), 'hex')));
        } catch {
            return true;
        }
        next = next.normalize('NFKC');
        if (next === text) break;
        text = next;
    }
    const segments = text.split(/[/\\∕⧵]/).map(s => s.split(/[;?#]/, 1)[0]);
    const stack: string[] = [];
    segments.forEach((segment, i) => {
        // Only dots plus spaces/controls, with at least one dot.
        const dotsOnly = segment.includes('.') && /^[.\u0000- \u007f-\u009f]*$/.test(segment);
        const dots = segment.replace(/[^.]/g, '').length;
        if (!dotsOnly || (dots >= 3 && i === segments.length - 1)) {
            if (segment !== '') stack.push(segment);
        } else if (dots >= 2) {
            if (stack.length === 0) stack.push('\u0000escaped');
            else stack.pop();
        }
    });
    return stack[0] !== 'v1';
}

describe('fuzz: baseUrl containment', () => {
    it('no accepted request path lands outside the base path, however a lenient server decodes it', async (t: TestContext) => {
        // A loopback server records the request target exactly as it arrives.
        let sent: string | undefined;
        const sockets = new Set<Socket>();
        const server = http.createServer((req, res) => { sent = req.url; res.writeHead(200, { 'content-type': 'text/plain' }); res.end(); });
        server.on('connection', (s: Socket) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => server.close(() => r())); });
        const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/`;
        const client = new UltraTonClient({ baseUrl: base, permitReservedIps: true, timeoutMs: 2000 });
        t.after(() => client.close());

        await forAll(r => r.array(1, 8, () => r.pick(PIECES)), async pieces => {
            sent = undefined;
            const path = pieces.join('');
            try {
                await client.get(path);
            } catch {
                // Refused (TypeError, invalid URL): only a path that reached the server is judged below.
            }
            if (sent !== undefined) assert.equal(escapesBase(sent), false, `accepted ${JSON.stringify(path)}, sent as ${sent}`);
        });
    });
});
