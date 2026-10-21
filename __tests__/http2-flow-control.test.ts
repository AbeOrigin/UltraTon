import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type ServerHttp2Stream } from 'node:http2';
import type { AddressInfo } from 'node:net';
import { UltraTonClient } from '../src/http-client.ts';
import { H2_CONNECTION_WINDOW, H2_STREAM_WINDOW } from '../src/constants.ts';

/** An h2c server on loopback that hands each stream to `onStream`. */
async function h2Server(t: TestContext, onStream: (stream: ServerHttp2Stream) => void) {
    const server = createServer().on('stream', onStream);
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(() => new Promise<void>(r => server.close(() => r())));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function clientOf(t: TestContext) {
    const client = new UltraTonClient({ http2: true, permitReservedIps: true, maxBodySize: 4 * 1024 * 1024 });
    t.after(() => client.close());
    return client;
}

describe('HTTP/2 flow control', () => {
    it('advertises the stream window and raises the connection window', async (t) => {
        let seen: { stream?: number; connection?: number } = {};
        const base = await h2Server(t, stream => {
            seen = { stream: stream.session?.remoteSettings.initialWindowSize, connection: stream.session?.state.remoteWindowSize };
            stream.respond({ ':status': 200 });
            stream.end('ok');
        });
        await clientOf(t).get(`${base}/`);
        assert.equal(seen.stream, H2_STREAM_WINDOW);
        // What the server may still send on the connection: the raised window, minus nothing yet.
        assert.equal(seen.connection, H2_CONNECTION_WINDOW);
    });

    it('lets a server send at most one stream window to a stream() body nobody reads', async (t) => {
        let written = 0;
        let flowing = true;
        const base = await h2Server(t, stream => {
            const chunk = Buffer.alloc(16 * 1024);
            stream.respond({ ':status': 200 });
            const pump = () => {
                while (written < 3 * H2_STREAM_WINDOW) {
                    written += chunk.length;
                    if (!stream.write(chunk)) { flowing = false; stream.once('drain', pump); return; }
                }
                stream.end();
            };
            stream.on('error', () => {});
            pump();
        });
        const res = await clientOf(t).stream(`${base}/`, { maxBodySize: 8 * H2_STREAM_WINDOW });
        await new Promise(r => setTimeout(r, 300));
        assert.equal(flowing, false);
        // One window, plus what the server's own stream buffer accepted before write() returned false.
        assert.ok(written <= H2_STREAM_WINDOW + 64 * 1024, `server wrote ${written} bytes`);
        await res.body.cancel();
    });

    it('still delivers a body larger than both default windows', async (t) => {
        const body = Buffer.alloc(2 * H2_STREAM_WINDOW, 7);
        const base = await h2Server(t, stream => {
            stream.respond({ ':status': 200 });
            stream.end(body);
        });
        const res = await clientOf(t).get(`${base}/`);
        assert.equal(res.data.length, body.length);
        assert.ok(res.data.equals(body));
    });
});
