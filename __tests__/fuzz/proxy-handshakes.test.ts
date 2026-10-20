/**
 * Property tests (no dependencies, see fuzz.ts) for the proxy handshakes against a hostile proxy on loopback: generated
 * CONNECT responses and SOCKS5 replies, split at random points. A valid, complete answer must open the tunnel; an
 * invalid one must never open it, and must fail cleanly (a refusal, a reset, or the caller's abort when the proxy goes
 * silent mid-answer). Nothing may hang.
 *
 * Bytes after a valid answer must be refused when they arrive in the same write as its end (loopback writes may merge,
 * never split, so one write arrives whole). Bytes in a later write are tunnel traffic (what the target sends), which
 * TLS then rejects, since its client speaks first: for those either outcome is correct.
 */
import { describe, it, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import net, { type AddressInfo } from 'node:net';
import { setImmediate as tick } from 'node:timers/promises';
import { tunnelTo, type ProxyConfig } from '../../src/proxy/tunnel.ts';
import { forAll, type Rand } from './fuzz.ts';

interface Answer { chunks: Buffer[]; close: boolean }

/** Splits `bytes` at random points into 1 to 4 chunks. */
function split(r: Rand, bytes: Buffer): Buffer[] {
    const cuts = [...new Set(r.array(0, 3, () => r.int(bytes.length + 1)))].sort((a, b) => a - b);
    const chunks: Buffer[] = [];
    let at = 0;
    for (const cut of [...cuts, bytes.length]) { chunks.push(bytes.subarray(at, cut)); at = cut; }
    return chunks.filter(c => c.length > 0);
}

/**
 * A proxy on loopback that answers the n-th read of each connection with `answers.current[n]` (CONNECT: one step;
 * SOCKS5: the method choice, then the reply), chunk by chunk, then closes if asked.
 */
async function hostileProxy(t: TestContext) {
    const answers: { current: Answer[] } = { current: [] };
    const sockets = new Set<net.Socket>();
    const server = net.createServer(socket => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        socket.on('error', () => undefined);
        let step = 0;
        const script = answers.current;
        socket.on('data', async () => {
            const answer = script[step++];
            if (!answer) return;
            for (const chunk of answer.chunks) { if (socket.destroyed) return; socket.write(chunk); await tick(); }
            if (answer.close) socket.end();
        });
    });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    t.after(async () => { for (const s of sockets) s.destroy(); await new Promise<void>(r => server.close(() => r())); });
    return { port: (server.address() as AddressInfo).port, answers };
}

/** What tunnelTo did: opened, or failed with which error. Never longer than the abort. */
async function attempt(proxy: ProxyConfig): Promise<{ opened: boolean; error?: any }> {
    try {
        const socket = await tunnelTo(proxy, ['127.0.0.1'], 443, AbortSignal.timeout(250));
        socket.destroy();
        return { opened: true };
    } catch (error) {
        return { opened: false, error };
    }
}

type Verdict = 'valid' | 'invalid' | 'valid-then-extra';

/** Whether the write that carries byte `last` (the answer's final byte) also carries bytes after it. */
function extraInSameWrite(chunks: readonly Buffer[], last: number): boolean {
    let start = 0;
    for (const chunk of chunks) {
        const end = start + chunk.length;
        if (last >= start && last < end) return end > last + 1;
        start = end;
    }
    return false;
}

/**
 * The property for one attempt. A clean failure is the proxy's refusal or malformed answer, a reset, or the abort
 * when the proxy went silent mid-answer (`mayHang`).
 */
function check(verdict: Verdict, result: { opened: boolean; error?: any }, mayHang: boolean, extraWithAnswer: boolean, context: string) {
    if (verdict === 'valid') {
        assert.equal(result.opened, true, `${context}: valid answer refused (${result.error?.code} ${result.error?.message})`);
        return;
    }
    if (verdict === 'invalid') assert.equal(result.opened, false, `${context}: tunnel opened on an invalid answer`);
    if (verdict === 'valid-then-extra' && extraWithAnswer) {
        assert.equal(result.opened, false, `${context}: tunnel opened although bytes came with the answer`);
        assert.equal(result.error?.code, 'ERR_ULTRATON_PROXY', `${context}: ${result.error?.message}`);
    }
    if (result.opened) return;
    const e = result.error;
    const clean = e?.code === 'ERR_ULTRATON_PROXY' || e?.code === 'ECONNRESET' || (mayHang && (e?.name === 'TimeoutError' || e?.name === 'AbortError'));
    assert.ok(clean, `${context}: unexpected failure ${e?.name} ${e?.code} ${e?.message}`);
}

const STATUS_LINES = ['HTTP/1.1 200 OK', 'HTTP/1.0 200 Connection established', 'HTTP/1.1 204', 'HTTP/1.1 299 X', 'HTTP/1.1 2e2 X', 'HTTP/2 200 OK', 'HTTP/1.1 200OK', 'HTTP/1.1 407 Proxy Auth', 'HTTP/1.1 502 Bad Gateway', 'garbage', ''];
const HEADER_PIECES = ['\r\n', 'x-a: b\r\n', 'proxy-agent: p\r\n', '\n', '\r', 'via: 1.1 p\r\n'];

/** A CONNECT answer: a status line, some header pieces, maybe the blank line, maybe bytes after it. */
function connectAnswer(r: Rand): { text: string; close: boolean } {
    let text = r.pick(STATUS_LINES) + r.array(0, 3, () => r.pick(HEADER_PIECES)).join('');
    if (r.chance(0.8)) text += '\r\n\r\n';
    if (r.chance(0.15)) text += r.pick(['\x16\x03\x01', 'junk', '\r\n']);
    return { text, close: r.chance(0.85) };
}

/** An HTTP/1.0 or 1.1 2xx status line (three digits, then a space or the end) with complete headers. */
function connectVerdict(text: string): Verdict {
    const end = text.indexOf('\r\n\r\n');
    if (end === -1) return 'invalid';
    const line = text.slice(0, text.indexOf('\r\n'));
    if (!/^HTTP\/1\.[01] 2\d\d( |$)/.test(line)) return 'invalid';
    return text.length === end + 4 ? 'valid' : 'valid-then-extra';
}

/** A SOCKS5 reply to a CONNECT: valid by construction, then maybe mutated (a byte changed, cut short, extended). */
function socksReply(r: Rand): number[] {
    const atyp = r.pick([1, 4, 3]);
    const name = [...Buffer.from(r.pick(['a', 'proxy.example', '']))];
    const address = atyp === 1 ? [127, 0, 0, 1] : atyp === 4 ? Array.from({ length: 16 }, () => r.int(256)) : [name.length, ...name];
    const reply = [5, r.chance(0.8) ? 0 : r.int(10), 0, atyp, ...address, r.int(256), r.int(256)];
    const mutation = r.int(5);
    if (mutation === 0) reply[r.int(reply.length)] = r.int(256);
    if (mutation === 1) reply.length = r.int(reply.length);
    if (mutation === 2) reply.push(r.int(256));
    return reply;
}

/** The total length a SOCKS5 reply declares (from its address type), or -1 when it cannot be known. */
function socksLength(reply: number[]): number {
    if (reply.length < 4 || (reply[3] === 3 && reply.length < 5)) return -1;
    const address = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? 1 + reply[4] : -1;
    return address === -1 ? -1 : 4 + address + 2;
}

/** Whether the client is left waiting for more: the method answer or the reply stopped before it could be judged. */
function socksIncomplete(method: number[], reply: number[]): boolean {
    if (method.length < 2) return true;
    if (method[0] !== 5 || method[1] !== 0) return false;
    if (reply.length < 2) return true;
    if (reply[0] !== 5 || reply[1] !== 0) return false;
    if (reply.length < 5) return true;
    if (reply[2] !== 0 || ![1, 3, 4].includes(reply[3])) return false;
    return reply.length < socksLength(reply);
}

function socksVerdict(method: number[], reply: number[]): Verdict {
    if (method.length !== 2 || method[0] !== 5 || method[1] !== 0) return 'invalid';
    if (reply.length < 5 || reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) return 'invalid';
    const total = socksLength(reply);
    if (total === -1 || reply.length < total) return 'invalid';
    return reply.length === total ? 'valid' : 'valid-then-extra';
}

describe('fuzz: proxy handshakes against a hostile proxy', () => {
    it('CONNECT: a valid answer opens the tunnel, an invalid one never does, and nothing hangs', async (t) => {
        const proxy = await hostileProxy(t);
        const config: ProxyConfig = { url: new URL(`http://127.0.0.1:${proxy.port}`), kind: 'connect', resolve: 'local' };
        await forAll(r => { const a = connectAnswer(r); return { ...a, chunks: split(r, Buffer.from(a.text, 'latin1')) }; }, async input => {
            proxy.answers.current = [{ chunks: input.chunks, close: input.close }];
            const result = await attempt(config);
            const end = input.text.indexOf('\r\n\r\n');
            const extra = end !== -1 && extraInSameWrite(input.chunks, end + 3);
            check(connectVerdict(input.text), result, !input.close && end === -1, extra, JSON.stringify(input.text));
        });
    });

    it('SOCKS5: a valid method choice and reply open the tunnel, anything else never does, and nothing hangs', async (t) => {
        const proxy = await hostileProxy(t);
        const config: ProxyConfig = { url: new URL(`socks5://127.0.0.1:${proxy.port}`), kind: 'socks5', resolve: 'local' };
        await forAll(r => {
            const method = r.chance(0.85) ? [5, 0] : r.pick([[5, 0xff], [4, 0], [5, 2], [5]]);
            const reply = socksReply(r);
            return { method, reply, close: r.chance(0.85), methodChunks: split(r, Buffer.from(method)), replyChunks: split(r, Buffer.from(reply)) };
        }, async input => {
            proxy.answers.current = [{ chunks: input.methodChunks, close: false }, { chunks: input.replyChunks, close: input.close }];
            const result = await attempt(config);
            // Only an answer cut short leaves the client waiting (the abort is then the clean way out); a complete
            // refusal or malformed answer must fail at once. The method answer is never followed by a close.
            const mayHang = socksIncomplete(input.method, input.reply) && (!input.close || input.method.length < 2);
            const total = socksLength(input.reply);
            const extra = total > 0 && extraInSameWrite(input.replyChunks, total - 1);
            check(socksVerdict(input.method, input.reply), result, mayHang, extra, JSON.stringify({ method: input.method, reply: input.reply }));
        });
    });
});
