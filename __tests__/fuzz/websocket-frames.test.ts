/**
 * Property tests (no dependencies, see fuzz.ts) for the WebSocket frame parser: however the server's bytes are cut
 * into chunks (inside a header, an extended length, a payload, a multi-byte character), the result is the one the
 * unsplit bytes give; and random bytes never make it throw anything but a FrameError, nor hold more than its limit.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FrameError, FrameParser, Opcode } from '../../src/helpers/websocket.ts';
import { forAll, type Rand } from './fuzz.ts';

const TEXT = ['a', 'ñ', '€', '😀', ' ', 'xyz'];

function serverFrame(opcode: number, payload: Buffer, fin: boolean): Buffer {
    const len = payload.length;
    const head = len < 126 ? Buffer.from([0, len]) : len < 0x10000 ? Buffer.alloc(4) : Buffer.alloc(10);
    head[0] = (fin ? 0x80 : 0) | opcode;
    if (len >= 126 && len < 0x10000) { head[1] = 126; head.writeUInt16BE(len, 2); }
    if (len >= 0x10000) { head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    return Buffer.concat([head, payload]);
}

/** A valid sequence of messages, each in one or more fragments, with control frames between them. */
function stream(r: Rand): { bytes: Buffer; cuts: number[] } {
    const frames: Buffer[] = [];
    for (const _ of r.array(1, 6, () => 0)) {
        const binary = r.chance(0.3);
        const whole = binary
            ? Buffer.from(r.array(0, r.chance(0.1) ? 70_000 : 300, () => r.int(256)))
            : Buffer.from(r.array(0, 60, () => r.pick(TEXT)).join(''));
        // Split anywhere, a multi-byte character included: only the whole message must be UTF-8.
        const cuts = r.array(0, 3, () => r.int(whole.length + 1)).sort((a, b) => a - b);
        let at = 0;
        const parts = [...cuts, whole.length].map(cut => { const part = whole.subarray(at, cut); at = cut; return part; });
        parts.forEach((part, i) => {
            frames.push(serverFrame(i === 0 ? (binary ? Opcode.Binary : Opcode.Text) : Opcode.Continuation, part, i === parts.length - 1));
            if (r.chance(0.3)) frames.push(serverFrame(r.pick([Opcode.Ping, Opcode.Pong]), Buffer.from(r.array(0, 125, () => r.int(256))), true));
        });
    }
    if (r.chance(0.3)) frames.push(serverFrame(Opcode.Close, Buffer.from([0x03, 0xe8, 0x6f, 0x6b]), true));
    const bytes = Buffer.concat(frames);
    return { bytes, cuts: r.array(0, 12, () => r.int(bytes.length + 1)).sort((a, b) => a - b) };
}

function feed(bytes: Buffer, cuts: number[], max: number): unknown[] {
    const parser = new FrameParser(max);
    const out: unknown[] = [];
    let at = 0;
    for (const cut of [...cuts, bytes.length]) {
        out.push(...parser.push(bytes.subarray(at, cut)));
        at = cut;
    }
    return out;
}

describe('fuzz: WebSocket frame parser', () => {
    it('gives the same messages however the bytes are split into chunks', async () => {
        await forAll(stream, ({ bytes, cuts }) => {
            assert.deepEqual(feed(bytes, cuts, 1 << 20), feed(bytes, [], 1 << 20));
        });
    });

    it('random bytes only ever fail with a FrameError, within the limit', async () => {
        const max = 4096;
        await forAll(r => {
            const bytes = Buffer.from(r.array(0, 400, () => r.int(256)));
            return { bytes, cuts: r.array(0, 6, () => r.int(bytes.length + 1)).sort((a, b) => a - b) };
        }, ({ bytes, cuts }) => {
            try {
                for (const item of feed(bytes, cuts, max) as { kind: string; data?: string | Buffer }[]) {
                    if (item.kind === 'message') assert.ok(Buffer.byteLength(item.data as string | Buffer) <= max);
                }
            } catch (err) {
                assert.ok(err instanceof FrameError, String(err));
            }
        });
    });
});
