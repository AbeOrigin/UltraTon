/**
 * The WebSocket frame parser and encoder (RFC 6455), on frames built by hand: every bound is checked from the header,
 * before any payload is read, and every frame a server may not send fails with the close code the RFC names.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encodeFrame, FrameError, FrameParser, Opcode, type Incoming } from '../src/helpers/websocket.ts';
import { closePayload, frame } from './fixtures/ws-server.ts';

function parse(bytes: Uint8Array, max = 1 << 20): Incoming[] {
    return new FrameParser(max).push(bytes);
}

function failsWith(code: number, bytes: Uint8Array, max = 1 << 20): void {
    assert.throws(() => parse(bytes, max), (err: unknown) => err instanceof FrameError && err.closeCode === code);
}

describe('FrameParser', () => {
    it('reads a text frame with each length form', () => {
        for (const n of [0, 125, 126, 65535, 65536]) {
            const [msg] = parse(frame(Opcode.Text, 'x'.repeat(n)), 70_000);
            assert.deepEqual(msg, { kind: 'message', data: 'x'.repeat(n) });
        }
    });

    it('reads a binary frame as a Buffer', () => {
        const [msg] = parse(frame(Opcode.Binary, Buffer.from([0, 255, 7])));
        assert.ok(msg.kind === 'message' && Buffer.isBuffer(msg.data));
        assert.deepEqual([...(msg.data as Buffer)], [0, 255, 7]);
    });

    it('joins fragments and lets a ping through between them', () => {
        const out = parse(Buffer.concat([
            frame(Opcode.Text, 'ab', { fin: false }),
            frame(Opcode.Ping, 'p'),
            frame(Opcode.Continuation, '', { fin: false }),
            frame(Opcode.Continuation, 'c'),
        ]));
        assert.deepEqual(out, [{ kind: 'ping', payload: Buffer.from('p') }, { kind: 'message', data: 'abc' }]);
    });

    it('a multibyte character split across fragments is one string', () => {
        const euro = Buffer.from('€');
        const out = parse(Buffer.concat([frame(Opcode.Text, euro.subarray(0, 1), { fin: false }), frame(Opcode.Continuation, euro.subarray(1))]));
        assert.deepEqual(out, [{ kind: 'message', data: '€' }]);
    });

    it('reads a frame fed one byte at a time', () => {
        const parser = new FrameParser(1 << 20);
        const out: Incoming[] = [];
        for (const byte of frame(Opcode.Text, 'y'.repeat(300))) out.push(...parser.push(Uint8Array.of(byte)));
        assert.deepEqual(out, [{ kind: 'message', data: 'y'.repeat(300) }]);
    });

    it('rejects a masked server frame with 1002', () => {
        failsWith(1002, frame(Opcode.Text, 'a', { mask: true }));
    });

    it('rejects RSV1, RSV2, RSV3 and reserved opcodes with 1002', () => {
        for (const rsv of [4, 2, 1]) failsWith(1002, frame(Opcode.Text, 'a', { rsv }));
        for (const opcode of [3, 4, 5, 6, 7, 0xb, 0xc, 0xd, 0xe, 0xf]) failsWith(1002, frame(opcode));
    });

    it('rejects a fragmented or oversized control frame with 1002', () => {
        failsWith(1002, frame(Opcode.Ping, 'a', { fin: false }));
        failsWith(1002, frame(Opcode.Ping, 'x'.repeat(126)));
    });

    it('rejects a continuation with nothing to continue, and a new data frame mid-message, with 1002', () => {
        failsWith(1002, frame(Opcode.Continuation, 'a'));
        failsWith(1002, Buffer.concat([frame(Opcode.Text, 'a', { fin: false }), frame(Opcode.Binary, 'b')]));
    });

    it('rejects a 64-bit length with the top bit set with 1002, before any payload', () => {
        const head = Buffer.from([0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        failsWith(1002, head);
    });

    it('rejects a frame announcing more than maxMessageSize with 1009, before any payload', () => {
        // Only the 10-byte header announcing 2^40 bytes: the parser fails without waiting for a byte of payload.
        const huge = Buffer.from([0x82, 127, 0, 0, 0x01, 0, 0, 0, 0, 0]);
        failsWith(1009, huge);
        failsWith(1009, Buffer.from([0x82, 127, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
        failsWith(1009, frame(Opcode.Binary, '', { length: 1025 }).subarray(0, 4), 1024);
    });

    it('rejects fragments that add up past maxMessageSize with 1009', () => {
        const first = frame(Opcode.Binary, Buffer.alloc(600), { fin: false });
        const second = frame(Opcode.Continuation, Buffer.alloc(600)).subarray(0, 4);
        failsWith(1009, Buffer.concat([first, second]), 1024);
    });

    it('rejects invalid UTF-8 in a text message and in a close reason with 1007', () => {
        failsWith(1007, frame(Opcode.Text, Buffer.from([0xc3])));
        failsWith(1007, frame(Opcode.Close, Buffer.concat([Buffer.from([0x03, 0xe8]), Buffer.from([0xff])])));
    });

    it('close: no payload is 1005; one byte or an invalid code is 1002', () => {
        assert.deepEqual(parse(frame(Opcode.Close)), [{ kind: 'close', code: 1005, reason: '' }]);
        assert.deepEqual(parse(frame(Opcode.Close, closePayload(4000, 'bye'))), [{ kind: 'close', code: 4000, reason: 'bye' }]);
        failsWith(1002, frame(Opcode.Close, Buffer.from([3])));
        for (const code of [0, 999, 1004, 1005, 1006, 1015, 1016, 2000, 2999, 5000]) failsWith(1002, frame(Opcode.Close, closePayload(code)));
        for (const code of [1000, 1001, 1002, 1003, 1007, 1011, 1014, 3000, 4999]) {
            assert.deepEqual(parse(frame(Opcode.Close, closePayload(code))), [{ kind: 'close', code, reason: '' }]);
        }
    });
});

describe('encodeFrame', () => {
    it('masks the payload, and unmasking gives it back, with each length form', () => {
        const mask = Uint8Array.of(1, 2, 3, 4);
        for (const n of [0, 125, 126, 65536]) {
            const payload = Buffer.alloc(n, 'z');
            const out = encodeFrame(Opcode.Binary, payload, mask);
            assert.equal(out[0], 0x82);
            assert.equal(out[1] & 0x80, 0x80);
            const headerLen = n < 126 ? 2 : n < 65536 ? 4 : 10;
            assert.deepEqual([...out.subarray(headerLen, headerLen + 4)], [1, 2, 3, 4]);
            const body = out.subarray(headerLen + 4);
            assert.equal(body.length, n);
            assert.ok(body.every((byte, i) => (byte ^ mask[i & 3]) === 0x7a));
        }
    });
});
