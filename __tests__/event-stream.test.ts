/**
 * The Server-Sent Events parser (WHATWG HTML, "Parsing an event stream"), on its own: fed a stream built in the test,
 * chunk by chunk. `client.events()` over real servers is in events.test.ts.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEventStream } from '../src/helpers/event-stream.ts';
import type { UltraTonEvent } from '../src/types/request-response.ts';

const encoder = new TextEncoder();

/** A body that yields these chunks (strings are UTF-8 encoded), then ends. */
function bodyOf(chunks: Array<string | Uint8Array>): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(controller) {
            for (const chunk of chunks) controller.enqueue(typeof chunk === 'string' ? encoder.encode(chunk) : chunk);
            controller.close();
        },
    });
}

async function collect(chunks: Array<string | Uint8Array> | string, maxEventSize = 64 * 1024): Promise<UltraTonEvent[]> {
    const events: UltraTonEvent[] = [];
    const body = bodyOf(typeof chunks === 'string' ? [chunks] : chunks);
    for await (const event of parseEventStream(body.getReader(), { maxEventSize, idleMs: 0 })) events.push(event);
    return events;
}

const plain = (events: UltraTonEvent[]) => events.map(e => ({ ...e }));

describe('parseEventStream', () => {
    it('joins data lines and defaults the type to message', async () => {
        assert.deepEqual(plain(await collect('data: a\ndata: b\n\n')), [{ event: 'message', data: 'a\nb', id: '', retry: undefined }]);
    });

    it('takes CR, LF and CRLF as line ends, and drops a leading BOM', async () => {
        const events = await collect('﻿data: x\r\n\r\ndata: y\r\rdata: z\n\n');
        assert.deepEqual(events.map(e => e.data), ['x', 'y', 'z']);
    });

    it('ignores comments, unknown fields and an event without data', async () => {
        assert.deepEqual(await collect(': ping\n\nevent: e\n\nfoo: bar\n\n'), []);
    });

    it('removes one space after the colon, no more, and a field with no colon has an empty value', async () => {
        const events = await collect('data:  two spaces\n\ndata\ndata:x\n\n');
        assert.deepEqual(events.map(e => e.data), [' two spaces', '\nx']);
    });

    it('keeps the type for one event only, and id and retry across events', async () => {
        const events = await collect('event: tick\nid: 7\nretry: 1500\ndata: a\n\ndata: b\n\n');
        assert.deepEqual(plain(events), [
            { event: 'tick', data: 'a', id: '7', retry: 1500 },
            { event: 'message', data: 'b', id: '7', retry: 1500 },
        ]);
    });

    it('ignores an id with NUL and a retry that is not all ASCII digits', async () => {
        const events = await collect('id: 1\ndata: a\n\nid: 2\u00003\nretry: 12a\nretry: -5\nretry: ٣\ndata: b\n\n');
        assert.deepEqual(events.map(e => [e.id, e.retry]), [['1', undefined], ['1', undefined]]);
    });

    it('an empty id resets the last event id', async () => {
        const events = await collect('id: 1\ndata: a\n\nid\ndata: b\n\n');
        assert.deepEqual(events.map(e => e.id), ['1', '']);
    });

    it('drops an event the stream ends in the middle of', async () => {
        assert.deepEqual((await collect('data: a\n\ndata: cut')).map(e => e.data), ['a']);
    });

    it('decodes UTF-8 split across chunks, and a CRLF split across chunks is one line end', async () => {
        const bytes = encoder.encode('data: ñandú €\r\n\r\n');
        const chunks = Array.from(bytes, b => new Uint8Array([b]));
        assert.deepEqual((await collect(chunks)).map(e => e.data), ['ñandú €']);
    });

    it('replaces invalid UTF-8 instead of failing', async () => {
        const events = await collect([encoder.encode('data: a'), new Uint8Array([0xff]), encoder.encode('b\n\n')]);
        assert.equal(events[0].data, 'a�b');
    });

    it('fails an event over maxEventSize, also when no line ever ends', async () => {
        const tooLarge = { name: 'UltraTonMemoryError', code: 'ERR_ULTRATON_EVENT_TOO_LARGE' };
        await assert.rejects(collect(`data: ${'x'.repeat(2000)}`, 1024), tooLarge);
        await assert.rejects(collect(Array.from({ length: 40 }, () => `data: ${'x'.repeat(50)}\n`), 1024), tooLarge);
        // Each event under the limit: the count restarts at every dispatch.
        assert.equal((await collect(Array.from({ length: 40 }, () => `data: ${'x'.repeat(50)}\n\n`), 1024)).length, 40);
    });

    // Linear time is pinned by LineBuffer's growth count below: a wall-clock bound here flaked on slow CI runners.
    it('a line in one-byte chunks comes out whole', async () => {
        const line = `data: ${'x'.repeat(6_000)}\n\n`;
        const chunks = Array.from(encoder.encode(line), b => new Uint8Array([b]));
        assert.equal((await collect(chunks, 64 * 1024))[0].data.length, 6_000);
    });

    it('events have no prototype and are frozen', async () => {
        const [event] = await collect('data: a\n\n');
        assert.equal(Object.getPrototypeOf(event), null);
        assert.ok(Object.isFrozen(event));
    });
});

describe('LineBuffer', () => {
    it('holds a line that arrives a byte at a time in about twice its bytes, and gives it back whole', async () => {
        const { LineBuffer } = await import('../src/helpers/event-stream.ts');
        const buffer = new LineBuffer();
        const bytes = encoder.encode('x'.repeat(10_000));
        // Doubling keeps it linear (each byte copied about twice): a buffer grown to fit each chunk would reallocate
        // 10,000 times, a quadratic copy. 64 to 16 KiB is 9 growths.
        let growths = 0;
        for (let i = 0; i < bytes.length; i++) {
            const before = buffer.capacity;
            buffer.append(bytes.subarray(i, i + 1));
            if (buffer.capacity !== before) growths++;
        }
        assert.ok(growths <= 10, `${growths} reallocations`);
        assert.equal(buffer.length, 10_000);
        assert.ok(buffer.capacity <= 2 * 10_000, `capacity ${buffer.capacity}`);
        const line = buffer.take(encoder.encode('yz'));
        assert.equal(line.toString(), `${'x'.repeat(10_000)}yz`);
        assert.equal(buffer.length, 0);
        assert.equal(buffer.capacity, 0, 'the memory is let go once the line is taken');
    });
});
