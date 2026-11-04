/**
 * Property test (no dependencies, see fuzz.ts) for the Server-Sent Events parser: however the server's bytes are cut
 * into chunks (inside a multi-byte character, a CRLF, the BOM), the events are the ones the unsplit stream gives.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseEventStream } from '../../src/helpers/event-stream.ts';
import { forAll, type Rand } from './fuzz.ts';

const PIECES = ['data', 'event', 'id', 'retry', 'foo', ':', ': ', ' ', 'x', '42', 'ñ', '€', '😀', '\0', '\r', '\n', '\r\n', '\n\n', '\r\n\r\n'];

/** A stream body: an optional BOM, then pieces that make fields, comments, blank lines and line ends of all kinds. */
function stream(r: Rand): { bytes: Uint8Array; cuts: number[] } {
    const text = (r.chance(0.2) ? '﻿' : '') + r.array(0, 40, () => r.pick(PIECES)).join('');
    const bytes = new TextEncoder().encode(text);
    const cuts = r.array(0, 8, () => r.int(bytes.length + 1)).sort((a, b) => a - b);
    return { bytes, cuts };
}

function bodyOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
    return new ReadableStream({
        start(controller) {
            for (const chunk of chunks) controller.enqueue(chunk);
            controller.close();
        },
    });
}

async function parse(chunks: Uint8Array[]): Promise<unknown[]> {
    const events: unknown[] = [];
    for await (const event of parseEventStream(bodyOf(chunks).getReader(), { maxEventSize: 1 << 20, idleMs: 0 })) events.push({ ...event });
    return events;
}

describe('fuzz: Server-Sent Events parser', () => {
    it('gives the same events however the bytes are split into chunks', async () => {
        await forAll(stream, async ({ bytes, cuts }) => {
            const chunks: Uint8Array[] = [];
            let at = 0;
            for (const cut of [...cuts, bytes.length]) {
                chunks.push(bytes.subarray(at, cut));
                at = cut;
            }
            assert.deepEqual(await parse(chunks), await parse([bytes]));
        });
    });
});
