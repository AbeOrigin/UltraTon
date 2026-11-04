// Runs the Autobahn testsuite's client cases against UltraTon's WebSocket client (the built package in dist/), as the
// echo agent the suite expects: every message comes back as it was received. Then asks the fuzzing server for its
// report and fails unless every case passed. CI only (.github/workflows/autobahn.yml): case 9 sends messages of up to
// 16 MiB. The fuzzing server listens on 127.0.0.1:9001 (see config/fuzzingserver.json).
import fs from 'node:fs';
import { UltraTonClient } from '../../dist/index.js';

const BASE = 'ws://127.0.0.1:9001';
const AGENT = 'ultraton';
const REPORT = new URL('./reports/clients/index.json', import.meta.url);
// Case 9 goes up to 16 MiB in one message.
const MAX_MESSAGE_SIZE = 16 * 1024 * 1024 + 1024;
const PASSING = new Set(['OK', 'NON-STRICT', 'INFORMATIONAL']);

// Loopback is a reserved range: allowed on purpose, for this local server only.
const client = new UltraTonClient({ permitReservedIps: ['127.0.0.1'], timeoutMs: 60_000, socketTimeoutMs: 60_000 });

/** The messages of one connection, until the server closes it. */
async function messages(path) {
    const ws = await client.websocket(`${BASE}${path}`, { maxMessageSize: MAX_MESSAGE_SIZE });
    const got = [];
    for await (const message of ws) got.push(message);
    return got;
}

const [count] = await messages('/getCaseCount');
const total = Number(count);
for (let i = 1; i <= total; i++) {
    let ws;
    try {
        ws = await client.websocket(`${BASE}/runCase?case=${i}&agent=${AGENT}`, { maxMessageSize: MAX_MESSAGE_SIZE });
        for await (const message of ws) await ws.send(message);
    } catch {
        // A case that makes the client fail the connection is expected to: the report judges how it failed.
    } finally {
        await ws?.close().catch(() => {});
    }
}
await messages(`/updateReports?agent=${AGENT}`);
await client.close();

const results = JSON.parse(fs.readFileSync(REPORT, 'utf8'))[AGENT];
const failed = Object.entries(results).filter(([, r]) => !PASSING.has(r.behavior) || !PASSING.has(r.behaviorClose));
const tally = {};
for (const r of Object.values(results)) tally[r.behavior] = (tally[r.behavior] ?? 0) + 1;
console.log(`${Object.keys(results).length} cases:`, tally);
for (const [id, r] of failed) console.log(`FAILED ${id}: behavior ${r.behavior}, close ${r.behaviorClose}`);
if (failed.length > 0 || Object.keys(results).length !== total) process.exit(1);
