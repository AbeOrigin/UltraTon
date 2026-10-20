/**
 * Reproducible HTTP client benchmarks: UltraTon next to Node's own http and fetch (undici), axios, got and
 * node-fetch, against a loopback server. Each client runs in its own process; each measurement is the median of
 * several rounds after a warm-up.
 *
 * Runs in CI only (GitHub sets CI=true): a benchmark loads the machine, and contributors' laptops are not a place
 * for that. BENCH_SMOKE=1 runs a short pass per client, anywhere, just to check the harness works; it writes to the
 * system temp directory, never over the published results.
 *
 *   npm run bench          (in compat/, CI only) writes bench/RESULTS.md and bench/results.json
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';

const SMOKE = process.env.BENCH_SMOKE === '1';
if (!SMOKE && process.env.CI !== 'true') {
    console.error('Benchmarks run in CI only. Use BENCH_SMOKE=1 for a quick local check of the harness.');
    process.exit(1);
}

const CLIENTS = [
    'node:http (baseline)',
    'fetch (Node built-in, undici)',
    'axios',
    'got',
    'node-fetch',
    'UltraTonClient (HTTP/1.1)',
    'UltraTonClient (HTTP/2)',
    'axios + createSecureAgents',
] as const;

const SCENARIOS = [
    { name: '1 KiB body', bytes: 1024 },
    { name: '64 KiB body', bytes: 64 * 1024 },
] as const;

const SETTINGS = SMOKE
    ? { concurrency: 4, warmupMs: 100, roundMs: 200, rounds: 1 }
    : { concurrency: 16, warmupMs: 2000, roundMs: 5000, rounds: 3 };

/** A worker that runs longer than its rounds plus this margin is killed: a hang must not last until the job timeout. */
const WORKER_MARGIN_MS = 60_000;

interface Measurement { requestsPerSecond: number; p50Ms: number; p99Ms: number; cpuMsPer1k: number; rssMb: number; serverCpuPercent: number }

/** Starts the loopback servers (HTTP/1.1 and h2c) that answer every request with `bytes` of body. */
async function startServers(bytes: number) {
    const body = Buffer.alloc(bytes, 'x');
    const h1 = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': bytes }); res.end(body); });
    h1.keepAliveTimeout = 30_000;
    const h2 = http2.createServer().on('stream', stream => { stream.respond({ ':status': 200, 'content-type': 'application/octet-stream', 'content-length': bytes }); stream.end(body); });
    await new Promise<void>(r => h1.listen(0, '127.0.0.1', r));
    await new Promise<void>(r => h2.listen(0, '127.0.0.1', r));
    return {
        h1Url: `http://127.0.0.1:${(h1.address() as AddressInfo).port}/`,
        h2Url: `http://127.0.0.1:${(h2.address() as AddressInfo).port}/`,
        close: async () => {
            h1.closeAllConnections();
            await Promise.all([new Promise(r => h1.close(r)), new Promise(r => h2.close(r))]);
        },
    };
}

/**
 * Runs one client in its own process and returns its median measurement, plus the CPU the server (this process)
 * used meanwhile: near 100% means the server, not the client, set the pace.
 */
function measure(client: string, h1Url: string, h2Url: string): Promise<Measurement> {
    return new Promise((resolve, reject) => {
        const worker = fileURLToPath(new URL('./worker.ts', import.meta.url));
        const serverCpu = process.cpuUsage();
        const started = performance.now();
        const child = spawn(process.execPath, [worker], {
            env: { ...process.env, BENCH_CLIENT: client, BENCH_H1: h1Url, BENCH_H2: h2Url, BENCH_SETTINGS: JSON.stringify(SETTINGS) },
            stdio: ['ignore', 'pipe', 'inherit'],
        });
        const budget = SETTINGS.warmupMs + SETTINGS.rounds * SETTINGS.roundMs + WORKER_MARGIN_MS;
        const timer = setTimeout(() => child.kill(), budget);
        let out = '';
        child.stdout.on('data', chunk => { out += chunk; });
        child.on('error', reject);
        // 'close', not 'exit': stdout is fully read by then.
        child.on('close', code => {
            clearTimeout(timer);
            if (code !== 0) return reject(new Error(`${client}: worker exited with ${code ?? 'a signal (timed out?)'}`));
            const cpu = process.cpuUsage(serverCpu);
            try {
                const result = JSON.parse(out);
                resolve({ ...result, serverCpuPercent: ((cpu.user + cpu.system) / 1000 / (performance.now() - started)) * 100 });
            } catch (err) {
                reject(new Error(`${client}: unreadable worker output`, { cause: err }));
            }
        });
    });
}

const results: Record<string, Record<string, Measurement>> = {};
for (const scenario of SCENARIOS) {
    const servers = await startServers(scenario.bytes);
    results[scenario.name] = {};
    try {
        for (const client of CLIENTS) {
            results[scenario.name][client] = await measure(client, servers.h1Url, servers.h2Url);
            console.error(`${scenario.name} / ${client}: ${results[scenario.name][client].requestsPerSecond.toFixed(0)} req/s`);
        }
    } finally {
        await servers.close();
    }
}

const versions = (name: string) => JSON.parse(fs.readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8')).version;
const environment = {
    node: process.version,
    undici: process.versions.undici,
    ultraton: versions('ultraton'),
    axios: versions('axios'),
    got: versions('got'),
    'node-fetch': versions('node-fetch'),
    os: `${os.type()} ${os.release()}`,
    cpu: `${os.cpus()[0]?.model ?? 'unknown'} × ${os.cpus().length}`,
    commit: process.env.GITHUB_SHA ?? 'local',
    date: new Date().toISOString().slice(0, 10),
    settings: SETTINGS,
    smoke: SMOKE,
};

const fmt = (n: number, digits = 0) => n.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits });
const lines = [
    '# Benchmark results',
    '',
    ...(SMOKE ? ['> ⚠️ Smoke run: durations too short to mean anything. Real numbers come from the CI workflow.', ''] : []),
    `Generated by \`npm run bench\` in \`compat/\` (CI only), commit \`${environment.commit.slice(0, 7)}\`, ${environment.date}, on ${environment.os}, ${environment.cpu}. Node ${environment.node} (undici ${environment.undici}); ultraton ${environment.ultraton}, axios ${environment.axios}, got ${environment.got}, node-fetch ${environment['node-fetch']}.`,
    '',
    '**Method.**',
    '- **Server:** on loopback, in the parent process, answering every request with a fixed body.',
    `- **Clients:** each one runs in its own process with only its own library loaded, keeps its defaults and keep-alive, keeps ${SETTINGS.concurrency} GET requests in flight, and reads the whole body.`,
    `- **Timing:** a ${SETTINGS.warmupMs / 1000} s warm-up, then the median of ${SETTINGS.rounds} rounds of ${SETTINGS.roundMs / 1000} s.`,
    '',
    '**Read these numbers with their limits:**',
    '- **No TLS.** Everything is plain HTTP/1.1 or h2c, so the cost of TLS, often the largest per new connection, is not in the table.',
    '- **No DNS.** Every client gets an IP literal. UltraTon resolves and validates the name on every new connection, without a cache; with keep-alive that is rare, but this table does not show it.',
    '- **One machine, loopback.** There is no network latency, so per-request overheads look larger than they would against a real server. GET only, at one concurrency level.',
    '- **The HTTP/2 row** uses a different server (`node:http2`, h2c) and one multiplexed connection: compare it with the HTTP/1.1 rows with care.',
    '- **A shared CI runner is noisy.** Compare rows within one table, not across runs.',
    '- **Server CPU** is what the server used while that client ran. Near 100% (⚠️), the server, not the client, set the pace, and that row is a lower bound.',
    '',
    '**Columns.**',
    '- **req/s:** completed requests per second; higher is better.',
    '- **p50 / p99:** latency per request.',
    '- **CPU:** the client process\'s CPU time per 1 000 requests.',
    '- **RSS:** the client process\'s memory at the end, with only its own library loaded.',
    '',
    'The baseline row is Node\'s own `http.request`, with no checks at all. What UltraTon checks costs something relative to it: options, the address policy, body limits and integrity. Against the other clients, the table shows how much.',
    '',
];
for (const scenario of SCENARIOS) {
    lines.push(`## ${scenario.name}`, '', '| Client | req/s | p50 (ms) | p99 (ms) | CPU (ms / 1k req) | RSS (MB) | Server CPU |', '|---|---:|---:|---:|---:|---:|---:|');
    for (const client of CLIENTS) {
        const m = results[scenario.name][client];
        const server = `${fmt(m.serverCpuPercent)}%${m.serverCpuPercent >= 90 ? ' ⚠️' : ''}`;
        lines.push(`| ${client} | ${fmt(m.requestsPerSecond)} | ${fmt(m.p50Ms, 2)} | ${fmt(m.p99Ms, 2)} | ${fmt(m.cpuMsPer1k, 1)} | ${fmt(m.rssMb)} | ${server} |`);
    }
    lines.push('');
}

// A smoke run never overwrites the published results.
const outDir = SMOKE ? fs.mkdtempSync(path.join(os.tmpdir(), 'ultraton-bench-')) : fileURLToPath(new URL('.', import.meta.url));
fs.writeFileSync(path.join(outDir, 'RESULTS.md'), lines.join('\n'));
fs.writeFileSync(path.join(outDir, 'results.json'), JSON.stringify({ environment, results }, null, 2) + '\n');
console.error(`Wrote ${path.join(outDir, 'RESULTS.md')} and results.json`);
