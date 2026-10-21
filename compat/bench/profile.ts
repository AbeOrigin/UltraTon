/**
 * CPU profiles of UltraTon under the benchmark load, to find where its time goes. Runs worker.ts (the same client
 * code as bench.ts) with `--cpu-prof` against a loopback server, once per engine and body size, and writes
 * `profile/PROFILE.md` (the top functions by self and by inclusive time) next to the `.cpuprofile` files, which
 * Chrome DevTools opens. CI only, like the benchmarks; PROFILE_SMOKE=1 runs a short pass anywhere to check the script.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import http2 from 'node:http2';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';

const SMOKE = process.env.PROFILE_SMOKE === '1';
if (!SMOKE && process.env.CI !== 'true') {
    console.error('Profiling runs in CI only. Use PROFILE_SMOKE=1 for a quick local check of the script.');
    process.exit(1);
}

const CLIENTS = ['UltraTonClient (HTTP/1.1)', 'UltraTonClient (HTTP/2)'] as const;
const SCENARIOS = [{ name: '1 KiB body', bytes: 1024 }, { name: '64 KiB body', bytes: 64 * 1024 }] as const;
const SETTINGS = SMOKE
    ? { concurrency: 4, warmupMs: 100, roundMs: 300, rounds: 1 }
    : { concurrency: 16, warmupMs: 1000, roundMs: 8000, rounds: 1 };
const TOP = 20;

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, 'profile');
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir);

/** The bench servers: HTTP/1.1 and h2c on loopback, answering every request with `bytes` of body. */
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

/** Runs one client under --cpu-prof and returns the path of its profile. */
function profileRun(client: string, file: string, h1Url: string, h2Url: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ['--cpu-prof', `--cpu-prof-dir=${outDir}`, `--cpu-prof-name=${file}`, path.join(here, 'worker.ts')], {
            env: { ...process.env, BENCH_CLIENT: client, BENCH_H1: h1Url, BENCH_H2: h2Url, BENCH_SETTINGS: JSON.stringify(SETTINGS) },
            stdio: ['ignore', 'ignore', 'inherit'],
        });
        const timer = setTimeout(() => child.kill(), SETTINGS.warmupMs + SETTINGS.roundMs + 60_000);
        child.on('error', reject);
        child.on('exit', code => {
            clearTimeout(timer);
            if (code === 0) resolve(path.join(outDir, file));
            else reject(new Error(`${client} exited with ${code}`));
        });
    });
}

interface CpuProfile {
    nodes: { id: number; callFrame: { functionName: string; url: string; lineNumber: number }; children?: number[] }[];
    samples: number[];
    timeDeltas: number[];
}

/** Where a frame's code lives: UltraTon itself, Node's own JavaScript, the garbage collector, or the rest. */
function bucketOf(url: string, name: string): string {
    if (url.includes('/ultraton/')) return 'UltraTon';
    if (url.startsWith('node:')) return 'Node internals';
    if (name === '(garbage collector)') return 'Garbage collector';
    if (name === '(idle)' || name === '(program)') return 'Idle / V8 program';
    return 'Other (V8 builtins, the worker)';
}

/** A readable frame name: the function and its file (relative to the package for UltraTon) and line. */
function labelOf(frame: CpuProfile['nodes'][number]['callFrame']): string {
    const name = frame.functionName || '(anonymous)';
    if (!frame.url) return name;
    const file = frame.url.includes('/ultraton/') ? frame.url.slice(frame.url.lastIndexOf('/ultraton/') + 1) : frame.url.replace(/^file:\/\/\/?/, '');
    return `${name} ${file}:${frame.lineNumber + 1}`;
}

/** Self and inclusive time per frame label (a frame counted once per sample, however deep it recurses), in ms. */
function analyze(profile: CpuProfile) {
    const byId = new Map(profile.nodes.map(node => [node.id, node]));
    const parent = new Map<number, number>();
    for (const node of profile.nodes) for (const child of node.children ?? []) parent.set(child, node.id);
    const self = new Map<string, number>();
    const inclusive = new Map<string, number>();
    const buckets = new Map<string, number>();
    let total = 0;
    profile.samples.forEach((id, i) => {
        const ms = (profile.timeDeltas[i] ?? 0) / 1000;
        total += ms;
        const leaf = byId.get(id)!;
        const leafLabel = labelOf(leaf.callFrame);
        self.set(leafLabel, (self.get(leafLabel) ?? 0) + ms);
        const bucket = bucketOf(leaf.callFrame.url, leaf.callFrame.functionName);
        buckets.set(bucket, (buckets.get(bucket) ?? 0) + ms);
        const seen = new Set<string>();
        for (let at: number | undefined = id; at !== undefined; at = parent.get(at)) {
            const frame = byId.get(at)!.callFrame;
            if (!frame.url.includes('/ultraton/')) continue;
            const label = labelOf(frame);
            if (seen.has(label)) continue;
            seen.add(label);
            inclusive.set(label, (inclusive.get(label) ?? 0) + ms);
        }
    });
    return { self, inclusive, buckets, total };
}

const top = (entries: Map<string, number>, total: number, count: number) =>
    [...entries].sort((a, b) => b[1] - a[1]).slice(0, count)
        .map(([label, ms]) => `| ${(ms / total * 100).toFixed(1)}% | ${ms.toFixed(0)} | \`${label.replaceAll('|', '\\|')}\` |`);

const lines = [
    '# CPU profile',
    '',
    `Generated by \`npm run profile\` in \`compat/\` (CI only), commit \`${(process.env.GITHUB_SHA ?? 'local').slice(0, 7)}\`, Node ${process.version}. Each run is worker.ts with \`--cpu-prof\`: ${SETTINGS.concurrency} requests in flight against a loopback server, a ${SETTINGS.warmupMs / 1000} s warm-up then ${SETTINGS.roundMs / 1000} s, the warm-up included in the profile. The \`.cpuprofile\` files next to this one open in Chrome DevTools (Performance tab).`,
    '',
    '**Self** is time spent in the function itself; **inclusive** adds what it calls, and lists only UltraTon frames, to show which of its paths cost the most.',
];

for (const scenario of SCENARIOS) {
    const servers = await startServers(scenario.bytes);
    try {
        for (const client of CLIENTS) {
            const file = `${client.includes('HTTP/2') ? 'h2' : 'h1'}-${scenario.bytes / 1024}k.cpuprofile`;
            console.error(`Profiling ${client}, ${scenario.name}...`);
            const profile = JSON.parse(fs.readFileSync(await profileRun(client, file, servers.h1Url, servers.h2Url), 'utf8')) as CpuProfile;
            const { self, inclusive, buckets, total } = analyze(profile);
            lines.push('', `## ${client}, ${scenario.name}`, '', `Profile: \`${file}\`, ${total.toFixed(0)} ms sampled.`, '');
            lines.push('| Where | Share |', '|---|---:|');
            for (const [bucket, ms] of [...buckets].sort((a, b) => b[1] - a[1])) lines.push(`| ${bucket} | ${(ms / total * 100).toFixed(1)}% |`);
            lines.push('', `**Top ${TOP} by self time**`, '', '| Self | ms | Function |', '|---:|---:|---|', ...top(self, total, TOP));
            lines.push('', `**Top ${TOP} UltraTon functions by inclusive time**`, '', '| Inclusive | ms | Function |', '|---:|---:|---|', ...top(inclusive, total, TOP));
        }
    } finally {
        await servers.close();
    }
}

fs.writeFileSync(path.join(outDir, 'PROFILE.md'), lines.join('\n') + '\n');
console.error(`Wrote ${path.join(outDir, 'PROFILE.md')}`);
