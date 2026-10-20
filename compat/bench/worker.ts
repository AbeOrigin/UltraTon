/**
 * One benchmark client, in its own process (see bench.ts). Reads BENCH_CLIENT, BENCH_H1, BENCH_H2 and BENCH_SETTINGS,
 * runs a warm-up then the rounds, and prints the median round as JSON on stdout.
 */
import http from 'node:http';
import { performance } from 'node:perf_hooks';
import axios from 'axios';
import got from 'got';
import nodeFetch from 'node-fetch';
import { UltraTonClient, createSecureAgents } from 'ultraton';

const client = process.env.BENCH_CLIENT!;
const h1Url = process.env.BENCH_H1!;
const h2Url = process.env.BENCH_H2!;
const settings = JSON.parse(process.env.BENCH_SETTINGS!) as { concurrency: number; warmupMs: number; roundMs: number; rounds: number };

/** One request, with the whole body read, as each library's README shows it. */
function makeClient(name: string): (() => Promise<unknown>) | undefined {
    switch (name) {
        case 'node:http (baseline)': {
            const agent = new http.Agent({ keepAlive: true });
            return () => new Promise((resolve, reject) => {
                http.get(h1Url, { agent }, res => {
                    const chunks: Buffer[] = [];
                    res.on('data', chunk => chunks.push(chunk));
                    res.on('end', () => resolve(Buffer.concat(chunks)));
                    res.on('error', reject);
                }).on('error', reject);
            });
        }
        case 'fetch (Node built-in, undici)':
            return async () => (await fetch(h1Url)).arrayBuffer();
        case 'axios': {
            const api = axios.create({ proxy: false, responseType: 'arraybuffer' });
            return () => api.get(h1Url);
        }
        case 'got':
            return () => got(h1Url, { retry: { limit: 0 } }).buffer();
        case 'node-fetch':
            return async () => (await nodeFetch(h1Url)).arrayBuffer();
        case 'UltraTonClient (HTTP/1.1)': {
            const ultraton = new UltraTonClient({ permitReservedIps: ['127.0.0.1'] });
            return () => ultraton.get(h1Url);
        }
        case 'UltraTonClient (HTTP/2)': {
            const ultraton = new UltraTonClient({ http2: true, permitReservedIps: ['127.0.0.1'] });
            return () => ultraton.get(h2Url);
        }
        case 'axios + createSecureAgents': {
            const agents = createSecureAgents({ permitReservedIps: ['127.0.0.1'] });
            const api = axios.create({ httpAgent: agents.http, httpsAgent: agents.https, proxy: false, responseType: 'arraybuffer' });
            return () => api.get(h1Url);
        }
        default:
            return undefined;
    }
}

const request = makeClient(client);
if (!request) throw new Error(`Unknown client ${client}`);

/** Keeps `concurrency` requests in flight for `ms`; returns the latencies of the ones that completed. */
async function run(ms: number): Promise<number[]> {
    const latencies: number[] = [];
    const deadline = performance.now() + ms;
    await Promise.all(Array.from({ length: settings.concurrency }, async () => {
        while (performance.now() < deadline) {
            const started = performance.now();
            await request!();
            latencies.push(performance.now() - started);
        }
    }));
    return latencies;
}

const percentile = (sorted: number[], p: number) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

await run(settings.warmupMs);
const rounds = [];
for (let i = 0; i < settings.rounds; i++) {
    const cpuBefore = process.cpuUsage();
    const latencies = (await run(settings.roundMs)).sort((a, b) => a - b);
    const cpu = process.cpuUsage(cpuBefore);
    rounds.push({
        requestsPerSecond: latencies.length / (settings.roundMs / 1000),
        p50Ms: percentile(latencies, 50),
        p99Ms: percentile(latencies, 99),
        cpuMsPer1k: ((cpu.user + cpu.system) / 1000) / (latencies.length / 1000),
        rssMb: process.memoryUsage().rss / (1024 * 1024),
    });
}
rounds.sort((a, b) => a.requestsPerSecond - b.requestsPerSecond);
process.stdout.write(JSON.stringify(rounds[Math.floor(rounds.length / 2)]));
process.exit(0);
