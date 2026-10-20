/**
 * A dependency-free property-testing helper: a seeded PRNG, `forAll` to run a property on generated inputs, and a
 * shrinker for inputs built from pieces (token arrays). Generators are domain-specific (see the *.test.ts files): they
 * assemble inputs from the pieces real bypasses use, which finds more than generic random strings would.
 *
 * Runs: FUZZ_RUNS (default 200, light enough for a laptop) with a fixed seed, so `npm test` is deterministic. The
 * nightly workflow sets a large FUZZ_RUNS and a fresh FUZZ_SEED. Run n uses seed FUZZ_SEED + n, so a failure prints the
 * one command that replays just that case: `FUZZ_SEED=<seed + run> FUZZ_RUNS=1`.
 */
export interface Rand {
    /** An integer in [0, n). */
    int(n: number): number;
    pick<T>(items: readonly T[]): T;
    /** true with probability p. */
    chance(p: number): boolean;
    /** An array of length in [min, max], each element from `item`. */
    array<T>(min: number, max: number, item: () => T): T[];
}

/** mulberry32: small, fast, and good enough to drive generators. */
function mulberry32(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

export function rand(seed: number): Rand {
    const next = mulberry32(seed);
    const r: Rand = {
        int: n => Math.floor(next() * n),
        pick: items => items[Math.floor(next() * items.length)],
        chance: p => next() < p,
        array: (min, max, item) => Array.from({ length: min + Math.floor(next() * (max - min + 1)) }, item),
    };
    return r;
}

/** A positive integer from the environment, `fallback` when unset; anything else throws instead of silently changing the run. */
function envInt(name: string, fallback: number): number {
    const raw = process.env[name];
    if (raw === undefined) return fallback;
    const value = Number(raw);
    if (raw.trim() === '' || !Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer, got ${JSON.stringify(raw)}.`);
    return value;
}

const RUNS = envInt('FUZZ_RUNS', 200) || 200;
const SEED = envInt('FUZZ_SEED', 0x5eed);

/** Tries removing pieces one at a time while the property still fails, for a smaller counterexample. */
async function shrink<T>(input: T[], fails: (candidate: T[]) => Promise<boolean>): Promise<T[]> {
    let current = input;
    for (let changed = true; changed;) {
        changed = false;
        for (let i = 0; i < current.length; i++) {
            const candidate = [...current.slice(0, i), ...current.slice(i + 1)];
            if (await fails(candidate)) {
                current = candidate;
                changed = true;
                break;
            }
        }
    }
    return current;
}

/**
 * Runs `property` on RUNS inputs from `generate`, each with its own seed (SEED + run). The first failure throws with
 * the seed, the run, and the input (shrunk first when it is an array of pieces).
 */
export async function forAll<T>(generate: (r: Rand) => T, property: (input: T) => void | Promise<void>): Promise<void> {
    const failsOn = async (input: T) => {
        try { await property(input); return undefined; } catch (err: unknown) { return err; }
    };
    for (let run = 0; run < RUNS; run++) {
        const input = generate(rand(SEED + run));
        const err = await failsOn(input);
        if (err === undefined) continue;
        const minimal = Array.isArray(input)
            ? await shrink(input as unknown[], async c => (await failsOn(c as T)) !== undefined) as T
            : input;
        // The failure of the input shown (the shrunk one, when there is one).
        const shown = minimal === input ? err : (await failsOn(minimal)) ?? err;
        const message = shown instanceof Error ? shown.message : String(shown);
        throw new Error(`Property failed on run ${run}; reproduce with FUZZ_SEED=${SEED + run} FUZZ_RUNS=1. Input: ${JSON.stringify(minimal)}\n${message}`, { cause: shown });
    }
}
