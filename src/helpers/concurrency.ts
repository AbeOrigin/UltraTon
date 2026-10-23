import { absoluteTimeout } from '../errors.ts';

/** A call waiting for a slot: `grant` hands it one, `fail` takes it out of the queue with an error. */
interface Waiter {
    readonly grant: () => void;
    readonly fail: (error: unknown) => void;
}

/** The calls of one origin: how many hold a slot, and who waits for one, oldest first. */
interface OriginState {
    active: number;
    readonly queue: Waiter[];
}

/**
 * At most `limit` calls in flight per origin; the rest wait in order. Not public: the client's `maxConcurrency`. An
 * origin with nothing in flight and nobody waiting is forgotten, so the map only holds the origins in use.
 */
export class OriginLimiter {
    readonly #limit: number;
    readonly #origins = new Map<string, OriginState>();
    #closed?: Error;

    constructor(limit: number) {
        this.#limit = limit;
    }

    /**
     * Resolves with a release function once a slot is free. Rejects with the signal's reason if aborted while waiting,
     * or with absoluteTimeout when `remainingMs` runs out first (0: no timeout, it waits as long as it takes). The
     * release function gives the slot back; calling it again does nothing.
     */
    acquire(origin: string, signal: AbortSignal | undefined, remainingMs: number): Promise<() => void> {
        if (this.#closed) return Promise.reject(this.#closed);
        const free = this.tryAcquire(origin);
        if (free) return Promise.resolve(free);
        if (signal?.aborted) return Promise.reject(signal.reason);
        const state = this.#origins.get(origin)!;
        return new Promise((resolve, reject) => {
            let timer: NodeJS.Timeout | undefined;
            const leave = () => {
                clearTimeout(timer);
                signal?.removeEventListener('abort', onAbort);
                const index = state.queue.indexOf(waiter);
                if (index !== -1) state.queue.splice(index, 1);
            };
            const waiter: Waiter = {
                grant: () => { leave(); resolve(this.#releaser(origin, state)); },
                fail: (error) => { leave(); this.#forget(origin, state); reject(error); },
            };
            const onAbort = () => waiter.fail(signal!.reason);
            state.queue.push(waiter);
            signal?.addEventListener('abort', onAbort, { once: true });
            if (remainingMs > 0) timer = setTimeout(() => waiter.fail(absoluteTimeout(remainingMs)), remainingMs);
        });
    }

    /** A slot now, without waiting, or `undefined` when the origin is full or others wait already (they go first). */
    tryAcquire(origin: string): (() => void) | undefined {
        if (this.#closed) return undefined;
        let state = this.#origins.get(origin);
        if (!state) {
            state = { active: 0, queue: [] };
            this.#origins.set(origin, state);
        }
        if (state.active >= this.#limit || state.queue.length > 0) return undefined;
        state.active++;
        return this.#releaser(origin, state);
    }

    /** Rejects everyone still waiting with `error`, and every later call; what is in flight keeps its slot. */
    close(error: Error): void {
        this.#closed = error;
        for (const state of [...this.#origins.values()]) {
            for (const waiter of [...state.queue]) waiter.fail(error);
        }
    }

    /** The slot `state` just granted: given back once, to the oldest waiter if there is one. */
    #releaser(origin: string, state: OriginState): () => void {
        let released = false;
        return () => {
            if (released) return;
            released = true;
            const next = state.queue[0];
            // Handed over as is: the slot stays counted, now for the waiter.
            if (next) return next.grant();
            state.active--;
            this.#forget(origin, state);
        };
    }

    #forget(origin: string, state: OriginState): void {
        if (state.active === 0 && state.queue.length === 0 && this.#origins.get(origin) === state) this.#origins.delete(origin);
    }
}

/**
 * `body` as a stream that calls `release` once it ends, fails or is cancelled: until then the body holds its
 * connection, so its call holds its slot. Pulled one chunk at a time, as the engines' bodies are.
 */
export function releasingBody(body: ReadableStream<Uint8Array>, release: () => void): ReadableStream<Uint8Array> {
    const reader = body.getReader();
    return new ReadableStream<Uint8Array>({
        async pull(controller) {
            let next: ReadableStreamReadResult<Uint8Array>;
            try {
                next = await reader.read();
            } catch (err: unknown) {
                release();
                controller.error(err);
                return;
            }
            if (next.done) {
                release();
                controller.close();
            } else {
                controller.enqueue(next.value);
            }
        },
        async cancel(reason) {
            try {
                await reader.cancel(reason);
            } finally {
                release();
            }
        },
    }, { highWaterMark: 0 });
}
