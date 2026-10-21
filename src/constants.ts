export const HTTP_CODES_REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS_CEILING = 20;
/** `timeoutMs` when neither the request nor the client sets it. */
export const DEFAULT_TIMEOUT_MS = 30_000;

// Paranoid limits to prevent RAM exhaustion on HTTP/2 sessions (HPACK bombs, memory leaks).
export const MAX_HEADER_LIST_SIZE = 16384; // 16 KB
export const MAX_HEADER_LIST_PAIRS = 64;
export const MAX_SESSION_MEMORY_MB = 4; // 4 MB

export const IDLE_TIMEOUT = 10000;
export const MAX_SESSION_LIFESPAN = 30 * 60 * 1000;

/** The package version, sent in the default `user-agent`. A test keeps it equal to `package.json` `version`. */
export const VERSION = '2.3.0';
