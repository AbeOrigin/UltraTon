export const HTTP_CODES_REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS_CEILING = 20;

// Paranoid limits to prevent RAM exhaustion on HTTP/2 sessions (HPACK bombs, memory leaks).
export const MAX_HEADER_LIST_SIZE = 16384; // 16 KB
export const MAX_HEADER_LIST_PAIRS = 64;
export const MAX_SESSION_MEMORY_MB = 4; // 4 MB

export const IDLE_TIMEOUT = 10000;
export const MAX_SESSION_LIFESPAN = 30 * 60 * 1000;
