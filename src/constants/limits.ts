export const MAX_REDIRECTS_CEILING = 20;

/**
 * Sprint 7: Paranoid limits to prevent RAM exhaustion (HPACK bombs, memory leaks).
 */
export const MAX_HEADER_LIST_SIZE = 16384; // 16 KB
export const MAX_HEADER_LIST_PAIRS = 64;
export const MAX_SESSION_MEMORY_MB = 4; // 4 MB
