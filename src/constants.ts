export const HTTP_CODES_REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS_CEILING = 20;
/** `timeoutMs` when neither the request nor the client sets it. */
export const DEFAULT_TIMEOUT_MS = 30_000;

// Paranoid limits to prevent RAM exhaustion on HTTP/2 sessions (HPACK bombs, memory leaks).
export const MAX_HEADER_LIST_SIZE = 16384; // 16 KB
export const MAX_HEADER_LIST_PAIRS = 64;
export const MAX_SESSION_MEMORY_MB = 4; // 4 MB
/**
 * HTTP/2 receive window of each stream: the most a server can send on it that nobody has read yet, so the memory a
 * `stream()` body left unread can hold, and per stream the ceiling on throughput (window / RTT, ~10 MB/s at 100 ms).
 * Node's default, 64 KiB, made a 64 KiB body wait for a WINDOW_UPDATE.
 */
export const H2_STREAM_WINDOW = 1024 * 1024;
/**
 * HTTP/2 receive window of the whole connection. Node acknowledges connection-level data as it arrives, read or not,
 * so this bounds no memory (H2_STREAM_WINDOW does, per stream); Node's 64 KiB default made every stream of a session
 * wait on one shared window.
 */
export const H2_CONNECTION_WINDOW = 16 * 1024 * 1024;

export const IDLE_TIMEOUT = 10000;
export const MAX_SESSION_LIFESPAN = 30 * 60 * 1000;

/** The package version, sent in the default `user-agent`. A test keeps it equal to `package.json` `version`. */
export const VERSION = '2.6.0';
