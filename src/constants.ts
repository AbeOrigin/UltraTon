export const HTTP_CODES_REDIRECTS: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
export const MAX_REDIRECTS_CEILING = 20;
/** `timeoutMs` when neither the request nor the client sets it. */
export const DEFAULT_TIMEOUT_MS = 30_000;

// Paranoid limits to prevent RAM exhaustion on HTTP/2 sessions (HPACK bombs, memory leaks).
export const MAX_HEADER_LIST_SIZE = 16384; // 16 KB
// Node's default. MAX_HEADER_LIST_SIZE is what bounds the memory; at 64, a legitimate response with many set-cookie and
// CDN headers failed with an opaque protocol error.
export const MAX_HEADER_LIST_PAIRS = 128;
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

/**
 * The TLS floor of every connection UltraTon opens, set on each one rather than inherited from `tls.DEFAULT_MIN_VERSION`,
 * which `--tls-min-v1.0` (also through NODE_OPTIONS) or any module in the process can lower.
 */
export const TLS_MIN_VERSION = 'TLSv1.2';

export const IDLE_TIMEOUT = 10000;
/** Idle pooled HTTP/1.1 sockets are reaped after this, as with Node's global agent, in the client's agents and the secure ones. */
export const IDLE_SOCKET_TIMEOUT_MS = 5000;
/**
 * Idle HTTP/1.1 sockets a client's pool keeps per policy and origin, above Node's default of 256: with more requests
 * than that in flight, Node would close the extra sockets as they free up and the next requests would open new ones
 * (a lookup and a handshake each). The idle ones are still reaped after IDLE_SOCKET_TIMEOUT_MS.
 */
export const MAX_FREE_SOCKETS = 1024;
/** `websocket()`: the most bytes of one received message (and so of one frame) unless `maxMessageSize` says otherwise. */
export const WS_MAX_MESSAGE_SIZE = 1024 * 1024;
/**
 * `websocket()`: `send()` rejects while more than this is still queued on the socket, so a server that stops reading
 * cannot make a caller who does not await `send()` hold an unbounded queue. A single larger message on an empty queue
 * still goes.
 */
// ponytail: fixed, not an option; make it one if a caller ever needs to queue more without awaiting.
export const WS_MAX_BUFFERED_BYTES = 1024 * 1024;
/** `websocket()`: the longest the close handshake (the server's close frame, then the end of the connection) may take. */
export const WS_CLOSE_TIMEOUT_MS = 5000;
/** The largest delay `setTimeout` takes: the ceiling of every millisecond option. */
export const INT32_MAX = 2147483647;
export const MAX_SESSION_LIFESPAN = 30 * 60 * 1000;

/** The package version, sent in the default `user-agent`. A test keeps it equal to `package.json` `version`. */
export const VERSION = '2.11.0';
