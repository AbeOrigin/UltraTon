/**
 * Base class of every error UltraTon raises (invalid input is a `TypeError`, an abort is your `signal.reason`).
 * Messages never contain the target's IP or hostname; the original Node error (which may contain them) is in `cause`.
 */
export class SecureHttpError extends Error {
    /**
     * A stable code. Policy rejections: `ERR_ULTRATON_RESERVED_IP`, `ERR_ULTRATON_PLAIN_HTTP`, `ERR_ULTRATON_DOWNGRADE`,
     * and from `createSecureAgents()`, `ERR_ULTRATON_NON_CANONICAL_IP` (a host such as `127.1`) and, on a Node.js release
     * without the keep-alive fix, `ERR_ULTRATON_AGENT_KEEP_ALIVE` (`keepAlive`, `maxSockets` or `maxTotalSockets` set on an agent).
     * On `UltraTonNetworkError`, the underlying Node or resolver code (`ECONNREFUSED`, `ENOTFOUND`, ...). On
     * `UltraTonNetworkTimeoutError`, `ERR_ULTRATON_TIMEOUT` when `timeoutMs` ran out and `ERR_ULTRATON_SOCKET_TIMEOUT`
     * when the connection sat idle for `socketTimeoutMs`. A request body: `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE` (on
     * `UltraTonMemoryError`) and `ERR_ULTRATON_REQUEST_BODY_LENGTH` (a stream that did not match its `content-length`).
     */
    readonly code?: string;

    constructor(message: string, options?: { cause?: unknown; code?: string }) {
        super(message, options && 'cause' in options ? { cause: options.cause } : undefined);
        this.name = new.target.name;
        if (options?.code !== undefined) this.code = options.code;
    }
}

/** DNS, connect, TLS or mid-body failure, or a response truncated against its `content-length`. `code` says which. */
export class UltraTonNetworkError extends SecureHttpError {}
/**
 * A timeout is a network failure too: `instanceof UltraTonNetworkError` catches it along with resets and refusals.
 * `code` says which: `ERR_ULTRATON_TIMEOUT` (the `timeoutMs` budget is spent) or `ERR_ULTRATON_SOCKET_TIMEOUT` (no
 * bytes for `socketTimeoutMs`: the server or the network stalled).
 */
export class UltraTonNetworkTimeoutError extends UltraTonNetworkError {}

/** `timeoutMs` ran out. Never retried: the budget it measures covers every attempt. */
export const absoluteTimeout = (timeoutMs: number) =>
    new UltraTonNetworkTimeoutError(`UltraTon: Absolute execution time of ${timeoutMs}ms exceeded.`, { code: 'ERR_ULTRATON_TIMEOUT' });
/**
 * HTTP/2: the server never processed the request, so sending it again is safe (RFC 9113 8.7). Either it reset the
 * stream with REFUSED_STREAM before answering, or a GOAWAY left the stream above its last processed one.
 */
export const refusedStream = (cause?: unknown) =>
    new UltraTonNetworkError('UltraTon: The server did not process the request (REFUSED_STREAM).', { code: 'NGHTTP2_REFUSED_STREAM', cause });
/** No bytes arrived for `socketTimeoutMs`. */
export const idleTimeout = (socketTimeoutMs: number) =>
    new UltraTonNetworkTimeoutError(`UltraTon: Socket completely idle for ${socketTimeoutMs}ms.`, { code: 'ERR_ULTRATON_SOCKET_TIMEOUT' });
/**
 * The response body exceeded `maxBodySize`, and the response was aborted. Or, with `code`
 * `ERR_ULTRATON_REQUEST_BODY_TOO_LARGE`, the request body exceeded `maxRequestBodySize`.
 */
export class UltraTonMemoryError extends SecureHttpError {}
/** The request body went past `maxRequestBodySize`: before connecting for a buffered one, mid-upload for a stream. */
export const requestBodyTooLarge = (limit: number) =>
    new UltraTonMemoryError(`UltraTon: Request body exceeded the maximum allowed size of ${limit} bytes.`, { code: 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE' });
/** A streamed body yielded more or fewer bytes than the `content-length` it was sent with; the request was aborted. */
export const requestBodyLength = (length: number) =>
    new SecureHttpError(`UltraTon: Request body did not match its content-length of ${length} bytes.`, { code: 'ERR_ULTRATON_REQUEST_BODY_LENGTH' });
/** `json()` was called on a body that is not valid JSON; the `SyntaxError` is in `cause`. */
export class UltraTonParseError extends SecureHttpError {}
/** The server redirected more times than `maxRedirects` allows. */
export class UltraTonRedirectError extends SecureHttpError {}

// Codes Node and OpenSSL use when a TLS handshake or certificate check fails.
const TLS_CODE_PREFIXES = ['ERR_TLS_', 'ERR_SSL_', 'CERT_', 'UNABLE_TO_'];
const TLS_CODES = new Set(['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN']);

// OpenSSL formats its failures as "<hex>:error:<hex>:SSL routines:<function>:<reason>:<file>:<line>".
const OPENSSL_MESSAGE = /error:[0-9A-Fa-f]{8}:|SSL routines/;

function isTlsError(err: { code?: unknown; library?: unknown; message?: unknown }): boolean {
    const { code } = err;
    if (typeof code === 'string' && (TLS_CODES.has(code) || TLS_CODE_PREFIXES.some(p => code.startsWith(p)))) return true;
    // Older OpenSSL bindings expose the library as a property. A `reason` property is deliberately not checked: llhttp (HTTP parse) errors carry one too.
    if (typeof err.library === 'string') return true;
    // Newer ones report a handshake failure (e.g. a plain server answering a ClientHello) as a bare EPROTO whose
    // only TLS marker is the OpenSSL text in the message. The message is only inspected here, never copied out.
    return typeof err.message === 'string' && OPENSSL_MESSAGE.test(err.message);
}

/**
 * Maps a raw socket, connect or TLS error to an UltraTonNetworkError whose message carries only the error code:
 * Node's own messages embed the resolved IP and port (`connect ECONNREFUSED 10.0.0.5:8080`), which would leak internal
 * topology. The original error stays reachable through `cause`.
 * Errors that are already SecureHttpError and caller aborts (AbortError) pass through unchanged.
 */
export function toNetworkError(err: unknown): unknown {
    if (err instanceof SecureHttpError) return err;
    if (err instanceof Error && err.name === 'AbortError') return err;

    const raw = (typeof err === 'object' && err !== null ? err : {}) as { code?: unknown; library?: unknown; message?: unknown };
    const code = typeof raw.code === 'string' && raw.code !== '' ? raw.code : 'UNKNOWN';
    const kind = isTlsError(raw) ? 'TLS handshake failed' : 'Connection failed';
    return new UltraTonNetworkError(`UltraTon: ${kind} (${code}).`, { cause: err, code });
}
