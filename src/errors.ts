/** Every code UltraTon raises its own errors with. Internal: `UltraTonErrorCode` is built from it, and a test keeps it equal to what `src` raises. */
export const ERROR_CODES = [
    'ERR_ULTRATON_AGENT_KEEP_ALIVE',
    'ERR_ULTRATON_AGENT_PROXY',
    'ERR_ULTRATON_CONTENT_ENCODING',
    'ERR_ULTRATON_DOWNGRADE',
    'ERR_ULTRATON_MAX_PAGES',
    'ERR_ULTRATON_NON_CANONICAL_IP',
    'ERR_ULTRATON_PAGE_OUT_OF_SCOPE',
    'ERR_ULTRATON_PLAIN_HTTP',
    'ERR_ULTRATON_PROXY',
    'ERR_ULTRATON_REQUEST_BODY_LENGTH',
    'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE',
    'ERR_ULTRATON_RESERVED_IP',
    'ERR_ULTRATON_SOCKET_TIMEOUT',
    'ERR_ULTRATON_TIMEOUT',
] as const;

/** A code UltraTon raises its own errors with. `error.code` may also hold a Node, zlib or resolver code (`ECONNRESET`, `ENOTFOUND`). */
export type UltraTonErrorCode = (typeof ERROR_CODES)[number];

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
    readonly code?: UltraTonErrorCode | (string & {});

    constructor(message: string, options?: { cause?: unknown; code?: UltraTonErrorCode | (string & {}) }) {
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
 * What is left of the `timeoutMs` budget shared by every hop and step of a request, or `timeoutMs` itself when it is
 * not positive (0 means no timeout). Throws once the budget is spent: a non-positive value would silently disable the
 * timer it is passed to.
 */
export function remainingBudget(timeoutMs: number, startedAt: number): number {
    if (timeoutMs <= 0) return timeoutMs;
    const remaining = timeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) throw absoluteTimeout(timeoutMs);
    return remaining;
}
/** The request (or a step of it) ran into `close()`. */
export const clientClosed = () => new SecureHttpError('UltraTon: Client is closed.');
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
/** The response body went past `maxBodySize` and the response was aborted. One message for `get()` and `stream()`: the body-parity test holds them to it. */
export const bodyTooLarge = (maxBodySize: number) =>
    new UltraTonMemoryError(`UltraTon: Body size exceeded the maximum allowed size of ${maxBodySize} bytes. Raise maxBodySize.`);
/** The request body went past `maxRequestBodySize`: before connecting for a buffered one, mid-upload for a stream. */
export const requestBodyTooLarge = (limit: number) =>
    new UltraTonMemoryError(`UltraTon: Request body exceeded the maximum allowed size of ${limit} bytes. Raise maxRequestBodySize, or send less.`, { code: 'ERR_ULTRATON_REQUEST_BODY_TOO_LARGE' });
/** A streamed body yielded more or fewer bytes than the `content-length` it was sent with; the request was aborted. */
export const requestBodyLength = (length: number) =>
    new SecureHttpError(`UltraTon: Request body did not match its content-length of ${length} bytes.`, { code: 'ERR_ULTRATON_REQUEST_BODY_LENGTH' });
/** `json()` was called on a body that is not valid JSON; the `SyntaxError` is in `cause`. */
export class UltraTonParseError extends SecureHttpError {}
/** The server redirected more times than `maxRedirects` allows. */
export class UltraTonRedirectError extends SecureHttpError {}

/** The `name` of every error class above: what isUltraTonError recognizes an error by. */
const ERROR_NAMES = new Set(['SecureHttpError', 'UltraTonNetworkError', 'UltraTonNetworkTimeoutError', 'UltraTonMemoryError', 'UltraTonParseError', 'UltraTonRedirectError']);

/**
 * Whether `err` is an error UltraTon raised, optionally one with the given `code`. Judged by shape (`name` and `code`),
 * not by class, so it also recognizes errors from another copy of the package in `node_modules`. Never throws: anything
 * that is not an object, has another `name`, or whose properties cannot be read is not one.
 */
export function isUltraTonError(err: unknown, code?: UltraTonErrorCode): err is SecureHttpError {
    if (typeof err !== 'object' || err === null) return false;
    try {
        const { name, code: actual } = err as { name?: unknown; code?: unknown };
        if (typeof name !== 'string' || !ERROR_NAMES.has(name)) return false;
        return code === undefined || actual === code;
    } catch {
        return false;
    }
}

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
