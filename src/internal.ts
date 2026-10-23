/**
 * Internal test seams. Not exported from the package entry and not part of the public types: the client reads these
 * symbols from its constructor options when present, so tests can inject a transport or a session manager without a
 * public constructor parameter. Do NOT use in production code.
 */

/** A replacement for `http.request`/`https.request` used by the HTTP/1 engine. */
export const kTransport: unique symbol = Symbol('ultraton.transport');

/**
 * A pre-built `Http2SessionManager` used by the HTTP/2 engine instead of the client's own. Tests also use it to shorten
 * the pool timings (session idle timeout, maximum lifespan) through the manager's `SessionTimings` constructor argument.
 */
export const kSessionManager: unique symbol = Symbol('ultraton.sessionManager');

/**
 * The engine (and its connection pools) a client made with `extend()` shares with the client it was derived from,
 * with the count of clients using it. Set by `extend()` only; never by a caller.
 */
export const kSharedEngine: unique symbol = Symbol('ultraton.sharedEngine');
