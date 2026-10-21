import {
  type ClientHttp2Session,
  connect as nativeConnect,
  type SecureClientSessionOptions,
} from "node:http2";
import {
  H2_CONNECTION_WINDOW,
  H2_STREAM_WINDOW,
  IDLE_TIMEOUT,
  MAX_HEADER_LIST_PAIRS,
  MAX_HEADER_LIST_SIZE,
  MAX_SESSION_LIFESPAN,
  MAX_SESSION_MEMORY_MB,
} from "../constants.ts";
import { isIP } from "node:net";
import {
  assertAllowedIp,
  pinnedLookup,
  policyKey,
  type ReservedIpPolicy,
  resolveAndPinAll,
} from "../security/dns-pinner.ts";
import { SecureHttpError, toNetworkError } from "../errors.ts";
import { incompleteResponse } from "../helpers/response.ts";
import { tunnelTo, type ProxyConfig } from "../proxy/tunnel.ts";
import tls from "node:tls";
import type { Duplex } from "node:stream";

interface SessionEntry {
  session: ClientHttp2Session;
  createdAt: number;
  /** Every address the session may have connected to (all validated); every caller is checked against all of them. */
  ips: readonly string[];
}

/**
 * Timings of the pool, overridable through the constructor for tests only (the client never passes them):
 * `idleTimeoutMs` reaps a session with no stream in flight after that long without a frame (and, while a stream holds
 * it, is the interval of the PING liveness check), and `maxLifespanMs` retires a session from the pool once it is that old.
 */
export interface SessionTimings {
  readonly idleTimeoutMs?: number;
  readonly maxLifespanMs?: number;
}

/** A DNS lookup plus connect in flight for one pool key, shared by every caller that arrives while it runs. */
interface Attempt {
  promise: Promise<SessionEntry>;
  /** Callers still waiting for it. At zero nobody wants the result, so a late DNS answer must not open a connection. */
  waiters: number;
  /** Aborted when the last waiter leaves: a proxy tunnel still being set up for nobody is torn down. */
  readonly abandoned: AbortController;
}

/**
 * Both maps below are keyed per policy as well as per origin: a session resolved
 * under one `permitReservedIps` policy must never be reachable by a caller with another.
 * The policy key never contains '|', so the first '|' always separates it from the origin.
 */
const poolKey = (origin: string, policy: ReservedIpPolicy): string =>
  `${policyKey(policy)}|${origin}`;

const originOf = (key: string): string => key.slice(key.indexOf("|") + 1);

/**
 * Settles like `promise`, but rejects with `signal.reason` as soon as `signal` aborts; `onAbort` runs first.
 * The abort listener is removed once either side wins, so nothing outlives the call.
 */
const untilAborted = <T>(
  promise: Promise<T>,
  signal: AbortSignal,
  onAbort?: () => void,
): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    const abort = () => {
      onAbort?.();
      reject(signal.reason);
    };
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    promise
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", abort));
  });

/**
 * `hostname` may be a full origin URL (e.g. "https://example.com") because the
 * session pool is keyed by origin. Extract the bare hostname for DNS resolution,
 * TLS SNI and the allowlist match: all of them need a plain host, not a URL.
 */
const bareHostOf = (hostname: string): string => {
  let bareHost: string;
  try {
    bareHost = hostname.includes("://") ? new URL(hostname).hostname : hostname;
  } catch {
    bareHost = hostname;
  }
  // URL.hostname keeps the brackets of an IPv6 literal ("[::1]"); DNS and SNI need the bare address.
  return bareHost.replace(/^\[|\]$/g, "");
};

/** Streams in flight per session, for `holdSession`. */
const activeStreams = new WeakMap<ClientHttp2Session, number>();

/**
 * Keeps the process alive for as long as a request is using `session`: the first holder `ref()`s it and the last one to
 * release it `unref()`s it again. A pooled session with nothing in flight does not hold the process open, so a script
 * that never calls `close()` exits when its work is done instead of waiting out the session's idle timeout.
 * @returns A function that releases the hold; calling it more than once does nothing.
 */
export function holdSession(session: ClientHttp2Session): () => void {
  const count = activeStreams.get(session) ?? 0;
  activeStreams.set(session, count + 1);
  if (count === 0 && !session.destroyed) session.ref();
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const left = (activeStreams.get(session) ?? 1) - 1;
    activeStreams.set(session, left);
    if (left === 0 && !session.destroyed) session.unref();
  };
}

/** How many requests currently hold `session` (see `holdSession`). */
export const heldStreams = (session: ClientHttp2Session): number => activeStreams.get(session) ?? 0;

export class Http2SessionManager {
  #sessions: Map<string, SessionEntry> = new Map();
  /** Sessions that got a GOAWAY: out of the pool, finishing their streams, still closed by closeAll(). Value: pool key. */
  #draining: Map<ClientHttp2Session, string> = new Map();
  #pendingConnections: Map<string, Attempt> = new Map();
  readonly #tlsConfig?: SecureClientSessionOptions;
  readonly #connectFn: typeof nativeConnect;
  readonly #idleTimeoutMs: number;
  readonly #maxLifespanMs: number;
  readonly #proxy?: ProxyConfig;
  /** Aborted by closeAll(): a tunnel still being set up through the proxy is torn down with it. */
  #closing = new AbortController();

  constructor(
    tlsConfig: SecureClientSessionOptions = {},
    connectFn: typeof nativeConnect = nativeConnect,
    timings: SessionTimings = {},
    proxy?: ProxyConfig,
  ) {
    this.#tlsConfig = tlsConfig;
    this.#connectFn = connectFn;
    this.#proxy = proxy;
    this.#idleTimeoutMs = timings.idleTimeoutMs ?? IDLE_TIMEOUT;
    this.#maxLifespanMs = timings.maxLifespanMs ?? MAX_SESSION_LIFESPAN;
  }

  /**
   * Closes the sessions of a specific origin (under every reserved-IP policy)
   * and removes them from the manager.
   */
  public closeSession(hostname: string): void {
    for (const [key, entry] of [...this.#sessions]) {
      if (originOf(key) === hostname) {
        this.#destroySession(key, entry.session);
      }
    }
  }

  /**
   * Closes all active sessions and clears the manager.
   */
  public closeAll(): void {
    this.#closing.abort(new SecureHttpError("UltraTon: Client is closed."));
    this.#closing = new AbortController();
    for (const [key, entry] of this.#sessions.entries()) {
      this.#destroySession(key, entry.session);
    }
    for (const [session, key] of [...this.#draining]) {
      this.#destroySession(key, session);
    }
    this.#sessions.clear();
    this.#draining.clear();
    this.#pendingConnections.clear();
  }

  /**
   * Retrieves an existing active session or creates a new one.
   * Concurrent callers for the same origin and the same `permitReservedIps` policy share
   * one connection attempt; callers of another policy never join it (nor retry
   * after it), so a failed strict attempt cannot fail or multiply permissive ones.
   *
   * The pool is shared across callers and keyed by policy and origin, so a session
   * opened under one policy is never handed to a caller with another. The IP check
   * still runs on every hand-out as defence in depth.
   *
   * `signal` bounds how long THIS caller waits (DNS plus joining a pending connection):
   * when it aborts, the call rejects with `signal.reason` while other callers keep waiting.
   * If the aborting caller is the one that opened the connection attempt, the attempt leaves
   * the pending map at once, so the next request resolves the host again instead of joining
   * a lookup that may never answer. A lookup that answers after that is used only by callers
   * still waiting for it; if there are none, it opens no connection.
   */
  public async getSession(
    hostname: string,
    overrideOptions?: SecureClientSessionOptions,
    permitReservedIps: ReservedIpPolicy = false,
    signal?: AbortSignal,
  ): Promise<ClientHttp2Session> {
    const { session, ips } = await this.#acquire(
      hostname,
      overrideOptions,
      permitReservedIps,
      signal,
    );
    for (const ip of ips) assertAllowedIp(ip, permitReservedIps, bareHostOf(hostname));
    return session;
  }

  async #acquire(
    hostname: string,
    overrideOptions: SecureClientSessionOptions | undefined,
    permitReservedIps: ReservedIpPolicy,
    signal: AbortSignal | undefined,
  ): Promise<SessionEntry> {
    const key = poolKey(hostname, permitReservedIps);
    const entry = this.#sessions.get(key);

    if (entry) {
      const { session, createdAt } = entry;
      const isExpired = Date.now() - createdAt > this.#maxLifespanMs;

      if (!session.destroyed && !session.closed && !isExpired) {
        return entry;
      }

      if (isExpired) {
        // Graceful shutdown, like a GOAWAY: out of the pool at once (so concurrent callers arriving before the async
        // 'close' event hit the #pendingConnections deduplication gate instead of spawning a duplicate connection),
        // existing streams finish, and closeAll() still destroys it while they do.
        this.#retireSession(key, session);
      }
    }

    // If a connection attempt is already in progress for this policy, share it
    let attempt = this.#pendingConnections.get(key);
    const opened = attempt === undefined;
    let forget = () => {};

    if (attempt === undefined) {
      const abandoned = new AbortController();
      const created: Attempt = {
        waiters: 0,
        abandoned,
        promise: this.#establishConnection(
          key,
          hostname,
          overrideOptions,
          permitReservedIps,
          // Read after the DNS await, by which point this caller has registered as a waiter.
          () => created.waiters > 0,
          abandoned.signal,
        ),
      };
      attempt = created;
      this.#pendingConnections.set(key, created);
      // Only its own entry: a newer attempt may have taken the key since. Running on settle, however late,
      // also gives the promise a rejection handler for when every caller has already gone away.
      forget = () => {
        if (this.#pendingConnections.get(key) === created) {
          this.#pendingConnections.delete(key);
        }
      };
      created.promise.then(forget, forget);
    }

    attempt.waiters++;
    try {
      return await (signal
        ? untilAborted(attempt.promise, signal, opened ? forget : undefined)
        : attempt.promise);
    } finally {
      attempt.waiters--;
      // After a settled attempt this changes nothing; before, it stops a tunnel nobody will use.
      if (attempt.waiters === 0) attempt.abandoned.abort();
    }
  }

  async #establishConnection(
    key: string,
    hostname: string,
    overrideOptions: SecureClientSessionOptions | undefined,
    permitReservedIps: ReservedIpPolicy,
    wanted: () => boolean,
    abandoned: AbortSignal,
  ): Promise<SessionEntry> {
    const bareHost = bareHostOf(hostname);
    // Taken now: a closeAll() during the DNS lookup below aborts this one, and replaces #closing for later attempts.
    const closing = this.#closing.signal;

    // ponytail: getaddrinfo cannot be cancelled. A caller that gives up stops waiting, but its threadpool thread stays
    // busy until the OS answers, and every later request starts another lookup. Upgrade path: a dns.Resolver with a
    // timeout (c-ares), not done here because it ignores /etc/hosts.
    // Every address is validated (an IP literal is judged as itself): one disallowed address rejects the lookup.
    // The origin's scheme is part of the pool key, so an h2c session only ever holds addresses checked as loopback.
    const connectUrl = hostname.includes("://") ? hostname : `https://${hostname}`;
    const target = new URL(connectUrl);
    // Plain http goes to loopback only and never through the proxy. With resolve: 'proxy' the proxy resolves the name,
    // so nothing is looked up here; an IP literal is still judged as itself.
    const proxy = target.protocol === "https:" ? this.#proxy : undefined;
    const resolveHere = proxy?.resolve !== "proxy" || isIP(bareHost) !== 0;
    // Parsed, not compared as text: a scheme in any case ("HTTP://") is still plain http.
    const addresses = resolveHere
      ? await resolveAndPinAll(bareHost, permitReservedIps, target.protocol === "http:")
      : [];

    // Through the proxy: a CONNECT tunnel to the validated addresses in order (or the name), then TLS to the target
    // over it, with ALPN h2 and the certificate checked against the name, as on a direct connection.
    let tunnelled: Duplex | undefined;
    if (proxy) {
      const raw = await tunnelTo(
        proxy,
        resolveHere ? addresses.map(({ address }) => address) : [bareHost],
        Number(target.port) || 443,
        AbortSignal.any([closing, abandoned]),
      );
      const { ca, cert, key } = this.#tlsConfig ?? {};
      tunnelled = tls.connect({
        socket: raw,
        ca, cert, key,
        // The certificate is checked against `host` when there is no SNI (an IP literal): without it Node would fall
        // back to the name of the socket it wraps, the proxy's, and accept the proxy's own certificate.
        host: bareHost,
        ...(isIP(bareHost) === 0 ? { servername: bareHost } : {}),
        ALPNProtocols: ["h2"],
      });
    }

    const {
      // Each of these would let the socket go somewhere other than the validated addresses.
      host: _host,
      port: _port,
      path: _path,
      socket: _socket,
      createConnection: _createConnection,
      lookup: _lookup,
      servername: _servername,
      ...baseOptions
    } = {
      ...this.#tlsConfig,
      ...overrideOptions,
    } as SecureClientSessionOptions & Record<string, unknown>;
    const connectionOptions: SecureClientSessionOptions & {
      maxHeaderListPairs?: number;
    } = {
      maxHeaderListPairs: MAX_HEADER_LIST_PAIRS,
      maxSessionMemory: MAX_SESSION_MEMORY_MB,
      ...baseOptions,
      settings: {
        maxHeaderListSize: MAX_HEADER_LIST_SIZE,
        initialWindowSize: H2_STREAM_WINDOW,
        ...this.#tlsConfig?.settings,
        ...overrideOptions?.settings,
      },
      // The connect URL keeps the name; this is the only way it becomes addresses (see pinnedLookup). Node never
      // calls it for an IP literal, which connects to the literal resolveAndPinAll just judged.
      lookup: pinnedLookup(addresses),
      // SNI and the certificate check use the name. An IP literal is never sent as SNI (RFC 6066; Node's DEP0123).
      ...(isIP(bareHost) === 0 ? { servername: bareHost } : {}),
    };

    // Every caller timed out while the lookup hung: do not open a connection nobody will use.
    if (!wanted()) {
      tunnelled?.destroy();
      throw new SecureHttpError(
        "UltraTon: Connection attempt was abandoned before it connected.",
      );
    }

    // The caller that opened an attempt can give up and leave the pending map while a joiner keeps waiting, so a newer
    // attempt may have pooled a session for this key during our lookup. Setting ours would orphan that one from the
    // pool and closeAll(): use it. Nothing may be awaited between this check and the `set` below.
    const pooled = this.#sessions.get(key);
    if (
      pooled &&
      !pooled.session.closed &&
      !pooled.session.destroyed &&
      Date.now() - pooled.createdAt <= this.#maxLifespanMs
    ) {
      tunnelled?.destroy();
      return pooled;
    }

    // The origin itself (scheme, name, port): http2.connect hands the name, the options and so `lookup` to
    // net.connect (h2c) or tls.connect, where autoSelectFamily (on by default) races the validated addresses.

    let newSession: ClientHttp2Session;
    try {
      newSession = this.#connectFn(
        connectUrl,
        tunnelled ? { ...connectionOptions, createConnection: () => tunnelled } : connectionOptions,
      );
    } catch (err: unknown) {
      tunnelled?.destroy();
      throw toNetworkError(err);
    }

    // Attach 'error' FIRST — before setTimeout or any other logic — to eliminate
    // the synchronous gap between session creation and error handler registration.
    newSession.on("error", () => this.#destroySession(key, newSession));
    // The connection window has no setting of its own: it is raised by a WINDOW_UPDATE once the session is up.
    newSession.on("connect", () => {
      if (!newSession.destroyed) newSession.setLocalWindowSize(H2_CONNECTION_WINDOW);
    });

    newSession.setTimeout(this.#idleTimeoutMs);
    // Idle until a request holds it (holdSession): a pooled session must not keep the process alive by itself.
    newSession.unref();
    // A GOAWAY lets the streams it covers finish: destroying the session here would end them early, and a stream
    // whose body was cut could look complete. Take it out of the pool so new requests open a fresh session, and close
    // it gracefully (Node also destroys it by itself when the GOAWAY carries an error code).
    newSession.on("goaway", () => this.#retireSession(key, newSession));
    newSession.on("close", () => {
      this.#draining.delete(newSession);
      if (this.#sessions.get(key)?.session === newSession) {
        this.#sessions.delete(key);
      }
    });
    // The idle timeout reaps a session nobody uses. A stream may legitimately wait longer than that for its response
    // (its own limits are socketTimeoutMs and timeoutMs, 0 disabling them), so a held session is not reaped: it is
    // checked for liveness instead. Each idle period without a frame sends a PING; a live peer ACKs it at once, however
    // long it takes to answer the request. A PING still unanswered at the next check means the connection is dead (a
    // peer that vanished without FIN or RST): the session is destroyed and its streams fail as a reset connection,
    // so it never pins the pool. The timer is re-armed by hand because Node only refreshes it on the next frame, and a
    // stream that is given up may never be followed by one.
    // A closing session (GOAWAY, lifespan expiry, retire()) is out of the pool, so it cannot pin it, and Node cancels
    // every PING on it: it is never pinged nor killed here. Its streams keep their own timeouts, and closeAll() still
    // destroys it. A cancelled PING (ERR_HTTP2_PING_CANCEL, or a ping() that throws) proves nothing either way.
    let pingUnanswered = false;
    newSession.on("timeout", () => {
      if (heldStreams(newSession) === 0) return this.#destroySession(key, newSession);
      if (!newSession.closed) {
        if (pingUnanswered) {
          if (!newSession.destroyed) newSession.destroy(incompleteResponse());
          return;
        }
        pingUnanswered = true;
        try {
          newSession.ping((err) => {
            if (!err || (err as NodeJS.ErrnoException).code === "ERR_HTTP2_PING_CANCEL") pingUnanswered = false;
          });
        } catch {
          pingUnanswered = false;
        }
      }
      newSession.setTimeout(this.#idleTimeoutMs);
    });

    const entry: SessionEntry = {
      session: newSession,
      createdAt: Date.now(),
      ips: addresses.map(({ address }) => address),
    };
    this.#sessions.set(key, entry);

    return entry;
  }

  /**
   * Takes `session` out of the pool (see #retireSession) if it is pooled here: the next request opens a new session,
   * streams already on this one finish, and closeAll() still destroys it. Used when a stream on it was given up
   * because of a timeout, which may mean the connection is dead.
   */
  public retire(session: ClientHttp2Session): void {
    for (const [key, entry] of this.#sessions) {
      if (entry.session === session) return this.#retireSession(key, session);
    }
  }

  /** Removes a session from the pool and closes it gracefully: open streams finish, no new ones start. */
  #retireSession(key: string, session: ClientHttp2Session): void {
    if (this.#sessions.get(key)?.session === session) {
      this.#sessions.delete(key);
    }
    if (session.destroyed) return;
    this.#draining.set(session, key);
    try {
      if (!session.closed) session.close();
    } catch {
      /* Session might have already transitioned state */
    }
  }

  /**
   * Unified cleanup logic for destroying sessions.
   */
  #destroySession(key: string, session: ClientHttp2Session): void {
    try {
      if (!session.closed && !session.destroyed) {
        session.close();
      }
    } catch {
      /* Session might have already transitioned state */
    } finally {
      if (this.#sessions.get(key)?.session === session) {
        this.#sessions.delete(key);
      }
      if (!session.destroyed) {
        session.destroy();
      }
    }
  }
}
