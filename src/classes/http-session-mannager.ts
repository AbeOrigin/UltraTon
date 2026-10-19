import {
  type ClientHttp2Session,
  connect as nativeConnect,
  type SecureClientSessionOptions,
} from "node:http2";
import {
  IDLE_TIMEOUT,
  MAX_HEADER_LIST_PAIRS,
  MAX_HEADER_LIST_SIZE,
  MAX_SESSION_LIFESPAN,
  MAX_SESSION_MEMORY_MB,
} from "../constants.ts";
import { isIP } from "node:net";
import {
  assertAllowedIp,
  policyKey,
  type ReservedIpPolicy,
  resolveAndPinHost,
} from "../security/dns-pinner.ts";
import { SecureHttpError } from "../errors.ts";

interface SessionEntry {
  session: ClientHttp2Session;
  createdAt: number;
  /** The IP the session is pinned to; every caller is checked against it. */
  ip: string;
}

/** A DNS lookup plus connect in flight for one pool key, shared by every caller that arrives while it runs. */
interface Attempt {
  promise: Promise<SessionEntry>;
  /** Callers still waiting for it. At zero nobody wants the result, so a late DNS answer must not open a connection. */
  waiters: number;
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

export class Http2SessionManager {
  #sessions: Map<string, SessionEntry> = new Map();
  #pendingConnections: Map<string, Attempt> = new Map();
  readonly #tlsConfig?: SecureClientSessionOptions;
  readonly #connectFn: typeof nativeConnect;

  constructor(
    tlsConfig: SecureClientSessionOptions = {},
    connectFn: typeof nativeConnect = nativeConnect,
  ) {
    this.#tlsConfig = tlsConfig;
    this.#connectFn = connectFn;
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
    for (const [key, entry] of this.#sessions.entries()) {
      this.#destroySession(key, entry.session);
    }
    this.#sessions.clear();
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
    const { session, ip } = await this.#acquire(
      hostname,
      overrideOptions,
      permitReservedIps,
      signal,
    );
    assertAllowedIp(ip, permitReservedIps, bareHostOf(hostname));
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
      const isExpired = Date.now() - createdAt > MAX_SESSION_LIFESPAN;

      if (!session.destroyed && !session.closed && !isExpired) {
        return entry;
      }

      if (isExpired) {
        // Graceful shutdown: close prevents new streams but allows existing ones to finish.
        try {
          if (!session.closed && !session.destroyed) {
            session.close();
          }
        } catch {
          /* Session might have already transitioned state */
        }
        // Eagerly evict from the pool so concurrent callers arriving before the
        // async 'close' event fires correctly hit the #pendingConnections
        // deduplication gate instead of spawning a duplicate TCP connection.
        if (this.#sessions.get(key)?.session === session) {
          this.#sessions.delete(key);
        }
      }
    }

    // If a connection attempt is already in progress for this policy, share it
    let attempt = this.#pendingConnections.get(key);
    const opened = attempt === undefined;
    let forget = () => {};

    if (attempt === undefined) {
      const created: Attempt = {
        waiters: 0,
        promise: this.#establishConnection(
          key,
          hostname,
          overrideOptions,
          permitReservedIps,
          // Read after the DNS await, by which point this caller has registered as a waiter.
          () => created.waiters > 0,
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
    }
  }

  async #establishConnection(
    key: string,
    hostname: string,
    overrideOptions: SecureClientSessionOptions | undefined,
    permitReservedIps: ReservedIpPolicy,
    wanted: () => boolean,
  ): Promise<SessionEntry> {
    const bareHost = bareHostOf(hostname);

    const connectionOptions: SecureClientSessionOptions & {
      maxHeaderListPairs?: number;
    } = {
      maxHeaderListPairs: MAX_HEADER_LIST_PAIRS,
      maxSessionMemory: MAX_SESSION_MEMORY_MB,
      ...this.#tlsConfig,
      ...overrideOptions,
      settings: {
        maxHeaderListSize: MAX_HEADER_LIST_SIZE,
        ...this.#tlsConfig?.settings,
        ...overrideOptions?.settings,
      },
      servername: bareHost,
    };

    // ponytail: getaddrinfo cannot be cancelled. A caller that gives up stops waiting, but its threadpool thread stays
    // busy until the OS answers, and every later request starts another lookup. Upgrade path: a dns.Resolver with a
    // timeout (c-ares), not done here because it ignores /etc/hosts.
    const pinnedHost = await resolveAndPinHost(bareHost, permitReservedIps);

    // Every caller timed out while the lookup hung: do not open a connection nobody will use.
    if (!wanted()) {
      throw new SecureHttpError(
        `UltraTon: Connection attempt to ${bareHost} was abandoned before it connected.`,
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
      Date.now() - pooled.createdAt <= MAX_SESSION_LIFESPAN
    ) {
      return pooled;
    }

    // http2.connect() requires a full URL (e.g. "https://172.233.17.91"), not a
    // bare IP. Reconstruct it using the original origin's scheme and port so the
    // TCP connection targets the resolved IP while SNI (servername) stays as the
    // original hostname for correct TLS certificate validation.
    let connectUrl: string;
    try {
      const parsed = new URL(
        hostname.includes("://") ? hostname : `https://${hostname}`,
      );
      const port = parsed.port ? `:${parsed.port}` : "";
      // A bare IPv6 address is not a valid URL host: it needs its brackets back.
      const host = isIP(pinnedHost) === 6 ? `[${pinnedHost}]` : pinnedHost;
      connectUrl = `${parsed.protocol}//${host}${port}`;
    } catch {
      connectUrl = `https://${pinnedHost}`;
    }

    let newSession: ClientHttp2Session;
    try {
      newSession = this.#connectFn(connectUrl, connectionOptions);
    } catch (err: unknown) {
      throw new SecureHttpError(
        `UltraTon: Failed to establish HTTP/2 connection to ${bareHost}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    // Attach 'error' FIRST — before setTimeout or any other logic — to eliminate
    // the synchronous gap between session creation and error handler registration.
    newSession.on("error", () => this.#destroySession(key, newSession));

    newSession.setTimeout(IDLE_TIMEOUT);
    newSession.on("goaway", () => this.#destroySession(key, newSession));
    newSession.on("close", () => {
      if (this.#sessions.get(key)?.session === newSession) {
        this.#sessions.delete(key);
      }
    });
    newSession.on("timeout", () => this.#destroySession(key, newSession));

    const entry: SessionEntry = {
      session: newSession,
      createdAt: Date.now(),
      ip: pinnedHost,
    };
    this.#sessions.set(key, entry);

    return entry;
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
