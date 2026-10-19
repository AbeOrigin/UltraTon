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
import { assertAllowedIp, resolveAndPinHost } from "../security/dns-pinner.ts";
import { SecureHttpError } from "../errors.ts";

interface SessionEntry {
  session: ClientHttp2Session;
  createdAt: number;
  /** The IP the session is pinned to; every caller is checked against it. */
  ip: string;
}

interface PendingConnection {
  promise: Promise<SessionEntry>;
  /** The policy the attempt was resolved under (a strict attempt can fail for a permissive caller). */
  permitReservedIps: boolean;
}

export class Http2SessionManager {
  #sessions: Map<string, SessionEntry> = new Map();
  #pendingConnections: Map<string, PendingConnection> = new Map();
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
   * Closes a specific session and removes it from the manager.
   */
  public closeSession(hostname: string): void {
    const entry = this.#sessions.get(hostname);
    if (entry) {
      this.#destroySession(hostname, entry.session);
    }
  }

  /**
   * Closes all active sessions and clears the manager.
   */
  public closeAll(): void {
    for (const [hostname, entry] of this.#sessions.entries()) {
      this.#destroySession(hostname, entry.session);
    }
    this.#sessions.clear();
    this.#pendingConnections.clear();
  }

  /**
   * Retrieves an existing active session or creates a new one.
   * Handles concurrent requests for the same hostname by returning the same promise.
   *
   * The pool is shared across callers, so the reserved-IP policy is enforced per
   * caller on the way out: a session opened with `permitReservedIps: true` is never
   * handed to a caller that forbids it, whether it was pooled, still connecting,
   * or just created.
   */
  public async getSession(
    hostname: string,
    overrideOptions?: SecureClientSessionOptions,
    permitReservedIps = false,
  ): Promise<ClientHttp2Session> {
    const { session, ip } = await this.#acquire(
      hostname,
      overrideOptions,
      permitReservedIps,
    );
    assertAllowedIp(ip, permitReservedIps);
    return session;
  }

  async #acquire(
    hostname: string,
    overrideOptions: SecureClientSessionOptions | undefined,
    permitReservedIps: boolean,
  ): Promise<SessionEntry> {
    const entry = this.#sessions.get(hostname);

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
        if (this.#sessions.get(hostname)?.session === session) {
          this.#sessions.delete(hostname);
        }
      }
    }

    // If a connection attempt is already in progress, share it
    const pendingConnection = this.#pendingConnections.get(hostname);
    if (pendingConnection) {
      try {
        return await pendingConnection.promise;
      } catch (err: unknown) {
        // An attempt made under a stricter policy may fail (reserved IP) for reasons
        // that do not apply to this caller, so it retries under its own.
        if (!permitReservedIps || pendingConnection.permitReservedIps) {
          throw err;
        }
        return this.#establishConnection(
          hostname,
          overrideOptions,
          permitReservedIps,
        );
      }
    }

    const connectionPromise = this.#establishConnection(
      hostname,
      overrideOptions,
      permitReservedIps,
    );
    this.#pendingConnections.set(hostname, {
      promise: connectionPromise,
      permitReservedIps,
    });

    try {
      return await connectionPromise;
    } finally {
      this.#pendingConnections.delete(hostname);
    }
  }

  async #establishConnection(
    hostname: string,
    overrideOptions: SecureClientSessionOptions | undefined,
    permitReservedIps: boolean,
  ): Promise<SessionEntry> {
    // `hostname` may be a full origin URL (e.g. "https://example.com") because
    // the session pool is keyed by origin. Extract the bare hostname for DNS
    // resolution and TLS SNI — both require a plain host, not a URL.
    let bareHost: string;
    try {
      bareHost = hostname.includes("://")
        ? new URL(hostname).hostname
        : hostname;
    } catch {
      bareHost = hostname;
    }
    // URL.hostname keeps the brackets of an IPv6 literal ("[::1]"); DNS and SNI need the bare address.
    bareHost = bareHost.replace(/^\[|\]$/g, "");

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

    const pinnedHost = await resolveAndPinHost(bareHost, permitReservedIps);

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
    newSession.on("error", () => this.#destroySession(hostname, newSession));

    newSession.setTimeout(IDLE_TIMEOUT);
    newSession.on("goaway", () => this.#destroySession(hostname, newSession));
    newSession.on("close", () => {
      if (this.#sessions.get(hostname)?.session === newSession) {
        this.#sessions.delete(hostname);
      }
    });
    newSession.on("timeout", () => this.#destroySession(hostname, newSession));

    const entry: SessionEntry = {
      session: newSession,
      createdAt: Date.now(),
      ip: pinnedHost,
    };
    this.#sessions.set(hostname, entry);

    return entry;
  }

  /**
   * Unified cleanup logic for destroying sessions.
   */
  #destroySession(hostname: string, session: ClientHttp2Session): void {
    try {
      if (!session.closed && !session.destroyed) {
        session.close();
      }
    } catch {
      /* Session might have already transitioned state */
    } finally {
      if (this.#sessions.get(hostname)?.session === session) {
        this.#sessions.delete(hostname);
      }
      if (!session.destroyed) {
        session.destroy();
      }
    }
  }
}
