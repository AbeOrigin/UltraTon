import {
  type ClientHttp2Session,
  connect as nativeConnect,
  type SecureClientSessionOptions,
} from "node:http2";
import { MAX_SESSION_LIFESPAN } from "../constants/session.ts";
import { IDLE_TIMEOUT } from "../constants/idle.ts";
import { resolveAndPinHost } from "../security/dns-pinner.ts";
import { SecureHttpError } from "../exceptions/secure-http.error.ts";

interface SessionEntry {
  session: ClientHttp2Session;
  createdAt: number;
}

export class Http2SessionManager {
  #sessions: Map<string, SessionEntry> = new Map();
  #pendingConnections: Map<string, Promise<ClientHttp2Session>> = new Map();
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
   */
  public async getSession(
    hostname: string,
    overrideOptions?: SecureClientSessionOptions,
  ): Promise<ClientHttp2Session> {
    const entry = this.#sessions.get(hostname);

    if (entry) {
      const { session, createdAt } = entry;
      const isExpired = Date.now() - createdAt > MAX_SESSION_LIFESPAN;

      if (!session.destroyed && !session.closed && !isExpired) {
        return session;
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

    // If a connection attempt is already in progress, return that promise
    const pendingConnection = this.#pendingConnections.get(hostname);
    if (pendingConnection) {
      return pendingConnection;
    }

    const connectionPromise = this.#establishConnection(
      hostname,
      overrideOptions,
    );
    this.#pendingConnections.set(hostname, connectionPromise);

    try {
      return await connectionPromise;
    } finally {
      this.#pendingConnections.delete(hostname);
    }
  }

  async #establishConnection(
    hostname: string,
    overrideOptions?: SecureClientSessionOptions,
  ): Promise<ClientHttp2Session> {
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

    const connectionOptions: SecureClientSessionOptions = {
      ...this.#tlsConfig,
      ...overrideOptions,
      servername: bareHost,
    };

    const pinnedHost = await resolveAndPinHost(bareHost);

    // http2.connect() requires a full URL (e.g. "https://172.233.17.91"), not a
    // bare IP. Reconstruct it using the original origin's scheme and port so the
    // TCP connection targets the resolved IP while SNI (servername) stays as the
    // original hostname for correct TLS certificate validation.
    let connectUrl: string;
    try {
      const parsed = new URL(hostname.includes("://") ? hostname : `https://${hostname}`);
      const port = parsed.port ? `:${parsed.port}` : "";
      connectUrl = `${parsed.protocol}//${pinnedHost}${port}`;
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

    this.#sessions.set(hostname, {
      session: newSession,
      createdAt: Date.now(),
    });

    return newSession;
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
