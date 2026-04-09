import {
  type ClientHttp2Session,
  connect as nativeConnect,
  type SecureClientSessionOptions,
} from "node:http2";
import { MAX_SESSION_LIFESPAN } from "../constants/session.ts";
import { IDLE_TIMEOUT } from "../constants/idle.ts";
import { resolveAndPinHost } from "../security/dns-pinner.ts";

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
        // The 'close' event listener will handle removing it from the map.
        try {
          if (!session.closed && !session.destroyed) {
            session.close();
          }
        } catch (error: unknown) {
          /* Session might have already transitioned state */
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
    const connectionOptions: SecureClientSessionOptions = {
      ...this.#tlsConfig,
      ...overrideOptions,
      servername: hostname,
    };

    const pinnedHost = await resolveAndPinHost(hostname);
    const newSession = this.#connectFn(pinnedHost, connectionOptions);
    newSession.setTimeout(IDLE_TIMEOUT);

    // Attach event listeners for lifecycle management
    newSession.on("error", () => this.#destroySession(hostname, newSession));
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
