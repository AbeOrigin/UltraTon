import {
  ClientHttp2Session,
  connect,
  SecureClientSessionOptions,
} from "node:http2";
import { IDLE_TIMEOUT } from "../constants/idle.ts";

export class Http2SessionManager {
  #sessions: Map<string, ClientHttp2Session> = new Map();
  #pendingConnections: Map<string, Promise<ClientHttp2Session>> = new Map();
  readonly #tlsConfig?: SecureClientSessionOptions;

  constructor(tlsConfig: SecureClientSessionOptions = {}) {
    this.#tlsConfig = tlsConfig;
  }

  /**
   * Closes a specific session and removes it from the manager.
   */
  public closeSession(hostname: string): void {
    const session = this.#sessions.get(hostname);
    if (session) {
      this.#destroySession(hostname, session);
    }
  }

  /**
   * Closes all active sessions and clears the manager.
   */
  public closeAll(): void {
    for (const [hostname, session] of this.#sessions.entries()) {
      this.#destroySession(hostname, session);
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
    const existingSession = this.#sessions.get(hostname);

    if (
      existingSession &&
      !existingSession.destroyed &&
      !existingSession.closed
    ) {
      return existingSession;
    }

    // If a connection attempt is already in progress, return that promise
    const pending = this.#pendingConnections.get(hostname);
    if (pending) {
      return pending;
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

  /**
   * Internal method to handle the actual connection logic and event binding.
   */
  async #establishConnection(
    hostname: string,
    overrideOptions?: SecureClientSessionOptions,
  ): Promise<ClientHttp2Session> {
    const connectionOptions: SecureClientSessionOptions = {
      ...this.#tlsConfig,
      ...overrideOptions,
    };

    const newSession = connect(hostname, connectionOptions);
    newSession.setTimeout(IDLE_TIMEOUT);

    // Attach event listeners for lifecycle management
    newSession.on("error", () => this.#destroySession(hostname, newSession));
    newSession.on("goaway", () => this.#destroySession(hostname, newSession));
    newSession.on("close", () => this.#sessions.delete(hostname));
    newSession.on("timeout", () => this.#destroySession(hostname, newSession));

    this.#sessions.set(hostname, newSession);
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
      this.#sessions.delete(hostname);
      if (!session.destroyed) {
        session.destroy();
      }
    }
  }
}
