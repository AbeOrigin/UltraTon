import {
    ClientHttp2Session,
    connect,
    SecureClientSessionOptions
} from "node:http2";
import { IDLE_TIMEOUT } from "../constants/idle.ts";

export class Http2SessionManager {
    #sessions: Map<string, ClientHttp2Session> = new Map();
    readonly #tlsConfig?: SecureClientSessionOptions;

    constructor(tlsConfig: SecureClientSessionOptions = {}) {
        this.#tlsConfig = tlsConfig;
    }

    public closeSession(hostname: string): void {
        const session = this.#sessions.get(hostname);
        if (session && !session.closed && !session.destroyed) {
            session.close();
            this.#sessions.delete(hostname);
        }
    }

    public closeAll(): void {
        for (const [hostname, session] of this.#sessions.entries()) {
            if (!session.closed && !session.destroyed) {
                session.close();
            }
        }
        this.#sessions.clear();
    }

    public getSession(hostname: string, overrideOptions?: SecureClientSessionOptions): ClientHttp2Session {
        const existingSession = this.#sessions.get(hostname);

        if (existingSession && !existingSession.destroyed && !existingSession.closed) {
            return existingSession;
        }

        const connectionOptions: SecureClientSessionOptions = {
            ...this.#tlsConfig,
            ...overrideOptions
        };

        const newSession = connect(hostname, connectionOptions);
        newSession.setTimeout(IDLE_TIMEOUT);
        newSession.on('error', () => this.#sessions.delete(hostname));
        newSession.on('goaway', () => this.#sessions.delete(hostname));
        newSession.on('close', () => this.#sessions.delete(hostname));
        newSession.on('timeout', () => {
            newSession.destroy();
            this.#sessions.delete(hostname);
        });
        this.#sessions.set(hostname, newSession);
        return newSession;
    }
}