import { ClientHttp2Session, connect, ClientSessionOptions } from "node:http2";

export class Http2SessionManager {

    #sessions: Map<string, ClientHttp2Session> = new Map();

    constructor() {}

    public getSession(hostname: string, options?: ClientSessionOptions): ClientHttp2Session {
        const existingSession = this.#sessions.get(hostname);

        if (existingSession && !existingSession.destroyed && !existingSession.closed) {
            return existingSession;
        }
        const newSession = connect(hostname, options);

        newSession.on('error', (err) => {
            this.#sessions.delete(hostname);
        });

        newSession.on('goaway', () => {
            this.#sessions.delete(hostname);
        });

        newSession.on('close', () => {
            this.#sessions.delete(hostname);
        });

        newSession.on('timeout', () => {
            newSession.destroy();
            this.#sessions.delete(hostname);
        });
        
        this.#sessions.set(hostname, newSession);
        return newSession;
    }
}