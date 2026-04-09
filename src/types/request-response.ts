import type { IncomingHttpHeaders } from 'node:http';

export interface UltraTonResponse<T = unknown> {
    /**
     * The HTTP status code of the response (e.g., 200, 404, 500).
     * If the connection fails entirely before a response is received, 
     * the Promise should reject an Error rather than returning this object.
     */
    readonly statusCode: number | undefined
    /**
     * The raw HTTP headers returned by the server. 
     * We use Node's native IncomingHttpHeaders type to ensure 
     * complete compatibility with the native socket data.
     */
    readonly headers: IncomingHttpHeaders;
    /**
     * The response payload.
     * 🛡️ SECURITY COMMITMENT: Automatic parsing of valid 'application/json' payloads.
     * Massive payloads (>5MB) bypass automatic sync parsing returning the raw Buffer
     * to protect the V8 Event Loop. Prototype injection vectors are stripped.
     */
    readonly body: T | Buffer;
    
    /**
     * Synchronously parses the raw stream Buffer into a generic output context.
     * Guaranteed to explicitly intercept native V8 SyntaxError faults.
     */
    json(): T;
}