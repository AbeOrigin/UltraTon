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
     * The aggregated response payload.
     * 🛡️ SECURITY COMMITMENT: This MUST always be a unified raw Buffer.
     * We do not auto-parse JSON or convert to UTF-8 at this core layer to
     * prevent prototype pollution or V8 heap exhaustion attacks that can 
     * happen when implicitly allocating massive strings.
     */
    readonly data: Buffer;
    
    /**
     * Synchronously parses the raw stream Buffer into a generic output context.
     * Guaranteed to explicitly intercept native V8 SyntaxError faults.
     */
    json(): T;
}