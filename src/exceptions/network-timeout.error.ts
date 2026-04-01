import { SecureHttpError } from "./secure-http.error.ts";

export class UltraTonNetworkTimeoutError extends SecureHttpError {
    constructor(message: string) {
        super(message);
        this.name = 'UltraTonNetworkTimeoutError';
    }
}