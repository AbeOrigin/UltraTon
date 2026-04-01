import { SecureHttpError } from "./secure-http.error.ts";

export class UltraTonMemoryError extends SecureHttpError {
    constructor(message: string) {
        super(message);
        this.name = 'UltraTonMemoryError';
    }
}