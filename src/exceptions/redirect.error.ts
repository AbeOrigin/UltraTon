import { SecureHttpError } from "./secure-http.error.ts";

export class UltraTonRedirectError extends SecureHttpError {
    constructor(message: string) {
        super(message);
        this.name = 'UltraTonRedirectError';
    }
}