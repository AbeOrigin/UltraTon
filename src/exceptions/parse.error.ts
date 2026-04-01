import { SecureHttpError } from "./secure-http.error.ts";

export class UltraTonParseError extends SecureHttpError {
    constructor(message: string) {
        super(message);
        this.name = 'UltraTonParseError';
    }
}
