export class SecureHttpError extends Error {
    constructor(message: string) {
        super(message);
        this.name = new.target.name;
    }
}

export class UltraTonNetworkTimeoutError extends SecureHttpError {}
export class UltraTonMemoryError extends SecureHttpError {}
export class UltraTonParseError extends SecureHttpError {}
export class UltraTonRedirectError extends SecureHttpError {}
