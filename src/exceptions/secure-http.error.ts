export class SecureHttpError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SecureHttpError';
    }
}
