import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';

import { resolveAndPinHost } from '../src/security/dns-pinner.ts';
import { SecureHttpError } from '../src/exceptions/secure-http.error.ts';

describe('DNS Pinner Security Validation (Dual-Stack SSRF Mitigation)', () => {
    it('Allowed: Public IPv4 (8.8.8.8) resolves successfully', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '8.8.8.8', family: 4 };
        });

        const ip = await resolveAndPinHost('public.api.com');
        assert.equal(ip, '8.8.8.8', 'Resolver must allow externally routable IPv4 addresses');
    });

    it('Allowed: Public IPv6 (2001:4860:4860::8888) resolves successfully', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '2001:4860:4860::8888', family: 6 };
        });

        const ip = await resolveAndPinHost('ipv6.api.com');
        assert.equal(ip, '2001:4860:4860::8888', 'Resolver must allow externally routable IPv6 addresses');
    });

    it('Blocked (IPv4): AWS Metadata (169.254.169.254) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '169.254.169.254', family: 4 };
        });

        await assert.rejects(
            () => resolveAndPinHost('metadata.aws.internal'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (IPv4): Localhost (127.0.0.1) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '127.0.0.1', family: 4 };
        });

        await assert.rejects(
            () => resolveAndPinHost('localhost.rebound.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (IPv6): Localhost (::1) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '::1', family: 6 };
        });

        await assert.rejects(
            () => resolveAndPinHost('localhost6.rebound.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (Mapped): IPv4-mapped AWS Metadata (::ffff:169.254.169.254) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return { address: '::ffff:169.254.169.254', family: 6 };
        });

        await assert.rejects(
            () => resolveAndPinHost('mapped.aws.internal'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Network Failure: Mock an ENOTFOUND error and assert the error message formatting', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            const error = new Error('getaddrinfo ENOTFOUND ghost.domain.com') as NodeJS.ErrnoException;
            error.code = 'ENOTFOUND';
            throw error;
        });

        await assert.rejects(
            () => resolveAndPinHost('ghost.domain.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as Error).message, /ghost\.domain\.com/);
                assert.match((err as Error).message, /ENOTFOUND/);
                return true;
            }
        );
    });

});
