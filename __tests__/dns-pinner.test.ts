import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';

import { assertAllowedIp, isReservedIp, policyKey, resolveAndPinHost } from '../src/security/dns-pinner.ts';
import { SecureHttpError } from '../src/errors.ts';

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

    it('isReservedIp classifies special-purpose and public addresses', () => {
        const reserved = [
            '::ffff:7f00:1', '::ffff:a9fe:a9fe', '::7f00:1', '0:0:0:0:0:0:0:1',
            '224.0.0.1', '239.255.255.250', '255.255.255.255', '198.18.0.1',
            '192.0.0.1', '192.0.2.1', 'fec0::1', 'ff02::1', '2001:db8::1',
            '100.64.0.1', '172.31.255.255',
            '64:ff9b::a00:5', '64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::10.0.0.5',
            '64:ff9b:0:0:0:0:a00:5', '64:ff9b::', '64:ff9b:1::1'
        ];
        const publicIps = [
            '8.8.8.8', '172.32.0.1', '100.128.0.1', '::ffff:8.8.8.8',
            '2001:4860:4860::8888', 'not-an-ip',
            '64:ff9b::808:808', '64:ff9b::8.8.8.8'
        ];

        for (const ip of reserved) {
            assert.equal(isReservedIp(ip), true, `${ip} must be classified as reserved`);
        }
        for (const ip of publicIps) {
            assert.equal(isReservedIp(ip), false, `${ip} must not be classified as reserved`);
        }
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
                // S5: the message must not become an oracle for the hostname that was looked up.
                assert.match((err as Error).message, /ENOTFOUND/);
                assert.doesNotMatch((err as Error).message, /ghost\.domain\.com/);
                return true;
            }
        );
    });

});

describe('Reserved-IP policy (allowlist form of permitReservedIps)', () => {

    it('a CIDR entry permits a reserved IP inside it and only inside it', () => {
        assert.doesNotThrow(() => assertAllowedIp('127.0.0.1', ['127.0.0.0/8']));
        assert.throws(() => assertAllowedIp('127.0.0.1', ['10.0.0.0/8']), SecureHttpError);
    });

    it('a single-IP entry permits exactly that address', () => {
        assert.doesNotThrow(() => assertAllowedIp('10.1.2.3', ['10.1.2.3']));
        assert.throws(() => assertAllowedIp('10.1.2.4', ['10.1.2.3']), SecureHttpError);
        assert.doesNotThrow(() => assertAllowedIp('::1', ['::1']));
    });

    it('a hostname entry permits a reserved IP only for that exact hostname', () => {
        assert.doesNotThrow(() => assertAllowedIp('10.1.2.3', ['api.internal'], 'api.internal'));
        assert.throws(() => assertAllowedIp('10.1.2.3', ['api.internal'], 'other.internal'), SecureHttpError);
        assert.throws(() => assertAllowedIp('10.1.2.3', ['api.internal']), SecureHttpError, 'no hostname given');
    });

    it('hostname matching is case-insensitive and exact (no wildcards, no suffixes)', () => {
        assert.doesNotThrow(() => assertAllowedIp('10.1.2.3', ['API.Internal'], 'api.INTERNAL'));
        assert.throws(() => assertAllowedIp('10.1.2.3', ['*.internal'], 'api.internal'), SecureHttpError);
        assert.throws(() => assertAllowedIp('10.1.2.3', ['internal'], 'api.internal'), SecureHttpError);
        // An IP literal is never matched through the hostname set.
        assert.throws(() => assertAllowedIp('127.0.0.1', ['localhost'], '127.0.0.1'), SecureHttpError);
    });

    it('public IPs always pass, whatever the policy', () => {
        assert.doesNotThrow(() => assertAllowedIp('8.8.8.8', []));
        assert.doesNotThrow(() => assertAllowedIp('8.8.8.8', false));
        assert.doesNotThrow(() => assertAllowedIp('8.8.8.8', ['10.0.0.0/8']));
    });

    it('an IPv6 CIDR entry permits a reserved IPv6 address', () => {
        assert.doesNotThrow(() => assertAllowedIp('::1', ['::1/128']));
        assert.throws(() => assertAllowedIp('::1', ['fe80::/10']), SecureHttpError);
    });

    it('an IPv4 entry also covers the IPv4-mapped form of an address inside it', () => {
        assert.doesNotThrow(() => assertAllowedIp('::ffff:127.0.0.1', ['127.0.0.0/8']));
    });

    it('an IPv6 entry never covers a native IPv4 address, whatever its prefix length', () => {
        // BlockList checks an IPv4 address against IPv6 rules as ::ffff:a.b.c.d, so ::/0 .. ::/80 and ::ffff:0:0/96 contain all of IPv4.
        for (const entry of ['::/0', '::/80', '::/96', '::ffff:0:0/96']) {
            for (const ip of ['169.254.169.254', '127.0.0.1', '10.1.2.3']) {
                assert.throws(() => assertAllowedIp(ip, [entry]), SecureHttpError, `${entry} must not cover ${ip}`);
                assert.throws(() => assertAllowedIp(ip, [entry], 'api.internal'), SecureHttpError, `${entry} must not cover ${ip}`);
            }
        }
    });

    it('an IPv4 entry never covers a native IPv6 address', () => {
        for (const ip of ['fe80::1', '::1', 'fd00:ec2::254']) {
            assert.throws(() => assertAllowedIp(ip, ['0.0.0.0/0']), SecureHttpError, `0.0.0.0/0 must not cover ${ip}`);
        }
        assert.doesNotThrow(() => assertAllowedIp('127.0.0.1', ['0.0.0.0/0']));
    });

    it('an IPv6 entry still covers the IPv6 addresses inside it, including mapped ones it contains', () => {
        assert.doesNotThrow(() => assertAllowedIp('fd00::1', ['::/0']));
        assert.doesNotThrow(() => assertAllowedIp('::1', ['::/0']));
        assert.throws(() => assertAllowedIp('fd00::1', ['fe80::/10']), SecureHttpError);
        // A mapped address is an IPv6 address: an IPv6 rule that contains it covers it, as BlockList does.
        assert.doesNotThrow(() => assertAllowedIp('::ffff:127.0.0.1', ['::ffff:0:0/96']));
        // ...and an IPv4 rule covers its mapped form, an IPv6 rule that does not contain it does not.
        assert.doesNotThrow(() => assertAllowedIp('::ffff:10.0.0.1', ['10.0.0.0/8']));
        assert.throws(() => assertAllowedIp('::ffff:10.0.0.1', ['fe80::/10']), SecureHttpError);
    });

    it('true permits everything; false and an empty list block every reserved IP', () => {
        assert.doesNotThrow(() => assertAllowedIp('169.254.169.254', true));
        assert.throws(() => assertAllowedIp('169.254.169.254', false), SecureHttpError);
        assert.throws(() => assertAllowedIp('169.254.169.254', []), SecureHttpError);
    });

    it('the reserved-IP message names the option and leaks neither the IP nor the hostname', () => {
        for (const policy of [false, [], ['10.0.0.0/8']] as const) {
            assert.throws(
                () => assertAllowedIp('127.0.0.1', policy, 'secret-host.internal'),
                (err: unknown) => {
                    assert.ok(err instanceof SecureHttpError);
                    assert.match(err.message, /prohibited internal\/reserved network IP/);
                    assert.match(err.message, /permitReservedIps/);
                    assert.doesNotMatch(err.message, /127\.0\.0\.1/);
                    assert.doesNotMatch(err.message, /secret-host/);
                    return true;
                }
            );
        }
    });

    it('policyKey: false and [] are deny, true is all, lists are normalized and order-independent', () => {
        assert.equal(policyKey(false), 'deny');
        assert.equal(policyKey([]), 'deny');
        assert.equal(policyKey(true), 'all');
        assert.equal(policyKey(['B.example', '10.0.0.0/8']), 'list:10.0.0.0/8,b.example');
        assert.equal(policyKey(['B.example', '10.0.0.0/8']), policyKey(['10.0.0.0/8', 'b.example']));
        assert.notEqual(policyKey(['10.0.0.0/8']), policyKey(['10.0.0.0/9']));
    });

    it('resolveAndPinHost hands the looked-up hostname to the policy', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => ({ address: '10.1.2.3', family: 4 }));

        assert.equal(await resolveAndPinHost('api.internal', ['api.internal']), '10.1.2.3');
        await assert.rejects(() => resolveAndPinHost('other.internal', ['api.internal']), SecureHttpError);
        await assert.rejects(() => resolveAndPinHost('api.internal', []), SecureHttpError);
        assert.equal(await resolveAndPinHost('anything.example', ['10.0.0.0/8']), '10.1.2.3');
    });

    it('a DNS failure message carries the error code but not the hostname', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            throw Object.assign(new Error('getaddrinfo EAI_AGAIN ghost.domain.com'), { code: 'EAI_AGAIN' });
        });

        await assert.rejects(
            () => resolveAndPinHost('ghost.domain.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.equal(err.message, 'UltraTon: Hostname resolution failed (EAI_AGAIN).');
                return true;
            }
        );
    });

});
