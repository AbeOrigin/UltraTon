import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import dnsPromises from 'node:dns/promises';

import { assertAllowedIp, isReservedIp, policyKey, resolveAndPinAll } from '../src/security/dns-pinner.ts';
import { SecureHttpError } from '../src/errors.ts';

describe('DNS Pinner Security Validation (Dual-Stack SSRF Mitigation)', () => {
    
    it('Allowed: Public IPv4 (8.8.8.8) resolves successfully', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '8.8.8.8', family: 4 }];
        });

        const addresses = await resolveAndPinAll('public.api.com');
        assert.deepEqual(addresses, [{ address: '8.8.8.8', family: 4 }], 'Resolver must allow externally routable IPv4 addresses');
    });

    it('Allowed: Public IPv6 (2001:4860:4860::8888) resolves successfully', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '2001:4860:4860::8888', family: 6 }];
        });

        const addresses = await resolveAndPinAll('ipv6.api.com');
        assert.deepEqual(addresses, [{ address: '2001:4860:4860::8888', family: 6 }], 'Resolver must allow externally routable IPv6 addresses');
    });

    it('Blocked (IPv4): AWS Metadata (169.254.169.254) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '169.254.169.254', family: 4 }];
        });

        await assert.rejects(
            () => resolveAndPinAll('metadata.aws.internal'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (IPv4): Localhost (127.0.0.1) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '127.0.0.1', family: 4 }];
        });

        await assert.rejects(
            () => resolveAndPinAll('localhost.rebound.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (IPv6): Localhost (::1) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '::1', family: 6 }];
        });

        await assert.rejects(
            () => resolveAndPinAll('localhost6.rebound.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match((err as SecureHttpError).message, /prohibited internal\/reserved network IP/);
                return true;
            }
        );
    });

    it('Blocked (Mapped): IPv4-mapped AWS Metadata (::ffff:169.254.169.254) throws SecureHttpError', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            return [{ address: '::ffff:169.254.169.254', family: 6 }];
        });

        await assert.rejects(
            () => resolveAndPinAll('mapped.aws.internal'),
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
            () => resolveAndPinAll('ghost.domain.com'),
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

    it('an IPv6 entry still covers the native IPv6 addresses inside it', () => {
        assert.doesNotThrow(() => assertAllowedIp('fd00::1', ['::/0']));
        assert.doesNotThrow(() => assertAllowedIp('fe80::1', ['::/0']));
        // :: and ::1 are the unspecified and loopback addresses, not IPv4-compatible ones: they stay native IPv6.
        assert.doesNotThrow(() => assertAllowedIp('::1', ['::/0']));
        assert.doesNotThrow(() => assertAllowedIp('::1', ['::1/128']));
        assert.throws(() => assertAllowedIp('fd00::1', ['fe80::/10']), SecureHttpError);
    });

    // An IPv6 address that embeds an IPv4 in its low 32 bits (mapped ::ffff:0:0/96, compatible ::/96, NAT64 64:ff9b::/96
    // and 64:ff9b:1::/48) is judged only by that IPv4 against the IPv4 entries; IPv6 entries never cover it.
    const embeddingForms = [
        // [address, the IPv4 it embeds]
        ['::ffff:169.254.169.254', '169.254.169.254'],
        ['::ffff:a9fe:a9fe', '169.254.169.254'],
        ['0:0:0:0:0:ffff:a9fe:a9fe', '169.254.169.254'],
        ['0000:0000:0000:0000:0000:FFFF:A9FE:A9FE', '169.254.169.254'],
        ['::7f00:1', '127.0.0.1'],
        ['::127.0.0.1', '127.0.0.1'],
        ['0:0:0:0:0:0:7f00:1', '127.0.0.1'],
        ['64:ff9b::a9fe:a9fe', '169.254.169.254'],
        ['64:ff9b::169.254.169.254', '169.254.169.254'],
        ['64:ff9b:0:0:0:0:a9fe:a9fe', '169.254.169.254'],
        ['64:ff9b:1::a9fe:a9fe', '169.254.169.254'],
        ['::ffff:10.0.0.1', '10.0.0.1'],
        ['::ffff:a00:1', '10.0.0.1'],
        ['64:ff9b::a00:1', '10.0.0.1'],
        ['64:ff9b:1::a00:1', '10.0.0.1'],
        ['::a00:1', '10.0.0.1'],
    ] as const;

    it('an IPv6 address embedding an IPv4 is not covered by IPv6 entries, not even ::/0', () => {
        for (const [ip] of embeddingForms) {
            for (const entry of ['::/0', '::/80', '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', ip]) {
                assert.throws(() => assertAllowedIp(ip, [entry]), SecureHttpError, `${entry} must not cover ${ip}`);
            }
        }
    });

    it('an IPv6 address embedding an IPv4 is covered exactly when its embedded IPv4 is', () => {
        for (const [ip, embedded] of embeddingForms) {
            assert.doesNotThrow(() => assertAllowedIp(ip, [`${embedded}/32`]), `${embedded}/32 must cover ${ip}`);
            assert.doesNotThrow(() => assertAllowedIp(ip, [embedded]), `${embedded} must cover ${ip}`);
            assert.doesNotThrow(() => assertAllowedIp(ip, ['0.0.0.0/0']), `0.0.0.0/0 must cover ${ip}`);
            assert.throws(() => assertAllowedIp(ip, ['203.0.113.0/24']), SecureHttpError, `an unrelated IPv4 entry must not cover ${ip}`);
        }
        assert.doesNotThrow(() => assertAllowedIp('::ffff:10.0.0.1', ['10.0.0.0/8']));
        assert.doesNotThrow(() => assertAllowedIp('64:ff9b::a00:1', ['10.0.0.0/8']));
        assert.throws(() => assertAllowedIp('::ffff:127.0.0.1', ['10.0.0.0/8']), SecureHttpError);
        assert.throws(() => assertAllowedIp('64:ff9b::7f00:1', ['10.0.0.0/8']), SecureHttpError);
    });

    it('an IPv6 entry written in mapped form is inert: it covers neither the mapped nor the native IPv4 address', () => {
        assert.throws(() => assertAllowedIp('::ffff:10.0.0.1', ['::ffff:0:0/96']), SecureHttpError);
        assert.throws(() => assertAllowedIp('10.0.0.1', ['::ffff:0:0/96']), SecureHttpError);
    });

    it('a hostname entry still allows an embedding address reached through that hostname', () => {
        assert.doesNotThrow(() => assertAllowedIp('::ffff:a9fe:a9fe', ['api.internal'], 'api.internal'));
        assert.throws(() => assertAllowedIp('::ffff:a9fe:a9fe', ['api.internal'], 'other.internal'), SecureHttpError);
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

    it('resolveAndPinAll hands the looked-up hostname to the policy', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => [{ address: '10.1.2.3', family: 4 }]);
        const pinned = [{ address: '10.1.2.3', family: 4 }];

        assert.deepEqual(await resolveAndPinAll('api.internal', ['api.internal']), pinned);
        await assert.rejects(() => resolveAndPinAll('other.internal', ['api.internal']), SecureHttpError);
        await assert.rejects(() => resolveAndPinAll('api.internal', []), SecureHttpError);
        assert.deepEqual(await resolveAndPinAll('anything.example', ['10.0.0.0/8']), pinned);
    });

    it('resolveAndPinAll asks for every address and returns them all when each one is allowed', async (t) => {
        const lookup = t.mock.method(dnsPromises, 'lookup', async () => [
            { address: '2606:4700::1111', family: 6 },
            { address: '93.184.216.34', family: 4 },
        ]);

        assert.deepEqual(await resolveAndPinAll('dual.example'), [
            { address: '2606:4700::1111', family: 6 },
            { address: '93.184.216.34', family: 4 },
        ]);
        assert.deepEqual(lookup.mock.calls[0].arguments, ['dual.example', { all: true }]);
    });

    it('resolveAndPinAll fails closed when any one address is reserved, wherever it sits in the answer', async (t) => {
        for (const answer of [
            ['93.184.216.34', '10.0.0.1'],
            ['10.0.0.1', '93.184.216.34'],
            ['8.8.8.8', '1.1.1.1', '::ffff:169.254.169.254'],
            ['2001:4860:4860::8888', 'fd00:ec2::254'],
        ]) {
            t.mock.method(dnsPromises, 'lookup', async () => answer.map(address => ({ address, family: address.includes(':') ? 6 : 4 })));
            await assert.rejects(() => resolveAndPinAll('mixed.example'), (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match(err.message, /prohibited internal\/reserved network IP/);
                assert.doesNotMatch(err.message, /mixed\.example|10\.0\.0\.1|169\.254|fd00/);
                return true;
            }, answer.join(','));
        }
        // An allowlist must cover every reserved address of the answer, not just one of them.
        t.mock.method(dnsPromises, 'lookup', async () => [{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }]);
        await assert.rejects(() => resolveAndPinAll('localhost', ['127.0.0.0/8']), SecureHttpError);
        assert.equal((await resolveAndPinAll('localhost', ['127.0.0.0/8', '::1'])).length, 2);
        assert.equal((await resolveAndPinAll('localhost', ['localhost'])).length, 2);
    });

    it('resolveAndPinAll rejects an empty answer and anything that is not an IP address', async (t) => {
        for (const answer of [[], undefined, { address: '8.8.8.8', family: 4 }, [{ address: 'evil.example', family: 4 }]]) {
            t.mock.method(dnsPromises, 'lookup', async () => answer);
            await assert.rejects(() => resolveAndPinAll('odd.example'), (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.match(err.message, /^UltraTon: Hostname resolution failed \(.+\)\.$/);
                assert.doesNotMatch(err.message, /odd\.example/);
                return true;
            }, JSON.stringify(answer));
        }
    });

    it('resolveAndPinAll judges an IP literal as itself, without DNS', async (t) => {
        const lookup = t.mock.method(dnsPromises, 'lookup', async () => [{ address: '93.184.216.34', family: 4 }]);

        assert.deepEqual(await resolveAndPinAll('8.8.8.8'), [{ address: '8.8.8.8', family: 4 }]);
        assert.deepEqual(await resolveAndPinAll('::1', true), [{ address: '::1', family: 6 }]);
        await assert.rejects(() => resolveAndPinAll('127.0.0.1'), SecureHttpError);
        await assert.rejects(() => resolveAndPinAll('::1', ['localhost']), SecureHttpError);
        assert.equal(lookup.mock.callCount(), 0);
    });

    it('a DNS failure message carries the error code but not the hostname', async (t) => {
        t.mock.method(dnsPromises, 'lookup', async () => {
            throw Object.assign(new Error('getaddrinfo EAI_AGAIN ghost.domain.com'), { code: 'EAI_AGAIN' });
        });

        await assert.rejects(
            () => resolveAndPinAll('ghost.domain.com'),
            (err: unknown) => {
                assert.ok(err instanceof SecureHttpError);
                assert.equal(err.message, 'UltraTon: Hostname resolution failed (EAI_AGAIN).');
                return true;
            }
        );
    });

});
