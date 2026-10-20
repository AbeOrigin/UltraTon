/**
 * The SSRF corpus as a gate: UltraTonClient and every library wired through createSecureAgents() must block every
 * case, for the reason the case is about (so a case blocked by an unrelated rule cannot hide a regression), and in a
 * redirect case only after the allowed first hop. The unprotected clients run too, for the comparison table
 * (npm run corpus), but are not asserted on.
 */
import { it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { CASES, runCorpus } from './ssrf-corpus/corpus.ts';

const ipv6 = await new Promise<boolean>(resolve => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, '::1', () => probe.close(() => resolve(true)));
});

const PROTECTED = new Set(['UltraTonClient', 'axios + createSecureAgents', 'got + createSecureAgents', 'node-fetch + createSecureAgents']);

it('UltraTon (client and secure agents) blocks every case of the SSRF corpus, for the right reason', { timeout: 120_000 }, async () => {
    const results = await runCorpus(ipv6);
    const byId = new Map(CASES.map(c => [c.id, c]));
    const problems = results.filter(r => PROTECTED.has(r.client)).flatMap(r => {
        const c = byId.get(r.caseId)!;
        const issues: string[] = [];
        if (r.outcome !== 'blocked') issues.push(`${r.outcome} (${r.detail})`);
        else if (!c.expect.includes(r.detail as any)) issues.push(`blocked as ${r.detail}, expected ${c.expect.join(' or ')}`);
        if (c.redirect && r.firstHop !== true) issues.push('the allowed first hop never reached the redirector');
        return issues.map(issue => `${r.client} / ${r.caseId}: ${issue}`);
    });
    assert.deepEqual(problems, []);
    const expected = CASES.filter(c => ipv6 || !c.ipv6).length * PROTECTED.size;
    assert.equal(results.filter(r => PROTECTED.has(r.client)).length, expected);
});
