// Ports dnsdata-go `verifier/answer_test.go`: Result.answer carries the
// validated RRset and the RRSIGs that verified it, only when Secure,
// and survives a JSON round trip (DESIGN.md §4 MUST 10). The chain is
// the in-memory signed hierarchy of the resolver/memory specs.

import { StringToRRType } from '../../src/types/dns_type_table';
import { Result, Verdict } from '../../src/verifier';
import { buildHierarchy, expiration, newAuthority, newVerifier, now } from '../resolver/memory/helpers';

const TYPE_A = StringToRRType('A');
const ALGORITHM_ECDSAP256SHA256 = 13;
const MS_PER_DAY = 24 * 3600 * 1000;
// RFC 3339 UTC with whole seconds, as Go's encoding/json writes time.Time.
const RFC3339_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;

describe('Result.answer', () => {
    const h = buildHierarchy();
    const auth = newAuthority(h, h.leaf);

    it('carries the validated RRset', async () => {
        const res = await newVerifier(h, auth, now).validate('www.example.test.', TYPE_A);
        expect(res.verdict).toBe(Verdict.Secure);
        const a = res.answer;
        expect(a).toBeDefined();
        expect([a?.name, a?.type, a?.records.length]).toEqual(['www.example.test.', TYPE_A, 1]);
        expect(a?.records[0]).toEqual({
            name: 'www.example.test.', ttl: 3600, class: 1, type: TYPE_A,
            value: '192.0.2.10', rdata: Buffer.from([192, 0, 2, 10]).toString('base64'),
        });

        expect(a?.signatures).toHaveLength(1);
        const sig = a?.signatures[0];
        expect([sig?.signer, sig?.algorithm]).toEqual(['example.test.', ALGORITHM_ECDSAP256SHA256]);
        expect(sig?.keyTag).not.toBe(0);
        expect(sig?.inception).toMatch(RFC3339_UTC);
        expect(sig?.expiration).toMatch(RFC3339_UTC);
        expect(Date.parse(sig?.inception ?? '')).toBeLessThan(now.getTime());
        expect(Date.parse(sig?.expiration ?? '')).toBe(expiration.getTime());

        const back = JSON.parse(JSON.stringify(res)) as Result;
        expect(back).toEqual(res);
    });

    it.each([
        ['bogus (expired)', new Date(expiration.getTime() + 2 * MS_PER_DAY), 'www.example.test.'],
        ['no records', now, 'missing.example.test.'],
    ] as const)('is absent when %s', async (_name, clock, qname) => {
        const res = await newVerifier(h, auth, clock).validate(qname, TYPE_A);
        expect(res.verdict).not.toBe(Verdict.Secure);
        expect(res.answer).toBeUndefined();
        expect(JSON.stringify(res)).not.toContain('"answer"');
    });
});
