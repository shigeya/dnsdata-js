// Ports dnsdata-go `resolver/memory/memory_test.go` TestHierarchy_*:
// a fake root is the trust anchor (signer.root_anchors → the verifier's
// trustAnchors, the clock via its `now` option), and the in-memory
// authority answers every query the verifier makes.

import { StringToRRType } from '../../../src/types/dns_type_table';
import { with_fault } from '../../../src/resolver/memory';
import { Verdict } from '../../../src/verifier/verdict';
import { VerifierResolverError } from '../../../src/verifier/errors';
import { ResourceRecord, Zone } from '../../../src/zone/dns_zone';
import { buildHierarchy, expiration, inception, newAuthority, newVerifier, now, readZone, sign } from './helpers';

const T = (name: string): number => StringToRRType(name);
const RCODE_SERVFAIL = 2;
const MS_PER_DAY = 24 * 3600 * 1000;

describe('memory authority: private-root hierarchy verdicts', () => {
    const h = buildHierarchy();
    const v = newVerifier(h, newAuthority(h, h.leaf), now);

    it.each([
        ['positive answer', 'www.example.test.', T('A'), Verdict.Secure],
        ['apex answer', 'example.test.', T('SOA'), Verdict.Secure],
        ['type without a mnemonic', 'key.example.test.', 65400, Verdict.Secure],
        ['name does not exist', 'nope.example.test.', T('A'), Verdict.SecureNXDomain],
        ['type does not exist', 'www.example.test.', T('MX'), Verdict.SecureNoData],
        ['wildcard expansion', 'x.wild.example.test.', T('A'), Verdict.Secure],
        ['CNAME followed', 'alias.example.test.', T('A'), Verdict.Secure],
        ['unsigned delegation', 'www.insecure.test.', T('A'), Verdict.Insecure],
    ] as const)('%s', async (_name, qname, qtype, want) => {
        const res = await v.validate(qname, qtype);
        expect(`${res.verdict} ${res.bogusAt ?? ''} ${res.bogusReason ?? ''}`.trim()).toBe(want);
    });

    it('records the wildcard expansion and the CNAME hop', async () => {
        const wild = await v.validate('x.wild.example.test.', T('A'));
        expect(wild.wildcard?.source).toBe('*.wild.example.test.');
        const alias = await v.validate('alias.example.test.', T('A'));
        expect(alias.aliases?.map((a) => [a.type, a.from, a.target, a.verdict])).toEqual([
            ['cname', 'alias.example.test.', 'www.example.test.', Verdict.Secure],
        ]);
    });
});

// C-7: Result.answer is the RRset that was validated — after a CNAME
// the target's RRset, for a wildcard the synthesised RRset at the query
// name, and for a type without a mnemonic its exact octets.
describe('memory authority: the validated answer', () => {
    const h = buildHierarchy();
    const v = newVerifier(h, newAuthority(h, h.leaf), now);
    const rfc3339 = (d: Date): string => d.toISOString().replace('.000Z', 'Z');

    it.each([
        ['alias.example.test.', 'www.example.test.', T('A'), '192.0.2.10', 3],
        ['x.wild.example.test.', 'x.wild.example.test.', T('A'), '192.0.2.20', 3],
        ['key.example.test.', 'key.example.test.', 65400,
            '\\# 35 030101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 3],
    ] as const)('%s', async (qname, wantName, qtype, wantValue, wantLabels) => {
        const res = await v.validate(qname, qtype);
        const a = res.answer;
        expect(res.verdict).toBe(Verdict.Secure);
        expect(a?.records).toHaveLength(1);
        expect(a?.signatures.length).toBeGreaterThan(0);
        expect([a?.name, a?.records[0].value]).toEqual([wantName, wantValue]);
        expect(a?.signatures[0]).toMatchObject({
            labels: wantLabels,
            inception: rfc3339(inception),
            expiration: rfc3339(expiration),
        });
    });

    it('carries the exact TYPE65400 RDATA', async () => {
        const res = await v.validate('key.example.test.', 65400);
        const rdata = Buffer.from(res.answer?.records[0].rdata ?? '', 'base64');
        expect(rdata).toHaveLength(35);
        expect(rdata[0]).toBe(3);
    });
});

describe('memory authority: bogus hierarchies', () => {
    const h = buildHierarchy();

    it('a tampered RRset is Bogus', async () => {
        const tampered = new Zone();
        for (const rr of h.leaf.all_records()) {
            const value = rr.label === 'www.example.test.' && rr.type === T('A') ? '192.0.2.99' : rr.value;
            tampered.add_rr(new ResourceRecord(rr.label, rr.ttl, rr.rrclass, rr.type, value));
        }
        const v = newVerifier(h, newAuthority(h, tampered), now);
        expect((await v.validate('www.example.test.', T('A'))).verdict).toBe(Verdict.Bogus);
    });

    it('an expired signature is Bogus', async () => {
        const expired = sign(h.leafUnsigned, 'example.test.', h.leafKeys, inception,
            new Date(inception.getTime() + MS_PER_DAY));
        const v = newVerifier(h, newAuthority(h, expired), now);
        expect((await v.validate('www.example.test.', T('A'))).verdict).toBe(Verdict.Bogus);
    });
});

// C-1 acceptance: a zone with a TYPE65400 RRset is read, signed, printed,
// read back, and still validates.
describe('memory authority: print and read back', () => {
    it('TYPE65400 still validates after a canonical round trip', async () => {
        const h = buildHierarchy();
        const reread = readZone(h.leaf.print_canonical());
        const v = newVerifier(h, newAuthority(h, reread), now);
        const res = await v.validate('key.example.test.', 65400);
        expect(`${res.verdict} ${res.bogusReason ?? ''}`.trim()).toBe(Verdict.Secure);
    });
});

describe('memory authority: fault injection', () => {
    it('answers the faulted query with the RCODE and the verifier fails with a resolver error', async () => {
        const h = buildHierarchy();
        const a = newAuthority(h, h.leaf, with_fault('www.example.test.', T('A'), RCODE_SERVFAIL));
        const resp = await a.query('www.example.test.', T('A'));
        expect(resp).toEqual({ records: [], ad: false, rcode: RCODE_SERVFAIL });
        const v = newVerifier(h, a, now);
        await expect(v.validate('www.example.test.', T('A'))).rejects.toBeInstanceOf(VerifierResolverError);
    });
});
