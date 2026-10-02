// Ports dnsdata-go `resolver/memory/memory_test.go` TestAuthority_* and
// TestNew_Errors: the responses of the authority itself.

import { RRSig } from '../../../src/dnssec/rrsig';
import { StringToRRType } from '../../../src/types/dns_type_table';
import {
    MemoryConfigError,
    Option,
    new_authority,
    with_fault,
    with_zone,
} from '../../../src/resolver/memory';
import { Zone } from '../../../src/zone/dns_zone';
import { buildHierarchy, newAuthority, readZone } from './helpers';

const T = (name: string): number => StringToRRType(name);
const RCODE_NXDOMAIN = 3;
const RCODE_SERVFAIL = 2;
const RCODE_REFUSED = 5;

function countTypes(records: ReadonlyArray<{ type: number }>): Record<number, number> {
    const got: Record<number, number> = {};
    for (const rr of records) got[rr.type] = (got[rr.type] ?? 0) + 1;
    return got;
}

describe('memory authority: answers', () => {
    const h = buildHierarchy();
    const a = newAuthority(h, h.leaf);

    it.each([
        ['answer with signature', 'www.example.test.', T('A'), 0, { [T('A')]: 1, [T('RRSIG')]: 1 }],
        ['case and missing dot', 'WWW.Example.Test', T('A'), 0, { [T('A')]: 1, [T('RRSIG')]: 1 }],
        ['DS answered by the parent', 'example.test.', T('DS'), 0, { [T('DS')]: 1, [T('RRSIG')]: 1 }],
        ['DNSKEY answered by the child', 'example.test.', T('DNSKEY'), 0, { [T('DNSKEY')]: 2, [T('RRSIG')]: 1 }],
        ['no DS at an unsigned delegation', 'insecure.test.', T('DS'), 0, { [T('NSEC')]: 1, [T('RRSIG')]: 1 }],
        ['referral below an unsigned delegation', 'www.insecure.test.', T('A'), 0,
            { [T('NS')]: 1, [T('NSEC')]: 1, [T('RRSIG')]: 1 }],
        ['NODATA', 'www.example.test.', T('MX'), 0, { [T('NSEC')]: 1, [T('RRSIG')]: 1 }],
        ['NXDOMAIN', 'nope.example.test.', T('A'), RCODE_NXDOMAIN, { [T('NSEC')]: 2, [T('RRSIG')]: 2 }],
        ['wildcard', 'x.wild.example.test.', T('A'), 0, { [T('A')]: 1, [T('NSEC')]: 1, [T('RRSIG')]: 2 }],
        // The NSEC at *.wild both covers the next closer name and proves
        // the wildcard has no MX; it is sent once.
        ['wildcard NODATA', 'x.wild.example.test.', T('MX'), 0, { [T('NSEC')]: 1, [T('RRSIG')]: 1 }],
        ['empty non-terminal', 'wild.example.test.', T('A'), 0, { [T('NSEC')]: 1, [T('RRSIG')]: 1 }],
        ['CNAME itself', 'alias.example.test.', T('CNAME'), 0, { [T('CNAME')]: 1, [T('RRSIG')]: 1 }],
        ['CNAME for another type', 'alias.example.test.', T('A'), 0, { [T('CNAME')]: 1, [T('RRSIG')]: 1 }],
        // One NSEC covers both example. and *.
        ['name in no delegated zone answered by the root', 'example.', T('A'), RCODE_NXDOMAIN, { [T('NSEC')]: 1 }],
    ] as const)('%s', async (_name, qname, qtype, rcode, want) => {
        const resp = await a.query(qname, qtype);
        expect(resp.rcode).toBe(rcode);
        expect(resp.ad).toBe(false);
        const got = countTypes(resp.records);
        for (const [typ, n] of Object.entries(want)) expect([typ, got[Number(typ)] ?? 0]).toEqual([typ, n]);
    });

    it('refuses names outside every zone', async () => {
        const only = new_authority(with_zone('example.test.', h.leaf));
        expect(await only.query('other.test.', T('A'))).toEqual({ records: [], ad: false, rcode: RCODE_REFUSED });
    });

    it('rewrites the synthesised wildcard owner but not the proof', async () => {
        const resp = await a.query('x.wild.example.test.', T('A'));
        for (const rr of resp.records) {
            const covered = rr.type === T('RRSIG') ? new RRSig(null, rr.value).type_covered : rr.type;
            if (covered === T('A')) expect(rr.label).toBe('x.wild.example.test.');
            if (covered === T('NSEC')) expect(rr.label).toBe('*.wild.example.test.');
        }
    });

    it('returns fresh copies', async () => {
        const first = await a.query('www.example.test.', T('A'));
        first.records.splice(0, first.records.length);
        const second = await a.query('www.example.test.', T('A'));
        expect(second.records.find((rr) => rr.type === T('A'))?.value).toBe('192.0.2.10');
        const again = await a.query('www.example.test.', T('A'));
        expect(again.records[0]).not.toBe(second.records[0]);
        expect(h.leaf.find_rr('www.example.test.', T('A'))).not.toBe(second.records[0]);
    });

    it('rejects when the signal is already aborted', async () => {
        const ctrl = new AbortController();
        ctrl.abort();
        await expect(a.query('www.example.test.', T('A'), ctrl.signal)).rejects.toMatchObject({ name: 'AbortError' });
    });
});

describe('memory authority: DNAME', () => {
    it('answers a name below a DNAME with the DNAME and the CNAME synthesised from it', async () => {
        const z = readZone('example.test. 3600 SOA ns1.example.test. h.example.test. 1 2 3 4 5\n' +
            'old.example.test. 3600 DNAME new.example.test.\n');
        const a = new_authority(with_zone('example.test.', z));
        const resp = await a.query('www.old.example.test.', T('A'));
        expect(resp.rcode).toBe(0);
        expect(resp.records.map((rr) => [rr.label, rr.type, rr.value])).toEqual([
            ['old.example.test.', T('DNAME'), 'new.example.test.'],
            ['www.old.example.test.', T('CNAME'), 'www.new.example.test.'],
        ]);
    });
});

describe('memory authority: new_authority errors', () => {
    const h = buildHierarchy();
    const badRRSIG = new Zone();
    badRRSIG.add_rr_from_parts('example.test.', 60, 'IN', 'RRSIG', 'not an rrsig');
    const badNSEC = new Zone();
    badNSEC.add_rr_from_parts('example.test.', 60, 'IN', 'NSEC', 'lonely');

    it.each([
        ['no zones', []],
        ['relative apex', [with_zone('test', h.tld)]],
        ['duplicate apex', [with_zone('test.', h.tld), with_zone('TEST.', h.tld)]],
        ['missing zone', [with_zone('test.', null as unknown as Zone)]],
        ['record outside', [with_zone('example.test.', h.tld)]],
        ['fault without zone', [with_fault('x.', T('A'), RCODE_SERVFAIL)]],
        ['fault qtype out of range', [with_zone('test.', h.tld), with_fault('x.', 0x10000, RCODE_SERVFAIL)]],
        ['fault rcode out of range', [with_zone('test.', h.tld), with_fault('x.', T('A'), -1)]],
        ['RRSIG that does not parse', [with_zone('example.test.', badRRSIG)]],
        ['NSEC that does not parse', [with_zone('example.test.', badNSEC)]],
    ] as ReadonlyArray<readonly [string, Option[]]>)('%s', (_name, opts) => {
        expect(() => new_authority(...opts)).toThrow(MemoryConfigError);
    });
});
