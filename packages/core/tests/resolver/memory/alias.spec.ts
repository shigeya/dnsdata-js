// Ports dnsdata-go `resolver/memory/alias_test.go`: alias answers as real
// authoritative servers send them — a wildcard CNAME synthesised for a
// query of any type (RFC 4592 §3.3.3), and a DNAME answer carrying the
// unsigned CNAME synthesised from it (RFC 6672 §5.3.1).

import { StringToRRType } from '../../../src/types/dns_type_table';
import { Verdict } from '../../../src/verifier/verdict';
import { ResourceRecord, Zone } from '../../../src/zone/dns_zone';
import { Hierarchy, buildHierarchy, expiration, inception, newAuthority, newVerifier, now, readZone, sign } from './helpers';

const T = (name: string): number => StringToRRType(name);

// aliasLeafText is example.test. with a wildcard CNAME and a DNAME. It is
// kept apart from leafText so the shared vectors in testdata/signed stay
// unchanged.
const aliasLeafText = `$ORIGIN example.test.
$TTL 3600
@        SOA   ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@        NS    ns1.example.test.
ns1      A     192.0.2.1
www      A     192.0.2.10
www      TXT   "hello"
*.wc     CNAME www.example.test.
old      DNAME new.example.test.
www.new  TXT   "moved"
`;

function aliasLeaf(h: Hierarchy): Zone {
    return sign(readZone(aliasLeafText), 'example.test.', h.leafKeys, inception, expiration);
}

function find(records: readonly ResourceRecord[], owner: string, type: number): ResourceRecord | undefined {
    return records.find((rr) => rr.label === owner && rr.type === type);
}

describe('memory authority: alias answers', () => {
    const h = buildHierarchy();
    const a = newAuthority(h, aliasLeaf(h));

    it('synthesises a wildcard CNAME for a query of another type', async () => {
        const resp = await a.query('x.sub.wc.example.test.', T('TXT'));
        expect(resp.rcode).toBe(0);
        expect(find(resp.records, 'x.sub.wc.example.test.', T('CNAME'))?.value).toBe('www.example.test.');
        expect(find(resp.records, '*.wc.example.test.', T('NSEC'))).toBeDefined();
    });

    it('adds the unsigned CNAME synthesised from a DNAME', async () => {
        const resp = await a.query('www.old.example.test.', T('TXT'));
        expect(resp.rcode).toBe(0);
        expect(find(resp.records, 'old.example.test.', T('DNAME'))).toBeDefined();
        const cname = find(resp.records, 'www.old.example.test.', T('CNAME'));
        expect(cname && `${cname.value} ${cname.ttl}`).toBe('www.new.example.test. 3600');
        expect(find(resp.records, 'www.old.example.test.', T('RRSIG'))).toBeUndefined();
    });

    it.each([
        ['wildcard CNAME for another type', 'x.sub.wc.example.test.', 'cname x.sub.wc.example.test. www.example.test.'],
        ['DNAME with the synthesised CNAME', 'www.old.example.test.', 'dname old.example.test. www.new.example.test.'],
    ])('validates %s', async (_name, qname, hop) => {
        const res = await newVerifier(h, a, now).validate(qname, T('TXT'));
        expect(`${res.verdict} ${res.bogusReason ?? ''}`.trim()).toBe(Verdict.Secure);
        expect(res.aliases?.map((s) => `${s.type} ${s.from} ${s.target}`)).toEqual([hop]);
    });
});
