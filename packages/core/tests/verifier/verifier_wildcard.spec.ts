// Wildcard-synthesised positive answer tests (UP-006 / #10).
//
// Three scenarios mirroring the Go side's TestValidate_Wildcard_*:
//
//   1. Wildcard synthesis + covering NSEC for next-closer → Secure
//      with result.wildcard populated.
//   2. Wildcard synthesis without a next-closer proof → Bogus per
//      RFC 4035 §5.3.4 (the wildcard rrset could be replayed at
//      any non-existent name without the proof).
//   3. A regular (non-wildcard) signed answer leaves result.wildcard
//      undefined — guards against false positives in the detector.

import * as crypto from 'crypto';

import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../src/zone/dns_zone';
import { StringToRRType, RRTypeToString } from '../../src/types/dns_type_table';
import { RootAnchors } from '../../src/dnssec/root_anchors';
import {
    Verifier,
    Verdict,
    Resolver,
} from '../../src/verifier';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS     = StringToRRType('DS');
const TYPE_RRSIG  = StringToRRType('RRSIG');
const TYPE_NSEC   = StringToRRType('NSEC');
const TYPE_A      = StringToRRType('A');

const INCEPTION = 1000000000;
const EXPIRE    = 2000000000;

//////////////////////////////////////////////////////////// fixtures

interface ZoneSetup {
    apex: string;
    zone: DNSSecZone;
    ksk:  DNSKey;
}

function rsa_key_b64(privateKey: crypto.KeyObject, publicKey: crypto.KeyObject): string {
    const jwk = publicKey.export({ format: 'jwk' } as { format: 'jwk' }) as { n: string; e: string };
    const n = Buffer.from(jwk.n, 'base64url');
    const e = Buffer.from(jwk.e, 'base64url');
    void privateKey;
    return Buffer.concat([Buffer.from([e.length]), e, n]).toString('base64');
}

function make_zone(apex: string): ZoneSetup {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyB64 = rsa_key_b64(privateKey, publicKey);
    const zone = new DNSSecZone();
    const apexLabel = apex;
    const nsValue = apex === '.' ? 'ns1.' : `ns1.${apex}`;
    const adminValue = apex === '.' ? 'admin.' : `admin.${apex}`;
    zone.add_rr_from_parts(apexLabel, 3600, 'IN', 'SOA',
        `${nsValue} ${adminValue} 2021010101 3600 900 604800 86400`);
    zone.add_rr_from_parts(apexLabel, 3600, 'IN', 'DNSKEY', `257 3 8 ${keyB64}`);
    const dnskeyRR = zone.find_rr(apexLabel, TYPE_DNSKEY)!;
    const ksk = dnskeyRR.get_handler() as DNSKey;
    ksk.set_private_key(privateKey);
    const rrsig = zone.sign_rr(apexLabel, 3600, TYPE_DNSKEY, ksk, INCEPTION, EXPIRE);
    if (rrsig) zone.add_rr(rrsig);
    return { apex: apexLabel, zone, ksk };
}

function delegate(parent: ZoneSetup, child: ZoneSetup): void {
    const dsInput = child.ksk.get_ds_digest_data();
    const dsHash = crypto.createHash('sha256').update(Buffer.from(dsInput)).digest();
    parent.zone.add_rr_from_parts(child.apex, 3600, 'IN', 'DS',
        `${child.ksk.key_tag} ${child.ksk.algorithm} 2 ${dsHash.toString('hex')}`);
    const rrsig = parent.zone.sign_rr(child.apex, 3600, TYPE_DS, parent.ksk, INCEPTION, EXPIRE);
    if (rrsig) parent.zone.add_rr(rrsig);
}

function add_signed(setup: ZoneSetup, label: string, type: string, value: string): void {
    setup.zone.add_rr_from_parts(label, 3600, 'IN', type, value);
    const typeNum = StringToRRType(type);
    const rrsig = setup.zone.sign_rr(label, 3600, typeNum, setup.ksk, INCEPTION, EXPIRE);
    if (rrsig) setup.zone.add_rr(rrsig);
}

// add_wildcard_synthesised places a synthesised rrset at synthName in
// setup.zone. The RR itself appears at synthName but its RRSIG.Labels
// says only the closest-encloser labels were originally signed — that
// is how validators detect wildcard expansion (RFC 4034 §3.1.3 +
// RFC 4035 §5.3.2). labels_override must equal the label count of the
// closest encloser (i.e. the wildcard owner minus the leading "*.").
// For *.example.com. that is 2.
function add_wildcard_synthesised(setup: ZoneSetup, synthName: string, type: string,
                                  value: string, labels_override: number): void {
    setup.zone.add_rr_from_parts(synthName, 3600, 'IN', type, value);
    const typeNum = StringToRRType(type);
    const rrsig = setup.zone.sign_rr(synthName, 3600, typeNum, setup.ksk, INCEPTION, EXPIRE, labels_override);
    if (rrsig) setup.zone.add_rr(rrsig);
}

function trust_anchor_for(setup: ZoneSetup): RootAnchors {
    const dsInput = setup.ksk.get_ds_digest_data();
    const dsHash = crypto.createHash('sha256').update(Buffer.from(dsInput)).digest();
    return {
        lastUpdated: '2026-01-01',
        source: 'test',
        ds: [{
            keyTag: setup.ksk.key_tag,
            algorithm: setup.ksk.algorithm,
            digestType: 2,
            digest: dsHash.toString('hex'),
        }],
        dnskeys: [],
    };
}

class MapResolver implements Resolver {
    private readonly map = new Map<string, ResourceRecord[]>();

    constructor(entries: [string, ResourceRecord[]][]) {
        for (const [k, rs] of entries) this.map.set(k, rs);
    }

    async query(name: string, qtype: number): Promise<{ records: ResourceRecord[]; ad: boolean; rcode: number }> {
        return { records: this.map.get(key(name, qtype)) ?? [], ad: false, rcode: 0 };
    }
}

function key(name: string, qtype: number): string {
    return `${name} ${qtype}`;
}

// find_with_sigs returns z's records at (name, qtype) together with
// any RRSIG at the same name covering qtype.
function find_with_sigs(z: DNSSecZone, name: string, qtype: number): ResourceRecord[] {
    const out: ResourceRecord[] = [];
    out.push(...z.find_rrset(name, qtype));
    for (const rr of z.find_rrset(name, TYPE_RRSIG)) {
        const h = rr.get_handler();
        if (h instanceof RRSig && h.type_covered === qtype) {
            out.push(rr);
        }
    }
    return out;
}

//////////////////////////////////////////////////////////// tests

describe('Verifier wildcard synthesis (UP-006 / #10)', () => {
    it('returns Secure with result.wildcard when a wildcard-synthesised answer carries a covering NSEC', async () => {
        // Chain: root → com. → example.com. (all signed).
        // foo.example.com./A is signed as if at *.example.com.
        // (RRSIG.Labels = 2 over the qname's 3 labels). An NSEC at
        // example.com. with next_domain z.example.com. covers
        // foo.example.com. (example.com. < foo.example.com. <
        // z.example.com. in canonical order).
        const root    = make_zone('.');
        const com     = make_zone('com.');
        const example = make_zone('example.com.');
        delegate(root, com);
        delegate(com, example);

        add_wildcard_synthesised(example, 'foo.example.com.', 'A', '192.0.2.99', 2);
        add_signed(example, 'example.com.', 'NSEC', 'z.example.com. NS SOA RRSIG NSEC');

        // Resolver bundles the synthesised A + its RRSIG together with
        // the apex NSEC + its RRSIG, mirroring what a real
        // authoritative server returns alongside a wildcard answer.
        const fooA = find_with_sigs(example.zone, 'foo.example.com.', TYPE_A);
        const apexNsec = find_with_sigs(example.zone, 'example.com.', TYPE_NSEC);

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY),                find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS),                 find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY),             find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS),         find_with_sigs(com.zone, 'example.com.', TYPE_DS)],
            [key('example.com.', TYPE_DNSKEY),     find_with_sigs(example.zone, 'example.com.', TYPE_DNSKEY)],
            [key('foo.example.com.', TYPE_DS),     []],
            [key('foo.example.com.', TYPE_A),      [...fooA, ...apexNsec]],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('foo.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.wildcard).toBeDefined();
        expect(result.wildcard!.source).toBe('*.example.com.');
        expect(result.wildcard!.closestEncloser).toBe('example.com.');
        expect(result.wildcard!.nextCloser).toBe('foo.example.com.');
        expect(result.wildcard!.proofReason).toMatch(/NSEC/);
    });

    it('returns Bogus when a wildcard-synthesised answer lacks a next-closer non-existence proof', async () => {
        // Same wildcard synthesis but the resolver omits the NSEC
        // covering foo.example.com.. RFC 4035 §5.3.4 requires the
        // proof — without it the wildcard rrset could be replayed at
        // a name that actually has its own rrset.
        const root    = make_zone('.');
        const com     = make_zone('com.');
        const example = make_zone('example.com.');
        delegate(root, com);
        delegate(com, example);

        add_wildcard_synthesised(example, 'foo.example.com.', 'A', '192.0.2.99', 2);

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY),             find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS),              find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY),          find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS),      find_with_sigs(com.zone, 'example.com.', TYPE_DS)],
            [key('example.com.', TYPE_DNSKEY),  find_with_sigs(example.zone, 'example.com.', TYPE_DNSKEY)],
            [key('foo.example.com.', TYPE_DS),  []],
            [key('foo.example.com.', TYPE_A),   find_with_sigs(example.zone, 'foo.example.com.', TYPE_A)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('foo.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Bogus);
        expect(result.bogusReason).toMatch(/wildcard/);
        expect(result.bogusReason).toMatch(/foo\.example\.com\./);
        expect(result.wildcard).toBeUndefined();
    });

    it('leaves result.wildcard undefined for a non-wildcard signed answer', async () => {
        // Sanity check: an ordinary signed rrset (RRSIG.Labels equals
        // the qname's label count) must not be reported as a wildcard.
        const root    = make_zone('.');
        const com     = make_zone('com.');
        const example = make_zone('example.com.');
        delegate(root, com);
        delegate(com, example);

        add_signed(example, 'www.example.com.', 'A', '192.0.2.1');

        const resolver = new MapResolver([
            [key('.', TYPE_DNSKEY),             find_with_sigs(root.zone, '.', TYPE_DNSKEY)],
            [key('com.', TYPE_DS),              find_with_sigs(root.zone, 'com.', TYPE_DS)],
            [key('com.', TYPE_DNSKEY),          find_with_sigs(com.zone, 'com.', TYPE_DNSKEY)],
            [key('example.com.', TYPE_DS),      find_with_sigs(com.zone, 'example.com.', TYPE_DS)],
            [key('example.com.', TYPE_DNSKEY),  find_with_sigs(example.zone, 'example.com.', TYPE_DNSKEY)],
            [key('www.example.com.', TYPE_DS),  []],
            [key('www.example.com.', TYPE_A),   find_with_sigs(example.zone, 'www.example.com.', TYPE_A)],
        ]);
        const v = new Verifier({ resolver, trustAnchors: trust_anchor_for(root) });

        const result = await v.validate('www.example.com.', TYPE_A);
        expect(result.verdict).toBe(Verdict.Secure);
        expect(result.wildcard).toBeUndefined();
    });
});

// Touch unused imports the test file declares for parity with the
// surrounding suite — keeps tsc / eslint happy when these symbols
// become referenced in a later edit.
void RRTypeToString;
