// Ports dnsdata-go `dnssec/signer/sign_test.go`, plus sign → verify for
// every algorithm and the negative cases (tampered data, a clock
// outside the RRSIG window).

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DNSRR_NSEC } from '../../../src/dnssec/dnssec_rr';
import { StringToRRType } from '../../../src/types/dns_type_table';
import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../../../src/types/algorithm';
import { ResourceRecord, Zone } from '../../../src/zone/dns_zone';
import * as signer from '../../../src/dnssec/signer';
import {
    TYPE_RRSIG,
    checkAllRRSIGs,
    exampleZone,
    findTool,
    mustKey,
    rrsigsAt,
    signOpts,
    testExpiration,
    testInception,
    toDNSSecZone,
} from './helpers';

const T = (name: string): number => StringToRRType(name);
const APEX = 'example.test.';
const SECONDS_PER_HOUR = 3600;
const MS_PER_SECOND = 1000;

function kskZsk(): signer.Key[] {
    return [mustKey(APEX, 'ksk', signer.FlagsKSK), mustKey(APEX, 'zsk', signer.FlagsZSK)];
}

function child(): signer.Key {
    return mustKey('sub.example.test.', 'child', signer.FlagsKSK);
}

function unixSeconds(d: Date): number {
    return Math.floor(d.getTime() / MS_PER_SECOND);
}

describe('signer.sign_zone NSEC chain', () => {
    const signed = signer.sign_zone(exampleZone(child()), APEX, kskZsk(), signOpts());
    const want: Array<[string, string[]]> = [
        ['example.test.', ['NS', 'SOA', 'RRSIG', 'NSEC', 'DNSKEY']],
        ['key.example.test.', ['RRSIG', 'NSEC', 'TYPE65400']],
        ['nods.example.test.', ['NS', 'RRSIG', 'NSEC']],
        ['ns1.example.test.', ['A', 'RRSIG', 'NSEC']],
        ['sub.example.test.', ['NS', 'DS', 'RRSIG', 'NSEC']],
        ['*.wild.example.test.', ['A', 'RRSIG', 'NSEC']],
        ['www.example.test.', ['A', 'TXT', 'RRSIG', 'NSEC']],
    ];

    it.each(want.map((w, i) => [w[0], w[1], want[(i + 1) % want.length][0]] as const))(
        '%s', (owner, types, next) => {
            const rrs = signed.find_rrset(owner, T('NSEC'));
            expect(rrs).toHaveLength(1);
            const n = new DNSRR_NSEC(null, rrs[0].value);
            expect(n.next_domain).toBe(next);
            expect(n.covered_types).toEqual(types.map(T).sort((a, b) => a - b));
        });

    it.each(['ns.sub.example.test.', 'ns.nods.example.test.', 'wild.example.test.'])(
        '%s has no NSEC (glue or empty non-terminal)', (name) => {
            expect(signed.find_rrset(name, T('NSEC'))).toHaveLength(0);
        });
});

describe('signer.sign_zone what is signed', () => {
    const [ksk, zsk] = kskZsk();
    const signed = signer.sign_zone(exampleZone(child()), APEX, [ksk, zsk], signOpts());

    it('KSK signs DNSKEY, ZSK signs the rest', () => {
        const apex = rrsigsAt(signed, APEX);
        expect(apex.get(T('DNSKEY'))?.map((s) => s.key_tag)).toEqual([ksk.key_tag]);
        expect(apex.get(T('SOA'))?.map((s) => s.key_tag)).toEqual([zsk.key_tag]);
        expect(signed.find_rrset(APEX, T('DNSKEY'))).toHaveLength(2);
    });

    it('signs only DS and NSEC at a delegation, and no glue', () => {
        const sub = rrsigsAt(signed, 'sub.example.test.');
        expect(sub.get(T('NS'))).toBeUndefined();
        expect(sub.get(T('DS'))).toHaveLength(1);
        expect(sub.get(T('NSEC'))).toHaveLength(1);
        for (const glue of ['ns.sub.example.test.', 'ns.nods.example.test.']) {
            expect(signed.find_rrset(glue, TYPE_RRSIG)).toHaveLength(0);
        }
        expect(rrsigsAt(signed, 'nods.example.test.').get(T('NS'))).toBeUndefined();
    });

    it('computes Labels per RFC 4034 §3.1.3 and uses the given window', () => {
        const wild = rrsigsAt(signed, '*.wild.example.test.').get(T('A'));
        expect(wild?.map((s) => s.labels)).toEqual([3]);
        const key = rrsigsAt(signed, 'key.example.test.').get(65400);
        expect(key).toHaveLength(1);
        expect(key?.[0].labels).toBe(3);
        expect(key?.[0].signer).toBe(APEX);
        expect(key?.[0].inception).toBe(unixSeconds(testInception));
        expect(key?.[0].expire).toBe(unixSeconds(testExpiration));
    });
});

describe('signer.sign_zone signatures verify', () => {
    it.each(['KSK+ZSK', 'CSK'])('%s: every RRSIG verifies under the zone keys', (name) => {
        const keys = name === 'CSK' ? [mustKey(APEX, 'ksk', signer.FlagsKSK)] : kskZsk();
        const signed = signer.sign_zone(exampleZone(child()), APEX, keys, signOpts());
        const { failed, count } = checkAllRRSIGs(signed);
        expect(failed).toEqual([]);
        expect(count).toBeGreaterThan(0);
    });

    it.each([AlgoECDSAP256SHA256, AlgoECDSAP384SHA384, AlgoED25519, AlgoRSASHA256, AlgoRSASHA512])(
        'algorithm %i: KSK+ZSK signed zone verifies', (alg) => {
            const keys = [signer.generate_key(APEX, alg, signer.FlagsKSK), signer.generate_key(APEX, alg, signer.FlagsZSK)];
            const signed = signer.sign_zone(exampleZone(child()), APEX, keys, signOpts());
            const { failed, count } = checkAllRRSIGs(signed);
            expect(failed).toEqual([]);
            expect(count).toBeGreaterThan(0);
            expect(rrsigsAt(signed, APEX).get(T('SOA'))?.[0].algorithm).toBe(alg);
        });
});

describe('signer.sign_zone negative cases', () => {
    const signed = signer.sign_zone(exampleZone(child()), APEX, kskZsk(), signOpts());

    it('a tampered record no longer verifies', () => {
        const tampered = new Zone();
        for (const rr of signed.all_records()) {
            const value = rr.label === 'www.example.test.' && rr.type === T('A') ? '192.0.2.99' : rr.value;
            tampered.add_rr(new ResourceRecord(rr.label, rr.ttl, rr.rrclass, rr.type, value));
        }
        const dz = toDNSSecZone(tampered);
        expect(dz.verify_rrset('www.example.test.', T('A'))).toBe(false);
        expect(dz.verify_rrset('www.example.test.', T('TXT'))).toBe(true);
        expect(checkAllRRSIGs(tampered).failed).toEqual(['www.example.test./1']);
    });

    it('fails with a clock after expiration or before inception', () => {
        const late = new Date(testExpiration.getTime() + MS_PER_SECOND);
        const early = new Date(testInception.getTime() - MS_PER_SECOND);
        expect(toDNSSecZone(signed, late).verify_rrset(APEX, T('SOA'))).toBe(false);
        expect(toDNSSecZone(signed, early).verify_rrset(APEX, T('SOA'))).toBe(false);
        expect(toDNSSecZone(signed, testExpiration).verify_rrset(APEX, T('SOA'))).toBe(true);
    });

    it('an expired window can be produced on purpose', () => {
        const expired = signer.sign_zone(exampleZone(child()), APEX, kskZsk(), {
            inception: new Date(Date.UTC(2020, 0, 1)), expiration: new Date(Date.UTC(2021, 0, 1)),
        });
        const { failed, count } = checkAllRRSIGs(expired);
        expect(failed).toHaveLength(count);
    });
});

describe('signer.sign_zone root', () => {
    it('signs the root with Labels 0 and a TLD DS with Labels 1', () => {
        const ksk = mustKey('.', 'root', signer.FlagsKSK);
        const ds = mustKey('test.', 'tld', signer.FlagsKSK).ds(signer.DigestSHA256);
        const z = new Zone();
        z.read_string_strict('. 86400 SOA a.root.test. h.root.test. 1 2 3 4 5\n' +
            '. 86400 NS a.root.test.\ntest. 86400 NS a.root.test.\ntest. 86400 DS ' + ds + '\n');
        const signed = signer.sign_zone(z, '.', [ksk], signOpts());
        expect(rrsigsAt(signed, '.').get(T('DNSKEY'))?.map((s) => s.labels)).toEqual([0]);
        expect(rrsigsAt(signed, 'test.').get(T('DS'))?.map((s) => s.labels)).toEqual([1]);
        expect(checkAllRRSIGs(signed).failed).toEqual([]);
    });
});

describe('signer.sign_zone re-signing', () => {
    it('does not modify its input and drops old signatures', () => {
        const ksk = mustKey(APEX, 'ksk', signer.FlagsKSK);
        const input = exampleZone(child());
        const before = input.print_canonical();
        const once = signer.sign_zone(input, APEX, [ksk], signOpts());
        expect(input.print_canonical()).toBe(before);
        const twice = signer.sign_zone(once, APEX, [ksk], signOpts());
        expect(twice.all_records()).toHaveLength(once.all_records().length);
    });

    it('uses the DNSKEY and NSEC TTLs it is given', () => {
        const signed = signer.sign_zone(exampleZone(child()), APEX, kskZsk(),
            { ...signOpts(), dnskeyTTL: 120, nsecTTL: 60 });
        expect(signed.find_rrset(APEX, T('DNSKEY')).map((rr) => rr.ttl)).toEqual([120, 120]);
        expect(signed.find_rrset(APEX, T('NSEC')).map((rr) => rr.ttl)).toEqual([60]);
    });

    it('defaults the DNSKEY TTL to the SOA TTL, or 3600 without an SOA', () => {
        const withSOA = signer.sign_zone(exampleZone(child()), APEX, kskZsk(), signOpts());
        expect(withSOA.find_rr(APEX, T('DNSKEY'))?.ttl).toBe(3600);
        const bare = new Zone();
        bare.read_string_strict('www.example.test. 60 A 192.0.2.1\n');
        const signed = signer.sign_zone(bare, APEX, kskZsk(), signOpts());
        expect(signed.find_rr(APEX, T('DNSKEY'))?.ttl).toBe(3600);
        expect(signed.find_rr('www.example.test.', T('NSEC'))?.ttl).toBe(3600);
    });
});

describe('signer.sign_zone errors', () => {
    const ksk = mustKey(APEX, 'ksk', signer.FlagsKSK);
    const other = mustKey('other.test.', 'other', signer.FlagsKSK);
    const z = exampleZone(child());
    const outside = exampleZone(child());
    outside.add_rr_from_parts('www.other.test.', 60, 'IN', 'A', '192.0.2.1');
    const unencodable = exampleZone(child());
    unencodable.add_rr_from_parts('bad.example.test.', 60, 'IN', 'A', 'not-an-address');
    const noInception = { expiration: testExpiration } as unknown as signer.SignOptions;
    const noExpiration = { inception: testInception } as unknown as signer.SignOptions;
    const badDate = { inception: new Date(NaN), expiration: testExpiration };

    it.each([
        ['no keys', z, APEX, [] as signer.Key[], signOpts()],
        ['key for another zone', z, APEX, [other], signOpts()],
        ['no inception', z, APEX, [ksk], noInception],
        ['no expiration', z, APEX, [ksk], noExpiration],
        ['invalid date', z, APEX, [ksk], badDate],
        ['record outside the apex', outside, APEX, [ksk], signOpts()],
        ['relative apex', z, 'example.test', [ksk], signOpts()],
        ['record that does not encode', unencodable, APEX, [ksk], signOpts()],
    ])('%s', (_name, zone, apex, keys, opts) => {
        expect(() => signer.sign_zone(zone, apex, keys, opts)).toThrow(signer.SignerError);
    });
});

describe('signer.build_nsec', () => {
    it('derives the TTL from the SOA (RFC 9077)', () => {
        const nsecs = signer.build_nsec(exampleZone(child()), APEX);
        expect(nsecs.length).toBeGreaterThan(0);
        for (const rr of nsecs) expect(rr.ttl).toBe(300); // min(SOA TTL 3600, MINIMUM 300)
    });

    it('falls back to the SOA TTL when MINIMUM cannot be read (generic RDATA)', () => {
        const z = new Zone();
        // Root MNAME and RNAME, then SERIAL..MINIMUM = 1..5, in RFC 3597 form.
        z.add_rr_from_parts(APEX, 900, 'IN', 'SOA',
            '\\# 22 0000' + '00000001' + '00000002' + '00000003' + '00000004' + '00000005');
        const nsecs = signer.build_nsec(z, APEX, 0);
        expect(nsecs.map((rr) => rr.ttl)).toEqual([900]);
        expect(nsecs[0].value).toBe('example.test. SOA RRSIG NSEC');
    });

    it('rejects records outside the apex', () => {
        const z = new Zone();
        z.read_string_strict('www.other.test. 60 A 192.0.2.1\n');
        expect(() => signer.build_nsec(z, APEX)).toThrow(signer.SignerError);
    });
});

describe('signer.rrsig_labels', () => {
    it.each([['.', 0], ['test.', 1], ['example.test.', 2], ['*.wild.example.test.', 3], ['*.', 0]] as const)(
        '%s → %i', (owner, want) => {
            expect(signer.rrsig_labels(owner)).toBe(want);
        });
});

describe('signer.sign_zone output', () => {
    it('has no stray mnemonics', () => {
        const signed = signer.sign_zone(exampleZone(child()), APEX, [mustKey(APEX, 'ksk', signer.FlagsKSK)], signOpts());
        const text = signed.print_canonical();
        expect(text).not.toMatch(/INVALID|UNALLOC/);
    });
});

// Independent check: BIND's zone checker loads the canonical output and
// BIND's DNSSEC verifier accepts the signatures and the NSEC chain. A
// single-key (CSK) zone needs `dnssec-verify -z`, since no key has only
// the ZSK role. Skipped when the tools are not on PATH.
const checkzone = findTool('named-checkzone');
const verify = findTool('dnssec-verify');
const itWithBIND = checkzone !== null || verify !== null ? it : it.skip;
const itWithVerify = verify !== null ? it : it.skip;

// signedNow signs the example zone with a window around the real clock,
// as BIND checks signatures against it.
function signedNow(keys: signer.Key[]): Zone {
    const now = Date.now();
    return signer.sign_zone(exampleZone(child()), APEX, keys, {
        inception: new Date(now - SECONDS_PER_HOUR * MS_PER_SECOND),
        expiration: new Date(now + 24 * SECONDS_PER_HOUR * MS_PER_SECOND),
    });
}

// runOnZoneFile writes text to a temporary zone file and runs tool with
// args followed by that file; throws when the tool exits non-zero.
function runOnZoneFile(text: string, tool: string, args: string[]): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-bind-'));
    const file = path.join(dir, 'example.test.zone');
    try {
        fs.writeFileSync(file, text + '\n', { mode: 0o600 });
        return execFileSync(tool, [...args, file], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

describe('signer.sign_zone accepted by BIND', () => {
    itWithBIND.each(['KSK+ZSK', 'CSK'])('%s', (name) => {
        const keys = name === 'CSK' ? [mustKey(APEX, 'ksk', signer.FlagsKSK)] : kskZsk();
        const text = signedNow(keys).print_canonical();
        if (checkzone !== null) {
            expect(() => runOnZoneFile(text, checkzone, ['example.test'])).not.toThrow();
        }
        if (verify !== null) {
            const args = name === 'CSK' ? ['-z', '-o', 'example.test'] : ['-o', 'example.test'];
            expect(() => runOnZoneFile(text, verify, args)).not.toThrow();
        }
    });

    // Negative control: the same check rejects a tampered zone.
    itWithVerify('dnssec-verify rejects a tampered zone', () => {
        const text = signedNow(kskZsk()).print_canonical()
            .replace(/(www\.example\.test\. \d+ IN A) 192\.0\.2\.10/, '$1 192.0.2.99');
        expect(text).toContain('192.0.2.99');
        expect(() => runOnZoneFile(text, verify as string, ['-o', 'example.test'])).toThrow();
    });
});
