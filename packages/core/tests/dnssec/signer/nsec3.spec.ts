// Ports dnsdata-go `dnssec/signer/nsec3_test.go`: NSEC3 chains from
// sign_zone and build_nsec3 (RFC 5155 §7.1, RFC 9276).

import { DNSRR_NSEC3, owner_hash_from_name } from '../../../src/dnssec/nsec3';
import { StringToRRType } from '../../../src/types/dns_type_table';
import { base32hex_encode } from '../../../src/wire/rdata_decoder';
import { Zone } from '../../../src/zone/dns_zone';
import * as signer from '../../../src/dnssec/signer';
import {
    checkAllRRSIGs,
    exampleZone,
    findTool,
    mustKey,
    rrsigsAt,
    runOnZoneFile,
    signOpts,
} from './helpers';

const T = (name: string): number => StringToRRType(name);
const APEX = 'example.test.';
const MS_PER_HOUR = 3600 * 1000;

function keys(): signer.Key[] {
    return [mustKey(APEX, 'ksk', signer.FlagsKSK), mustKey(APEX, 'zsk', signer.FlagsZSK)];
}

function child(): signer.Key {
    return mustKey('sub.example.test.', 'child', signer.FlagsKSK);
}

function signNSEC3(params: signer.NSEC3Options): Zone {
    return signer.sign_zone(exampleZone(child()), APEX, keys(), { ...signOpts(), nsec3: params });
}

// nsec3At returns the NSEC3 for the original name, or null.
function nsec3At(signed: Zone, name: string, params: signer.NSEC3Options): DNSRR_NSEC3 | null {
    const h = DNSRR_NSEC3.compute_hash(name, 1, params.iterations ?? 0, params.salt ?? new Uint8Array(0));
    const rrs = signed.find_rrset(`${base32hex_encode(h)}.${APEX}`, T('NSEC3'));
    if (rrs.length === 0) return null;
    expect(rrs).toHaveLength(1);
    return new DNSRR_NSEC3(null, rrs[0].value);
}

function hex(b: Uint8Array): string {
    return Buffer.from(b).toString('hex');
}

// checkNSEC3Chain checks that the n NSEC3 records form one closed ring
// in hash order, each signed, and that the NSEC3PARAM is signed.
function checkNSEC3Chain(signed: Zone, n: number): void {
    const links = signed.all_records()
        .filter((rr) => rr.type === T('NSEC3'))
        .map((rr) => {
            expect(rrsigsAt(signed, rr.label).get(T('NSEC3'))?.length ?? 0).toBeGreaterThan(0);
            return { owner: hex(owner_hash_from_name(rr.label)), next: hex(new DNSRR_NSEC3(null, rr.value).next_hashed_owner) };
        })
        .sort((a, b) => (a.owner < b.owner ? -1 : a.owner > b.owner ? 1 : 0));
    expect(links).toHaveLength(n);
    links.forEach((l, i) => expect(l.next).toBe(links[(i + 1) % links.length].owner));
    expect(rrsigsAt(signed, APEX).get(T('NSEC3PARAM'))?.length ?? 0).toBeGreaterThan(0);
}

describe('signer.sign_zone NSEC3 chain (RFC 9276)', () => {
    const params: signer.NSEC3Options = {};
    const signed = signNSEC3(params);
    const want: [string, string[]][] = [
        ['example.test.', ['NS', 'SOA', 'RRSIG', 'DNSKEY', 'NSEC3PARAM']],
        ['key.example.test.', ['RRSIG', 'TYPE65400']],
        ['nods.example.test.', ['NS']],
        ['ns1.example.test.', ['A', 'RRSIG']],
        ['sub.example.test.', ['NS', 'DS', 'RRSIG']],
        ['*.wild.example.test.', ['A', 'RRSIG']],
        ['wild.example.test.', []],
        ['www.example.test.', ['A', 'TXT', 'RRSIG']],
    ];

    it.each(want)('%s has an NSEC3 with the types at the name', (name, types) => {
        const n = nsec3At(signed, name, params);
        expect(n).not.toBeNull();
        expect(n?.covered_types).toEqual(types.map(T).sort((a, b) => a - b));
        expect([n?.hash_algorithm, n?.flags, n?.iterations, n?.salt.length]).toEqual([1, 0, 0, 0]);
    });

    it.each(['ns.sub.example.test.', 'ns.nods.example.test.'])('glue %s has no NSEC3', (glue) => {
        expect(nsec3At(signed, glue, params)).toBeNull();
    });

    it('links the NSEC3 records into one signed ring, with no NSEC', () => {
        checkNSEC3Chain(signed, want.length);
        expect(signed.all_records().filter((rr) => rr.type === T('NSEC'))).toHaveLength(0);
    });

    it('puts NSEC3PARAM 1 0 0 - at the apex', () => {
        expect(signed.find_rrset(APEX, T('NSEC3PARAM')).map((rr) => rr.value)).toEqual(['1 0 0 -']);
    });

    it('signs so that every RRSIG verifies', () => {
        const { failed, count } = checkAllRRSIGs(signed);
        expect(failed).toEqual([]);
        expect(count).toBeGreaterThan(0);
    });
});

// RFC 5155 §6: with opt-out the unsigned delegation leaves the chain
// and every NSEC3 has the opt-out flag; NSEC3PARAM keeps flags 0.
describe('signer.sign_zone NSEC3 opt-out', () => {
    const params: signer.NSEC3Options = { iterations: 5, salt: new Uint8Array([0xaa, 0xbb]), optOut: true };
    const signed = signNSEC3(params);

    it('leaves the unsigned delegation out', () => {
        expect(nsec3At(signed, 'nods.example.test.', params)).toBeNull();
    });

    it.each(['example.test.', 'sub.example.test.', 'wild.example.test.', 'www.example.test.'])(
        '%s has the opt-out flag, iterations and salt', (name) => {
            const n = nsec3At(signed, name, params);
            expect(n?.has_opt_out()).toBe(true);
            expect(n?.iterations).toBe(5);
            expect(hex(n?.salt ?? new Uint8Array(0))).toBe('aabb');
        });

    it('links 7 NSEC3 records and puts NSEC3PARAM 1 0 5 AABB at the apex', () => {
        checkNSEC3Chain(signed, 7);
        expect(signed.find_rrset(APEX, T('NSEC3PARAM')).map((rr) => rr.value)).toEqual(['1 0 5 AABB']);
        expect(checkAllRRSIGs(signed).failed).toEqual([]);
    });
});

describe('signer.build_nsec3', () => {
    it('derives the TTL from the SOA (RFC 9077) for the NSEC3 records and the NSEC3PARAM', () => {
        const recs = signer.build_nsec3(exampleZone(child()), APEX, 0, {});
        expect(recs).toHaveLength(9);
        expect(recs.map((rr) => rr.ttl)).toEqual(Array(9).fill(300));
    });

    it('rejects a salt longer than 255 octets', () => {
        expect(() => signer.build_nsec3(exampleZone(child()), APEX, 0, { salt: new Uint8Array(256) }))
            .toThrow(signer.SignerError);
    });
});

const checkzone = findTool('named-checkzone');
const verify = findTool('dnssec-verify');
const itWithBIND = checkzone !== null || verify !== null ? it : it.skip;

describe('signer.sign_zone NSEC3 accepted by BIND', () => {
    itWithBIND.each([
        ['RFC 9276', {}],
        ['opt-out', { iterations: 5, salt: new Uint8Array([0xaa, 0xbb]), optOut: true }],
    ] as [string, signer.NSEC3Options][])('%s', (_name, params) => {
        const now = Date.now();
        const text = signer.sign_zone(exampleZone(child()), APEX, keys(), {
            inception: new Date(now - MS_PER_HOUR),
            expiration: new Date(now + 24 * MS_PER_HOUR),
            nsec3: params,
        }).print_canonical();
        if (checkzone !== null) {
            expect(() => runOnZoneFile(text, checkzone, ['example.test'])).not.toThrow();
        }
        if (verify !== null) {
            expect(() => runOnZoneFile(text, verify, ['-o', 'example.test'])).not.toThrow();
        }
    });
});
