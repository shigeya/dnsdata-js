// RRSIG digest target canonical order (RFC 4034 §6.3) and RRSIG
// validity window (RFC 4035 §5.3.1).
//
// Ports dnsdata-go `dnssec/canonical_digest_test.go` (UF-005, UF-006).

import * as crypto from 'crypto';
import { DNSSecZone } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { RRTypeName, StringToRRType } from '../../src/types/dns_type_table';

const TEST_RR_TYPE = 65400;
const TYPE_A = StringToRRType('A');
const TYPE_NS = StringToRRType('NS');

function digest_for(zone: DNSSecZone, name: string, type: number): Uint8Array {
    const sig = new RRSig(null, `${RRTypeName(type)} 13 2 60 0 0 0 example. AA==`);
    const dt = zone.create_digest_target(sig, name, type);
    if (dt === null) throw new Error('create_digest_target returned null');
    return dt;
}

function index_of(haystack: Uint8Array, needle: readonly number[]): number {
    return Buffer.from(haystack).indexOf(Buffer.from(needle));
}

describe('create_digest_target canonical RRset order (UF-005)', () => {
    // RFC 4034 §6.3: RRs are ordered by RDATA alone. With the RDLENGTH
    // prefix included, the shorter "b" would wrongly sort before "ab".
    it('orders by RDATA only', () => {
        const zone = new DNSSecZone();
        for (const v of ['\\# 1 62', '\\# 2 6162']) {
            zone.add_rr_from_parts('x.example.', 60, 'IN', 'TYPE65400', v);
        }
        const dt = digest_for(zone, 'x.example.', TEST_RR_TYPE);
        const ab = index_of(dt, [0x00, 0x02, 0x61, 0x62]);
        const b = index_of(dt, [0x00, 0x01, 0x62]);
        expect(ab).toBeGreaterThanOrEqual(0);
        expect(b).toBeGreaterThanOrEqual(0);
        expect(ab).toBeLessThan(b);
    });

    // NS names of different lengths: "a.b.example." (13 octets) sorts
    // before "ns.example." (12 octets) because its first octet (label
    // length 1) is smaller; ordering by RDLENGTH would reverse them.
    it('orders NS members of different lengths by RDATA', () => {
        const zone = new DNSSecZone();
        zone.add_rr_from_parts('example.', 60, 'IN', 'NS', 'ns.example.');
        zone.add_rr_from_parts('example.', 60, 'IN', 'NS', 'a.b.example.');
        const dt = digest_for(zone, 'example.', TYPE_NS);
        const aB = index_of(dt, [0x00, 0x0d, 0x01, 0x61, 0x01, 0x62]);
        const ns = index_of(dt, [0x00, 0x0c, 0x02, 0x6e, 0x73]);
        expect(aB).toBeGreaterThanOrEqual(0);
        expect(ns).toBeGreaterThanOrEqual(0);
        expect(aB).toBeLessThan(ns);
    });

    // RFC 4034 §6.3: duplicate RRs are removed before signing / verifying.
    it('drops duplicate RRs', () => {
        const single = new DNSSecZone();
        const double = new DNSSecZone();
        for (const zone of [single, double, double]) {
            zone.add_rr_from_parts('x.example.', 60, 'IN', 'TYPE65400', '\\# 1 62');
        }
        expect(digest_for(double, 'x.example.', TEST_RR_TYPE))
            .toEqual(digest_for(single, 'x.example.', TEST_RR_TYPE));
    });
});

describe('verify_rrset validity window (UF-006)', () => {
    const inception = new Date(Date.UTC(2026, 0, 1));
    const expire = new Date(Date.UTC(2026, 1, 1));
    const SECOND_MS = 1000;
    const DAY_MS = 24 * 60 * 60 * SECOND_MS;

    function signed_zone(): DNSSecZone {
        const zone = new DNSSecZone();
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = publicKey.export({ format: 'jwk' });
        // RFC 6605 key field is X || Y.
        const pub = Buffer.concat([
            Buffer.from(jwk.x as string, 'base64url'),
            Buffer.from(jwk.y as string, 'base64url'),
        ]);
        const keyRR = zone.add_rr_from_parts('example.', 60, 'IN', 'DNSKEY', `257 3 13 ${pub.toString('base64')}`);
        const key = keyRR.get_handler() as DNSKey;
        key.set_private_key(privateKey);
        zone.add_rr_from_parts('x.example.', 60, 'IN', 'A', '192.0.2.1');
        const sig = zone.sign_rr('x.example.', 60, TYPE_A, key,
            inception.getTime() / SECOND_MS, expire.getTime() / SECOND_MS);
        if (sig === null) throw new Error('sign_rr returned null');
        zone.add_rr(sig);
        return zone;
    }

    const zone = signed_zone();

    const cases: { name: string; now: Date; want: boolean }[] = [
        { name: 'inside', now: new Date(inception.getTime() + DAY_MS), want: true },
        { name: 'at inception', now: inception, want: true },
        { name: 'at expiration', now: expire, want: true },
        { name: 'before inception', now: new Date(inception.getTime() - SECOND_MS), want: false },
        { name: 'after expiration', now: new Date(expire.getTime() + SECOND_MS), want: false },
    ];
    for (const tc of cases) {
        it(tc.name, () => {
            zone.set_clock(() => tc.now);
            expect(zone.verify_rrset('x.example.', TYPE_A)).toBe(tc.want);
        });
    }

    it('does not check the window without a clock (existing behaviour)', () => {
        zone.set_clock(null);
        expect(zone.verify_rrset('x.example.', TYPE_A)).toBe(true);
    });
});
