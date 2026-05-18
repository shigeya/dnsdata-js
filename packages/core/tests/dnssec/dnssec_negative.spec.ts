// Negative-proof primitive tests for NSEC and NSEC3 (UP-004 / #8).
//
// These tests cover the pure question-answering layer — "does this
// record's bitmap have the no-DS shape", "does this hash fall in the
// covered range", etc. The compositional verifier proofs (proveNoDS,
// proveNoData, proveNXDomain) live in verifier.spec.ts.

import {
    DNSRR_NSEC,
    DNSRR_NSEC3,
    owner_hash_from_name,
} from '../../src/dnssec/dnssec_rr';
import { StringToRRType } from '../../src/types/dns_type_table';

const TYPE_A    = StringToRRType('A');
const TYPE_AAAA = StringToRRType('AAAA');
const TYPE_NS   = StringToRRType('NS');
const TYPE_DS   = StringToRRType('DS');
const TYPE_SOA  = StringToRRType('SOA');

//////////////////////////////////////////////////////////// NSEC

describe('DNSRR_NSEC.matches_name', () => {
    it('matches case-insensitively and ignores trailing dot', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example.com. A RRSIG');
        expect(nsec.matches_name('Example.COM.', 'example.com')).toBe(true);
        expect(nsec.matches_name('foo.example.com.', 'bar.example.com.')).toBe(false);
    });
});

describe('DNSRR_NSEC.covers_name', () => {
    it('covers names strictly between owner and next_domain', () => {
        // owner = b.example. next_domain = d.example.
        const nsec = new DNSRR_NSEC(null, 'd.example. A RRSIG');
        expect(nsec.covers_name('b.example.', 'c.example.')).toBe(true);
        // Equal-to-endpoint is NOT a cover.
        expect(nsec.covers_name('b.example.', 'b.example.')).toBe(false);
        expect(nsec.covers_name('b.example.', 'd.example.')).toBe(false);
        // Out-of-range.
        expect(nsec.covers_name('b.example.', 'a.example.')).toBe(false);
        expect(nsec.covers_name('b.example.', 'e.example.')).toBe(false);
    });

    it('handles wrap-around at the zone tail', () => {
        // Last NSEC: owner > next_domain, wraps to apex.
        const nsec = new DNSRR_NSEC(null, 'example. A RRSIG');
        // owner = z.example. — anything > owner OR < next_domain is covered.
        expect(nsec.covers_name('z.example.', 'zz.example.')).toBe(true);
        expect(nsec.covers_name('z.example.', 'aa.example.')).toBe(false); // greater than apex but < owner
        // The wrap test is "covered if > owner OR < next_domain". With
        // next_domain = "example." nothing in the zone sorts lower, so
        // names below owner are NOT covered.
    });
});

describe('DNSRR_NSEC.proves_no_data', () => {
    it('returns true when qtype absent and CNAME absent', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. A NS RRSIG NSEC');
        expect(nsec.proves_no_data(TYPE_AAAA)).toBe(true);
    });

    it('returns false when qtype is present', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. A AAAA RRSIG NSEC');
        expect(nsec.proves_no_data(TYPE_AAAA)).toBe(false);
    });

    it('returns false when CNAME is present (would have answered)', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. CNAME RRSIG NSEC');
        expect(nsec.proves_no_data(TYPE_AAAA)).toBe(false);
    });
});

describe('DNSRR_NSEC.proves_no_ds', () => {
    it('returns true for NS-without-DS-without-SOA bitmaps', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. NS RRSIG NSEC');
        expect(nsec.proves_no_ds()).toBe(true);
    });

    it('rejects bitmaps that include DS', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. NS DS RRSIG NSEC');
        expect(nsec.proves_no_ds()).toBe(false);
    });

    it('rejects bitmaps that include SOA (zone apex, not a delegation)', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. NS SOA RRSIG NSEC');
        expect(nsec.proves_no_ds()).toBe(false);
    });

    it('rejects bitmaps missing NS (parent never delegated)', () => {
        const nsec = new DNSRR_NSEC(null, 'next.example. A RRSIG NSEC');
        expect(nsec.proves_no_ds()).toBe(false);
    });
});

//////////////////////////////////////////////////////////// NSEC3

describe('DNSRR_NSEC3.has_opt_out', () => {
    it('reads flag bit 0', () => {
        // flags = 1 → opt-out set
        const yes = new DNSRR_NSEC3(null, '1 1 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS');
        expect(yes.has_opt_out()).toBe(true);
        // flags = 0 → opt-out clear
        const no = new DNSRR_NSEC3(null, '1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS');
        expect(no.has_opt_out()).toBe(false);
    });
});

describe('DNSRR_NSEC3.covers_hash', () => {
    // base32hex 'U' is 31 = 0b11111, so 32 'U's decode to 20 × 0xFF.
    const nsecHigh = new DNSRR_NSEC3(null, '1 0 0 - UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU NS');

    // base32hex '04000…' decodes to [0x01, 0x00, 0x00, …]. Useful as a
    // small-but-non-zero next_hashed_owner for the wrap-around test.
    const nsecWrap = new DNSRR_NSEC3(null, '1 0 0 - 04000000000000000000000000000000 NS');

    it('covers a hash strictly between owner and next', () => {
        // owner = 0x10…, target = 0x80…, next = 0xFF… → covered.
        expect(nsecHigh.covers_hash(bytes_at(0x10), bytes_at(0x80))).toBe(true);
    });

    it('does not cover hash equal to either endpoint', () => {
        const owner = bytes_at(0x10);
        const next  = nsecHigh.next_hashed_owner;
        expect(nsecHigh.covers_hash(owner, owner)).toBe(false);
        expect(nsecHigh.covers_hash(owner, next)).toBe(false);
    });

    it('handles wrap-around (next <= owner)', () => {
        // owner = 0xC0…, next = 0x01,0x00,… → wrap. A target less than
        // next is covered via the < next arm.
        expect(nsecWrap.covers_hash(bytes_at(0xc0), bytes_at(0x00))).toBe(true);
        // A target greater than owner is covered via the > owner arm.
        expect(nsecWrap.covers_hash(bytes_at(0xc0), bytes_at(0xf0))).toBe(true);
        // A target strictly between next and owner is NOT covered.
        expect(nsecWrap.covers_hash(bytes_at(0xc0), bytes_at(0x80))).toBe(false);
    });
});

describe('DNSRR_NSEC3.proves_no_data / proves_no_ds', () => {
    it('proves NODATA when qtype and CNAME both absent', () => {
        const nsec3 = new DNSRR_NSEC3(null, '1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG');
        expect(nsec3.proves_no_data(TYPE_AAAA)).toBe(true);
        expect(nsec3.proves_no_data(TYPE_A)).toBe(false);
    });

    it('proves no-DS for NS without DS and SOA', () => {
        const nsec3 = new DNSRR_NSEC3(null, '1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS RRSIG NSEC3');
        expect(nsec3.proves_no_ds()).toBe(true);
        void TYPE_NS; void TYPE_DS; void TYPE_SOA;
    });

    it('rejects no-DS proof when DS bit is set', () => {
        const nsec3 = new DNSRR_NSEC3(null, '1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS DS RRSIG');
        expect(nsec3.proves_no_ds()).toBe(false);
    });
});

describe('owner_hash_from_name', () => {
    it('decodes the leftmost label as base32hex', () => {
        const decoded = owner_hash_from_name('2T7B4G4VSA5SMI47K61MV5BV1A22BOJR.example.com.');
        expect(decoded.length).toBe(20);
    });

    it('accepts owner without trailing dot', () => {
        const a = owner_hash_from_name('2T7B4G4VSA5SMI47K61MV5BV1A22BOJR.example.com');
        const b = owner_hash_from_name('2T7B4G4VSA5SMI47K61MV5BV1A22BOJR.example.com.');
        expect(Array.from(a)).toEqual(Array.from(b));
    });

    it('throws on empty input', () => {
        expect(() => owner_hash_from_name('')).toThrow();
        expect(() => owner_hash_from_name('.')).toThrow();
    });
});

// Helper: returns a 20-byte hash buffer with the given first byte and
// zeros elsewhere. Lets the cover-range tests reason purely on the
// high-order byte without writing out a full hex string.
function bytes_at(first: number): Uint8Array {
    const b = new Uint8Array(20);
    b[0] = first;
    return b;
}
