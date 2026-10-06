// SigStatus, DNSSecZone.check_rrsig / check_rrset and rrset_verified.
// Ports dnsdata-go `dnssec/sigstatus_test.go`.

import * as crypto from 'crypto';

import { DNSSecUnsupportedAlgorithmError } from '../../src/dns_exception';
import { DNSSecZone, KeyVerifyMode } from '../../src/dnssec/dnssec_zone';
import { DNSKey, RRSig } from '../../src/dnssec/dnssec_rr';
import { SigStatus, rrset_verified } from '../../src/dnssec/sigcheck';
import { RRTypeName } from '../../src/types/dns_type_table';
import {
    CHILD_ADDR, EXPIRE, INCEPTION, NOW, TTL, TYPE_A, add_signed, make_zone,
} from '../verifier/key_auth_fixtures';

const APEX = 'check.example.';
const LEAF = 'www.check.example.';
const UNSUPPORTED_ALGORITHM = 12; // ECC-GOST: recognised, not implemented
const SECONDS_PER_DAY = 86400;

interface RRSigFields {
    algorithm?: number;
    key_tag?: number;
    signature?: Uint8Array;
}

// rrsig_with returns a copy of sig with the given fields replaced.
function rrsig_with(sig: RRSig, f: RRSigFields): RRSig {
    const signature = Buffer.from(f.signature ?? sig.signature).toString('base64');
    return new RRSig(null, `${RRTypeName(sig.type_covered)} ${f.algorithm ?? sig.algorithm} ${sig.labels} ` +
        `${sig.original_ttl} ${sig.expire} ${sig.inception} ${f.key_tag ?? sig.key_tag} ${sig.signer} ${signature}`);
}

function at(seconds: number): () => Date {
    return () => new Date(seconds * 1000);
}

// unsupported_key adds a DNSKEY of an algorithm the library does not
// implement and returns an RRSIG naming it.
function unsupported_key(z: DNSSecZone, sig: RRSig): RRSig {
    const keyData = crypto.randomBytes(64).toString('base64');
    const rr = z.add_rr_from_parts(sig.signer, TTL, 'IN', 'DNSKEY', `256 3 ${UNSUPPORTED_ALGORITHM} ${keyData}`);
    const key = z.handler(rr) as DNSKey;
    return rrsig_with(sig, { algorithm: UNSUPPORTED_ALGORITHM, key_tag: key.key_tag });
}

function signed_zone(): DNSSecZone {
    const setup = make_zone(APEX);
    add_signed(setup.zone, LEAF, CHILD_ADDR, setup.ksk);
    setup.zone.set_clock(() => NOW);
    return setup.zone;
}

describe('SigStatus', () => {
    it('has the stable kebab-case names', () => {
        expect([
            SigStatus.Verified, SigStatus.Expired, SigStatus.NotYetValid,
            SigStatus.UnsupportedAlgorithm, SigStatus.NoMatchingKey, SigStatus.Invalid,
        ]).toEqual(['verified', 'expired', 'not-yet-valid', 'unsupported-algorithm', 'no-matching-key', 'invalid']);
    });
});

describe('DNSSecZone.check_rrsig', () => {
    const flip = (sig: RRSig): RRSig => {
        const s = Uint8Array.from(sig.signature);
        s[0] ^= 0x01;
        return rrsig_with(sig, { signature: s });
    };
    it.each([
        ['verified', (_z: DNSSecZone, s: RRSig) => s, SigStatus.Verified, false],
        ['expired', (z: DNSSecZone, s: RRSig) => { z.set_clock(at(EXPIRE + 2 * SECONDS_PER_DAY)); return s; },
            SigStatus.Expired, false],
        ['not yet valid', (z: DNSSecZone, s: RRSig) => { z.set_clock(at(INCEPTION - 2 * SECONDS_PER_DAY)); return s; },
            SigStatus.NotYetValid, false],
        ['no matching key', (_z: DNSSecZone, s: RRSig) => rrsig_with(s, { key_tag: (s.key_tag + 1) & 0xffff }),
            SigStatus.NoMatchingKey, false],
        ['invalid', (_z: DNSSecZone, s: RRSig) => flip(s), SigStatus.Invalid, false],
        ['unsupported algorithm', unsupported_key, SigStatus.UnsupportedAlgorithm, true],
    ] as const)('classifies %s', (_name, prepare, want, wantError) => {
        const z = signed_zone();
        const sigs = z.find_rrsigs(LEAF, TYPE_A);
        expect(sigs).toHaveLength(1);
        const sig = prepare(z, sigs[0]);

        const got = z.check_rrsig(LEAF, TYPE_A, sig, KeyVerifyMode.None);
        expect(got.status).toBe(want);
        expect(got.rrsig).toBe(sig);
        expect(got.error !== undefined).toBe(wantError);
        if (wantError) expect(got.error).toBeInstanceOf(DNSSecUnsupportedAlgorithmError);

        // verify_rrsig is check_rrsig reduced to a bool: it throws the
        // error when there is one.
        if (wantError) {
            expect(() => z.verify_rrsig(LEAF, TYPE_A, sig, KeyVerifyMode.None)).toThrow(DNSSecUnsupportedAlgorithmError);
        } else {
            expect(z.verify_rrsig(LEAF, TYPE_A, sig, KeyVerifyMode.None)).toBe(want === SigStatus.Verified);
        }
    });

    it('reports no-matching-key when the key mode accepts no candidate', () => {
        const z = signed_zone();
        const sig = z.find_rrsigs(LEAF, TYPE_A)[0];
        expect(z.check_rrsig(LEAF, TYPE_A, sig, KeyVerifyMode.KSK).status).toBe(SigStatus.NoMatchingKey);
        expect(z.check_rrsig(LEAF, TYPE_A, sig, KeyVerifyMode.ZSK).status).toBe(SigStatus.NoMatchingKey);
    });

    it('reports invalid for an absent rrset', () => {
        const z = signed_zone();
        const sig = z.find_rrsigs(LEAF, TYPE_A)[0];
        expect(z.check_rrsig('absent.check.example.', TYPE_A, sig, KeyVerifyMode.None).status).toBe(SigStatus.Invalid);
    });
});

describe('DNSSecZone.check_rrset', () => {
    it('lists every RRSIG with its status and agrees with verify_rrset', () => {
        const setup = make_zone('set.example.');
        add_signed(setup.zone, 'www.set.example.', CHILD_ADDR, setup.ksk);
        const z = setup.zone;
        z.set_clock(() => NOW);
        // A second, expired signature by the same key.
        const old = z.sign_rr('www.set.example.', TTL, TYPE_A, setup.ksk, INCEPTION - 3 * SECONDS_PER_DAY,
            INCEPTION - 2 * SECONDS_PER_DAY);
        if (!old) throw new Error('sign_rr failed');
        z.add_rr(old);

        const results = z.check_rrset('www.set.example.', TYPE_A, KeyVerifyMode.None);
        expect(results.map((r) => r.status).sort()).toEqual([SigStatus.Expired, SigStatus.Verified]);
        expect(results.every((r) => r.rrsig instanceof RRSig)).toBe(true);
        expect(rrset_verified(results)).toEqual({ verified: true });
        expect(z.verify_rrset('www.set.example.', TYPE_A, KeyVerifyMode.None)).toBe(true);
    });

    it('folds failures into the first error', () => {
        expect(rrset_verified([])).toEqual({ verified: false });
        const e = new Error('x');
        const sig = signed_zone().find_rrsigs(LEAF, TYPE_A)[0];
        expect(rrset_verified([
            { rrsig: sig, status: SigStatus.Invalid },
            { rrsig: sig, status: SigStatus.UnsupportedAlgorithm, error: e },
        ])).toEqual({ verified: false, error: e });
    });
});
