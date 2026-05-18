// Spec for dnssec/crypto.ts dispatchers.

import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoED448,
    AlgoRSAMD5,
    AlgoRSASHA1,
    AlgoRSASHA1NSEC3SHA1,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../../../src/types/algorithm';
import {
    algo_to_hash,
    ecdsa_coord_len,
    ecdsa_curve,
    is_ecdsa_algorithm,
    is_eddsa_algorithm,
} from '../../../src/lib/dnssec/crypto';

describe('is_ecdsa_algorithm', () => {
    test('true for ECDSA P-256 / P-384', () => {
        expect(is_ecdsa_algorithm(AlgoECDSAP256SHA256)).toBe(true);
        expect(is_ecdsa_algorithm(AlgoECDSAP384SHA384)).toBe(true);
    });
    test('false for non-ECDSA', () => {
        expect(is_ecdsa_algorithm(AlgoRSASHA256)).toBe(false);
        expect(is_ecdsa_algorithm(AlgoED25519)).toBe(false);
        expect(is_ecdsa_algorithm(0)).toBe(false);
    });
});

describe('is_eddsa_algorithm', () => {
    test('true for Ed25519 / Ed448', () => {
        expect(is_eddsa_algorithm(AlgoED25519)).toBe(true);
        expect(is_eddsa_algorithm(AlgoED448)).toBe(true);
    });
    test('false for non-EdDSA', () => {
        expect(is_eddsa_algorithm(AlgoECDSAP256SHA256)).toBe(false);
        expect(is_eddsa_algorithm(AlgoRSASHA512)).toBe(false);
    });
});

describe('ecdsa_curve / ecdsa_coord_len', () => {
    test('P-256 / 32 bytes', () => {
        expect(ecdsa_curve(AlgoECDSAP256SHA256)).toBe('P-256');
        expect(ecdsa_coord_len(AlgoECDSAP256SHA256)).toBe(32);
    });
    test('P-384 / 48 bytes', () => {
        expect(ecdsa_curve(AlgoECDSAP384SHA384)).toBe('P-384');
        expect(ecdsa_coord_len(AlgoECDSAP384SHA384)).toBe(48);
    });
    test('throws for non-ECDSA inputs', () => {
        expect(() => ecdsa_curve(AlgoRSASHA256)).toThrow(/Not an ECDSA algorithm/);
        expect(() => ecdsa_coord_len(AlgoED25519)).toThrow(/Not an ECDSA algorithm/);
    });
});

describe('algo_to_hash', () => {
    test.each([
        [AlgoRSASHA1, 'sha1'],
        [AlgoRSASHA1NSEC3SHA1, 'sha1'],
        [AlgoRSASHA256, 'sha256'],
        [AlgoRSASHA512, 'sha512'],
        [AlgoECDSAP256SHA256, 'sha256'],
        [AlgoECDSAP384SHA384, 'sha384'],
    ])('maps algorithm %d to %s', (algo, hash) => {
        expect(algo_to_hash(algo)).toBe(hash);
    });

    test('throws for RSAMD5 (recognised but rejected)', () => {
        expect(() => algo_to_hash(AlgoRSAMD5)).toThrow(/Unsupported DNSSEC algorithm/);
    });

    test('throws for EdDSA (built-in hashing; caller branches first)', () => {
        expect(() => algo_to_hash(AlgoED25519)).toThrow(/Unsupported DNSSEC algorithm/);
        expect(() => algo_to_hash(AlgoED448)).toThrow(/Unsupported DNSSEC algorithm/);
    });
});
