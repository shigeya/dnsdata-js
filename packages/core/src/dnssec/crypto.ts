// DNSSEC algorithm-to-crypto-primitive dispatchers.
//
// Maps DNSSEC algorithm numbers (see ../types/algorithm.ts) to the
// Node.js crypto identifiers consumed by createPublicKey / createSign
// / createVerify. Mirrors dnsdata-go's `dnssec/crypto.go` dispatchers
// (ecdsaCurveFor / rsaHash / ecdsaHash); JS uses string algorithm
// names where Go uses `crypto.Hash` / `elliptic.Curve`.
//
// The public-key loaders and DER↔raw signature converters that
// dnssec/crypto.go also exposes live in dnssec_rr.ts for now; they
// move into this file under P6 (the dnssec_rr.ts split).

import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoED448,
    AlgoRSASHA1,
    AlgoRSASHA1NSEC3SHA1,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../types/algorithm';

// is_ecdsa_algorithm reports whether algorithm is one of the DNSSEC
// ECDSA algorithms (RFC 6605): P-256 / SHA-256 or P-384 / SHA-384.
export function is_ecdsa_algorithm(algorithm: number): boolean {
    return algorithm === AlgoECDSAP256SHA256 || algorithm === AlgoECDSAP384SHA384;
}

// is_eddsa_algorithm reports whether algorithm is one of the DNSSEC
// EdDSA algorithms (RFC 8080): Ed25519 or Ed448.
export function is_eddsa_algorithm(algorithm: number): boolean {
    return algorithm === AlgoED25519 || algorithm === AlgoED448;
}

// ecdsa_curve returns the JWK curve name for a DNSSEC ECDSA
// algorithm. Throws for non-ECDSA inputs so callers don't silently
// fall through to an unrelated curve.
export function ecdsa_curve(algorithm: number): string {
    switch (algorithm) {
        case AlgoECDSAP256SHA256: return 'P-256';
        case AlgoECDSAP384SHA384: return 'P-384';
    }
    throw new Error(`Not an ECDSA algorithm: ${algorithm}`);
}

// ecdsa_coord_len returns the byte length of a single coordinate
// (x or y, r or s) for a DNSSEC ECDSA algorithm: 32 bytes for P-256,
// 48 bytes for P-384.
export function ecdsa_coord_len(algorithm: number): number {
    switch (algorithm) {
        case AlgoECDSAP256SHA256: return 32;
        case AlgoECDSAP384SHA384: return 48;
    }
    throw new Error(`Not an ECDSA algorithm: ${algorithm}`);
}

// algo_to_hash returns the Node-crypto hash algorithm name paired with
// a DNSSEC RSA or ECDSA algorithm. EdDSA (15, 16) uses built-in
// hashing in createSign / createVerify and is intentionally not
// covered here — callers should branch on is_eddsa_algorithm first.
//
// RSAMD5 (algorithm 1) is intentionally not mapped: it is recognised
// by AlgorithmToString but deprecated per RFC 6944 and is never an
// acceptable validator input.
export function algo_to_hash(algorithm: number): string {
    switch (algorithm) {
        case AlgoRSASHA1:
        case AlgoRSASHA1NSEC3SHA1:  return 'sha1';
        case AlgoRSASHA256:         return 'sha256';
        case AlgoRSASHA512:         return 'sha512';
        case AlgoECDSAP256SHA256:   return 'sha256';
        case AlgoECDSAP384SHA384:   return 'sha384';
    }
    throw new Error(`Unsupported DNSSEC algorithm: ${algorithm}`);
}
