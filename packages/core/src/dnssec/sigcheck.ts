// Why an RRSIG check failed: SigStatus, SigResult and the helpers
// behind DNSSecZone.check_rrsig / check_rrset.
//
// Ports dnsdata-go `dnssec/sigcheck.go`.

import { DNSSecUnsupportedAlgorithmError } from '../dns_exception';
import { AlgoED448, AlgorithmSupported } from '../types/algorithm';
import type { DNSKey } from './dnskey';
import type { RRSig } from './rrsig';

// SigStatus classifies the outcome of checking one RRSIG
// (DNSSecZone.check_rrsig). Its values are the stable, kebab-case names
// the verifier puts into JSON.
export enum SigStatus {
    // The signature verified (in the requested key mode).
    Verified = 'verified',
    // The zone's clock is after the RRSIG's expiration.
    Expired = 'expired',
    // The zone's clock is before the RRSIG's inception.
    NotYetValid = 'not-yet-valid',
    // The signing key uses an algorithm this library does not implement
    // (DNSSecUnsupportedAlgorithmError).
    UnsupportedAlgorithm = 'unsupported-algorithm',
    // No DNSKEY at the signer name has the RRSIG's key tag and
    // algorithm, or none of those keys is accepted in the requested
    // KeyVerifyMode (e.g. in KSK mode, a key that is neither trusted
    // nor matched by a parent DS).
    NoMatchingKey = 'no-matching-key',
    // The signature does not verify over the rrset under any accepted
    // key, or the key or signature is malformed, or the covered rrset is
    // absent.
    Invalid = 'invalid',
}

// SigResult is the outcome of checking one RRSIG. error is set when the
// check could not be carried out (an unsupported algorithm, a malformed
// key, an rrset that does not encode): the errors verify_rrsig throws.
export interface SigResult {
    rrsig: RRSig;
    status: SigStatus;
    error?: Error;
}

// SigVerdict is a status with the error met while deciding it.
export interface SigVerdict {
    status: SigStatus;
    error?: Error;
}

// rrset_verified applies RFC 4035 §5.3.3 "any-valid" semantics to
// results: verified when one signature verified, otherwise not, with the
// first error met (none when there is none). This is what
// DNSSecZone.verify_rrset decides for the same rrset.
export function rrset_verified(results: readonly SigResult[]): { verified: boolean; error?: Error } {
    let first: Error | undefined;
    for (const r of results) {
        if (r.status === SigStatus.Verified) return { verified: true };
        if (first === undefined && r.error !== undefined) first = r.error;
    }
    return first === undefined ? { verified: false } : { verified: false, error: first };
}

// verifiable_algorithm reports whether DNSKey.verify implements
// algorithm: the algorithms AlgorithmSupported names, plus Ed448, which
// Node's crypto verifies (dnsdata-go does not).
export function verifiable_algorithm(algorithm: number): boolean {
    return AlgorithmSupported(algorithm) || algorithm === AlgoED448;
}

// verify_with_any checks signature over data under each key in turn:
// Verified as soon as one verifies, otherwise the status and error of
// the first key.
export function verify_with_any(keys: readonly DNSKey[], data: Uint8Array, signature: Uint8Array): SigVerdict {
    let first: SigVerdict = { status: SigStatus.Invalid };
    for (let i = 0; i < keys.length; i++) {
        const v = verify_status(keys[i], data, signature);
        if (v.status === SigStatus.Verified) return v;
        if (i === 0) first = v;
    }
    return first;
}

// verify_status maps DNSKey.verify's outcome to a status.
function verify_status(key: DNSKey, data: Uint8Array, signature: Uint8Array): SigVerdict {
    if (!verifiable_algorithm(key.algorithm)) {
        return {
            status: SigStatus.UnsupportedAlgorithm,
            error: new DNSSecUnsupportedAlgorithmError(`dnssec: unsupported algorithm ${key.algorithm}`),
        };
    }
    try {
        return { status: key.verify(data, signature) ? SigStatus.Verified : SigStatus.Invalid };
    } catch (e: unknown) {
        return { status: SigStatus.Invalid, error: as_error(e) };
    }
}

// as_error returns e as an Error.
export function as_error(e: unknown): Error {
    return e instanceof Error ? e : new Error(String(e));
}
