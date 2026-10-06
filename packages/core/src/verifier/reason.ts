// Machine-readable failure reasons: ReasonCode, result_error, and the
// rrset check the chain walker names RRSIG failures with.
//
// Ports dnsdata-go `verifier/reason.go`.

import { DNSSecZone, KeyVerifyMode } from '../dnssec/dnssec_zone';
import { SigResult, SigStatus, rrset_verified } from '../dnssec/sigcheck';
import { Verdict } from './verdict';
import { HopOutcome, Result } from './result';
import {
    VerifierBogusError, VerifierDSMismatchError, VerifierError, VerifierNoDNSKEYError, VerifierNoDSError,
    VerifierSigExpiredError, VerifierSigInvalidError, VerifierTrustAnchorMismatchError,
    VerifierUnsupportedAlgoError,
} from './errors';
import { qtype_mnemonic } from './verifier';

// ReasonCode: the machine-readable cause in Result.reasonCode. Each maps
// to the Error subclass result_error returns (VerifierBogusError alone
// where none is named).
export enum ReasonCode {
    // Insecure delegation proven by NSEC / NSEC3 → VerifierNoDSError.
    NoDS = 'no-ds',
    // A child zone with a DS has no DNSKEY → VerifierNoDNSKEYError.
    NoDNSKEY = 'no-dnskey',
    // No root KSK matches a trust anchor (or none is configured) →
    // VerifierTrustAnchorMismatchError.
    TrustAnchorMismatch = 'trust-anchor-mismatch',
    // No child DNSKEY matches a parent DS → VerifierDSMismatchError.
    DSMismatch = 'ds-mismatch',
    // An rrset that must be signed has no RRSIG → VerifierSigInvalidError.
    NoRRSIG = 'no-rrsig',
    // No DNSKEY matches the RRSIGs (signer, key tag, algorithm), or the
    // key is not authenticated → VerifierSigInvalidError.
    NoMatchingKey = 'no-matching-key',
    // A signature does not verify → VerifierSigInvalidError.
    SigInvalid = 'sig-invalid',
    // The clock is after the expiration → VerifierSigExpiredError.
    SigExpired = 'sig-expired',
    // The clock is before the inception → VerifierSigExpiredError.
    SigNotYetValid = 'sig-not-yet-valid',
    // Every RRSIG uses an algorithm the library does not implement →
    // VerifierUnsupportedAlgoError. Set on the Indeterminate Result
    // carried by the error validate() rejects with.
    UnsupportedAlgorithm = 'unsupported-algorithm',
    // A CNAME / DNAME chain revisits a name → VerifierBogusError.
    AliasLoop = 'alias-loop',
    // More than MAX_ALIAS_HOPS redirects → VerifierBogusError.
    AliasLimit = 'alias-limit',
    // A CNAME / DNAME target is empty or cannot be synthesised →
    // VerifierBogusError.
    AliasTargetInvalid = 'alias-target-invalid',
    // A wildcard-synthesised answer lacks the proof that the next closer
    // name does not exist → VerifierBogusError.
    WildcardProofMissing = 'wildcard-proof-missing',
}

type ErrorFactory = (message: string) => VerifierError;

// CODE_ERRORS maps a code to its error class; codes not listed map to
// VerifierBogusError alone.
const CODE_ERRORS: ReadonlyMap<ReasonCode, ErrorFactory> = new Map<ReasonCode, ErrorFactory>([
    [ReasonCode.NoDS, (m) => new VerifierNoDSError(m)],
    [ReasonCode.NoDNSKEY, (m) => new VerifierNoDNSKEYError(m)],
    [ReasonCode.TrustAnchorMismatch, (m) => new VerifierTrustAnchorMismatchError(m)],
    [ReasonCode.DSMismatch, (m) => new VerifierDSMismatchError(m)],
    [ReasonCode.NoRRSIG, (m) => new VerifierSigInvalidError(m)],
    [ReasonCode.NoMatchingKey, (m) => new VerifierSigInvalidError(m)],
    [ReasonCode.SigInvalid, (m) => new VerifierSigInvalidError(m)],
    [ReasonCode.SigExpired, (m) => new VerifierSigExpiredError(m)],
    [ReasonCode.SigNotYetValid, (m) => new VerifierSigExpiredError(m)],
    [ReasonCode.UnsupportedAlgorithm, (m) => new VerifierUnsupportedAlgoError(m)],
]);

// result_error returns the failure of result as an Error, or undefined
// when it has no reasonCode (Secure, SecureNoData, SecureNXDomain, and
// an Indeterminate without a known cause). The error is an instance of
// the code's class; for a Bogus verdict it is also a VerifierBogusError
// (dnsdata-go's Result.Err wraps ErrBogus as well as the code's
// sentinel). Its message carries "<code> at <zone>: <reason>" from
// bogusAt / bogusReason or insecureAt / insecureReason:
//
//   if (result_error(res) instanceof VerifierSigExpiredError) { ... }
export function result_error(result: Result): VerifierError | undefined {
    const code = result.reasonCode;
    if (code === undefined) return undefined;
    const message = `verifier: ${failure_detail(result, code)}`;
    const make = CODE_ERRORS.get(code);
    if (make === undefined) return new VerifierBogusError(message);
    const err = make(message);
    if (result.verdict === Verdict.Bogus && !(err instanceof VerifierBogusError)) {
        // A code whose class is not a Bogus one on a Bogus verdict:
        // keep both, the code's error as the cause.
        return new VerifierBogusError(message, err);
    }
    return err;
}

// failure_detail renders "<code> at <zone>: <reason>" from the fields
// that go with the verdict.
function failure_detail(result: Result, code: ReasonCode): string {
    const insecure = result.verdict === Verdict.Insecure;
    const where = insecure ? result.insecureAt : result.bogusAt;
    const reason = insecure ? result.insecureReason : result.bogusReason;
    let detail: string = code;
    if (where) detail += ` at ${where}`;
    if (reason) detail += `: ${reason}`;
    return detail;
}

// SIG_FAILURE_ORDER ranks RRSIG failures: the code of the first status
// present among an rrset's RRSIGs names the rrset's failure.
const SIG_FAILURE_ORDER: ReadonlyArray<[SigStatus, ReasonCode]> = [
    [SigStatus.Expired, ReasonCode.SigExpired],
    [SigStatus.NotYetValid, ReasonCode.SigNotYetValid],
    [SigStatus.Invalid, ReasonCode.SigInvalid],
    [SigStatus.NoMatchingKey, ReasonCode.NoMatchingKey],
    [SigStatus.UnsupportedAlgorithm, ReasonCode.UnsupportedAlgorithm],
];

// sig_failure_code names why an rrset whose RRSIGs are results did not
// verify. UnsupportedAlgorithm comes out only when every RRSIG has an
// unsupported algorithm.
export function sig_failure_code(results: readonly SigResult[]): ReasonCode {
    if (results.length === 0) return ReasonCode.NoRRSIG;
    for (const [status, code] of SIG_FAILURE_ORDER) {
        if (results.some((r) => r.status === status)) return code;
    }
    return ReasonCode.SigInvalid;
}

// RRSetCheck is the outcome of checking every RRSIG over one rrset.
export interface RRSetCheck {
    ok: boolean;
    // why it failed, when !ok
    code?: ReasonCode;
}

// check_rrset verifies (name, rrtype) in z under mode with "any-valid"
// semantics (RFC 4035 §5.3.3), keeping each RRSIG's outcome. When the
// check cannot be carried out (no RRSIG verified and one met an error)
// it throws: VerifierUnsupportedAlgoError carrying result, with
// result.reasonCode set, when every RRSIG used an unsupported
// algorithm, otherwise a VerifierError naming the cause.
export function check_rrset(z: DNSSecZone, name: string, rrtype: number, mode: KeyVerifyMode,
                            result: Result): RRSetCheck {
    const results = z.check_rrset(name, rrtype, mode);
    const { verified, error } = rrset_verified(results);
    const check: RRSetCheck = verified ? { ok: true } : { ok: false, code: sig_failure_code(results) };
    if (error === undefined) return check;
    const message = `verifier: ${name}/${qtype_mnemonic(rrtype)}: ${error.message}`;
    if (check.code === ReasonCode.UnsupportedAlgorithm) {
        result.reasonCode = check.code;
        throw new VerifierUnsupportedAlgoError(message, result);
    }
    throw new VerifierError(message);
}

// bogus_outcome is the terminal hop outcome of a Bogus verdict.
export function bogus_outcome(at: string, reason: string, code: ReasonCode | undefined): HopOutcome {
    const out: HopOutcome = { verdict: Verdict.Bogus, bogusAt: at, bogusReason: reason };
    if (code !== undefined) out.reasonCode = code;
    return out;
}
