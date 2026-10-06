// Verifier error hierarchy. Ports dnsdata-go `verifier/errors.go`.
//
// All verifier-thrown errors inherit from VerifierError so callers
// can route them through one `instanceof` check at the outer
// boundary while still discriminating by subclass when they care.

import type { Result } from './result';

export class VerifierError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierError';
    }
}

export class VerifierConfigError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierConfigError';
    }
}

export class VerifierInvalidQNameError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierInvalidQNameError';
    }
}

export class VerifierResolverError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause?: unknown) {
        super(message);
        this.name = 'VerifierResolverError';
        this.cause = cause;
    }
}

export class VerifierChainTimeoutError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause?: unknown) {
        super(message);
        this.name = 'VerifierChainTimeoutError';
        this.cause = cause;
    }
}

// The classified failures below (dnsdata-go ErrBogus, ErrNoDS, ...)
// are never thrown by validate(): Bogus and Insecure are verdicts, not
// errors. result_error(result) returns one for a Result whose
// reasonCode names it (DESIGN.md §4 MUST 12). VerifierUnsupportedAlgoError
// is also what validate() rejects with when every RRSIG over an rrset
// uses an unsupported algorithm.

// VerifierBogusError: a Bogus verdict (dnsdata-go ErrBogus). The
// failure classes that only occur with a Bogus verdict extend it, so
// `instanceof VerifierBogusError` holds for every error result_error
// returns for a Bogus result.
export class VerifierBogusError extends VerifierError {
    // The code's own error, when its class is not a VerifierBogusError
    // (e.g. a Bogus verdict that carries 'no-ds').
    public readonly cause?: VerifierError;
    constructor(message: string, cause?: VerifierError) {
        super(message);
        this.name = 'VerifierBogusError';
        if (cause !== undefined) this.cause = cause;
    }
}

// VerifierNoDSError (ReasonCode.NoDS): the parent proved with NSEC /
// NSEC3 that a child zone has no DS rrset, so the chain ends there and
// the verdict is Insecure.
export class VerifierNoDSError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierNoDSError';
    }
}

// VerifierNoDNSKEYError (ReasonCode.NoDNSKEY): a zone whose parent holds
// a DS returned no DNSKEY rrset. Bogus.
export class VerifierNoDNSKEYError extends VerifierBogusError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierNoDNSKEYError';
    }
}

// VerifierTrustAnchorMismatchError (ReasonCode.TrustAnchorMismatch): no
// root DNSKEY matches a configured trust anchor. Bogus.
export class VerifierTrustAnchorMismatchError extends VerifierBogusError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierTrustAnchorMismatchError';
    }
}

// VerifierDSMismatchError (ReasonCode.DSMismatch): no DNSKEY of a child
// zone matches a DS record at its parent. Bogus.
export class VerifierDSMismatchError extends VerifierBogusError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierDSMismatchError';
    }
}

// VerifierSigExpiredError (ReasonCode.SigExpired, SigNotYetValid): an
// RRSIG fell outside its validity window at the verifier's clock. Bogus.
export class VerifierSigExpiredError extends VerifierBogusError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierSigExpiredError';
    }
}

// VerifierSigInvalidError (ReasonCode.SigInvalid, NoMatchingKey,
// NoRRSIG): no RRSIG over an rrset verified because the signature did
// not verify, no key matched it, or there was none. Bogus.
export class VerifierSigInvalidError extends VerifierBogusError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierSigInvalidError';
    }
}

// VerifierUnsupportedAlgoError (ReasonCode.UnsupportedAlgorithm): every
// signature over an rrset uses a DNSSEC algorithm this verifier does not
// implement. validate() rejects with it; `result` is then the
// Indeterminate Result carrying the code (dnsdata-go returns that Result
// together with its ErrVerifier error). result_error returns it without
// `result`.
export class VerifierUnsupportedAlgoError extends VerifierError {
    readonly result?: Result;
    constructor(message: string, result?: Result) {
        super(message);
        this.name = 'VerifierUnsupportedAlgoError';
        if (result !== undefined) this.result = result;
    }
}
