// Verifier error hierarchy. Ports dnsdata-go `verifier/errors.go`.
//
// All verifier-thrown errors inherit from VerifierError so callers
// can route them through one `instanceof` check at the outer
// boundary while still discriminating by subclass when they care.

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

export class VerifierTrustAnchorMismatchError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierTrustAnchorMismatchError';
    }
}
