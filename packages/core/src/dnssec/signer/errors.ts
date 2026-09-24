// Errors of the zone signer. Ports the sentinel errors of dnsdata-go
// `dnssec/signer` (ErrSigner, ErrKeyFormat, ErrUnsupportedAlgorithm):
// callers discriminate with `instanceof`, and every error the signer
// throws is a SignerError.

import { CustomError } from 'ts-custom-error';

// SignerError is the umbrella error of the signer (Go `ErrSigner`).
export class SignerError extends CustomError {
    public constructor(message?: string) {
        super(message);
    }
}

// SignerKeyFormatError reports a private key that cannot be parsed or
// does not suit the declared algorithm (Go `ErrKeyFormat`).
export class SignerKeyFormatError extends SignerError {
    public constructor(message?: string) {
        super(message);
    }
}

// SignerUnsupportedAlgorithmError reports a DNSSEC algorithm or DS
// digest type the signer does not produce (Go `ErrUnsupportedAlgorithm`).
export class SignerUnsupportedAlgorithmError extends SignerError {
    public constructor(message?: string) {
        super(message);
    }
}

// error_message returns the message of an unknown thrown value.
export function error_message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
}
