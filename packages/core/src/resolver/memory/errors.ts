// Errors of the in-memory authority. Ports the sentinel error of
// dnsdata-go `resolver/memory` (ErrConfig).

import { CustomError } from 'ts-custom-error';

// MemoryConfigError reports an invalid [new_authority] configuration
// (Go `ErrConfig`): no zones, a relative or repeated apex, a missing
// zone, a record outside its zone, or an RRSIG / NSEC that does not
// parse.
export class MemoryConfigError extends CustomError {
    public constructor(message: string) {
        super(`memory authority: configuration: ${message}`);
    }
}
