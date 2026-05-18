// DNS library exceptions
import { CustomError } from 'ts-custom-error';

//

export class DNSZoneException extends CustomError {
    public constructor(message? : string) {
        super(message);
    }
};

export class DNSZonePresentationFormatError extends DNSZoneException {
    public constructor(message? : string) {
        super(message);
    }
};

export class DNSZoneRDataFormatError extends DNSZoneException {
    public constructor(message? : string) {
        super(message);
    }
};

// Wire format errors (RFC 1035 §2.3.4 / §4.1.4): label or name overflow,
// invalid length octets, and truncated input.
export class DNSWireError extends CustomError {
    public constructor(message? : string) {
        super(message);
    }
};
