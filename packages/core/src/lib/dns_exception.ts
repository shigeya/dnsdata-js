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

// Unknown enum-value errors thrown by the dns_type_table converters.
// Callers can discriminate via `instanceof` instead of message matching
// (RangeError stays in the prototype chain for back-compat with callers
// that look for the broader category).

export class UnknownOpCodeError extends RangeError {
    public readonly value: number | string;
    public constructor(value: number | string, message?: string) {
        super(message ?? `unknown ns_opcode: <${value}>`);
        this.value = value;
        // Set name explicitly so instanceof works after error serialisation.
        this.name = 'UnknownOpCodeError';
    }
}

export class UnknownRCodeError extends RangeError {
    public readonly value: number | string;
    public constructor(value: number | string, message?: string) {
        super(message ?? `unknown ns_rcode: <${value}>`);
        this.value = value;
        this.name = 'UnknownRCodeError';
    }
}

export class UnknownRRTypeError extends RangeError {
    public readonly value: number | string;
    public constructor(value: number | string, message?: string) {
        super(message ?? `unknown ns_type: <${value}>`);
        this.value = value;
        this.name = 'UnknownRRTypeError';
    }
}

export class UnknownRRClassError extends RangeError {
    public readonly value: number | string;
    public constructor(value: number | string, message?: string) {
        super(message ?? `unknown ns_class: <${value}>`);
        this.value = value;
        this.name = 'UnknownRRClassError';
    }
}
