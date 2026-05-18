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

// RFC 1035 §4.1.4 compression-pointer cycle. Surfaces when a pointer
// chain in parse_domain_name revisits an offset it has already
// traversed, or when the hop cap is exceeded on pathological input.
export class DNSWirePointerLoopError extends DNSWireError {
    public constructor(message? : string) {
        super(message);
    }
};

// RFC 1035 §4.1.4 requires compression pointers to point *earlier* in
// the message. A pointer that points at or past its own position is
// malformed (and a common malicious-input shape).
export class DNSWirePointerForwardError extends DNSWireError {
    public constructor(message? : string) {
        super(message);
    }
};

// parse_message / parse_rr detected a structurally invalid DNS
// message (header truncated, section RR header truncated, RDATA
// length overruns the buffer, unsupported QDCount, etc.).
export class DNSMessageMalformedError extends DNSWireError {
    public constructor(message? : string) {
        super(message);
    }
};

// rdata_to_string saw an RDATA payload whose length / shape does not
// match the per-type encoding (e.g. A rdata length != 4, NSEC3 salt
// runs off the end).
export class DNSRDataDecodeError extends DNSWireError {
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
