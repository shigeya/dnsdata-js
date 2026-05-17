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
