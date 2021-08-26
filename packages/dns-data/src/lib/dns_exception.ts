// DNS library exceptions
import { CustomError } from 'ts-custom-error';

//

class DNSZoneException extends CustomError {
    public constructor(message? : string) {
        super(message);
    }
};

class DNSZonePresentationFormatError extends DNSZoneException {
    public constructor(message? : string) {
        super(message);
    }
};

class DNSZoneRDataFormatError extends DNSZoneException {
    public constructor(message? : string) {
        super(message);
    }
};
