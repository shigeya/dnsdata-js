// EUI48 (type 108) and EUI64 (type 109) Resource Records (RFC 7043)
//
// EUI48 wire format (RFC 7043 §3.1):
//   Address(6 octets) — EUI-48 address in network byte order
//
// EUI64 wire format (RFC 7043 §4.1):
//   Address(8 octets) — EUI-64 address in network byte order
//
// Presentation format (RFC 7043 §3.3 / §4.3):
//   Hex digits separated by hyphens: e.g. "00-00-5e-00-53-2a"

import { WireBuilder } from '../dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';

// RFC 7043 §3/§4: EUI48 and EUI64 share the same structure (fixed-length address).
// This class handles both; only the expected byte length differs.
export class DNSRR_EUI extends ResourceRecordHandler {
    readonly address: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string, private readonly expectedLength: number) {
        super(rr);
        // RFC 7043 §3.3/§4.3: Presentation format is hex digits separated by hyphens
        const parts = value.trim().split('-');
        if (parts.length !== expectedLength) {
            const typeName = expectedLength === 6 ? 'EUI48' : 'EUI64';
            throw new DNSZonePresentationFormatError(
                `${typeName}: expected ${expectedLength} hex octets separated by hyphens: ${value}`);
        }
        this.address = new Uint8Array(expectedLength);
        for (let i = 0; i < expectedLength; i++) {
            this.address[i] = parseInt(parts[i], 16);
        }
    }

    // RFC 7043 §3.1/§4.1: RDATA = fixed-length address in network byte order
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(this.address.length);  // rdlen
        builder.append_bytes(this.address);
    }

    clone(): DNSRR_EUI {
        return new DNSRR_EUI(this._rr, this.value, this.expectedLength);
    }
}

// Register EUI48 (type 108) handler
register_rr_handler(StringToRRType('EUI48'), (rr, value) => new DNSRR_EUI(rr, value, 6));

// Register EUI64 (type 109) handler
// RFC 7043 §4: EUI64 uses the same structure as EUI48 but with 8-octet address.
register_rr_handler(StringToRRType('EUI64'), (rr, value) => new DNSRR_EUI(rr, value, 8));
