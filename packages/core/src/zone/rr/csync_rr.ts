// CSYNC (Child-to-Parent Synchronization) Resource Record (RFC 7477)
//
// Wire format (RFC 7477 §2):
//   SOA_Serial(4) + Flags(2) + Type_Bit_Map(variable)
//
// Flags (RFC 7477 §3):
//   Bit 0 (0x0001): "immediate" - enables immediate processing
//   Bit 1 (0x0002): "soaminimum" - activates serial number validation
//
// Type Bit Map (RFC 7477 §2): Encoded identically to NSEC type bitmap (RFC 4034 §4.1.2).
// We reuse DNSRR_NSEC.encode_type_bitmap() for this encoding.
//
// Presentation format: SOA_serial flags type-list
//   e.g.  66 3 A NS AAAA

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
// RFC 7477 §2: Type Bit Map uses same encoding as NSEC (RFC 4034 §4.1.2).
// Reuse DNSRR_NSEC.encode_type_bitmap() for bitmap encoding.
import { DNSRR_NSEC } from '../../lib/dnssec_rr';
import { DNSZonePresentationFormatError } from '../../lib/dns_exception';

export class DNSRR_CSYNC extends ResourceRecordHandler {
    readonly soa_serial: number;
    readonly flags: number;
    readonly covered_types: number[];
    readonly type_bitmap: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{soa_serial} {flags} {type1} {type2} ..."
        const parts = value.trim().split(/\s+/);
        if (parts.length < 2) {
            throw new DNSZonePresentationFormatError("CSYNC: Presentation format error: " + value);
        }

        this.soa_serial = parseInt(parts[0]);
        this.flags = parseInt(parts[1]);

        // Parse type mnemonics (remaining tokens)
        this.covered_types = [];
        for (let i = 2; i < parts.length; i++) {
            this.covered_types.push(StringToRRType(parts[i]));
        }

        // RFC 7477 §2: Type Bit Map encoded same as NSEC (RFC 4034 §4.1.2)
        this.type_bitmap = DNSRR_NSEC.encode_type_bitmap(this.covered_types);
    }

    // RFC 7477 §2: SOA_Serial(4) + Flags(2) + Type_Bit_Map(variable)
    get_wire_body(builder: WireBuilder): void {
        const rdlen = 4 + 2 + this.type_bitmap.length;
        builder.append_uint16(rdlen);
        builder.append_uint32(this.soa_serial);
        builder.append_uint16(this.flags);
        builder.append_bytes(this.type_bitmap);
    }

    clone(): DNSRR_CSYNC {
        return new DNSRR_CSYNC(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('CSYNC'), (rr, value) => new DNSRR_CSYNC(rr, value));
