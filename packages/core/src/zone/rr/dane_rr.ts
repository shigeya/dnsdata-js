// DANE Resource Records (TLSA / SMIMEA)
//
// RFC 6698 (TLSA), RFC 8162 (SMIMEA)
// Both share identical wire format:
//   usage(1) + selector(1) + matching_type(1) + certificate_association_data(variable)

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

export class DNSRR_TLSA extends ResourceRecordHandler {
    readonly usage: number;
    readonly selector: number;
    readonly matching_type: number;
    readonly certificate_association_data: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{usage} {selector} {matching_type} {hex_data}"
        const m = value.match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) throw new DNSZonePresentationFormatError("TLSA: Presentation format error: " + value);

        this.usage = parseInt(m[1]);
        this.selector = parseInt(m[2]);
        this.matching_type = parseInt(m[3]);
        this.certificate_association_data = new Uint8Array(Buffer.from(m[4].replace(/\s+/g, ''), 'hex'));
    }

    // TLSA RDATA wire: rdlen(2) + usage(1) + selector(1) + matching_type(1) + data
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(3 + this.certificate_association_data.length);
        builder.append_uint8(this.usage);
        builder.append_uint8(this.selector);
        builder.append_uint8(this.matching_type);
        builder.append_bytes(this.certificate_association_data);
    }

    clone(): DNSRR_TLSA {
        return new DNSRR_TLSA(this._rr, this.value);
    }
}

export class DNSRR_SMIMEA extends ResourceRecordHandler {
    readonly usage: number;
    readonly selector: number;
    readonly matching_type: number;
    readonly certificate_association_data: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{usage} {selector} {matching_type} {hex_data}"
        const m = value.match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) throw new DNSZonePresentationFormatError("SMIMEA: Presentation format error: " + value);

        this.usage = parseInt(m[1]);
        this.selector = parseInt(m[2]);
        this.matching_type = parseInt(m[3]);
        this.certificate_association_data = new Uint8Array(Buffer.from(m[4].replace(/\s+/g, ''), 'hex'));
    }

    // SMIMEA RDATA wire: rdlen(2) + usage(1) + selector(1) + matching_type(1) + data
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(3 + this.certificate_association_data.length);
        builder.append_uint8(this.usage);
        builder.append_uint8(this.selector);
        builder.append_uint8(this.matching_type);
        builder.append_bytes(this.certificate_association_data);
    }

    clone(): DNSRR_SMIMEA {
        return new DNSRR_SMIMEA(this._rr, this.value);
    }
}

// Register handlers
