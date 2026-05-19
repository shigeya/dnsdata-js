// URI Resource Record (RFC 7553)
//
// Wire format (RFC 7553 §4.5):
//   priority(2) + weight(2) + target(variable, raw octets — NOT length-prefixed)
//
// The target field contains the URI as a sequence of octets (UTF-8 encoded).
// Unlike TXT records, there is no length prefix on the target string in wire format.
//
// Presentation format (RFC 7553 §4.4):
//   priority weight "target-URI"
//
// Example:
//   _http._tcp.example.com.  IN  URI  10 1 "http://www.example.com/path"

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

export class DNSRR_URI extends ResourceRecordHandler {
    readonly priority: number;
    readonly weight: number;
    readonly target: string;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        const result = parseURI(value);
        this.priority = result.priority;
        this.weight = result.weight;
        this.target = result.target;
    }

    // RFC 7553 §4.5: priority(2) + weight(2) + target(raw octets)
    get_wire_body(builder: WireBuilder): void {
        const target_buf = Buffer.from(this.target, 'utf-8');
        const rdlen = 2 + 2 + target_buf.length;

        builder.append_uint16(rdlen);
        builder.append_uint16(this.priority);
        builder.append_uint16(this.weight);
        builder.append_bytes(target_buf);
    }

    clone(): DNSRR_URI {
        return new DNSRR_URI(this._rr, this.value);
    }
}

// Parse URI presentation format: priority weight "target"
function parseURI(value: string): { priority: number; weight: number; target: string } {
    const trimmed = value.trim();

    // Match: priority(number) weight(number) "target"
    const m = trimmed.match(/^(\d+)\s+(\d+)\s+"([^"]*)"$/);
    if (!m) {
        throw new DNSZonePresentationFormatError("URI: invalid format: " + value);
    }

    return {
        priority: parseInt(m[1]),
        weight: parseInt(m[2]),
        target: m[3],
    };
}

