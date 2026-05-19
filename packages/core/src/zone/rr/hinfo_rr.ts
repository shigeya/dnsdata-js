// HINFO Resource Record (RFC 1035 §3.3.2)
//
// Wire format (RFC 1035 §3.3.2):
//   cpu<character-string> + os<character-string>
//
// Each <character-string> is a length octet followed by that number of octets (RFC 1035 §3.3).
//
// Presentation format: CPU OS (quoted strings allowed)
//   e.g. "INTEL-386" "UNIX"  or  INTEL-386 UNIX

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

// Parse two character-strings from presentation format (supports quoted and unquoted)
function parseTwoStrings(value: string): [string, string] {
    const trimmed = value.trim();
    const strings: string[] = [];
    let pos = 0;

    for (let i = 0; i < 2; i++) {
        // Skip whitespace
        while (pos < trimmed.length && /\s/.test(trimmed[pos])) pos++;
        if (pos >= trimmed.length) break;

        if (trimmed[pos] === '"') {
            // Quoted string
            pos++; // skip opening quote
            let s = '';
            while (pos < trimmed.length && trimmed[pos] !== '"') {
                if (trimmed[pos] === '\\' && pos + 1 < trimmed.length) {
                    pos++;
                }
                s += trimmed[pos];
                pos++;
            }
            if (pos < trimmed.length) pos++; // skip closing quote
            strings.push(s);
        } else {
            // Unquoted token
            const start = pos;
            while (pos < trimmed.length && !/\s/.test(trimmed[pos])) pos++;
            strings.push(trimmed.substring(start, pos));
        }
    }

    if (strings.length < 2) {
        throw new DNSZonePresentationFormatError("HINFO: expected two character-strings (CPU OS): " + value);
    }
    return [strings[0], strings[1]];
}

export class DNSRR_HINFO extends ResourceRecordHandler {
    readonly cpu: string;
    readonly os: string;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        [this.cpu, this.os] = parseTwoStrings(value);
    }

    // RFC 1035 §3.3.2: RDATA = cpu<character-string> + os<character-string>
    // Each character-string: length(1) + data(variable)
    get_wire_body(builder: WireBuilder): void {
        const cpuBuf = Buffer.from(this.cpu, 'utf-8');
        const osBuf = Buffer.from(this.os, 'utf-8');
        const rdlen = 1 + cpuBuf.length + 1 + osBuf.length;
        builder.append_uint16(rdlen);
        builder.append_uint8(cpuBuf.length);
        builder.append_bytes(cpuBuf);
        builder.append_uint8(osBuf.length);
        builder.append_bytes(osBuf);
    }

    clone(): DNSRR_HINFO {
        return new DNSRR_HINFO(this._rr, this.value);
    }
}

