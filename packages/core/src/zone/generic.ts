// RFC 3597 §5 generic RDATA (`\# <length> <hex>`).
//
// Ports dnsdata-go `zone/generic.go` (UP-010). The ResourceRecord
// methods that use these helpers (generic_rdata, txt_strings, and the
// generic branches of get_handler / get_wire_body) live in dns_zone.ts;
// this module stays free of zone imports so that dns_zone.ts can depend
// on it without an import cycle.

import { DNSZonePresentationFormatError, DNSZoneRDataFormatError } from '../dns_exception';

// GENERIC_RDATA_MARKER introduces the RFC 3597 §5 generic RDATA form.
export const GENERIC_RDATA_MARKER = '\\#';

// MAX_RDATA_LENGTH is the largest RDLENGTH a uint16 can carry.
export const MAX_RDATA_LENGTH = 0xFFFF;

// parse_generic_rdata parses the RFC 3597 §5 generic RDATA form
// `\# <length> <hex>` (the hex may be split by whitespace). Returns null
// when value is not in that form. Throws DNSZonePresentationFormatError
// when it is, but the declared length does not match the hex or the hex
// is malformed.
export function parse_generic_rdata(value: string): Uint8Array | null {
    const fields = value.trim().split(/\s+/);
    if (fields[0] !== GENERIC_RDATA_MARKER) return null;
    if (fields.length < 2) {
        throw new DNSZonePresentationFormatError(`generic RDATA: missing length in "${value}"`);
    }
    const declared = parse_rdata_length(fields[1]);
    const hex = fields.slice(2).join('');
    if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
        throw new DNSZonePresentationFormatError(`generic RDATA hex: invalid hex "${hex}"`);
    }
    const raw = new Uint8Array(Buffer.from(hex, 'hex'));
    if (raw.length !== declared) {
        throw new DNSZonePresentationFormatError(
            `generic RDATA: length ${declared}, hex has ${raw.length} octets`);
    }
    return raw;
}

function parse_rdata_length(field: string): number {
    const n = /^[0-9]+$/.test(field) ? Number(field) : NaN;
    if (!(n <= MAX_RDATA_LENGTH)) {
        throw new DNSZonePresentationFormatError(`generic RDATA: length "${field}"`);
    }
    return n;
}

// split_character_strings splits RDATA made of RFC 1035 §3.3
// <character-string>s, decoding each as UTF-8.
export function split_character_strings(rdata: Uint8Array): string[] {
    const decoder = new TextDecoder();
    const out: string[] = [];
    let pos = 0;
    while (pos < rdata.length) {
        const n = rdata[pos];
        pos++;
        if (pos + n > rdata.length) {
            throw new DNSZoneRDataFormatError('character-string truncated');
        }
        out.push(decoder.decode(rdata.subarray(pos, pos + n)));
        pos += n;
    }
    return out;
}
