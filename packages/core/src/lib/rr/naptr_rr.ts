// NAPTR Resource Record (RFC 3403)
//
// Wire format (RFC 3403 §4.1):
//   order(2) + preference(2) + flags(character-string) + services(character-string)
//   + regexp(character-string) + replacement(domain-name)
//
// Character-string: length(1) + data(variable), as per RFC 1035 §3.3.
//
// Presentation format:
//   order preference "flags" "services" "regexp" replacement
//
// Used for DDDS (Dynamic Delegation Discovery System) applications
// including ENUM (E.164 to URI mapping) and SIP.

import { WireBuilder } from '../../wire/dns_wire_util';
import { domain_name2wire } from '../../wire/dns_wire';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';

export class DNSRR_NAPTR extends ResourceRecordHandler {
    readonly order: number;
    readonly preference: number;
    readonly flags: string;
    readonly services: string;
    readonly regexp: string;
    readonly replacement: string;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: order preference "flags" "services" "regexp" replacement
        // Flags, services, and regexp are quoted strings; replacement is a domain name.
        const result = parseNAPTR(value);
        this.order = result.order;
        this.preference = result.preference;
        this.flags = result.flags;
        this.services = result.services;
        this.regexp = result.regexp;
        this.replacement = result.replacement;
    }

    // RFC 3403 §4.1: Wire format
    get_wire_body(builder: WireBuilder): void {
        const flags_buf = Buffer.from(this.flags, 'utf-8');
        const services_buf = Buffer.from(this.services, 'utf-8');
        const regexp_buf = Buffer.from(this.regexp, 'utf-8');
        const replacement_wire = domain_name2wire(this.replacement);

        const rdlen = 2 + 2
            + 1 + flags_buf.length
            + 1 + services_buf.length
            + 1 + regexp_buf.length
            + replacement_wire.length;

        builder.append_uint16(rdlen);
        builder.append_uint16(this.order);
        builder.append_uint16(this.preference);

        // flags as character-string
        builder.append_uint8(flags_buf.length);
        builder.append_bytes(flags_buf);

        // services as character-string
        builder.append_uint8(services_buf.length);
        builder.append_bytes(services_buf);

        // regexp as character-string
        builder.append_uint8(regexp_buf.length);
        builder.append_bytes(regexp_buf);

        // replacement as uncompressed domain name
        builder.append_bytes(replacement_wire);
    }

    clone(): DNSRR_NAPTR {
        return new DNSRR_NAPTR(this._rr, this.value);
    }
}

// Parse NAPTR presentation format
// RFC 3403 §4.1: order preference "flags" "services" "regexp" replacement
function parseNAPTR(value: string): {
    order: number; preference: number; flags: string;
    services: string; regexp: string; replacement: string;
} {
    const trimmed = value.trim();
    let pos = 0;

    // Parse order (integer)
    const orderMatch = trimmed.substring(pos).match(/^(\d+)\s+/);
    if (!orderMatch) {
        throw new DNSZonePresentationFormatError("NAPTR: invalid format: " + value);
    }
    const order = parseInt(orderMatch[1]);
    pos += orderMatch[0].length;

    // Parse preference (integer)
    const prefMatch = trimmed.substring(pos).match(/^(\d+)\s+/);
    if (!prefMatch) {
        throw new DNSZonePresentationFormatError("NAPTR: invalid format: " + value);
    }
    const preference = parseInt(prefMatch[1]);
    pos += prefMatch[0].length;

    // Parse three quoted strings: flags, services, regexp
    const flags = parseQuotedString(trimmed, pos);
    pos = flags.nextPos;

    const services = parseQuotedString(trimmed, pos);
    pos = services.nextPos;

    const regexp = parseQuotedString(trimmed, pos);
    pos = regexp.nextPos;

    // Parse replacement (domain name) - remainder of the string
    const replacement = trimmed.substring(pos).trim().split(/\s+/)[0];
    if (!replacement) {
        throw new DNSZonePresentationFormatError("NAPTR: missing replacement: " + value);
    }

    return { order, preference, flags: flags.value, services: services.value, regexp: regexp.value, replacement };
}

// Parse a quoted string at position, returns value and next position after closing quote + whitespace
function parseQuotedString(s: string, pos: number): { value: string; nextPos: number } {
    // Skip whitespace
    while (pos < s.length && /\s/.test(s[pos])) pos++;

    if (pos >= s.length || s[pos] !== '"') {
        throw new DNSZonePresentationFormatError("NAPTR: expected quoted string at position " + pos);
    }
    pos++; // skip opening quote

    let value = '';
    while (pos < s.length && s[pos] !== '"') {
        if (s[pos] === '\\' && pos + 1 < s.length) {
            pos++;
            value += s[pos];
        } else {
            value += s[pos];
        }
        pos++;
    }

    if (pos >= s.length) {
        throw new DNSZonePresentationFormatError("NAPTR: unterminated quoted string");
    }
    pos++; // skip closing quote

    // Skip trailing whitespace
    while (pos < s.length && /\s/.test(s[pos])) pos++;

    return { value, nextPos: pos };
}

register_rr_handler(StringToRRType('NAPTR'), (rr, value) => new DNSRR_NAPTR(rr, value));
