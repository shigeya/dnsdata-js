// Converting between DNS wire format and string(utf)

import { randomBytes } from 'crypto';
import {
    DNSWireError,
    DNSWirePointerLoopError,
    DNSWirePointerForwardError,
} from './dns_exception';

// RFC 1035 §2.3.4 size limits.
const MAX_LABEL_LENGTH = 63;
const MAX_NAME_LENGTH = 255;

// RFC 4034 §6.2 canonical-form: lowercase A-Z only, leave everything else
// (including '_' 0x5F) untouched. The naive `b | 0x20` shortcut also flips
// bit 5 of '_', corrupting it to 0x7F (DEL) and breaking DKIM / DMARC /
// TLSA / MTA-STS lookups that rely on underscore-prefixed labels.
function ascii_to_lower(c: number): number {
    return (c >= 0x41 && c <= 0x5A) ? c + 0x20 : c;
}

export function domain_name2wire(domain_name: string): Uint8Array {
    const bytes: number[] = [];
    const d = domain_name;
    const l = d.length;

    for (let i = 0, j = 0; i < l;) {
        for (j = i; j < l && d[j] != '.'; ++j) {
            ;
        }

        if (j - i != 0) { // if there is text to copy
            const labelLen = j - i;
            // RFC 1035 §2.3.4: labels are <= 63 octets. Writing a longer
            // length octet would silently corrupt the wire (low 8 bits) and
            // may collide with the 0xC0 compression-pointer prefix.
            if (labelLen > MAX_LABEL_LENGTH) {
                throw new DNSWireError(
                    `label too long: ${labelLen} octets (max ${MAX_LABEL_LENGTH}) in "${domain_name}"`,
                );
            }
            bytes.push(labelLen); // length
            for (let k = i; k < j; k++) {
                bytes.push(ascii_to_lower(d.charCodeAt(k)));
            }
        } else if (j < l && i !== 0) {
            // An empty label mid-name (e.g. "a..b") is invalid.
            throw new DNSWireError(`empty label in "${domain_name}"`);
        }

        if (j < l) {
            i = j + 1;
            if (i == l) {
                bytes.push(0x00);
            }
        }
        else {
            i = j;
        }
    }

    // RFC 1035 §2.3.4: total encoded name is <= 255 octets.
    if (bytes.length > MAX_NAME_LENGTH) {
        throw new DNSWireError(
            `name too long: ${bytes.length} octets (max ${MAX_NAME_LENGTH}) in "${domain_name}"`,
        );
    }

    return new Uint8Array(bytes);
}

// parse_domain_name decodes a possibly-compressed DNS name from msg
// starting at offset. It returns the decoded name (terminated by a
// trailing ".") and the offset of the first byte immediately after
// the name *as it appears at offset* — i.e. compression pointers do
// not advance the cursor past the pointer target, only past the
// pointer bytes themselves.
//
// RFC 1035 §4.1.4 compliance:
//   - Pointers MUST point strictly earlier in the message; a pointer
//     to its own position or later raises DNSWirePointerForwardError
//     (the common malicious-input shape).
//   - Length octets 0x40 / 0x80 (reserved extended-label types) are
//     rejected, matching wire2domain_name's behaviour.
//   - Labels exceeding 63 octets are rejected.
//   - The pointer chain is cycle-detected via a `visited` set AND
//     capped at MAX_POINTER_HOPS, so pathological inputs abort fast.
//
// Names are returned in their original case as they appear on the
// wire (no lowercasing). Callers that need a canonical form should
// apply their own normalisation.
//
// Ports the dnsdata-go `wire.ParseDomainName` function (originated
// in dnsdata-go v0.1.0; see UPSTREAM_FEEDBACK.md UP-002).
const MAX_POINTER_HOPS = 32;

export interface ParsedDomainName {
    name: string;
    // Offset of the first byte immediately after the name encoding
    // *as it appeared at the original offset*. Compression pointers
    // advance this by 2 bytes regardless of how long the pointed-to
    // name is.
    next: number;
}

export function parse_domain_name(msg: Uint8Array, offset: number): ParsedDomainName {
    if (offset < 0 || offset >= msg.length) {
        throw new DNSWireError(`truncated: offset ${offset} out of bounds (len=${msg.length})`);
    }

    const labels: string[] = [];
    let pos = offset;
    let next = -1;
    const visited = new Set<number>();
    let hops = 0;

    for (;;) {
        if (pos >= msg.length) {
            throw new DNSWireError(`truncated: at offset ${pos}`);
        }
        const b = msg[pos];

        if (b === 0) {
            pos++;
            if (next < 0) next = pos;
            return { name: assemble_name(labels), next };
        }

        if ((b & 0xC0) === 0xC0) {
            if (pos + 1 >= msg.length) {
                throw new DNSWireError(`truncated: pointer at offset ${pos}`);
            }
            const ptr = ((b & 0x3F) << 8) | msg[pos + 1];
            if (ptr >= pos) {
                throw new DNSWirePointerForwardError(
                    `pointer 0x${ptr.toString(16).padStart(4, '0')} at offset ${pos} does not point earlier`,
                );
            }
            if (next < 0) next = pos + 2;
            if (visited.has(ptr)) {
                throw new DNSWirePointerLoopError(`revisit 0x${ptr.toString(16).padStart(4, '0')}`);
            }
            visited.add(ptr);
            hops++;
            if (hops > MAX_POINTER_HOPS) {
                throw new DNSWirePointerLoopError(`too many pointer hops (>${MAX_POINTER_HOPS})`);
            }
            pos = ptr;
            continue;
        }

        if ((b & 0xC0) !== 0) {
            // 0x40 / 0x80 prefixes are reserved (extended label types).
            throw new DNSWireError(
                `invalid label length byte 0x${b.toString(16).padStart(2, '0')} at offset ${pos}`,
            );
        }

        const length = b;
        if (length > MAX_LABEL_LENGTH) {
            throw new DNSWireError(`label length ${length} at offset ${pos} exceeds ${MAX_LABEL_LENGTH}`);
        }
        pos++;
        if (pos + length > msg.length) {
            throw new DNSWireError(`truncated: label of ${length} octets at offset ${pos}`);
        }
        let label = '';
        for (let k = 0; k < length; k++) {
            label += String.fromCharCode(msg[pos + k]);
        }
        labels.push(label);
        pos += length;
    }
}

function assemble_name(labels: string[]): string {
    if (labels.length === 0) return '.';
    return labels.join('.') + '.';
}

// DNS message header flag bits used by build_query. Layout from
// RFC 1035 §4.1.1; the EDNS-DO bit per RFC 3225 lives in the OPT TTL
// field.
const FLAG_RD = 0x0100;

// OPT pseudo-RR constants for the EDNS(0) record built into every
// query. Mirrors dnsdata-go wire/query.go so DoH and plain DNS share
// the same query shape.
const OPT_TYPE = 41;          // IANA OPT pseudo-RR type (RFC 6891 §6.1.2)
const UDP_PAYLOAD_SIZE = 4096; // OPT.CLASS — RFC 6891 §6.1.2
const DO_BIT = 0x8000;         // DNSSEC OK flag (RFC 3225 §3 / RFC 6891 §6.1.3)
const CLASS_IN = 1;

// random_query_id draws a cryptographically random uint16 for use as
// the DNS transaction ID. Used by resolver/auth (and any caller that
// composes build_query_with_id with a separately-tracked ID for
// response correlation).
//
// Ports the dnsdata-go `wire.RandomQueryID` function (UP-003).
export function random_query_id(): number {
    const b = randomBytes(2);
    return (b[0] << 8) | b[1];
}

// ensure_fqdn appends a trailing dot when the caller didn't. An empty
// string encodes as the root label.
function ensure_fqdn(name: string): string {
    if (name === '') return '.';
    if (name[name.length - 1] === '.') return name;
    return name + '.';
}

// build_query constructs a DNS query message for (qname, qtype) in
// class IN with the RD bit set and an EDNS(0) OPT pseudo-RR in the
// additional section carrying the DO bit. The same wire format works
// for DoH (RFC 8484) and plain UDP / TCP DNS (RFC 1035).
//
// Ports the dnsdata-go `wire.BuildQuery` function (UP-003).
export function build_query(qname: string, qtype: number): Uint8Array {
    return build_query_with_id(random_query_id(), qname, qtype);
}

// build_query_with_id is the deterministic variant of build_query —
// tests and protocols that need to correlate a specific transaction
// ID with a response set it explicitly.
export function build_query_with_id(id: number, qname: string, qtype: number): Uint8Array {
    const name_wire = domain_name2wire(ensure_fqdn(qname));

    // Header (12 bytes): id, flags, qd=1, an=0, ns=0, ar=1 (the OPT).
    // Question (name + qtype + qclass): name_wire.length + 4.
    // OPT pseudo-RR (root + type + class + ttl + rdlen): 11 bytes.
    const buf = new Uint8Array(12 + name_wire.length + 4 + 11);
    const view = new DataView(buf.buffer);
    let p = 0;
    view.setUint16(p, id);          p += 2;
    view.setUint16(p, FLAG_RD);     p += 2;
    view.setUint16(p, 1);           p += 2; // QDCOUNT
    view.setUint16(p, 0);           p += 2; // ANCOUNT
    view.setUint16(p, 0);           p += 2; // NSCOUNT
    view.setUint16(p, 1);           p += 2; // ARCOUNT (one OPT)

    // Question: name + qtype + qclass(IN).
    buf.set(name_wire, p);          p += name_wire.length;
    view.setUint16(p, qtype);       p += 2;
    view.setUint16(p, CLASS_IN);    p += 2;

    // EDNS(0) OPT pseudo-RR: root name (0x00) + type(41) + class(payload size)
    //                       + ttl(DO bit) + rdlen(0).
    buf[p] = 0x00;                  p += 1;
    view.setUint16(p, OPT_TYPE);    p += 2;
    view.setUint16(p, UDP_PAYLOAD_SIZE); p += 2;
    view.setUint32(p, DO_BIT);      p += 4;
    view.setUint16(p, 0);           p += 2;

    return buf;
}

export function wire2domain_name(wire: Uint8Array): string {
    let x = "";
    const l = wire.length;

    for (let i = 0; i < l;) {
        const s = wire[i];
        if (s != 0x00) {
            // RFC 1035 §4.1.4: length octets >= 0x40 are reserved. 0xC0 is a
            // compression pointer (this function doesn't decompress); 0x40 /
            // 0x80 are reserved by the spec. Treat all as invalid here.
            if (s >= 0x40) {
                throw new DNSWireError(
                    `invalid length octet 0x${s.toString(16).padStart(2, '0')} at offset ${i}`,
                );
            }
            // Truncation: declared label length runs past the buffer.
            if (i + 1 + s > l) {
                throw new DNSWireError(
                    `truncated wire: label of ${s} octets at offset ${i} exceeds buffer (length ${l})`,
                );
            }
            if (i != 0) {
                x += ".";
            }
            ++i;
            for (let k = 0; k < s; k++) {
                x += String.fromCharCode(wire[i + k]);
            }
            i += s;
        }
        else { // terminal dot
            ++i;
            x += ".";
        }
    }
    return x;
}
