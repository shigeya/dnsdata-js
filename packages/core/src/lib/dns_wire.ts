// Converting between DNS wire format and string(utf)

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
