// Converting between DNS wire format and string(utf)

import { DNSWireError } from './dns_exception';

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
