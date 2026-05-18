// CERT Resource Record (RFC 4398)
//
// Wire format (RFC 4398 §2):
//   type(2) + key_tag(2) + algorithm(1) + certificate(variable)
//
// Certificate type values (RFC 4398 §2.1):
//   1=PKIX, 2=SPKI, 3=PGP, 4=IPKIX, 5=ISPKI, 6=IPGP, 7=ACPKIX, 8=IACPKIX,
//   253=URI, 254=OID
//
// Algorithm field has same semantics as DNSKEY/RRSIG algorithm field.
//
// Presentation format (RFC 4398 §2.2):
//   type(decimal or mnemonic) key_tag(decimal) algorithm(decimal or mnemonic) certificate(base64)

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

// RFC 4398 §2.1: Certificate type mnemonics
const CERT_TYPE_MAP: Record<string, number> = {
    'PKIX': 1,
    'SPKI': 2,
    'PGP': 3,
    'IPKIX': 4,
    'ISPKI': 5,
    'IPGP': 6,
    'ACPKIX': 7,
    'IACPKIX': 8,
    'URI': 253,
    'OID': 254,
};

function parseCertType(s: string): number {
    if (s in CERT_TYPE_MAP) return CERT_TYPE_MAP[s];
    const n = parseInt(s);
    if (!isNaN(n)) return n;
    throw new DNSZonePresentationFormatError("CERT: invalid certificate type: " + s);
}

export class DNSRR_CERT extends ResourceRecordHandler {
    readonly cert_type: number;
    readonly key_tag: number;
    readonly algorithm: number;
    readonly certificate: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{type} {key_tag} {algorithm} {base64_certificate}"
        const parts = value.trim().split(/\s+/);
        if (parts.length < 4) {
            throw new DNSZonePresentationFormatError("CERT: Presentation format error: " + value);
        }

        this.cert_type = parseCertType(parts[0]);
        this.key_tag = parseInt(parts[1]);
        this.algorithm = parseInt(parts[2]);
        // Remaining parts are base64-encoded certificate (may be split across whitespace)
        const b64 = parts.slice(3).join('');
        this.certificate = new Uint8Array(Buffer.from(b64, 'base64'));
    }

    // RFC 4398 §2: type(2) + key_tag(2) + algorithm(1) + certificate(variable)
    get_wire_body(builder: WireBuilder): void {
        const rdlen = 2 + 2 + 1 + this.certificate.length;
        builder.append_uint16(rdlen);
        builder.append_uint16(this.cert_type);
        builder.append_uint16(this.key_tag);
        builder.append_uint8(this.algorithm);
        builder.append_bytes(this.certificate);
    }

    clone(): DNSRR_CERT {
        return new DNSRR_CERT(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('CERT'), (rr, value) => new DNSRR_CERT(rr, value));
