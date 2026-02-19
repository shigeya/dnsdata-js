// SSHFP Resource Record (RFC 4255)
//
// Wire format (RFC 4255 §3.1):
//   algorithm(1) + fp_type(1) + fingerprint(variable)
//
// Algorithm numbers: 1=RSA, 2=DSS, 3=ECDSA (RFC 6594), 4=Ed25519 (RFC 7479)
// Fingerprint types: 1=SHA-1, 2=SHA-256 (RFC 6594)

import { WireBuilder } from '../dns_wire_util';
import { StringToRRType } from '../dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';

export class DNSRR_SSHFP extends ResourceRecordHandler {
    readonly algorithm: number;
    readonly fp_type: number;
    readonly fingerprint: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{algorithm} {fp_type} {hex_fingerprint}"
        const m = value.match(/^(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) throw new DNSZonePresentationFormatError("SSHFP: Presentation format error: " + value);

        this.algorithm = parseInt(m[1]);
        this.fp_type = parseInt(m[2]);
        this.fingerprint = new Uint8Array(Buffer.from(m[3].replace(/\s+/g, ''), 'hex'));
    }

    // RFC 4255 §3.1: rdlen(2) + algorithm(1) + fp_type(1) + fingerprint
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(2 + this.fingerprint.length);
        builder.append_uint8(this.algorithm);
        builder.append_uint8(this.fp_type);
        builder.append_bytes(this.fingerprint);
    }

    clone(): DNSRR_SSHFP {
        return new DNSRR_SSHFP(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('SSHFP'), (rr, value) => new DNSRR_SSHFP(rr, value));
