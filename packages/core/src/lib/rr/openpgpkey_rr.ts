// OPENPGPKEY Resource Record (RFC 7929)
//
// Wire format (RFC 7929 §2.1):
//   Transferable Public Key (raw binary, RFC 4880 §11.1)
//   No additional structure — the entire RDATA is the key material.
//
// Presentation format (RFC 7929 §2.2):
//   Base64-encoded Transferable Public Key (RFC 4648 §4)

import { WireBuilder } from '../../wire/dns_wire_util';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';

export class DNSRR_OPENPGPKEY extends ResourceRecordHandler {
    readonly key_data: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // RFC 7929 §2.2: Presentation format is base64-encoded key
        const b64 = value.trim().replace(/\s+/g, '');
        if (b64.length === 0) {
            throw new DNSZonePresentationFormatError("OPENPGPKEY: empty key data");
        }
        this.key_data = new Uint8Array(Buffer.from(b64, 'base64'));
    }

    // RFC 7929 §2.1: RDATA = raw key binary (no additional fields)
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(this.key_data.length);  // rdlen
        builder.append_bytes(this.key_data);
    }

    clone(): DNSRR_OPENPGPKEY {
        return new DNSRR_OPENPGPKEY(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('OPENPGPKEY'), (rr, value) => new DNSRR_OPENPGPKEY(rr, value));
