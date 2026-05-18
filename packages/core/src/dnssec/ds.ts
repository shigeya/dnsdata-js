// DS / CDS record handler. Ports dnsdata-go `dnssec/ds.go`.

import * as crypto from 'crypto';
import { WireBuilder } from '../wire/dns_wire_util';
import { ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';

// Map DS digest type to Node.js hash algorithm name.
function ds_digest_type_to_hash(digest_type: number): string {
    switch (digest_type) {
    case 1: return 'sha1';
    case 2: return 'sha256';
    case 4: return 'sha384';
    default: throw new Error(`Unsupported DS digest type: ${digest_type}`);
    }
}

export class DNSRR_DS extends ResourceRecordHandler {
    readonly key_tag: number;
    readonly algorithm: number;
    readonly digest_type: number;
    readonly digest: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{keytag} {algorithm} {digesttype} {hexdigest}"
        const m = value.match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) throw new DNSZonePresentationFormatError("DS: Presentation format error: " + value);

        this.key_tag = parseInt(m[1]);
        this.algorithm = parseInt(m[2]);
        this.digest_type = parseInt(m[3]);
        this.digest = new Uint8Array(Buffer.from(m[4].replace(/\s+/g, ''), 'hex'));
    }

    // DS RDATA wire: rdlen(2) + keytag(2) + algo(1) + digesttype(1) + digest
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(4 + this.digest.length);
        builder.append_uint16(this.key_tag);
        builder.append_uint8(this.algorithm);
        builder.append_uint8(this.digest_type);
        builder.append_bytes(this.digest);
    }

    verify_digest(key_digest: Uint8Array): boolean {
        const hash_algo = ds_digest_type_to_hash(this.digest_type);
        const computed = crypto.createHash(hash_algo).update(Buffer.from(key_digest)).digest();
        return Buffer.from(computed).equals(Buffer.from(this.digest));
    }

    clone(): DNSRR_DS {
        return new DNSRR_DS(this._rr, this.value);
    }
}
