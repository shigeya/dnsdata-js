// RP (Responsible Person) Resource Record (RFC 1183 §2.2)
//
// Wire format (RFC 1183 §2.2):
//   mbox-dname(wire domain name) + txt-dname(wire domain name)
//
// mbox-dname: mailbox of responsible person (DNS mailbox encoding, same as SOA RNAME)
// txt-dname: domain name where associated TXT records can be found
// Either field may be "." to indicate no value.
//
// Presentation format: mbox-dname txt-dname
//   e.g.  admin.example.com. devnull.example.com.

import { WireBuilder } from '../../wire/dns_wire_util';
import { domain_name2wire } from '../../wire/dns_wire';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

export class DNSRR_RP extends ResourceRecordHandler {
    readonly mbox: string;
    readonly txt_dname: string;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{mbox-dname} {txt-dname}"
        const parts = value.trim().split(/\s+/);
        if (parts.length < 2) {
            throw new DNSZonePresentationFormatError("RP: expected mbox-dname and txt-dname: " + value);
        }
        this.mbox = parts[0];
        this.txt_dname = parts[1];
    }

    // RFC 1183 §2.2: RDATA = mbox-dname + txt-dname (both uncompressed wire domain names)
    get_wire_body(builder: WireBuilder): void {
        const mbox_wire = domain_name2wire(this.mbox);
        const txt_wire = domain_name2wire(this.txt_dname);
        builder.append_uint16(mbox_wire.length + txt_wire.length);  // rdlen
        builder.append_bytes(mbox_wire);
        builder.append_bytes(txt_wire);
    }

    clone(): DNSRR_RP {
        return new DNSRR_RP(this._rr, this.value);
    }
}

register_rr_handler(StringToRRType('RP'), (rr, value) => new DNSRR_RP(rr, value));
