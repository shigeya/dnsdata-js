// RRSIG record handler. Ports dnsdata-go `dnssec/rrsig.go`.

import { WireBuilder } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { StringToRRType, RRTypeToString } from '../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';
import { DNSKey } from './dnskey';

export class RRSig extends ResourceRecordHandler {
    readonly type_covered: number;
    readonly algorithm: number;
    // RFC 4034 §3.1.3 wildcard semantics rely on rewriting this field
    // after construction: wildcard-synthesised answers carry a Labels
    // count equal to the closest encloser's label count (i.e. the
    // wildcard owner minus the leading "*."). The signing helper
    // [DNSSecZone.sign_rr] exposes a labelsOverride parameter that
    // performs the override; the field is otherwise written once by
    // the parser / signing constructor.
    labels: number;
    readonly original_ttl: number;
    readonly expire: number;     // Unix timestamp
    readonly inception: number;  // Unix timestamp
    readonly key_tag: number;
    readonly signer: string;
    readonly signature: Uint8Array;

    private _digest_target: Uint8Array | null = null;

    constructor(rr: ResourceRecord | null, value: string);
    constructor(rr: ResourceRecord | null, label: string, ttl: number, type: number,
                inception: number, expire: number, key: DNSKey);
    constructor(rr: ResourceRecord | null, value_or_label: string, ttl?: number, type?: number,
                inception?: number, expire?: number, key?: DNSKey) {
        super(rr);
        if (ttl !== undefined && type !== undefined && key !== undefined) {
            // Construct for signing.
            this.type_covered = type;
            this.algorithm = key.algorithm;
            this.labels = (value_or_label.match(/\./g) || []).length;
            this.original_ttl = ttl;
            this.expire = expire!;
            this.inception = inception!;
            this.key_tag = key.key_tag;
            this.signer = key.label;
            this.signature = new Uint8Array(0); // set later via set_signature
        } else {
            // Parse from presentation format.
            const m = value_or_label.match(/^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s(.*)$/);
            if (!m) throw new DNSZonePresentationFormatError("RRSIG: Presentation format error: " + value_or_label);

            this.type_covered = StringToRRType(m[1]);
            this.algorithm = parseInt(m[2]);
            this.labels = parseInt(m[3]);
            this.original_ttl = parseInt(m[4]);
            this.expire = RRSig.datetime_str_to_int(m[5]);
            this.inception = RRSig.datetime_str_to_int(m[6]);
            this.key_tag = parseInt(m[7]);
            this.signer = m[8];
            this.signature = new Uint8Array(Buffer.from(m[9].replace(/\s+/g, ''), 'base64'));
        }
    }

    static datetime_str_to_int(ts: string): number {
        if (ts.length === 14) {
            const year = parseInt(ts.slice(0, 4));
            const mon = parseInt(ts.slice(4, 6)) - 1;
            const day = parseInt(ts.slice(6, 8));
            const hr = parseInt(ts.slice(8, 10));
            const min = parseInt(ts.slice(10, 12));
            const sec = parseInt(ts.slice(12, 14));
            return Math.floor(Date.UTC(year, mon, day, hr, min, sec) / 1000);
        }
        return parseInt(ts);
    }

    // RRSIG RDATA wire format (without signature) — used as digest target.
    get_rdata_digest_target(): Uint8Array {
        if (!this._digest_target) {
            const signer_wire = domain_name2wire(this.signer);
            const builder = new WireBuilder();
            builder.append_uint16(this.type_covered);
            builder.append_uint8(this.algorithm);
            builder.append_uint8(this.labels);
            builder.append_uint32(this.original_ttl);
            builder.append_uint32(this.expire);
            builder.append_uint32(this.inception);
            builder.append_uint16(this.key_tag);
            builder.append_bytes(signer_wire);
            this._digest_target = builder.build();
        }
        return this._digest_target;
    }

    // Full RRSIG RDATA wire (with signature), including rdlen prefix.
    get_wire_body(builder: WireBuilder): void {
        const dt = this.get_rdata_digest_target();
        builder.append_uint16(dt.length + this.signature.length);
        builder.append_bytes(dt);
        builder.append_bytes(this.signature);
    }

    get_value_string(): string {
        const sig_b64 = Buffer.from(this.signature).toString('base64');
        return `${RRTypeToString(this.type_covered)} ${this.algorithm} ${this.labels} ` +
            `${this.original_ttl} ${this.expire} ${this.inception} ` +
            `${this.key_tag} ${this.signer} ${sig_b64}`;
    }

    clone(): RRSig {
        const c = new RRSig(this._rr, this.value);
        return c;
    }
}
