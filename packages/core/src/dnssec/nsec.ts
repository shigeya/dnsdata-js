// NSEC record handler. Ports dnsdata-go `dnssec/nsec.go`.
//
// The static encode_type_bitmap / decode_type_bitmap helpers live on
// this class because they are RFC 4034 §4.1.2 primitives — NSEC3
// (RFC 5155) and CSYNC (RFC 7477) both reuse the same bitmap layout
// and import them from here.

import { WireBuilder } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { StringToRRType } from '../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';
import { compare_canonical_names, equal_canonical_names } from './dnssec_util';

const TYPE_NS    = StringToRRType('NS');
const TYPE_DS    = StringToRRType('DS');
const TYPE_SOA   = StringToRRType('SOA');
const TYPE_CNAME = StringToRRType('CNAME');

export class DNSRR_NSEC extends ResourceRecordHandler {
    readonly next_domain: string;
    readonly type_bitmap: Uint8Array;
    readonly covered_types: number[];

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{next_domain} {type1} [type2] ..."
        const parts = value.trim().split(/\s+/);
        if (parts.length < 2) throw new DNSZonePresentationFormatError("NSEC: Presentation format error: " + value);

        this.next_domain = parts[0];
        this.covered_types = [];
        for (let i = 1; i < parts.length; i++) {
            try {
                this.covered_types.push(StringToRRType(parts[i]));
            } catch (_) {
                // Ignore unknown types.
            }
        }
        this.covered_types.sort((a, b) => a - b);
        this.type_bitmap = DNSRR_NSEC.encode_type_bitmap(this.covered_types);
    }

    // Encode type bitmap per RFC 4034 §4.1.2.
    static encode_type_bitmap(types: number[]): Uint8Array {
        if (types.length === 0) return new Uint8Array(0);

        // Group by window (high byte).
        const windows = new Map<number, number[]>();
        for (const t of types) {
            const window = (t >> 8) & 0xff;
            const offset = t & 0xff;
            if (!windows.has(window)) windows.set(window, []);
            windows.get(window)!.push(offset);
        }

        const parts: Uint8Array[] = [];
        for (const [window, offsets] of Array.from(windows.entries()).sort((a, b) => a[0] - b[0])) {
            const max_offset = Math.max(...offsets);
            const bitmap_len = Math.floor(max_offset / 8) + 1;
            const bitmap = new Uint8Array(bitmap_len);
            for (const off of offsets) {
                bitmap[Math.floor(off / 8)] |= (0x80 >> (off % 8));
            }
            // window(1) + bitmap_length(1) + bitmap
            const entry = new Uint8Array(2 + bitmap_len);
            entry[0] = window;
            entry[1] = bitmap_len;
            entry.set(bitmap, 2);
            parts.push(entry);
        }

        const total = parts.reduce((sum, p) => sum + p.length, 0);
        const result = new Uint8Array(total);
        let pos = 0;
        for (const p of parts) {
            result.set(p, pos);
            pos += p.length;
        }
        return result;
    }

    // Decode type bitmap per RFC 4034 §4.1.2.
    static decode_type_bitmap(bitmap: Uint8Array): number[] {
        const types: number[] = [];
        let pos = 0;
        while (pos < bitmap.length) {
            const window = bitmap[pos++];
            const len = bitmap[pos++];
            for (let i = 0; i < len; i++) {
                const byte = bitmap[pos + i];
                for (let bit = 0; bit < 8; bit++) {
                    if (byte & (0x80 >> bit)) {
                        types.push((window << 8) | (i * 8 + bit));
                    }
                }
            }
            pos += len;
        }
        return types;
    }

    covers_type(type: number): boolean {
        return this.covered_types.indexOf(type) !== -1;
    }

    // matches_name reports whether qname equals owner in canonical-name
    // order (RFC 4034 §6.1). Owner is passed explicitly because the
    // handler does not retain its label independently of its parent RR.
    matches_name(owner: string, qname: string): boolean {
        return equal_canonical_names(owner, qname);
    }

    // covers_name reports whether qname falls strictly between owner and
    // next_domain in canonical-name order (RFC 4035 §5.4 "covers").
    // Equal to either endpoint returns false — matching denial is a
    // distinct concept.
    //
    // The "wrap" case where next_domain <= owner in canonical order is
    // recognised as the zone-trailing NSEC and treated specially: qname
    // is covered if it is greater than owner OR less than next_domain.
    covers_name(owner: string, qname: string): boolean {
        const cmp_owner = compare_canonical_names(qname, owner);
        const cmp_next = compare_canonical_names(qname, this.next_domain);
        if (cmp_owner === 0 || cmp_next === 0) return false;
        if (compare_canonical_names(this.next_domain, owner) <= 0) {
            // Wrap-around NSEC at the zone end.
            return cmp_owner > 0 || cmp_next < 0;
        }
        return cmp_owner > 0 && cmp_next < 0;
    }

    // proves_no_data reports whether the bitmap shape is consistent with
    // a NODATA proof for qtype: qtype is absent AND CNAME is absent
    // (because a CNAME would otherwise have produced an answer rather
    // than NODATA, RFC 4035 §5.4).
    //
    // The caller must separately confirm this NSEC's owner equals qname
    // (matching denial) — that is what makes the absent qtype a
    // statement about qname rather than about a neighbour.
    proves_no_data(qtype: number): boolean {
        if (qtype === TYPE_CNAME) {
            // The caller is asking specifically about CNAME — the
            // absence of CNAME in the bitmap is itself the proof.
            return !this.covers_type(TYPE_CNAME);
        }
        return !this.covers_type(qtype) && !this.covers_type(TYPE_CNAME);
    }

    // proves_no_ds reports whether the bitmap shape matches a signed
    // no-DS delegation: NS present, DS absent, SOA absent. The SOA
    // absence distinguishes a delegation point from a zone apex NSEC;
    // the NS presence guards against accepting an NSEC at a name the
    // parent never delegated. Callers must separately confirm
    // matching or covering denial for the child name.
    proves_no_ds(): boolean {
        let has_ns = false;
        let has_ds = false;
        let has_soa = false;
        for (const t of this.covered_types) {
            if (t === TYPE_NS)  has_ns = true;
            else if (t === TYPE_DS)  has_ds = true;
            else if (t === TYPE_SOA) has_soa = true;
        }
        return has_ns && !has_ds && !has_soa;
    }

    get_wire_body(builder: WireBuilder): void {
        const next_wire = domain_name2wire(this.next_domain);
        builder.append_uint16(next_wire.length + this.type_bitmap.length);
        builder.append_bytes(next_wire);
        builder.append_bytes(this.type_bitmap);
    }

    clone(): DNSRR_NSEC {
        return new DNSRR_NSEC(this._rr, this.value);
    }
}
