// NSEC3 / NSEC3PARAM record handlers + owner-hash helpers.
// Ports dnsdata-go `dnssec/nsec3.go`.

import * as crypto from 'crypto';
import { WireBuilder } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { StringToRRType } from '../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';
import { DNSRR_NSEC } from './nsec';

const TYPE_NS    = StringToRRType('NS');
const TYPE_DS    = StringToRRType('DS');
const TYPE_SOA   = StringToRRType('SOA');
const TYPE_CNAME = StringToRRType('CNAME');

// NSEC3 opt-out flag (RFC 5155 §3.1.2.1, bit 0 of the Flags field).
const NSEC3_OPT_OUT_FLAG = 0x01;

export class DNSRR_NSEC3 extends ResourceRecordHandler {
    readonly hash_algorithm: number;
    readonly flags: number;
    readonly iterations: number;
    readonly salt: Uint8Array;
    readonly next_hashed_owner: Uint8Array;
    readonly type_bitmap: Uint8Array;
    readonly covered_types: number[];

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{hash_algo} {flags} {iterations} {salt} {next_hashed_owner} {type1} [type2] ..."
        const parts = value.trim().split(/\s+/);
        if (parts.length < 5) throw new DNSZonePresentationFormatError("NSEC3: Presentation format error: " + value);

        this.hash_algorithm = parseInt(parts[0]);
        this.flags = parseInt(parts[1]);
        this.iterations = parseInt(parts[2]);
        this.salt = parts[3] === '-' ? new Uint8Array(0) : new Uint8Array(Buffer.from(parts[3], 'hex'));
        this.next_hashed_owner = base32hex_decode(parts[4]);

        this.covered_types = [];
        for (let i = 5; i < parts.length; i++) {
            try {
                this.covered_types.push(StringToRRType(parts[i]));
            } catch (_) {
                // Ignore unknown types.
            }
        }
        this.covered_types.sort((a, b) => a - b);
        this.type_bitmap = DNSRR_NSEC.encode_type_bitmap(this.covered_types);
    }

    covers_type(type: number): boolean {
        return this.covered_types.indexOf(type) !== -1;
    }

    // has_opt_out reports whether the NSEC3 opt-out flag is set
    // (RFC 5155 §6 — when set, the NSEC3 may safely omit insecure
    // delegations from its [owner, next) range).
    has_opt_out(): boolean {
        return (this.flags & NSEC3_OPT_OUT_FLAG) !== 0;
    }

    // covers_hash reports whether target falls strictly between
    // owner_hash and next_hashed_owner in NSEC3 sort order (RFC 5155
    // §6.1: byte-wise numeric order on the hash output).
    //
    // Equal to either endpoint returns false. The wrap case where
    // next_hashed_owner <= owner_hash is treated as the zone-trailing
    // NSEC3 and handled symmetrically with [DNSRR_NSEC.covers_name].
    covers_hash(owner_hash: Uint8Array, target: Uint8Array): boolean {
        const cmp_owner = bytes_compare(target, owner_hash);
        const cmp_next  = bytes_compare(target, this.next_hashed_owner);
        if (cmp_owner === 0 || cmp_next === 0) return false;
        if (bytes_compare(this.next_hashed_owner, owner_hash) <= 0) {
            return cmp_owner > 0 || cmp_next < 0;
        }
        return cmp_owner > 0 && cmp_next < 0;
    }

    // proves_no_data mirrors [DNSRR_NSEC.proves_no_data]: the bitmap
    // must NOT cover qtype and must NOT cover CNAME.
    proves_no_data(qtype: number): boolean {
        if (qtype === TYPE_CNAME) {
            return !this.covers_type(TYPE_CNAME);
        }
        return !this.covers_type(qtype) && !this.covers_type(TYPE_CNAME);
    }

    // proves_no_ds mirrors [DNSRR_NSEC.proves_no_ds]: NS present, DS
    // absent, SOA absent. The caller must separately confirm matching
    // or covering denial for the child name.
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

    // Compute NSEC3 hash per RFC 5155 §5.
    static compute_hash(name: string, algorithm: number, iterations: number, salt: Uint8Array): Uint8Array {
        if (algorithm !== 1) throw new Error(`Unsupported NSEC3 hash algorithm: ${algorithm}`);
        const name_wire = domain_name2wire(name.toLowerCase());

        let digest = crypto.createHash('sha1')
            .update(Buffer.from(name_wire))
            .update(Buffer.from(salt))
            .digest();

        for (let i = 0; i < iterations; i++) {
            digest = crypto.createHash('sha1')
                .update(digest)
                .update(Buffer.from(salt))
                .digest();
        }
        return new Uint8Array(digest);
    }

    get_wire_body(builder: WireBuilder): void {
        const rdlen = 6 + this.salt.length + this.next_hashed_owner.length + this.type_bitmap.length;
        builder.append_uint16(rdlen);
        builder.append_uint8(this.hash_algorithm);
        builder.append_uint8(this.flags);
        builder.append_uint16(this.iterations);
        builder.append_uint8(this.salt.length);
        builder.append_bytes(this.salt);
        builder.append_uint8(this.next_hashed_owner.length);
        builder.append_bytes(this.next_hashed_owner);
        builder.append_bytes(this.type_bitmap);
    }

    clone(): DNSRR_NSEC3 {
        return new DNSRR_NSEC3(this._rr, this.value);
    }
}

// RFC 5155 §4.2: NSEC3PARAM RDATA mirrors the first four fields of
// NSEC3 (§3.2):
//   hash_algorithm(1) + flags(1) + iterations(2) + salt_length(1) + salt(variable)
// Unlike NSEC3, it does not contain Next Hashed Owner Name or Type Bit Maps.
export class DNSRR_NSEC3PARAM extends ResourceRecordHandler {
    readonly hash_algorithm: number;
    readonly flags: number;
    readonly iterations: number;
    readonly salt: Uint8Array;

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{hash_algo} {flags} {iterations} {salt}"
        const parts = value.trim().split(/\s+/);
        if (parts.length < 4) throw new DNSZonePresentationFormatError("NSEC3PARAM: Presentation format error: " + value);

        this.hash_algorithm = parseInt(parts[0]);
        this.flags = parseInt(parts[1]);
        this.iterations = parseInt(parts[2]);
        this.salt = parts[3] === '-' ? new Uint8Array(0) : new Uint8Array(Buffer.from(parts[3], 'hex'));
    }

    get_wire_body(builder: WireBuilder): void {
        const rdlen = 5 + this.salt.length;
        builder.append_uint16(rdlen);
        builder.append_uint8(this.hash_algorithm);
        builder.append_uint8(this.flags);
        builder.append_uint16(this.iterations);
        builder.append_uint8(this.salt.length);
        builder.append_bytes(this.salt);
    }

    clone(): DNSRR_NSEC3PARAM {
        return new DNSRR_NSEC3PARAM(this._rr, this.value);
    }
}

// owner_hash_from_name decodes the leftmost label of an NSEC3 owner
// name as base32hex (RFC 5155 §1.3). For owner "ABCD0123.example.com."
// this returns the raw hash bytes encoded in "ABCD0123".
export function owner_hash_from_name(owner: string): Uint8Array {
    const cleaned = owner.endsWith('.') ? owner.slice(0, -1) : owner;
    if (cleaned === '') {
        throw new DNSZonePresentationFormatError('NSEC3 owner is empty');
    }
    const dot = cleaned.indexOf('.');
    const label = dot >= 0 ? cleaned.slice(0, dot) : cleaned;
    if (label === '') {
        throw new DNSZonePresentationFormatError(`NSEC3 owner has no leftmost label: ${owner}`);
    }
    return base32hex_decode(label);
}

// bytes_compare returns the standard -1 / 0 / 1 byte-wise lexicographic
// ordering of two Uint8Arrays. Used by NSEC3 hash range comparisons,
// where RFC 5155 §6.1 requires byte-wise numeric order on the hash
// output.
function bytes_compare(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    if (a.length < b.length) return -1;
    if (a.length > b.length) return 1;
    return 0;
}

// Base32hex decode (RFC 4648, used by NSEC3).
function base32hex_decode(input: string): Uint8Array {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    const cleaned = input.toUpperCase().replace(/=+$/, '');
    const bits: number[] = [];
    for (const c of cleaned) {
        const val = alphabet.indexOf(c);
        if (val === -1) throw new Error(`Invalid base32hex character: ${c}`);
        for (let i = 4; i >= 0; i--) {
            bits.push((val >> i) & 1);
        }
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        let byte = 0;
        for (let bit = 0; bit < 8; bit++) {
            byte = (byte << 1) | bits[i * 8 + bit];
        }
        bytes[i] = byte;
    }
    return bytes;
}
