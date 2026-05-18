// DNSSEC Resource Records
//
// Ported from wide-cpp-lib/wide/dns/dnssec_rr.hpp / dnssec_rr.cpp

import * as crypto from 'crypto';
import { WireBuilder } from './dns_wire_util';
import { domain_name2wire } from './dns_wire';
import { StringToRRType, RRTypeToString } from './dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from './dns_zone';
import { DNSZonePresentationFormatError } from './dns_exception';
import {
    compare_canonical_names,
    equal_canonical_names,
} from './dnssec_util';
import { AlgoRSAMD5, AlgoED25519 } from './types/algorithm';
import {
    algo_to_hash,
    ecdsa_coord_len,
    ecdsa_curve,
    is_ecdsa_algorithm,
    is_eddsa_algorithm,
} from './dnssec/crypto';

// Cached RR-type codes used by the negative-proof primitives. Resolved
// at module load time so the hot path is a numeric comparison.
const TYPE_NS    = StringToRRType('NS');
const TYPE_DS    = StringToRRType('DS');
const TYPE_SOA   = StringToRRType('SOA');
const TYPE_CNAME = StringToRRType('CNAME');

// Map DS digest type to Node.js hash algorithm name
function ds_digest_type_to_hash(digest_type: number): string {
    switch (digest_type) {
    case 1: return 'sha1';
    case 2: return 'sha256';
    case 4: return 'sha384';
    default: throw new Error(`Unsupported DS digest type: ${digest_type}`);
    }
}

// Base64url encode without padding (for JWK)
function base64url_encode(buf: Uint8Array): string {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Convert ECDSA DER signature to DNSSEC raw (r||s) format
function ecdsa_der_to_raw(der: Uint8Array, algorithm: number): Uint8Array {
    const coord_len = ecdsa_coord_len(algorithm);
    // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
    let offset = 2; // skip 0x30 <len>
    offset++; // skip 0x02
    const r_len = der[offset++];
    const r = der.slice(offset, offset + r_len);
    offset += r_len;
    offset++; // skip 0x02
    const s_len = der[offset++];
    const s = der.slice(offset, offset + s_len);

    const raw = new Uint8Array(coord_len * 2);
    // Copy r (right-aligned, strip leading zero if present)
    const r_start = r.length > coord_len ? r.length - coord_len : 0;
    const r_dest = coord_len - (r.length - r_start);
    raw.set(r.slice(r_start), r_dest);
    // Copy s (right-aligned, strip leading zero if present)
    const s_start = s.length > coord_len ? s.length - coord_len : 0;
    const s_dest = coord_len + coord_len - (s.length - s_start);
    raw.set(s.slice(s_start), s_dest);
    return raw;
}

// Convert DNSSEC raw (r||s) signature to DER format for Node.js crypto
function ecdsa_raw_to_der(raw: Uint8Array, algorithm: number): Buffer {
    const coord_len = ecdsa_coord_len(algorithm);
    let r = raw.slice(0, coord_len);
    let s = raw.slice(coord_len);

    // Add leading zero if high bit set (DER requires unsigned encoding)
    if (r[0] & 0x80) {
        const padded = new Uint8Array(r.length + 1);
        padded.set(r, 1);
        r = padded;
    }
    if (s[0] & 0x80) {
        const padded = new Uint8Array(s.length + 1);
        padded.set(s, 1);
        s = padded;
    }

    // Strip leading zeros (but keep at least one byte)
    while (r.length > 1 && r[0] === 0 && !(r[1] & 0x80)) r = r.slice(1);
    while (s.length > 1 && s[0] === 0 && !(s[1] & 0x80)) s = s.slice(1);

    const total = 2 + r.length + 2 + s.length;
    const der = Buffer.alloc(2 + total);
    let pos = 0;
    der[pos++] = 0x30; // SEQUENCE
    der[pos++] = total;
    der[pos++] = 0x02; // INTEGER
    der[pos++] = r.length;
    der.set(r, pos); pos += r.length;
    der[pos++] = 0x02; // INTEGER
    der[pos++] = s.length;
    der.set(s, pos);
    return der;
}

// Load ECDSA public key from DNSSEC format (raw x||y coordinates)
// RFC 6605: key_data is the uncompressed point (x || y) without the 0x04 prefix
function load_ecdsa_public_key(key_data: Uint8Array, algorithm: number): crypto.KeyObject {
    const curve = ecdsa_curve(algorithm);
    const coord_len = ecdsa_coord_len(algorithm);
    if (key_data.length !== coord_len * 2) {
        throw new Error(`Invalid ECDSA key length: expected ${coord_len * 2}, got ${key_data.length}`);
    }
    const x = key_data.slice(0, coord_len);
    const y = key_data.slice(coord_len);
    const jwk = {
        kty: 'EC',
        crv: curve,
        x: base64url_encode(x),
        y: base64url_encode(y),
    };
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// Load Ed25519/Ed448 public key from DNSSEC format (raw key bytes)
// RFC 8080: key_data is the raw public key (32 bytes for Ed25519, 57 bytes for Ed448)
function load_eddsa_public_key(key_data: Uint8Array, algorithm: number): crypto.KeyObject {
    const crv = algorithm === AlgoED25519 ? 'Ed25519' : 'Ed448';
    const jwk = {
        kty: 'OKP',
        crv: crv,
        x: base64url_encode(key_data),
    };
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// Load RSA public key from RFC3110 binary format
function load_rsa_public_key_rfc3110(key_data: Uint8Array): crypto.KeyObject {
    let offset = 0;
    let exp_len = key_data[offset++];
    if (exp_len === 0) {
        exp_len = (key_data[offset] << 8) | key_data[offset + 1];
        offset += 2;
    }
    const exponent = key_data.slice(offset, offset + exp_len);
    const modulus = key_data.slice(offset + exp_len);

    const jwk = {
        kty: 'RSA',
        n: base64url_encode(modulus),
        e: base64url_encode(exponent),
    };
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

//////////////////////////////////////////////////////////// DNSKey

export class DNSKey extends ResourceRecordHandler {
    readonly flags: number;
    readonly protocol: number;
    readonly algorithm: number;
    readonly key_data: Uint8Array;
    readonly key_tag: number;
    private _public_key: crypto.KeyObject | null = null;
    private _private_key: crypto.KeyObject | null = null;

    constructor(rr: ResourceRecord | null, value: string);
    constructor(rr: ResourceRecord | null, flags: number, protocol: number, algorithm: number, key_data: Uint8Array);
    constructor(rr: ResourceRecord | null, flags_or_value: string | number, protocol?: number, algorithm?: number, key_data?: Uint8Array) {
        super(rr);
        if (typeof flags_or_value === 'string') {
            // Parse from presentation format: "{flags} {protocol} {algorithm} {base64key}"
            const m = flags_or_value.match(/^(\d+)\s+(\d+)\s+(\d+)\s(.*)$/);
            if (!m) throw new DNSZonePresentationFormatError("DNSKEY: Presentation format error: " + flags_or_value);
            this.flags = parseInt(m[1]);
            this.protocol = parseInt(m[2]);
            this.algorithm = parseInt(m[3]);
            this.key_data = new Uint8Array(Buffer.from(m[4].replace(/\s+/g, ''), 'base64'));
        } else {
            this.flags = flags_or_value;
            this.protocol = protocol!;
            this.algorithm = algorithm!;
            this.key_data = key_data!;
        }
        this.key_tag = this._calc_key_tag();
    }

    private _calc_key_tag(): number {
        // RFC4034 Appendix B
        // Algorithm 1 (RSAMD5) uses a special key tag calculation:
        // the low 16 bits of the key modulus (last 2 bytes of key_data)
        if (this.algorithm === AlgoRSAMD5) {
            if (this.key_data.length < 2) return 0;
            return ((this.key_data[this.key_data.length - 2] << 8) |
                     this.key_data[this.key_data.length - 1]) & 0xffff;
        }
        let value = 0;
        value += this.flags & 0xffff;
        value += ((this.protocol << 8) & 0xff00) | (this.algorithm & 0xff);
        const kd = this.key_data;
        for (let i = 0; i + 1 < kd.length; i += 2) {
            value += ((kd[i] << 8) & 0xff00) | (kd[i + 1] & 0xff);
        }
        if (kd.length % 2 === 1) {
            value += (kd[kd.length - 1] << 8) & 0xff00;
        }
        value += (value >> 16) & 0xffff;
        return value & 0xffff;
    }

    is_zone_key(): boolean { return (this.flags & 0x0100) === 0x0100; }
    is_secure_entry_point(): boolean { return (this.flags & 0x0001) === 0x0001; }

    // DNSKEY RDATA wire: rdlen(2) + flags(2) + protocol(1) + algorithm(1) + key_data
    get_wire_body(builder: WireBuilder): void {
        builder.append_uint16(4 + this.key_data.length);
        builder.append_uint16(this.flags);
        builder.append_uint8(this.protocol);
        builder.append_uint8(this.algorithm);
        builder.append_bytes(this.key_data);
    }

    // DS digest input: owner_wire + flags(2) + protocol(1) + algorithm(1) + key_data (no rdlen)
    get_ds_digest_data(): Uint8Array {
        const builder = new WireBuilder();
        const owner_wire = domain_name2wire(this.label);
        builder.append_bytes(owner_wire);
        builder.append_uint16(this.flags);
        builder.append_uint8(this.protocol);
        builder.append_uint8(this.algorithm);
        builder.append_bytes(this.key_data);
        return builder.build();
    }

    get_public_key(): crypto.KeyObject {
        if (!this._public_key) {
            if (is_eddsa_algorithm(this.algorithm)) {
                this._public_key = load_eddsa_public_key(this.key_data, this.algorithm);
            } else if (is_ecdsa_algorithm(this.algorithm)) {
                this._public_key = load_ecdsa_public_key(this.key_data, this.algorithm);
            } else {
                this._public_key = load_rsa_public_key_rfc3110(this.key_data);
            }
        }
        return this._public_key;
    }

    set_private_key(key: crypto.KeyObject): void {
        this._private_key = key;
    }

    verify(data: Uint8Array, signature: Uint8Array): boolean {
        const pub_key = this.get_public_key();
        if (is_eddsa_algorithm(this.algorithm)) {
            // EdDSA: uses crypto.verify directly (no separate hash step)
            return crypto.verify(null, Buffer.from(data), pub_key, Buffer.from(signature));
        } else if (is_ecdsa_algorithm(this.algorithm)) {
            // ECDSA: DNSSEC uses raw r||s format, Node.js expects DER
            const hash = algo_to_hash(this.algorithm);
            const der_sig = ecdsa_raw_to_der(signature, this.algorithm);
            const verifier = crypto.createVerify(hash.toUpperCase());
            verifier.update(Buffer.from(data));
            return verifier.verify(pub_key, der_sig);
        } else {
            const hash = algo_to_hash(this.algorithm);
            const verifier = crypto.createVerify('RSA-' + hash.toUpperCase());
            verifier.update(Buffer.from(data));
            return verifier.verify(pub_key, Buffer.from(signature));
        }
    }

    sign(data: Uint8Array): Uint8Array {
        if (!this._private_key) throw new Error("No private key set");
        if (is_eddsa_algorithm(this.algorithm)) {
            // EdDSA: uses crypto.sign directly (no separate hash step)
            return new Uint8Array(crypto.sign(null, Buffer.from(data), this._private_key));
        } else if (is_ecdsa_algorithm(this.algorithm)) {
            // ECDSA: Node.js produces DER, DNSSEC expects raw r||s
            const hash = algo_to_hash(this.algorithm);
            const signer = crypto.createSign(hash.toUpperCase());
            signer.update(Buffer.from(data));
            const der_sig = signer.sign(this._private_key);
            return ecdsa_der_to_raw(new Uint8Array(der_sig), this.algorithm);
        } else {
            const hash = algo_to_hash(this.algorithm);
            const signer = crypto.createSign('RSA-' + hash.toUpperCase());
            signer.update(Buffer.from(data));
            return new Uint8Array(signer.sign(this._private_key));
        }
    }

    get_isc_key_base_filename(): string {
        const algo_str = String(this.algorithm).padStart(3, '0');
        const tag_str = String(this.key_tag).padStart(5, '0');
        return `K${this.label}+${algo_str}+${tag_str}`;
    }

    clone(): DNSKey {
        return new DNSKey(this._rr, this.flags, this.protocol, this.algorithm, new Uint8Array(this.key_data));
    }
}

//////////////////////////////////////////////////////////// RRSig

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
            // Construct for signing
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
            // Parse from presentation format
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

    // RRSIG RDATA wire format (without signature) - used as digest target
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

    // Full RRSIG RDATA wire (with signature), including rdlen prefix
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

//////////////////////////////////////////////////////////// DNSRR_DS

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

//////////////////////////////////////////////////////////// NSEC

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
                // Ignore unknown types
            }
        }
        this.covered_types.sort((a, b) => a - b);
        this.type_bitmap = DNSRR_NSEC.encode_type_bitmap(this.covered_types);
    }

    // Encode type bitmap per RFC 4034 Section 4.1.2
    static encode_type_bitmap(types: number[]): Uint8Array {
        if (types.length === 0) return new Uint8Array(0);

        // Group by window (high byte)
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

    // Decode type bitmap per RFC 4034 Section 4.1.2
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

//////////////////////////////////////////////////////////// NSEC3

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
                // Ignore unknown types
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

    // Compute NSEC3 hash per RFC 5155 Section 5
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

//////////////////////////////////////////////////////////// NSEC3PARAM
// RFC 5155 §4.2: NSEC3PARAM RDATA mirrors the first four fields of NSEC3 (§3.2):
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

// NSEC3 opt-out flag (RFC 5155 §3.1.2.1, bit 0 of the Flags field).
const NSEC3_OPT_OUT_FLAG = 0x01;

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

// Base32hex decode (RFC 4648, used by NSEC3)
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

// Register handlers so that ResourceRecord.get_handler() can create them
register_rr_handler(StringToRRType('DNSKEY'), (rr, value) => new DNSKey(rr, value));
// RFC 7344 §3.2: CDNSKEY wire and presentation format is identical to DNSKEY (RFC 4034).
// The DNSKey handler class is reused; only the RR type code (60) differs.
register_rr_handler(StringToRRType('CDNSKEY'), (rr, value) => new DNSKey(rr, value));
register_rr_handler(StringToRRType('RRSIG'), (rr, value) => new RRSig(rr, value));
register_rr_handler(StringToRRType('DS'), (rr, value) => new DNSRR_DS(rr, value));
// RFC 7344 §3.1: CDS wire and presentation format is identical to DS (RFC 4034).
// The DNSRR_DS handler class is reused; only the RR type code (59) differs.
register_rr_handler(StringToRRType('CDS'), (rr, value) => new DNSRR_DS(rr, value));
register_rr_handler(StringToRRType('NSEC'), (rr, value) => new DNSRR_NSEC(rr, value));
register_rr_handler(StringToRRType('NSEC3'), (rr, value) => new DNSRR_NSEC3(rr, value));
register_rr_handler(StringToRRType('NSEC3PARAM'), (rr, value) => new DNSRR_NSEC3PARAM(rr, value));
