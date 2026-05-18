// DNSKEY record handler + the RSA / ECDSA / EdDSA crypto plumbing
// it relies on. Ports dnsdata-go `dnssec/dnskey.go` plus the
// public-key loaders and DER↔raw signature converters that live in
// `dnssec/crypto.go` on the Go side; in the TS port these stay
// adjacent to DNSKey because they are its only consumers (RRSig
// goes through DNSKey.verify / DNSKey.sign, never directly).

import * as crypto from 'crypto';
import { WireBuilder } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { DNSZonePresentationFormatError } from '../dns_exception';
import { AlgoED25519, AlgoRSAMD5 } from '../types/algorithm';
import {
    algo_to_hash,
    ecdsa_coord_len,
    ecdsa_curve,
    is_ecdsa_algorithm,
    is_eddsa_algorithm,
} from './crypto';

// Base64url encode without padding (for JWK).
function base64url_encode(buf: Uint8Array): string {
    return Buffer.from(buf).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Convert ECDSA DER signature to DNSSEC raw (r||s) format.
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
    // Copy r (right-aligned, strip leading zero if present).
    const r_start = r.length > coord_len ? r.length - coord_len : 0;
    const r_dest = coord_len - (r.length - r_start);
    raw.set(r.slice(r_start), r_dest);
    // Copy s (right-aligned, strip leading zero if present).
    const s_start = s.length > coord_len ? s.length - coord_len : 0;
    const s_dest = coord_len + coord_len - (s.length - s_start);
    raw.set(s.slice(s_start), s_dest);
    return raw;
}

// Convert DNSSEC raw (r||s) signature to DER format for Node.js crypto.
function ecdsa_raw_to_der(raw: Uint8Array, algorithm: number): Buffer {
    const coord_len = ecdsa_coord_len(algorithm);
    let r = raw.slice(0, coord_len);
    let s = raw.slice(coord_len);

    // Add leading zero if high bit set (DER requires unsigned encoding).
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

    // Strip leading zeros (but keep at least one byte).
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

// Load ECDSA public key from DNSSEC format (raw x||y coordinates).
// RFC 6605: key_data is the uncompressed point (x || y) without the 0x04 prefix.
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

// Load Ed25519/Ed448 public key from DNSSEC format (raw key bytes).
// RFC 8080: key_data is the raw public key (32 bytes for Ed25519, 57 bytes for Ed448).
function load_eddsa_public_key(key_data: Uint8Array, algorithm: number): crypto.KeyObject {
    const crv = algorithm === AlgoED25519 ? 'Ed25519' : 'Ed448';
    const jwk = {
        kty: 'OKP',
        crv: crv,
        x: base64url_encode(key_data),
    };
    return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

// Load RSA public key from RFC 3110 binary format.
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
        // the low 16 bits of the key modulus (last 2 bytes of key_data).
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
            // EdDSA: uses crypto.verify directly (no separate hash step).
            return crypto.verify(null, Buffer.from(data), pub_key, Buffer.from(signature));
        } else if (is_ecdsa_algorithm(this.algorithm)) {
            // ECDSA: DNSSEC uses raw r||s format, Node.js expects DER.
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
            // EdDSA: uses crypto.sign directly (no separate hash step).
            return new Uint8Array(crypto.sign(null, Buffer.from(data), this._private_key));
        } else if (is_ecdsa_algorithm(this.algorithm)) {
            // ECDSA: Node.js produces DER, DNSSEC expects raw r||s.
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
