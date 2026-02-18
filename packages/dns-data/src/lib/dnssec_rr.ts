// DNSSEC Resource Records
//
// Ported from wide-cpp-lib/wide/dns/dnssec_rr.hpp / dnssec_rr.cpp

import * as crypto from 'crypto';
import { WireBuilder } from './dns_wire_util';
import { domain_name2wire } from './dns_wire';
import { StringToRRType, RRTypeToString } from './dns_type_table';
import { ResourceRecord, ResourceRecordHandler, register_rr_handler } from './dns_zone';
import { DNSZonePresentationFormatError } from './dns_exception';

// Map DNSSEC algorithm code to Node.js hash algorithm name
function algo_to_hash(algorithm: number): string {
    switch (algorithm) {
    case 5: case 7:  return 'sha1';
    case 8:          return 'sha256';
    case 10:         return 'sha512';
    default: throw new Error(`Unsupported DNSSEC algorithm: ${algorithm}`);
    }
}

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
    return crypto.createPublicKey({ key: jwk, format: 'jwk' } as any);
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
        if (this.algorithm === 1) {
            throw new DNSZonePresentationFormatError("Algorithm 1 is not supported");
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
            this._public_key = load_rsa_public_key_rfc3110(this.key_data);
        }
        return this._public_key;
    }

    set_private_key(key: crypto.KeyObject): void {
        this._private_key = key;
    }

    verify(data: Uint8Array, signature: Uint8Array): boolean {
        const pub_key = this.get_public_key();
        const hash = algo_to_hash(this.algorithm);
        const verifier = crypto.createVerify('RSA-' + hash.toUpperCase());
        verifier.update(Buffer.from(data));
        return verifier.verify(pub_key, Buffer.from(signature));
    }

    sign(data: Uint8Array): Uint8Array {
        if (!this._private_key) throw new Error("No private key set");
        const hash = algo_to_hash(this.algorithm);
        const signer = crypto.createSign('RSA-' + hash.toUpperCase());
        signer.update(Buffer.from(data));
        return new Uint8Array(signer.sign(this._private_key));
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
    readonly labels: number;
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

// Register handlers so that ResourceRecord.get_handler() can create them
register_rr_handler(StringToRRType('DNSKEY'), (rr, value) => new DNSKey(rr, value));
register_rr_handler(StringToRRType('RRSIG'), (rr, value) => new RRSig(rr, value));
register_rr_handler(StringToRRType('DS'), (rr, value) => new DNSRR_DS(rr, value));
