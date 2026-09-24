// Signing keys of the zone signer. Ports dnsdata-go
// `dnssec/signer/key.go`.
//
// Everything is in memory. Nothing in the signer reads the clock
// (inception and expiration are always supplied by the caller, so
// expired or not-yet-valid signatures can be produced on purpose),
// writes files, or keeps global state.

import * as crypto from 'crypto';
import { ResourceRecord } from '../../zone/dns_zone';
import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../../types/algorithm';
import { DNSKey } from '../dnskey';
import { RootAnchorDS } from '../root_anchors';
import { anchor_ds_of, ds_value_of } from './ds';
import { SignerError, SignerKeyFormatError, SignerUnsupportedAlgorithmError, error_message } from './errors';
import { is_fqdn } from './names';

// DNSKEY flag values (RFC 4034 §2.1.1).
export const FlagZone = 0x0100;
export const FlagSEP = 0x0001;
// FlagsKSK marks a key-signing key (also used for a combined signing
// key): zone key + secure entry point, 257.
export const FlagsKSK = FlagZone | FlagSEP;
// FlagsZSK marks a zone-signing key, 256.
export const FlagsZSK = FlagZone;

// The only valid DNSKEY protocol value (RFC 4034 §2.1.2).
export const DNSKEY_PROTOCOL = 3;

// Modulus size generate_key uses for RSA algorithms.
const RSA_KEY_BITS = 2048;

// PEM block type of a PKCS#8 private key.
const PEM_TYPE_PKCS8 = 'PRIVATE KEY';

// Node's names for the ECDSA curves, by DNSSEC algorithm (RFC 6605).
const ECDSA_CURVES: ReadonlyMap<number, { node: string; jwk: string; coord: number }> = new Map([
    [AlgoECDSAP256SHA256, { node: 'prime256v1', jwk: 'P-256', coord: 32 }],
    [AlgoECDSAP384SHA384, { node: 'secp384r1', jwk: 'P-384', coord: 48 }],
]);

// Key is a DNSKEY together with its private key.
//
// The readonly fields describe the public DNSKEY; the private key is
// only reachable through [pkcs8_pem] and signing. Build one with
// [generate_key], [new_key], [parse_pkcs8_pem] or [parse_bind_private].
export class Key {
    readonly owner: string;          // zone apex, fully qualified
    readonly flags: number;
    readonly algorithm: number;
    readonly public_key: Uint8Array; // DNSKEY public-key field (RFC 3110 / 6605 / 8080)
    readonly key_tag: number;        // RFC 4034 Appendix B
    private readonly _private_key: crypto.KeyObject;

    // Throws SignerError for a relative owner, SignerKeyFormatError when
    // private_key does not suit algorithm, SignerUnsupportedAlgorithmError
    // for other key types.
    constructor(owner: string, flags: number, algorithm: number, private_key: crypto.KeyObject) {
        if (!is_fqdn(owner)) {
            throw new SignerError(`owner "${owner}" is not fully qualified`);
        }
        this.owner = owner;
        this.flags = flags;
        this.algorithm = algorithm;
        this.public_key = public_key_field(private_key, algorithm);
        this._private_key = private_key;
        this.key_tag = new DNSKey(null, flags, DNSKEY_PROTOCOL, algorithm, this.public_key).key_tag;
    }

    // is_ksk reports whether the secure-entry-point flag is set.
    is_ksk(): boolean {
        return (this.flags & FlagSEP) !== 0;
    }

    // dnskey_value returns the DNSKEY presentation value
    // `<flags> 3 <algorithm> <base64 key>`.
    dnskey_value(): string {
        return `${this.flags} ${DNSKEY_PROTOCOL} ${this.algorithm} ${Buffer.from(this.public_key).toString('base64')}`;
    }

    // dnskey_record returns a new DNSKEY record for the key at its owner.
    dnskey_record(ttl: number): ResourceRecord {
        return new ResourceRecord(this.owner, ttl, 'IN', 'DNSKEY', this.dnskey_value());
    }

    // pkcs8_pem returns the private key as a PEM-encoded PKCS#8 block, so
    // a generated key can be stored and loaded again with
    // [parse_pkcs8_pem].
    pkcs8_pem(): string {
        return this._private_key.export({ type: 'pkcs8', format: 'pem' }).toString();
    }

    // ds returns the DS presentation value for the key, `<key tag>
    // <algorithm> <digest type> <hex digest>`, for digest type 2
    // (SHA-256) or 4 (SHA-384). Place it at the key's owner in the parent
    // zone. Throws SignerUnsupportedAlgorithmError for other digest types.
    ds(digest_type: number): string {
        return ds_value_of(this, digest_type);
    }

    // anchor_ds returns the key's DS in the trust-anchor form the
    // verifier takes (digest in upper-case hex).
    anchor_ds(digest_type: number): RootAnchorDS {
        return anchor_ds_of(this, digest_type);
    }

    // signing_key returns a DNSKey at signer (the key's owner by
    // default; the RRSIG Signer's Name) with the private key attached,
    // ready for DNSSecZone.sign_rr. Internal to the signer.
    signing_key(signer: string = this.owner): DNSKey {
        const rr = new ResourceRecord(signer, 0, 'IN', 'DNSKEY', this.dnskey_value());
        const dnskey = new DNSKey(rr, this.flags, DNSKEY_PROTOCOL, this.algorithm, this.public_key);
        dnskey.set_private_key(this._private_key);
        return dnskey;
    }
}

// generate_key creates a fresh key for owner. Supported algorithms: 13
// (ECDSA P-256), 14 (ECDSA P-384), 15 (Ed25519), 8 and 10 (RSA, 2048-bit
// modulus). Randomness comes from Node's crypto; for reproducible keys
// load a fixed one with [parse_pkcs8_pem] or [parse_bind_private].
export function generate_key(owner: string, algorithm: number, flags: number): Key {
    return new Key(owner, flags, algorithm, generate_private_key(algorithm));
}

function generate_private_key(algorithm: number): crypto.KeyObject {
    const curve = ECDSA_CURVES.get(algorithm);
    try {
        if (curve) {
            return crypto.generateKeyPairSync('ec', { namedCurve: curve.jwk }).privateKey;
        }
        if (algorithm === AlgoED25519) {
            return crypto.generateKeyPairSync('ed25519').privateKey;
        }
        if (algorithm === AlgoRSASHA256 || algorithm === AlgoRSASHA512) {
            return crypto.generateKeyPairSync('rsa', { modulusLength: RSA_KEY_BITS }).privateKey;
        }
    } catch (e) {
        throw new SignerError(`generate: ${error_message(e)}`);
    }
    throw new SignerUnsupportedAlgorithmError(`generate algorithm ${algorithm}`);
}

// new_key wraps an existing private key (a Node crypto KeyObject of type
// EC, Ed25519 or RSA). algorithm 0 infers 13 / 14 from the ECDSA curve,
// 15 for Ed25519 and 8 for RSA.
export function new_key(owner: string, flags: number, algorithm: number, private_key: crypto.KeyObject): Key {
    const alg = algorithm === 0 ? infer_algorithm(private_key) : algorithm;
    return new Key(owner, flags, alg, private_key);
}

function infer_algorithm(key: crypto.KeyObject): number {
    switch (key.asymmetricKeyType) {
    case 'ec':
        return key.asymmetricKeyDetails?.namedCurve === ECDSA_CURVES.get(AlgoECDSAP384SHA384)?.node
            ? AlgoECDSAP384SHA384 : AlgoECDSAP256SHA256;
    case 'ed25519':
        return AlgoED25519;
    case 'rsa':
        return AlgoRSASHA256;
    }
    return 0;
}

// parse_pkcs8_pem loads a PEM-encoded PKCS#8 private key (a `PRIVATE
// KEY` block). algorithm 0 infers it from the key (see [new_key]).
export function parse_pkcs8_pem(owner: string, flags: number, algorithm: number, pem: string | Uint8Array): Key {
    const text = typeof pem === 'string' ? pem : Buffer.from(pem).toString('utf8');
    const block = text.match(/-----BEGIN ([A-Z0-9 ]+)-----/);
    if (!block || block[1] !== PEM_TYPE_PKCS8) {
        throw new SignerKeyFormatError(`no "${PEM_TYPE_PKCS8}" PEM block`);
    }
    let key: crypto.KeyObject;
    try {
        key = crypto.createPrivateKey({ key: text, format: 'pem' });
    } catch (e) {
        throw new SignerKeyFormatError(`PKCS#8: ${error_message(e)}`);
    }
    return new_key(owner, flags, algorithm, key);
}

// public_key_field encodes the DNSKEY public-key field for key and
// checks that key suits algorithm.
function public_key_field(key: crypto.KeyObject, algorithm: number): Uint8Array {
    if (key.type !== 'private') {
        throw new SignerKeyFormatError(`not a private key (${key.type})`);
    }
    const kind = key.asymmetricKeyType;
    if (kind === 'ec') return ecdsa_public_key_field(key, algorithm);
    if (kind === 'ed25519') {
        if (algorithm !== AlgoED25519) {
            throw new SignerKeyFormatError(`Ed25519 key does not suit algorithm ${algorithm}`);
        }
        return jwk_bytes(key.export({ format: 'jwk' }).x);
    }
    if (kind === 'rsa') {
        if (algorithm !== AlgoRSASHA256 && algorithm !== AlgoRSASHA512) {
            throw new SignerKeyFormatError(`RSA key does not suit algorithm ${algorithm}`);
        }
        const jwk = key.export({ format: 'jwk' });
        return rsa_public_key_field(jwk_bytes(jwk.e), jwk_bytes(jwk.n));
    }
    throw new SignerUnsupportedAlgorithmError(`private key type ${kind}`);
}

// ecdsa_public_key_field returns X || Y without the 0x04 prefix (RFC 6605).
function ecdsa_public_key_field(key: crypto.KeyObject, algorithm: number): Uint8Array {
    const curve = ECDSA_CURVES.get(algorithm);
    if (!curve || key.asymmetricKeyDetails?.namedCurve !== curve.node) {
        throw new SignerKeyFormatError(`ECDSA key does not suit algorithm ${algorithm}`);
    }
    const jwk = key.export({ format: 'jwk' });
    const out = new Uint8Array(curve.coord * 2);
    const x = strip_leading_zeros(jwk_bytes(jwk.x));
    const y = strip_leading_zeros(jwk_bytes(jwk.y));
    out.set(x, curve.coord - x.length);
    out.set(y, curve.coord * 2 - y.length);
    return out;
}

// rsa_public_key_field encodes an RSA public key per RFC 3110 §2.
function rsa_public_key_field(exponent: Uint8Array, modulus: Uint8Array): Uint8Array {
    const e = strip_leading_zeros(exponent);
    const n = strip_leading_zeros(modulus);
    const prefix = e.length <= 0xff ? [e.length] : [0, (e.length >> 8) & 0xff, e.length & 0xff];
    const out = new Uint8Array(prefix.length + e.length + n.length);
    out.set(prefix, 0);
    out.set(e, prefix.length);
    out.set(n, prefix.length + e.length);
    return out;
}

function jwk_bytes(field: string | undefined): Uint8Array {
    if (field === undefined) throw new SignerKeyFormatError('key has no public component');
    return new Uint8Array(Buffer.from(field, 'base64url'));
}

function strip_leading_zeros(b: Uint8Array): Uint8Array {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    return b.subarray(i);
}
