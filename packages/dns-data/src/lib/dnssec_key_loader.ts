// DNSSEC Private Key Loader
//
// Loads private keys from ISC/BIND keygen file format
// Ported from wide-cpp-lib/wide/crypto/key_dnssec.cpp

import * as crypto from 'crypto';

// Base64url encode without padding (for JWK)
function base64url_encode(buf: Buffer): string {
    return buf.toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// DER encoding helpers
function der_length(len: number): Buffer {
    if (len < 0x80) return Buffer.from([len]);
    if (len < 0x100) return Buffer.from([0x81, len]);
    return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function der_sequence(contents: Buffer): Buffer {
    return Buffer.concat([Buffer.from([0x30]), der_length(contents.length), contents]);
}

function der_octet_string(contents: Buffer): Buffer {
    return Buffer.concat([Buffer.from([0x04]), der_length(contents.length), contents]);
}

function der_integer(val: number): Buffer {
    return Buffer.from([0x02, 0x01, val]);
}

// OID for ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);

// OID for P-256 (prime256v1): 1.2.840.10045.3.1.7
const OID_P256 = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

// OID for P-384 (secp384r1): 1.3.132.0.34
const OID_P384 = Buffer.from([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]);

// Load ECDSA private key from raw scalar (d) by constructing PKCS#8 DER
function load_ecdsa_private_key(d: Buffer, algo: number): crypto.KeyObject {
    const curve_oid = algo === 13 ? OID_P256 : OID_P384;

    // SEC1 EC private key: SEQUENCE { INTEGER 1, OCTET STRING d }
    const sec1_inner = Buffer.concat([der_integer(1), der_octet_string(d)]);
    const sec1_key = der_sequence(sec1_inner);

    // PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID curve }, OCTET STRING { sec1_key } }
    const algo_id = der_sequence(Buffer.concat([OID_EC_PUBLIC_KEY, curve_oid]));
    const pkcs8_inner = Buffer.concat([der_integer(0), algo_id, der_octet_string(sec1_key)]);
    const pkcs8_der = der_sequence(pkcs8_inner);

    return crypto.createPrivateKey({ key: pkcs8_der, format: 'der', type: 'pkcs8' } as any);
}

// Parse ISC/BIND keygen private key file format
function parse_keygen_fields(text: string): Map<string, string> {
    const fields = new Map<string, string>();
    for (const line of text.split('\n')) {
        const m = line.match(/^(\S+):\s*(.*)$/);
        if (m) {
            fields.set(m[1], m[2].trim());
        }
    }
    return fields;
}

// Extract algorithm number from Algorithm field (e.g. "5 (RSASHA1)" -> 5)
function parse_algorithm(algo_str: string): number {
    const m = algo_str.match(/^(\d+)/);
    if (!m) throw new Error("Invalid Algorithm field: " + algo_str);
    return parseInt(m[1]);
}

// Load a private key from ISC/BIND keygen file format string
export function load_private_key_from_string(text: string): crypto.KeyObject {
    const fields = parse_keygen_fields(text);

    const algo_str = fields.get('Algorithm');
    if (!algo_str) throw new Error("Missing Algorithm field");
    const algo = parse_algorithm(algo_str);

    const get_field = (name: string): Buffer => {
        const val = fields.get(name);
        if (!val) throw new Error(`Missing field: ${name}`);
        return Buffer.from(val, 'base64');
    };

    // ECDSA algorithms (13=P-256, 14=P-384)
    if (algo === 13 || algo === 14) {
        const private_key_buf = get_field('PrivateKey');
        return load_ecdsa_private_key(private_key_buf, algo);
    }

    // RSA-based algorithms
    switch (algo) {
    case 1: case 5: case 7: case 8: case 10:
        break;
    default:
        throw new Error(`Unsupported algorithm: ${algo}`);
    }

    const jwk = {
        kty: 'RSA',
        n: base64url_encode(get_field('Modulus')),
        e: base64url_encode(get_field('PublicExponent')),
        d: base64url_encode(get_field('PrivateExponent')),
        p: base64url_encode(get_field('Prime1')),
        q: base64url_encode(get_field('Prime2')),
        dp: base64url_encode(get_field('Exponent1')),
        dq: base64url_encode(get_field('Exponent2')),
        qi: base64url_encode(get_field('Coefficient')),
    };

    return crypto.createPrivateKey({ key: jwk, format: 'jwk' } as any);
}

// Load a private key from ISC/BIND keygen file
export function load_private_key_from_file(path: string): crypto.KeyObject {
    const fs = require('fs');
    const text = fs.readFileSync(path, 'utf8');
    return load_private_key_from_string(text);
}

// Get the algorithm number from a keygen file string
export function get_algorithm_from_string(text: string): number {
    const fields = parse_keygen_fields(text);
    const algo_str = fields.get('Algorithm');
    if (!algo_str) throw new Error("Missing Algorithm field");
    return parse_algorithm(algo_str);
}
