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

    // Verify supported algorithm
    switch (algo) {
    case 1: case 5: case 7: case 8: case 10:
        break; // RSA-based algorithms
    default:
        throw new Error(`Unsupported algorithm: ${algo}`);
    }

    const get_field = (name: string): Buffer => {
        const val = fields.get(name);
        if (!val) throw new Error(`Missing field: ${name}`);
        return Buffer.from(val, 'base64');
    };

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
