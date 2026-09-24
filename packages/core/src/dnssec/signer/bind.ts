// BIND `K*.private` key loading for the zone signer. Ports dnsdata-go
// `dnssec/signer/bind.go`; the parsing itself is the existing
// dnssec_key_loader, whose plain errors are mapped to the signer's.

import * as crypto from 'crypto';
import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../../types/algorithm';
import { get_algorithm_from_string, load_private_key_from_string } from '../dnssec_key_loader';
import { SignerKeyFormatError, SignerUnsupportedAlgorithmError, error_message } from './errors';
import { Key } from './key';

// Algorithms parse_bind_private accepts (the ones the signer signs with).
const BIND_ALGORITHMS: ReadonlySet<number> = new Set([
    AlgoECDSAP256SHA256, AlgoECDSAP384SHA384, AlgoED25519, AlgoRSASHA256, AlgoRSASHA512,
]);

// parse_bind_private loads a private key in the ISC / BIND `K*.private`
// format (`Private-key-format: v1.x`, `Algorithm: 13 (ECDSAP256SHA256)`,
// `PrivateKey: <base64>`, …). The file carries no flags, so the caller
// supplies them. Supported algorithms: 13, 14 (`PrivateKey` = scalar),
// 15 (`PrivateKey` = seed), 8 and 10 (`Modulus`, `PublicExponent`,
// `PrivateExponent`, `Prime1`, `Prime2`, `Exponent1`, `Exponent2`,
// `Coefficient`). Throws SignerKeyFormatError for a malformed file and
// SignerUnsupportedAlgorithmError for other algorithms.
export function parse_bind_private(owner: string, flags: number, text: string | Uint8Array): Key {
    const body = typeof text === 'string' ? text : Buffer.from(text).toString('utf8');
    const algorithm = bind_algorithm(body);
    if (!BIND_ALGORITHMS.has(algorithm)) {
        throw new SignerUnsupportedAlgorithmError(`BIND key algorithm ${algorithm}`);
    }
    let key: crypto.KeyObject;
    try {
        key = load_private_key_from_string(body);
    } catch (e) {
        throw new SignerKeyFormatError(`BIND private key: ${error_message(e)}`);
    }
    return new Key(owner, flags, algorithm, key);
}

// bind_algorithm reads the leading number of `Algorithm: 13 (ECDSAP256SHA256)`.
function bind_algorithm(text: string): number {
    try {
        return get_algorithm_from_string(text);
    } catch (e) {
        throw new SignerKeyFormatError(error_message(e));
    }
}
