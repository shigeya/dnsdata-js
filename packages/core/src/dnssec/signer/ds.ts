// DS and trust-anchor derivation of the zone signer. Ports dnsdata-go
// `dnssec/signer/ds.go`.

import * as crypto from 'crypto';
import { domain_name2wire } from '../../wire/dns_wire';
import { WireBuilder } from '../../wire/dns_wire_util';
import { RootAnchorDS, RootAnchors } from '../root_anchors';
import { SignerError, SignerUnsupportedAlgorithmError, error_message } from './errors';
import type { Key } from './key';

// DS digest types the signer produces (RFC 4509, RFC 6605). SHA-1
// (type 1) is deliberately not offered.
export const DigestSHA256 = 2;
export const DigestSHA384 = 4;

// Node hash names by DS digest type.
const DIGEST_HASHES: ReadonlyMap<number, string> = new Map([
    [DigestSHA256, 'sha256'],
    [DigestSHA384, 'sha384'],
]);

// Names the producer in RootAnchors.source.
const ANCHORS_SOURCE = 'dnsdata-js/dnssec/signer';

// DNSKEY protocol field (RFC 4034 §2.1.2); repeated from key.ts to keep
// this module free of runtime imports from it.
const DNSKEY_PROTOCOL = 3;

// ds_digest computes the RFC 4034 §5.1.4 digest of the key's DNSKEY:
// H(owner || flags || protocol || algorithm || public key).
function ds_digest(key: Key, digest_type: number): Buffer {
    const hash = DIGEST_HASHES.get(digest_type);
    if (hash === undefined) {
        throw new SignerUnsupportedAlgorithmError(`DS digest type ${digest_type}`);
    }
    const builder = new WireBuilder();
    try {
        builder.append_bytes(domain_name2wire(key.owner));
    } catch (e) {
        throw new SignerError(`owner "${key.owner}": ${error_message(e)}`);
    }
    builder.append_uint16(key.flags);
    builder.append_uint8(DNSKEY_PROTOCOL);
    builder.append_uint8(key.algorithm);
    builder.append_bytes(key.public_key);
    return crypto.createHash(hash).update(builder.build()).digest();
}

// ds_value_of backs Key.ds: `<key tag> <algorithm> <digest type> <hex>`.
export function ds_value_of(key: Key, digest_type: number): string {
    const digest = ds_digest(key, digest_type);
    return `${key.key_tag} ${key.algorithm} ${digest_type} ${digest.toString('hex')}`;
}

// anchor_ds_of backs Key.anchor_ds: the DS as a trust-anchor entry.
export function anchor_ds_of(key: Key, digest_type: number): RootAnchorDS {
    const digest = ds_digest(key, digest_type);
    return {
        keyTag: key.key_tag,
        algorithm: key.algorithm,
        digestType: digest_type,
        digest: digest.toString('hex').toUpperCase(),
    };
}

// root_anchors builds trust anchors for a self-made root: one SHA-256
// DS per KSK among keys. Pass the result as the verifier's
// `trustAnchors` to validate a hierarchy signed under that root. Every
// key must be owned by "."; ZSKs are skipped. Throws SignerError when a
// key is not at the root or no key is a KSK.
export function root_anchors(...keys: Key[]): RootAnchors {
    const ds: RootAnchorDS[] = [];
    for (const key of keys) {
        if (key.owner !== '.') {
            throw new SignerError(`root_anchors: key owner "${key.owner}" is not the root`);
        }
        if (key.is_ksk()) ds.push(key.anchor_ds(DigestSHA256));
    }
    if (ds.length === 0) {
        throw new SignerError('root_anchors: no KSK among the keys');
    }
    return { lastUpdated: '', source: ANCHORS_SOURCE, ds, dnskeys: [] };
}
