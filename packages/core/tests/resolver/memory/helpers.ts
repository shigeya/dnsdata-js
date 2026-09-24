// Shared fixtures for the in-memory authority specs: a signed fake root,
// test., and example.test. Ports dnsdata-go
// `resolver/memory/hierarchy_test.go` (buildHierarchy and helpers).

import * as crypto from 'crypto';
import * as signer from '../../../src/dnssec/signer';
import { registerAllHandlers } from '../../../src/index';
import { Authority, Option, new_authority, with_zone } from '../../../src/resolver/memory';
import { Verifier } from '../../../src/verifier/verifier';
import { Zone } from '../../../src/zone/dns_zone';

export const inception = new Date(Date.UTC(2026, 0, 1));
export const expiration = new Date(Date.UTC(2036, 0, 1));
export const now = new Date(Date.UTC(2026, 5, 1));

// bindPrivateText is a BIND K*.private file for the deterministic P-256
// key derived from seed (the same derivation as the Go side, so the
// keys match testdata/signed/keys).
export function bindPrivateText(seed: string): string {
    const d = crypto.createHash('sha256').update(seed).digest();
    return 'Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: ' +
        d.toString('base64') + '\n';
}

export function fixedKey(owner: string, seed: string, flags: number): signer.Key {
    return signer.parse_bind_private(owner, flags, bindPrivateText(seed));
}

export function readZone(text: string): Zone {
    registerAllHandlers();
    const z = new Zone();
    z.read_string_strict(text);
    return z;
}

export function sign(z: Zone, apex: string, keys: signer.Key[], from: Date, until: Date): Zone {
    return signer.sign_zone(z, apex, keys, { inception: from, expiration: until });
}

export const leafText = `$ORIGIN example.test.
$TTL 3600
@      SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@      NS  ns1.example.test.
ns1    A   192.0.2.1
www    A   192.0.2.10
www    TXT "hello"
key    TYPE65400 \\# 35 030101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
*.wild A   192.0.2.20
alias  CNAME www.example.test.
`;

// hierarchyKeys are the fixed keys of the hierarchy; the seed also names
// the key file in testdata/signed/keys.
export const hierarchyKeys: ReadonlyArray<{ owner: string; seed: string; flags: number }> = [
    { owner: '.', seed: 'root-ksk', flags: signer.FlagsKSK },
    { owner: 'test.', seed: 'test-ksk', flags: signer.FlagsKSK },
    { owner: 'example.test.', seed: 'example-ksk', flags: signer.FlagsKSK },
    { owner: 'example.test.', seed: 'example-zsk', flags: signer.FlagsZSK },
];

export interface Hierarchy {
    root: Zone;
    tld: Zone;
    leaf: Zone;
    rootKSK: signer.Key;
    leafKeys: signer.Key[];
    leafUnsigned: Zone;
}

export function buildHierarchy(): Hierarchy {
    const [rootKSK, tldKSK, leafKSK, leafZSK] = hierarchyKeys.map((k) => fixedKey(k.owner, k.seed, k.flags));
    const root = readZone('. 86400 SOA a.root.test. hostmaster.root.test. 1 1800 900 604800 86400\n' +
        '. 86400 NS a.root.test.\n' +
        'test. 86400 NS ns.test.\n' +
        'test. 86400 DS ' + tldKSK.ds(signer.DigestSHA256) + '\n');
    const tld = readZone(`$ORIGIN test.
$TTL 3600
@ SOA ns.test. hostmaster.test. 1 7200 3600 1209600 300
@ NS ns.test.
ns A 192.0.2.53
example NS ns1.example.test.
example DS ${leafKSK.ds(signer.DigestSHA256)}
insecure NS ns.insecure.test.
ns.insecure A 192.0.2.54
`);
    const leaf = readZone(leafText);
    const leafKeys = [leafKSK, leafZSK];
    return {
        root: sign(root, '.', [rootKSK], inception, expiration),
        tld: sign(tld, 'test.', [tldKSK], inception, expiration),
        leaf: sign(leaf, 'example.test.', leafKeys, inception, expiration),
        rootKSK,
        leafKeys,
        leafUnsigned: leaf,
    };
}

export function newAuthority(h: Hierarchy, leaf: Zone, ...opts: Option[]): Authority {
    return new_authority(
        with_zone('.', h.root),
        with_zone('test.', h.tld),
        with_zone('example.test.', leaf),
        ...opts,
    );
}

export function newVerifier(h: Hierarchy, a: Authority, clock: Date): Verifier {
    return new Verifier({ resolver: a, trustAnchors: signer.root_anchors(h.rootKSK), now: () => clock });
}
