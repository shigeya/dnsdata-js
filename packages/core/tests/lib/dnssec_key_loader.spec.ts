// DNSSEC Private Key Loader tests

import * as crypto from 'crypto';
import { load_private_key_from_string, get_algorithm_from_string } from "../../src/lib/dnssec_key_loader";
import { DNSKey } from "../../src/lib/dnssec_rr";
import { ResourceRecord } from "../../src/zone/dns_zone";

// RSA/SHA1 key from C++ test data (Ktest1.local.+005+61037.private)
const RSAKeyFile4 =
`Private-key-format: v1.2
Algorithm: 5 (RSASHA1)
Modulus: C9+utsfoDjqceH6tSyE15GObD6VFY8wl6iU84ns1vPQw5xtG4eESOSKFh1K/FGS26KEWZ/SOY0JtS1u8FR4w/pLBRL+pF8Vzhsy5aQMge6bIe/s0krQwzx1iDnHjoR9PG1acK0U9p9aNHLwjww3mreHZFL/qcEH/ixELpoRxk2FDYa5+x9y8vViRqc5cy8JEAmbFL9m+eu2WvEfw1iSVpWXcUTUahqQC9Fl2sI3Mzx7ewZ5sttVDDKk6NyAZ79FaWYIsIgePX0SmVpJBJkuIsDiZIcPGtsdkMP9+LFJ+slmq6yZz2+eBHBdS8psoVx70q34UW9HZvxoF+G3LS+yQPsg7SeN9/nDvo/My/X8J7K1Y7cq0ME5dPtidAX0Xq0oB
PublicExponent: Aw==
PrivateExponent: B+p0edqatCcS+v8eMhYj7Ze8tRjY7TLD8W4olvzOffggmhIvQUC20MGuWjcqDZh58GtkRU20QixI3OfSuL7LVGHWLdUbZS5NBIh7m1dq/Rna/VIjDHggihOWtEvtFhTfZ48Sx4N+b+ReEygX116ZyUE7YyqcStaqXLYHxFhLt5Ys68mp2pMofjsLxomTMoGCYovncJEH4cr27jGkLSz1XQlBZPpAL94XE+5T9TFPYV4BJcdGi765BC21KGWT+4AQq3N2em3HD1aMWxFhqmuyrAuT4aWP8MBqhTHzmZGLLNY1OSil1zKaTIXOGqASEaA77CuFXsbWgdpkfmpi8xgv9qOz9kWS8m8RF40EhPV6aHG/cvOHPL6LijAAEpIaLovj
Prime1: O3YtKejtkkffyNWwlfqBoblO1yuyivNKk6rjGijI29fDp/9M6Ilh3p31C+K343shCDq9/J1KiR1riUkyYvcp9tQRTE0bxhtEIvKqpwLndh5sjMSlwgz/ScVUCyRID62DV9lUtrgu9doehoT/anJh9f9gS2M/YK2A+b/P7C5Q8PtlGWZmSObXcCpdI5uL4mwT
Prime2: Mx683RdFFfVEjifJ/Gaj+B6rYpIHs+OVwskVppsM4ToZYPQ1/K3Lp8a1bqUEExYgUBo8bcWaPyVoRK78Q7LSt1MqAv5TB4uARkHmHvVGePnuiKTVVw6aX4lJv4bFLQEXcWN3lu9pBnhQtEk3dNXmVtNNDRfiMhzVBt/cSeCBXwdUp/cDDEm0f2Y/wgZkgwwb
Exponent1: J6QeG/CeYYU/2zkgY/xWa9DfOh0hsfeHDRyXZsXbPTqCb/+ImwZBPxP4spclQlIWBXx+qGjcW2jyW4Yhl09xTzgLiDNn2WeCwfccb1dE+Wmdsy3D1rNU29jishgwCnOs5TuNzyV0o+a/BFiqRvbr+VTq3OzU6x5V+9U1SB7goKeYu5mZhe86SsbowmeylvK3
Exponent2: IhR96LouDqODCW/b/ZnCpWnHlwwFIpe5LIYObxIIlia7lfgj/ckyb9nOScNYDLlq4BF9noO8KhjwLcn9gnc3JOIcAf7iBQeq2YFEFKOEUKafBcM45LRm6luGf68uHgC6S5elD0pGBFA1zYYk+I6ZjzeIs2VBdr3jWeqS2+sA6gTjGqSsstvNqkQqgVmYV11n
Coefficient: JeSBzTaKPnGJeh88JkEOAQtAeD17nIY2DxYaQn7YNPSXjbcFSPmvqlV+RC9jGOtgIi95v9dUebamoS2nReQEaQBPPqLAyJqwE0JZH3jV3Kt0LDNgCAPjaRu74G47Ib+NOeRzgzs2ZRdKJkSP+ssIGzq/1z6JjKiOw2XAZMVYTvmu1nXFFKA6NM9kV1s4dIhW`;

// RRSIG digest data from C++ test (known test vector)
const RRSig_DigestData1 = new Uint8Array([
    0x00, 0x01, 0x05, 0x02, 0x00, 0x01, 0x51, 0x80,
    0x45, 0x8b, 0x82, 0x94, 0x45, 0x63, 0xf5, 0x94,
    0xee, 0x6d, 0x05, 0x74, 0x65, 0x73, 0x74, 0x31,
    0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x05,
    0x74, 0x65, 0x73, 0x74, 0x31, 0x05, 0x6c, 0x6f,
    0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x01, 0x51, 0x80, 0x00, 0x04, 0xc0, 0xa8,
    0x00, 0x01
]);

describe("load_private_key_from_string", () => {
    it("can load RSA/SHA1 private key", () => {
        const key = load_private_key_from_string(RSAKeyFile4);
        expect(key).toBeDefined();
        expect(key.type).toBe('private');
        expect(key.asymmetricKeyType).toBe('rsa');
    });

    it("can get algorithm from key file", () => {
        expect(get_algorithm_from_string(RSAKeyFile4)).toBe(5);
    });

    it("can sign and verify with loaded private key", () => {
        const privKey = load_private_key_from_string(RSAKeyFile4);

        // Sign the test data
        const signer = crypto.createSign('RSA-SHA1');
        signer.update(Buffer.from(RRSig_DigestData1));
        const signature = signer.sign(privKey);

        // Verify using the public key derived from private key
        const pubKey = crypto.createPublicKey(privKey);
        const verifier = crypto.createVerify('RSA-SHA1');
        verifier.update(Buffer.from(RRSig_DigestData1));
        expect(verifier.verify(pubKey, signature)).toBe(true);
    });

    it("sign-verify round trip with DNSKey integration", () => {
        const privKey = load_private_key_from_string(RSAKeyFile4);

        // Export public key as JWK to get n and e for RFC3110 format
        const pubKey = crypto.createPublicKey(privKey);
        const jwk = pubKey.export({ format: 'jwk' } as any) as any;
        const n = Buffer.from(jwk.n, 'base64url');
        const e = Buffer.from(jwk.e, 'base64url');

        // Build RFC3110 format
        const rfc3110 = Buffer.concat([Buffer.from([e.length]), e, n]);
        const key_b64 = rfc3110.toString('base64');

        // Create DNSKey directly (not via handler registry)
        const dnskey_rr = new ResourceRecord("test1.local.", 86400, "IN", "DNSKEY", `257 3 5 ${key_b64}`);
        const dnskey = new DNSKey(dnskey_rr, `257 3 5 ${key_b64}`);
        dnskey.set_private_key(privKey);

        // Sign and verify using DNSKey
        const signature = dnskey.sign(RRSig_DigestData1);
        expect(dnskey.verify(RRSig_DigestData1, signature)).toBe(true);
    });

    it("can load ECDSA P-256 private key (algorithm 13)", () => {
        // Generate an EC P-256 key, export as ISC format, and re-import
        const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const jwk = privateKey.export({ format: 'jwk' } as any) as any;
        const d_b64 = Buffer.from(jwk.d, 'base64url').toString('base64');

        const isc_text = `Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: ${d_b64}`;

        const loaded = load_private_key_from_string(isc_text);
        expect(loaded).toBeDefined();
        expect(loaded.type).toBe('private');
        expect(loaded.asymmetricKeyType).toBe('ec');
    });

    it("can sign and verify with loaded ECDSA P-256 key", () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const priv_jwk = privateKey.export({ format: 'jwk' } as any) as any;
        const pub_jwk = publicKey.export({ format: 'jwk' } as any) as any;
        const d_b64 = Buffer.from(priv_jwk.d, 'base64url').toString('base64');

        const isc_text = `Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: ${d_b64}`;

        const loaded_key = load_private_key_from_string(isc_text);

        // Build DNSKEY from public key
        const x = Buffer.from(pub_jwk.x, 'base64url');
        const y = Buffer.from(pub_jwk.y, 'base64url');
        const key_data = Buffer.concat([x, y]);
        const key_b64 = key_data.toString('base64');

        const dnskey_rr = new ResourceRecord("test.local.", 86400, "IN", "DNSKEY", `257 3 13 ${key_b64}`);
        const dnskey = new DNSKey(dnskey_rr, `257 3 13 ${key_b64}`);
        dnskey.set_private_key(loaded_key);

        const test_data = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
        const signature = dnskey.sign(test_data);
        expect(dnskey.verify(test_data, signature)).toBe(true);
    });

    it("can load Ed25519 private key (algorithm 15)", () => {
        const { privateKey } = crypto.generateKeyPairSync('ed25519');
        const jwk = privateKey.export({ format: 'jwk' } as any) as any;
        const d_b64 = Buffer.from(jwk.d, 'base64url').toString('base64');

        const isc_text = `Private-key-format: v1.2
Algorithm: 15 (ED25519)
PrivateKey: ${d_b64}`;

        const loaded = load_private_key_from_string(isc_text);
        expect(loaded).toBeDefined();
        expect(loaded.type).toBe('private');
        expect(loaded.asymmetricKeyType).toBe('ed25519');
    });

    it("can sign and verify with loaded Ed25519 key", () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const priv_jwk = privateKey.export({ format: 'jwk' } as any) as any;
        const pub_jwk = publicKey.export({ format: 'jwk' } as any) as any;
        const d_b64 = Buffer.from(priv_jwk.d, 'base64url').toString('base64');

        const isc_text = `Private-key-format: v1.2
Algorithm: 15 (ED25519)
PrivateKey: ${d_b64}`;

        const loaded_key = load_private_key_from_string(isc_text);

        const key_data = Buffer.from(pub_jwk.x, 'base64url');
        const key_b64 = key_data.toString('base64');

        const dnskey_rr = new ResourceRecord("test.local.", 86400, "IN", "DNSKEY", `257 3 15 ${key_b64}`);
        const dnskey = new DNSKey(dnskey_rr, `257 3 15 ${key_b64}`);
        dnskey.set_private_key(loaded_key);

        const test_data = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
        const signature = dnskey.sign(test_data);
        expect(dnskey.verify(test_data, signature)).toBe(true);
    });

    it("throws for unsupported algorithm", () => {
        const bad_key = `Private-key-format: v1.2
Algorithm: 99 (UNSUPPORTED)
Modulus: AAAA
PublicExponent: Aw==
PrivateExponent: AAAA
Prime1: AAAA
Prime2: AAAA
Exponent1: AAAA
Exponent2: AAAA
Coefficient: AAAA`;
        expect(() => load_private_key_from_string(bad_key)).toThrow("Unsupported algorithm");
    });
});
