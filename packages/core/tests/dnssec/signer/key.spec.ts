// Ports dnsdata-go `dnssec/signer/key_test.go`, plus known-answer DS
// values from RFC 6605 §6 and RFC 8080 §6.

import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DNSKey, DNSRR_DS } from '../../../src/dnssec/dnssec_rr';
import { ResourceRecord } from '../../../src/zone/dns_zone';
import {
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoRSASHA1,
    AlgoRSASHA256,
    AlgoRSASHA512,
} from '../../../src/types/algorithm';
import * as signer from '../../../src/dnssec/signer';
import { signer as exported } from '../../../src/index';
import { bindPrivateECDSA, findTool, stripBlanks } from './helpers';

describe('signer.generate_key', () => {
    it.each([AlgoECDSAP256SHA256, AlgoECDSAP384SHA384, AlgoED25519, AlgoRSASHA256, AlgoRSASHA512])(
        'algorithm %i yields a parseable DNSKEY', (alg) => {
            const k = signer.generate_key('example.test.', alg, signer.FlagsKSK);
            const parsed = new DNSKey(null, k.dnskey_value());
            expect(parsed.key_tag).toBe(k.key_tag);
            expect(parsed.algorithm).toBe(alg);
            expect(parsed.flags).toBe(signer.FlagsKSK);
            expect(() => parsed.get_public_key()).not.toThrow();
            expect(k.is_ksk()).toBe(true);
            expect(k.owner).toBe('example.test.');
        });

    it('ZSK flags are 256 and not a KSK', () => {
        const k = signer.generate_key('example.test.', AlgoED25519, signer.FlagsZSK);
        expect(k.flags).toBe(256);
        expect(k.is_ksk()).toBe(false);
    });

    it('rejects algorithms it does not produce', () => {
        expect(() => signer.generate_key('example.test.', AlgoRSASHA1, signer.FlagsZSK))
            .toThrow(signer.SignerUnsupportedAlgorithmError);
    });

    it('rejects a relative owner', () => {
        expect(() => signer.generate_key('example.test', AlgoED25519, signer.FlagsZSK))
            .toThrow(signer.SignerError);
    });

    it('is exported from the package entry point as a namespace', () => {
        expect(exported.generate_key).toBe(signer.generate_key);
        expect(exported.sign_zone).toBe(signer.sign_zone);
    });
});

describe('signer PKCS#8', () => {
    it.each([AlgoECDSAP256SHA256, AlgoED25519, AlgoRSASHA256])('round-trips algorithm %i', (alg) => {
        const k = signer.generate_key('example.test.', alg, signer.FlagsZSK);
        const pem = k.pkcs8_pem();
        expect(pem).toContain('-----BEGIN PRIVATE KEY-----');
        const back = signer.parse_pkcs8_pem('example.test.', signer.FlagsZSK, alg, pem);
        expect(back.dnskey_value()).toBe(k.dnskey_value());
        const fromBytes = signer.parse_pkcs8_pem('example.test.', signer.FlagsZSK, alg, Buffer.from(pem));
        expect(fromBytes.dnskey_value()).toBe(k.dnskey_value());
    });

    it('infers the algorithm and rejects a mismatch', () => {
        const ed = signer.generate_key('example.test.', AlgoED25519, signer.FlagsKSK).pkcs8_pem();
        expect(signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0, ed).algorithm).toBe(AlgoED25519);
        expect(() => signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, AlgoECDSAP256SHA256, ed))
            .toThrow(signer.SignerKeyFormatError);
        expect(() => signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0, 'not pem'))
            .toThrow(signer.SignerKeyFormatError);
    });

    it('infers 14 for a P-384 key and 8 for RSA', () => {
        const p384 = signer.generate_key('example.test.', AlgoECDSAP384SHA384, signer.FlagsKSK).pkcs8_pem();
        expect(signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0, p384).algorithm).toBe(AlgoECDSAP384SHA384);
        const rsa = signer.generate_key('example.test.', AlgoRSASHA512, signer.FlagsKSK).pkcs8_pem();
        expect(signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0, rsa).algorithm).toBe(AlgoRSASHA256);
    });

    it('rejects a PEM block that is not PKCS#8, and a broken body', () => {
        const sec1 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
            .export({ type: 'sec1', format: 'pem' }).toString();
        expect(() => signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0, sec1))
            .toThrow(signer.SignerKeyFormatError);
        expect(() => signer.parse_pkcs8_pem('example.test.', signer.FlagsKSK, 0,
            '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'))
            .toThrow(signer.SignerKeyFormatError);
    });
});

describe('signer.new_key', () => {
    it('rejects keys that do not suit the algorithm or are not private', () => {
        const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        expect(() => signer.new_key('example.test.', signer.FlagsKSK, AlgoECDSAP384SHA384, ec.privateKey))
            .toThrow(signer.SignerKeyFormatError);
        expect(() => signer.new_key('example.test.', signer.FlagsKSK, 0, ec.publicKey))
            .toThrow(signer.SignerKeyFormatError);
        const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
        expect(() => signer.new_key('example.test.', signer.FlagsKSK, AlgoED25519, rsa.privateKey))
            .toThrow(signer.SignerKeyFormatError);
        const ed = crypto.generateKeyPairSync('ed25519');
        expect(() => signer.new_key('example.test.', signer.FlagsKSK, AlgoRSASHA256, ed.privateKey))
            .toThrow(signer.SignerKeyFormatError);
        const x = crypto.generateKeyPairSync('x25519');
        expect(() => signer.new_key('example.test.', signer.FlagsKSK, 0, x.privateKey))
            .toThrow(signer.SignerUnsupportedAlgorithmError);
    });
});

describe('signer.parse_bind_private', () => {
    it('is deterministic for ECDSA', () => {
        const a = signer.parse_bind_private('example.test.', signer.FlagsKSK, bindPrivateECDSA('k1'));
        const b = signer.parse_bind_private('example.test.', signer.FlagsKSK, Buffer.from(bindPrivateECDSA('k1')));
        expect(a.dnskey_value()).toBe(b.dnskey_value());
        expect(a.key_tag).toBe(b.key_tag);
        const c = signer.parse_bind_private('example.test.', signer.FlagsKSK, bindPrivateECDSA('k2'));
        expect(a.dnskey_value()).not.toBe(c.dnskey_value());
    });

    it.each([
        ['no algorithm', 'Private-key-format: v1.3\nPrivateKey: AAAA\n', signer.SignerKeyFormatError],
        ['unsupported', 'Algorithm: 3 (DSA)\nPrivateKey: AAAA\n', signer.SignerUnsupportedAlgorithmError],
        ['missing field', 'Algorithm: 13 (ECDSAP256SHA256)\n', signer.SignerKeyFormatError],
        ['bad base64', 'Algorithm: 15 (ED25519)\nPrivateKey: !!!\n', signer.SignerKeyFormatError],
        ['short ed25519', 'Algorithm: 15 (ED25519)\nPrivateKey: AAAA\n', signer.SignerKeyFormatError],
        ['rsa missing', 'Algorithm: 8 (RSASHA256)\nModulus: AQAB\n', signer.SignerKeyFormatError],
    ])('%s: throws', (_name, text, errorClass) => {
        expect(() => signer.parse_bind_private('example.test.', signer.FlagsKSK, text)).toThrow(errorClass);
    });
});

// Known answers: the private keys, DNSKEYs and DS records of the
// examples in RFC 6605 §6.1 (ECDSA P-256) and RFC 8080 §6.1 (Ed25519).
describe('signer DS known values', () => {
    it.each([
        {
            name: 'RFC 6605 P-256',
            owner: 'example.net.',
            priv: 'Private-key-format: v1.2\nAlgorithm: 13 (ECDSAP256SHA256)\n' +
                'PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=\n',
            dnskey: '257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==',
            ds: '55648 13 2 b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17',
        },
        {
            name: 'RFC 8080 Ed25519',
            owner: 'example.com.',
            priv: 'Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\n' +
                'PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=\n',
            dnskey: '257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=',
            ds: '3613 15 2 3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b',
        },
    ])('$name', ({ owner, priv, dnskey, ds }) => {
        const k = signer.parse_bind_private(owner, signer.FlagsKSK, priv);
        expect(k.dnskey_value()).toBe(dnskey);
        expect(k.ds(signer.DigestSHA256)).toBe(ds);
    });
});

describe('signer Key.ds / anchor_ds', () => {
    const k = signer.parse_bind_private('example.test.', signer.FlagsKSK, bindPrivateECDSA('ds'));
    const rr = new ResourceRecord('example.test.', 3600, 'IN', 'DNSKEY', k.dnskey_value());
    const digestData = new DNSKey(rr, k.dnskey_value()).get_ds_digest_data();

    it.each([signer.DigestSHA256, signer.DigestSHA384])('digest type %i matches the DNSKEY', (dt) => {
        const ds = new DNSRR_DS(null, k.ds(dt));
        expect(ds.verify_digest(digestData)).toBe(true);
        expect(ds.key_tag).toBe(k.key_tag);
        const anchor = k.anchor_ds(dt);
        expect(anchor.keyTag).toBe(k.key_tag);
        expect(anchor.algorithm).toBe(AlgoECDSAP256SHA256);
        expect(anchor.digestType).toBe(dt);
        expect(anchor.digest).toBe(Buffer.from(ds.digest).toString('hex').toUpperCase());
    });

    it('does not produce SHA-1 digests', () => {
        expect(() => k.ds(1)).toThrow(signer.SignerUnsupportedAlgorithmError);
        expect(() => k.anchor_ds(1)).toThrow(signer.SignerUnsupportedAlgorithmError);
    });

    it('dnskey_record places the key at its owner', () => {
        const rec = k.dnskey_record(600);
        expect(rec.label).toBe('example.test.');
        expect(rec.ttl).toBe(600);
        expect(rec.value).toBe(k.dnskey_value());
    });
});

describe('signer.root_anchors', () => {
    it('takes one SHA-256 DS per root KSK', () => {
        const ksk = signer.generate_key('.', AlgoECDSAP256SHA256, signer.FlagsKSK);
        const zsk = signer.generate_key('.', AlgoECDSAP256SHA256, signer.FlagsZSK);
        const anchors = signer.root_anchors(ksk, zsk);
        expect(anchors.ds).toHaveLength(1);
        expect(anchors.ds[0].keyTag).toBe(ksk.key_tag);
        expect(anchors.ds[0].digestType).toBe(2);
        expect(anchors.dnskeys).toEqual([]);
        expect(anchors.source).toBe('dnsdata-js/dnssec/signer');
    });

    it('rejects a non-root key and a set without a KSK', () => {
        const notRoot = signer.generate_key('test.', AlgoECDSAP256SHA256, signer.FlagsKSK);
        expect(() => signer.root_anchors(notRoot)).toThrow(signer.SignerError);
        const zsk = signer.generate_key('.', AlgoED25519, signer.FlagsZSK);
        expect(() => signer.root_anchors(zsk)).toThrow(signer.SignerError);
        expect(() => signer.root_anchors()).toThrow(signer.SignerError);
    });
});

// Cross-check against BIND when its tools are installed: a key made by
// dnssec-keygen loads through parse_bind_private to the same DNSKEY and DS.
const keygen = findTool('dnssec-keygen');
const dsfromkey = findTool('dnssec-dsfromkey');
const itWithBIND = keygen !== null && dsfromkey !== null ? it : it.skip;

describe('signer.parse_bind_private matches dnssec-keygen', () => {
    itWithBIND.each(['ECDSAP256SHA256', 'ECDSAP384SHA384', 'ED25519', 'RSASHA256'])('%s', (alg) => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-keygen-'));
        try {
            const out = execFileSync(keygen as string, ['-q', '-K', dir, '-a', alg, '-f', 'KSK', 'example.test'],
                { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
            const base = path.join(dir, out.trim());
            const priv = fs.readFileSync(base + '.private', 'utf8');
            const pub = fs.readFileSync(base + '.key', 'utf8');
            const k = signer.parse_bind_private('example.test.', signer.FlagsKSK, priv);
            expect(stripBlanks(pub)).toContain(stripBlanks(k.dnskey_value()));
            const dsOut = execFileSync(dsfromkey as string, ['-2', base + '.key'],
                { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
            expect(stripBlanks(dsOut).toUpperCase()).toContain(stripBlanks(k.ds(2)).toUpperCase());
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});
