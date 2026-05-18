// Spec for types/algorithm.ts. Ports the dnsdata-go
// types/algorithm_test.go vectors (UP-007 follow-up: P3 of the
// dnsdata-js refactor extracts these from dnssec_rr.ts).

import {
    AlgoDeleted,
    AlgoRSAMD5,
    AlgoDH,
    AlgoDSA,
    AlgoRSASHA1,
    AlgoDSANSEC3SHA1,
    AlgoRSASHA1NSEC3SHA1,
    AlgoRSASHA256,
    AlgoRSASHA512,
    AlgoECCGOST,
    AlgoECDSAP256SHA256,
    AlgoECDSAP384SHA384,
    AlgoED25519,
    AlgoED448,
    AlgoIndirect,
    AlgoPrivateDNS,
    AlgoPrivateOID,
    AlgorithmToString,
    StringToAlgorithm,
    AlgorithmSupported,
    UnknownAlgorithmError,
} from '../../../src/lib/types/algorithm';

const VECTORS: ReadonlyArray<readonly [number, string]> = [
    [AlgoDeleted,            'DELETE'],
    [AlgoRSAMD5,             'RSAMD5'],
    [AlgoDH,                 'DH'],
    [AlgoDSA,                'DSA'],
    [AlgoRSASHA1,            'RSASHA1'],
    [AlgoDSANSEC3SHA1,       'DSA-NSEC3-SHA1'],
    [AlgoRSASHA1NSEC3SHA1,   'RSASHA1-NSEC3-SHA1'],
    [AlgoRSASHA256,          'RSASHA256'],
    [AlgoRSASHA512,          'RSASHA512'],
    [AlgoECCGOST,            'ECC-GOST'],
    [AlgoECDSAP256SHA256,    'ECDSAP256SHA256'],
    [AlgoECDSAP384SHA384,    'ECDSAP384SHA384'],
    [AlgoED25519,            'ED25519'],
    [AlgoED448,              'ED448'],
    [AlgoIndirect,           'INDIRECT'],
    [AlgoPrivateDNS,         'PRIVATEDNS'],
    [AlgoPrivateOID,         'PRIVATEOID'],
];

describe('AlgorithmToString', () => {
    for (const [code, str] of VECTORS) {
        test(`maps ${code} to ${str}`, () => {
            expect(AlgorithmToString(code)).toBe(str);
        });
    }

    test.each([4, 9, 11, 100])('throws UnknownAlgorithmError for unassigned %d', (code) => {
        expect(() => AlgorithmToString(code)).toThrow(UnknownAlgorithmError);
    });
});

describe('StringToAlgorithm', () => {
    for (const [code, str] of VECTORS) {
        test(`maps ${str} to ${code}`, () => {
            expect(StringToAlgorithm(str)).toBe(code);
        });
    }

    test('throws UnknownAlgorithmError for unknown mnemonic', () => {
        expect(() => StringToAlgorithm('XXX')).toThrow(UnknownAlgorithmError);
    });
});

describe('AlgorithmSupported', () => {
    test.each([
        AlgoRSASHA1,
        AlgoRSASHA1NSEC3SHA1,
        AlgoRSASHA256,
        AlgoRSASHA512,
        AlgoECDSAP256SHA256,
        AlgoECDSAP384SHA384,
        AlgoED25519,
    ])('reports %d as supported', (code) => {
        expect(AlgorithmSupported(code)).toBe(true);
    });

    test.each([
        AlgoDeleted,
        AlgoRSAMD5,
        AlgoDSA,
        AlgoECCGOST,
        AlgoED448,
        100,
    ])('reports %d as unsupported', (code) => {
        expect(AlgorithmSupported(code)).toBe(false);
    });
});
