// DNSSEC algorithm numbers per the IANA "DNS Security Algorithm
// Numbers" registry (RFC 4034 §A.1, RFC 5702, RFC 5933, RFC 6605,
// RFC 8080).
//
// Ports the dnsdata-go `types/algorithm.go` module so the TS and Go
// surfaces stay file-to-file aligned. Constant names mirror Go
// (`AlgoRSASHA256` etc.) and AlgorithmToString / StringToAlgorithm /
// AlgorithmSupported keep the Go signatures.
//
// Only algorithms still considered usable today are surfaced via
// AlgorithmSupported; deprecated ones (RSAMD5, DSA, ECC-GOST) are
// included by AlgorithmToString for round-trip identification only.

export const AlgoDeleted             = 0;   // RFC 4034 reserved
export const AlgoRSAMD5              = 1;   // RFC 2537, deprecated by RFC 6944
export const AlgoDH                  = 2;   // RFC 2539
export const AlgoDSA                 = 3;   // RFC 2536
export const AlgoRSASHA1             = 5;   // RFC 3110
export const AlgoDSANSEC3SHA1        = 6;   // RFC 5155
export const AlgoRSASHA1NSEC3SHA1    = 7;   // RFC 5155
export const AlgoRSASHA256           = 8;   // RFC 5702
export const AlgoRSASHA512           = 10;  // RFC 5702
export const AlgoECCGOST             = 12;  // RFC 5933, deprecated
export const AlgoECDSAP256SHA256     = 13;  // RFC 6605
export const AlgoECDSAP384SHA384     = 14;  // RFC 6605
export const AlgoED25519             = 15;  // RFC 8080
export const AlgoED448               = 16;  // RFC 8080
export const AlgoIndirect            = 252;
export const AlgoPrivateDNS          = 253;
export const AlgoPrivateOID          = 254;

// UnknownAlgorithmError is raised by AlgorithmToString / StringToAlgorithm
// for unassigned numeric or mnemonic values. Mirrors Go's
// `types.ErrUnknownAlgo` sentinel.
export class UnknownAlgorithmError extends RangeError {
    public readonly value: number | string;
    public constructor(value: number | string, message?: string) {
        super(message ?? `unknown DNSSEC algorithm: ${typeof value === 'number' ? value : `"${value}"`}`);
        this.value = value;
        this.name = 'UnknownAlgorithmError';
    }
}

// AlgorithmToString returns the canonical mnemonic for a DNSSEC
// algorithm number. Throws UnknownAlgorithmError for any unassigned
// value. Matches `types.AlgorithmToString` in dnsdata-go.
export function AlgorithmToString(a: number): string {
    switch (a) {
        case AlgoDeleted:           return 'DELETE';
        case AlgoRSAMD5:            return 'RSAMD5';
        case AlgoDH:                return 'DH';
        case AlgoDSA:               return 'DSA';
        case AlgoRSASHA1:           return 'RSASHA1';
        case AlgoDSANSEC3SHA1:      return 'DSA-NSEC3-SHA1';
        case AlgoRSASHA1NSEC3SHA1:  return 'RSASHA1-NSEC3-SHA1';
        case AlgoRSASHA256:         return 'RSASHA256';
        case AlgoRSASHA512:         return 'RSASHA512';
        case AlgoECCGOST:           return 'ECC-GOST';
        case AlgoECDSAP256SHA256:   return 'ECDSAP256SHA256';
        case AlgoECDSAP384SHA384:   return 'ECDSAP384SHA384';
        case AlgoED25519:           return 'ED25519';
        case AlgoED448:             return 'ED448';
        case AlgoIndirect:          return 'INDIRECT';
        case AlgoPrivateDNS:        return 'PRIVATEDNS';
        case AlgoPrivateOID:        return 'PRIVATEOID';
    }
    throw new UnknownAlgorithmError(a);
}

// StringToAlgorithm is the inverse of AlgorithmToString.
export function StringToAlgorithm(s: string): number {
    switch (s) {
        case 'DELETE':              return AlgoDeleted;
        case 'RSAMD5':              return AlgoRSAMD5;
        case 'DH':                  return AlgoDH;
        case 'DSA':                 return AlgoDSA;
        case 'RSASHA1':             return AlgoRSASHA1;
        case 'DSA-NSEC3-SHA1':      return AlgoDSANSEC3SHA1;
        case 'RSASHA1-NSEC3-SHA1':  return AlgoRSASHA1NSEC3SHA1;
        case 'RSASHA256':           return AlgoRSASHA256;
        case 'RSASHA512':           return AlgoRSASHA512;
        case 'ECC-GOST':            return AlgoECCGOST;
        case 'ECDSAP256SHA256':     return AlgoECDSAP256SHA256;
        case 'ECDSAP384SHA384':     return AlgoECDSAP384SHA384;
        case 'ED25519':             return AlgoED25519;
        case 'ED448':               return AlgoED448;
        case 'INDIRECT':            return AlgoIndirect;
        case 'PRIVATEDNS':          return AlgoPrivateDNS;
        case 'PRIVATEOID':          return AlgoPrivateOID;
    }
    throw new UnknownAlgorithmError(s);
}

// AlgorithmSupported reports whether the chain validator can verify
// signatures made with algorithm a today. RSA (SHA1 / SHA256 / SHA512),
// ECDSA (P-256 / P-384), and Ed25519 are supported; Ed448 and the
// deprecated RSAMD5 / DSA / GOST algorithms are recognised by
// AlgorithmToString but not validated.
export function AlgorithmSupported(a: number): boolean {
    switch (a) {
        case AlgoRSASHA1:
        case AlgoRSASHA1NSEC3SHA1:
        case AlgoRSASHA256:
        case AlgoRSASHA512:
        case AlgoECDSAP256SHA256:
        case AlgoECDSAP384SHA384:
        case AlgoED25519:
            return true;
    }
    return false;
}
