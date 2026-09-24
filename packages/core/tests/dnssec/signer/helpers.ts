// Shared fixtures for the zone signer specs (ports of the helpers in
// dnsdata-go `dnssec/signer/{key,sign}_test.go`).

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { DNSSecZone, KeyVerifyMode } from '../../../src/dnssec/dnssec_zone';
import { RRSig } from '../../../src/dnssec/dnssec_rr';
import { StringToRRType } from '../../../src/types/dns_type_table';
import { ResourceRecord, Zone } from '../../../src/zone/dns_zone';
import * as signer from '../../../src/dnssec/signer';

export const TYPE_RRSIG = StringToRRType('RRSIG');

export const testInception = new Date(Date.UTC(2026, 0, 1));
export const testExpiration = new Date(Date.UTC(2027, 0, 1));
export const testNow = new Date(Date.UTC(2026, 5, 1));

export function signOpts(): signer.SignOptions {
    return { inception: testInception, expiration: testExpiration };
}

// fixedScalar is a deterministic P-256 private scalar for tests.
export function fixedScalar(seed: string): Buffer {
    return crypto.createHash('sha256').update(seed).digest();
}

export function bindPrivateECDSA(seed: string): string {
    return 'Private-key-format: v1.3\n' +
        'Algorithm: 13 (ECDSAP256SHA256)\n' +
        'PrivateKey: ' + fixedScalar(seed).toString('base64') + '\n' +
        'Created: 20260101000000\n';
}

export function mustKey(owner: string, seed: string, flags: number): signer.Key {
    return signer.parse_bind_private(owner, flags, bindPrivateECDSA(seed));
}

// exampleZone is example.test. with a signed delegation (sub), an
// unsigned delegation (nods), glue under both, a wildcard, and a type
// without a mnemonic whose members differ in length.
export function exampleZone(childKSK: signer.Key): Zone {
    const ds = childKSK.ds(signer.DigestSHA256);
    const text = `$ORIGIN example.test.
$TTL 3600
@       SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@       NS  ns1.example.test.
ns1     A   192.0.2.1
www     A   192.0.2.10
www     TXT "hello" "world, longer"
key     TYPE65400 \\# 4 01020304
key     TYPE65400 \\# 1 62
key     TYPE65400 \\# 2 6162
*.wild  A   192.0.2.20
sub     NS  ns.sub.example.test.
sub     DS  ${ds}
ns.sub  A   192.0.2.53
nods    NS  ns.nods.example.test.
ns.nods A   192.0.2.54
`;
    const z = new Zone();
    z.read_string_strict(text);
    return z;
}

export function rrsigsAt(z: Zone, owner: string): Map<number, RRSig[]> {
    const out = new Map<number, RRSig[]>();
    for (const rr of z.find_rrset(owner, TYPE_RRSIG)) {
        const s = new RRSig(null, rr.value);
        out.set(s.type_covered, [...(out.get(s.type_covered) ?? []), s]);
    }
    return out;
}

// toDNSSecZone copies z into a DNSSecZone with its clock at now.
export function toDNSSecZone(z: Zone, now: Date = testNow): DNSSecZone {
    const dz = new DNSSecZone();
    for (const rr of z.all_records()) {
        dz.add_rr(new ResourceRecord(rr.label, rr.ttl, rr.rrclass, rr.type, rr.value));
    }
    dz.set_clock(() => now);
    return dz;
}

// failedRRSIGs returns the RRSIGs of z that do not verify at now, as
// "owner/type" strings, and how many RRSIGs there were.
export function checkAllRRSIGs(z: Zone, now: Date = testNow): { failed: string[]; count: number } {
    const dz = toDNSSecZone(z, now);
    const failed: string[] = [];
    let count = 0;
    for (const rr of dz.all_records()) {
        if (rr.type !== TYPE_RRSIG) continue;
        const sig = rr.get_handler() as RRSig;
        if (!dz.verify_rrsig(rr.label, sig.type_covered, sig, KeyVerifyMode.None)) {
            failed.push(`${rr.label}/${sig.type_covered}`);
        }
        count++;
    }
    return { failed, count };
}

// findTool looks name up on PATH, like Go's exec.LookPath; null when
// it is not installed.
export function findTool(name: string): string | null {
    for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
        if (dir === '') continue;
        const candidate = path.join(dir, name);
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return candidate;
        } catch {
            // not here
        }
    }
    return null;
}

export function stripBlanks(s: string): string {
    return s.split(/\s+/).join('');
}
