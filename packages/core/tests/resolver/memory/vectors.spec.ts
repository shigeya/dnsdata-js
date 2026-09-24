// Ports dnsdata-go `resolver/memory/vectors_test.go` (TestSignedVectors).
//
// tests/testdata/signed holds a signed hierarchy (a private root, test.,
// and example.test.) shared byte for byte with dnsdata-go: the zones as
// canonical master files, the BIND private keys that signed them, the
// root trust anchors, and the expected verdicts. The files are produced
// by the Go side and must never be regenerated here (ECDSA signatures
// differ on every run).

import * as fs from 'fs';
import * as path from 'path';
import * as signer from '../../../src/dnssec/signer';
import { RootAnchors } from '../../../src/dnssec/root_anchors';
import { Authority, new_authority, with_zone } from '../../../src/resolver/memory';
import { Verdict } from '../../../src/verifier/verdict';
import { Verifier } from '../../../src/verifier/verifier';
import { bindPrivateText, hierarchyKeys, readZone } from './helpers';

const signedDir = path.join(__dirname, '..', '..', 'testdata', 'signed');

const vectorZones: ReadonlyArray<{ apex: string; file: string }> = [
    { apex: '.', file: 'root.zone' },
    { apex: 'test.', file: 'test.zone' },
    { apex: 'example.test.', file: 'example.test.zone' },
];

interface VectorCase {
    qname: string;
    qtype: number;
    clock: string;
    verdict: string;
}

function read(name: string): string {
    return fs.readFileSync(path.join(signedDir, name), 'utf8');
}

function loadAuthority(): Authority {
    return new_authority(...vectorZones.map((vz) => with_zone(vz.apex, readZone(read(vz.file)))));
}

function loadAnchors(): RootAnchors {
    return JSON.parse(read('root-anchors.json')) as RootAnchors;
}

function loadCases(): VectorCase[] {
    return (JSON.parse(read('cases.json')) as { cases: VectorCase[] }).cases;
}

const cases = loadCases();

describe('shared signed vectors (testdata/signed)', () => {
    const auth = loadAuthority();
    const anchors = loadAnchors();

    it('has the nine cases', () => {
        expect(cases).toHaveLength(9);
    });

    it('every expected verdict is a TS Verdict spelling', () => {
        const spellings = Object.values(Verdict) as string[];
        for (const c of cases) expect(spellings).toContain(c.verdict);
    });

    it.each(cases.map((c) => [`${c.qname}/${c.qtype}@${c.clock}`, c] as const))('%s', async (_name, c) => {
        const clock = new Date(c.clock);
        expect(Number.isNaN(clock.getTime())).toBe(false);
        const v = new Verifier({ resolver: auth, trustAnchors: anchors, now: () => clock });
        const res = await v.validate(c.qname, c.qtype);
        // The bogus reason rides along so a failure explains itself.
        expect(`${res.verdict} (${res.bogusReason ?? ''})`).toBe(
            `${c.verdict} (${c.verdict === Verdict.Bogus ? res.bogusReason ?? '' : ''})`);
    });
});

// The key files are the keys the helpers derive from their seeds, and
// the root anchors are those of the root KSK: the TS signer and the Go
// signer agree on the key material behind the vectors.
describe('shared signed vectors: keys and anchors', () => {
    it.each(hierarchyKeys.map((k) => [k.seed, k] as const))('keys/%s.private', (_seed, k) => {
        const text = read(path.join('keys', `${k.seed}.private`));
        expect(text).toBe(bindPrivateText(k.seed));
        const key = signer.parse_bind_private(k.owner, k.flags, text);
        const zone = vectorZones.find((vz) => vz.apex === k.owner);
        expect(zone).toBeDefined();
        expect(read(zone?.file ?? '')).toContain(key.dnskey_value().split(' ').slice(3).join(' '));
    });

    it('root-anchors.json is signer.root_anchors of the root KSK', () => {
        const rootKSK = signer.parse_bind_private('.', signer.FlagsKSK, read('keys/root-ksk.private'));
        expect(loadAnchors().ds).toEqual(signer.root_anchors(rootKSK).ds);
    });
});
