// Ports dnsdata-go `verifier/handlers_test.go`
// (TestNewVerifier_EncodesZoneHandlerTypes).
//
// tests/testdata/handlers holds a signed root zone, shared byte for byte
// with dnsdata-go, whose answers (TLSA, SMIMEA, SVCB, HTTPS) only the
// zone handlers encode. It is read from a file, not signed in-process,
// because the signer registers every handler and would hide a missing
// registration. tests/jest.setup.ts registers every handler too, so the
// modules are loaded afresh in an isolated registry where nothing is
// registered: the Verifier constructor must register what it needs.

import * as fs from 'fs';
import * as path from 'path';
import type * as RootAnchorsModule from '../../src/dnssec/root_anchors';
import type * as MemoryModule from '../../src/resolver/memory';
import type * as VerdictModule from '../../src/verifier/verdict';
import type * as VerifierModule from '../../src/verifier/verifier';
import type * as ZoneModule from '../../src/zone/dns_zone';

const handlersDir = path.join(__dirname, '..', 'testdata', 'handlers');

function read(name: string): string {
    return fs.readFileSync(path.join(handlersDir, name), 'utf8');
}

interface Isolated {
    anchors: typeof RootAnchorsModule;
    memory: typeof MemoryModule;
    verdict: typeof VerdictModule;
    verifier: typeof VerifierModule;
    zone: typeof ZoneModule;
}

function loadIsolated(): Isolated {
    let mods: Isolated | undefined;
    jest.isolateModules(() => {
        mods = {
            anchors: require('../../src/dnssec/root_anchors'),
            memory: require('../../src/resolver/memory'),
            verdict: require('../../src/verifier/verdict'),
            verifier: require('../../src/verifier/verifier'),
            zone: require('../../src/zone/dns_zone'),
        };
    });
    if (mods === undefined) throw new Error('isolateModules did not run');
    return mods;
}

describe('answers that need the zone handlers (testdata/handlers)', () => {
    const m = loadIsolated();
    const z = new m.zone.Zone();
    z.read_string(read('root.zone'));
    const auth = m.memory.new_authority(m.memory.with_zone('.', z));
    const anchors = m.anchors.parseRootAnchors(read('root-anchors.json'));
    const clock = new Date('2026-06-01T00:00:00Z');

    it('starts with no zone handler registered', () => {
        expect([52, 53, 64, 65].map((t) => m.zone.has_encoder(t))).toEqual([false, false, false, false]);
    });

    it.each([
        ['svc.example.test.', 64],
        ['www.example.test.', 65],
        ['_443._tcp.www.example.test.', 52],
        ['x._smimecert.example.test.', 53],
    ] as const)('%s/%d is secure', async (qname, qtype) => {
        const v = new m.verifier.Verifier({ resolver: auth, trustAnchors: anchors, now: () => clock });
        const res = await v.validate(qname, qtype);
        expect(`${res.verdict} ${res.bogusReason ?? ''}`).toBe(`${m.verdict.Verdict.Secure} `);
        expect(res.answer?.type).toBe(qtype);
        expect(res.answer?.records).toHaveLength(1);
    });
});
