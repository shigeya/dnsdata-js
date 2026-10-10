// Every RRSIG of a zone signed by BIND with mixed-case names verifies.
// The NSEC next names and the SVCB / HTTPS targets are signed in their
// original case; lowercasing them made those signatures fail. Ports
// dnsdata-go dnssec/bind_case_test.go (UPSTREAM_FEEDBACK.md UF-008).
// Handlers are registered by tests/jest.setup.ts.

import * as fs from 'fs';
import * as path from 'path';
import { DNSSecZone, KeyVerifyMode } from "../../src/dnssec/dnssec_zone";
import { RRSig } from "../../src/dnssec/rrsig";
import { RRTypeName } from "../../src/types/dns_type_table";

const TYPE_CNAME = 5;
const TYPE_NSEC = 47;
const TYPE_SVCB = 64;
const TYPE_HTTPS = 65;

describe("BIND-signed zone with mixed-case names (UF-008)", () => {
    const file = path.join(__dirname, '..', 'testdata', 'bind', 'case.example.zone');
    const zone = new DNSSecZone();
    zone.read_string_strict(fs.readFileSync(file, 'utf8'));
    const sigs = zone.all_records().flatMap((rr) => {
        const h = rr.get_handler();
        return h instanceof RRSig ? [{ label: rr.label, sig: h }] : [];
    });

    it("covers NSEC, SVCB, HTTPS and CNAME", () => {
        const covered = new Set(sigs.map(({ sig }) => sig.type_covered));
        for (const type of [TYPE_NSEC, TYPE_SVCB, TYPE_HTTPS, TYPE_CNAME]) {
            expect(covered.has(type)).toBe(true);
        }
    });

    it.each(sigs.map(({ label, sig }) => [label, RRTypeName(sig.type_covered), sig] as const))(
        "%s RRSIG %s verifies", (label, _type, sig) => {
            expect(zone.verify_rrsig(label, sig.type_covered, sig, KeyVerifyMode.None)).toBe(true);
        });
});
