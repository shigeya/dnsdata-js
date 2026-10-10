// A name in RDATA is lowercased only for the types on the RFC 4034 §6.2
// list, whose canonical form folds it. NSEC (taken off the list by
// RFC 6840 §5.1) and SVCB / HTTPS (not on it) keep the case written in
// the presentation form. Same rows as dnsdata-go
// zone/name_case_test.go (UPSTREAM_FEEDBACK.md UF-008). Handlers are
// registered by tests/jest.setup.ts.

import { ResourceRecord } from "../../src/zone/dns_zone";
import { WireBuilder } from "../../src/wire/dns_wire_util";

function rdata_hex(rr: ResourceRecord): string {
    const builder = new WireBuilder();
    rr.get_wire_body(builder);
    return Buffer.from(builder.build().subarray(2)).toString('hex');
}

describe("get_wire_body name case (UF-008)", () => {
    it.each([
        ["SVCB", "1 Svc.Example.", "000103537663074578616d706c6500"],
        ["SVCB", "1 svc.example.", "000103737663076578616d706c6500"],
        ["HTTPS", "1 Svc.Example. alpn=h2", "000103537663074578616d706c650000010003026832"],
        ["NSEC", "Next.Example. A RRSIG", "044e657874074578616d706c65000006400000000002"],
        ["CNAME", "Svc.Example.", "03737663076578616d706c6500"],
        ["NS", "Svc.Example.", "03737663076578616d706c6500"],
        ["MX", "10 Svc.Example.", "000a03737663076578616d706c6500"],
        ["SRV", "0 0 25 Svc.Example.", "00000000001903737663076578616d706c6500"],
        ["RP", "Svc.Example. Txt.Example.", "03737663076578616d706c650003747874076578616d706c6500"],
        ["TXT", '"Svc"', "03537663"],
    ])("%s %s", (type, value, want) => {
        const rr = new ResourceRecord("case.example.", 300, "IN", type, value);
        expect(rdata_hex(rr)).toBe(want);
    });
});
