// Spec on: Converting between DNS wire format and string(utf)

import { domain_name2wire, wire2domain_name } from "../../src/lib/dns_wire";

describe("Domain name wire format conversion library", () => {
    const test_vector: Array<[string, Uint8Array]> = [
        ["xp.net.",        new Uint8Array([0x02, 0x78, 0x70, 0x03, 0x6e, 0x65, 0x74, 0x00])],
        ["Z.ISI.ARPA.",    new Uint8Array([0x01, 0x7a, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["FOO.ISI.ARPA.",  new Uint8Array([0x03, 0x66, 0x6f, 0x6f, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["ARPA.",          new Uint8Array([0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["ARPA",           new Uint8Array([0x04, 0x61, 0x72, 0x70, 0x61])],
        ["sh.wide.xx.jp.", new Uint8Array([0x02, 0x73, 0x68, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70, 0x00])],
        ["ns.wide.xx.jp",  new Uint8Array([0x02, 0x6e, 0x73, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70])],
    ];

    it("can translate to wire format", () => {
        test_vector.forEach(([domain_name, wire]) => {
            expect(domain_name2wire(domain_name)).toEqual(wire);
        })
    });

    it("can translate from wire format", () => {
        test_vector.forEach(([domain_name, wire]) => {
            expect(wire2domain_name(wire)).toBe(domain_name.toLowerCase());
        });
    });

    // UF-001: `| 0x20` lowercasing corrupted underscore (0x5F → 0x7F),
    // breaking DKIM / DMARC / TLSA / MTA-STS underscore-prefixed labels.
    describe("underscore-prefixed labels (UF-001)", () => {
        const underscore_vector: Array<[string, Uint8Array]> = [
            [
                "_dmarc.example.com.",
                new Uint8Array([
                    0x06, 0x5f, 0x64, 0x6d, 0x61, 0x72, 0x63,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
            [
                "_443._tcp.example.com.",
                new Uint8Array([
                    0x04, 0x5f, 0x34, 0x34, 0x33,
                    0x04, 0x5f, 0x74, 0x63, 0x70,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
            [
                "Selector._DomainKey.Example.Com.",
                new Uint8Array([
                    0x08, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72,
                    0x0a, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x6b, 0x65, 0x79,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
        ];

        it("encodes underscore-prefixed labels without corruption", () => {
            underscore_vector.forEach(([domain_name, wire]) => {
                expect(domain_name2wire(domain_name)).toEqual(wire);
            });
        });

        it("round-trips underscore-prefixed labels", () => {
            underscore_vector.forEach(([domain_name, wire]) => {
                expect(wire2domain_name(wire)).toBe(domain_name.toLowerCase());
            });
        });

        it("does not flip bit 5 of '_' (0x5F → 0x7F)", () => {
            const wire = domain_name2wire("_x.");
            expect(wire[1]).toBe(0x5f);
            expect(wire[1]).not.toBe(0x7f);
        });
    });
});
