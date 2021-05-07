// Spec on: Converting between DNS wire format and string(utf)

import { domain_name2wire, wire2domain_name } from "../../src/lib/dns_wire";

describe("Domain name wire format conversion library", () => {
    const test_vector = [
        ["xp.net.",        "\x02xp\x03net\x00" ],
        ["Z.ISI.ARPA.",    "\x01z\x03isi\x04arpa\x00" ],
        ["FOO.ISI.ARPA.",  "\x03foo\x03isi\x04arpa\x00" ],
        ["ARPA.",          "\x04arpa\x00" ],
        ["ARPA",           "\x04arpa" ],
        ["sh.wide.xx.jp.", "\x02sh\x04wide\x02xx\x02jp\x00" ],
        ["ns.wide.xx.jp", "\x02ns\x04wide\x02xx\x02jp" ]
    ];

    it("can translate to wire format", () => {
        test_vector.forEach(async ([domain_name, wire]) => {
            expect(domain_name2wire(domain_name)).toBe(wire);
        })
    });

    it("can translate from wire format", () => {
        test_vector.forEach(async ([domain_name, wire]) => {
            expect(wire2domain_name(wire)).toBe(domain_name.toLowerCase());
        });
    });
});
