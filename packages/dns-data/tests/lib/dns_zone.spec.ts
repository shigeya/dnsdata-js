// DNS Zone and ResourceRecord tests

import { ResourceRecord, Zone } from "../../src/lib/dns_zone";
import { WireBuilder } from "../../src/lib/dns_wire_util";

describe("ResourceRecord", () => {
    it("can create from string class and type", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "A", "192.168.1.1");
        expect(rr.label).toBe("example.com.");
        expect(rr.ttl).toBe(3600);
        expect(rr.rrclass).toBe(1); // IN
        expect(rr.type).toBe(1);    // A
        expect(rr.value).toBe("192.168.1.1");
    });

    it("can create from numeric class and type", () => {
        const rr = new ResourceRecord("example.com.", 3600, 1, 1, "192.168.1.1");
        expect(rr.rrclass).toBe(1);
        expect(rr.type).toBe(1);
    });

    it("builds wire header correctly", () => {
        const rr = new ResourceRecord("xp.net.", 3600, "IN", "A", "1.2.3.4");
        const wb = new WireBuilder();
        rr.get_wire_header(wb);
        expect(wb.build()).toEqual(new Uint8Array([
            0x02, 0x78, 0x70, 0x03, 0x6e, 0x65, 0x74, 0x00, // xp.net. in wire
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
        ]));
    });

    it("builds A record wire body", () => {
        const rr = new ResourceRecord("x.net.", 3600, "IN", "A", "192.168.0.1");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        expect(wb.build()).toEqual(new Uint8Array([
            0x00, 0x04,                   // rdlength = 4
            0xc0, 0xa8, 0x00, 0x01        // 192.168.0.1
        ]));
    });

    it("builds NS record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "NS", "ns1.example.com.");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // rdlength(2) + wire name of ns1.example.com.
        expect(result[0]).toBe(0x00); // high byte of rdlength
        expect(result[1]).toBe(17);   // 1+3(ns1) + 1+7(example) + 1+3(com) + 1(root) = 17
    });

    it("builds SOA record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "SOA",
            "ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // Should start with rdlength(2) then two wire domain names and 5 uint32s
        // rdlength(2) + ns1.example.com.(17) + admin.example.com.(19) + 5*4(20) = 58
        expect(result.length).toBe(58);
    });

    it("builds AAAA record wire body", () => {
        const rr = new ResourceRecord("x.net.", 3600, "IN", "AAAA", "2001:db8::1");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        expect(result[0]).toBe(0x00); // rdlength high
        expect(result[1]).toBe(0x10); // rdlength = 16
        // 2001:0db8:0000:0000:0000:0000:0000:0001
        expect(result[2]).toBe(0x20);
        expect(result[3]).toBe(0x01);
        expect(result[4]).toBe(0x0d);
        expect(result[5]).toBe(0xb8);
        expect(result[17]).toBe(0x01); // last byte
    });

    it("renders to_string correctly", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "A", "1.2.3.4");
        expect(rr.to_string()).toBe("example.com. 3600 IN A 1.2.3.4");
    });
});

describe("Zone", () => {
    it("can add and find records", () => {
        const zone = new Zone();
        zone.add_rr_from_parts("example.com.", 3600, "IN", "A", "1.2.3.4");
        zone.add_rr_from_parts("example.com.", 3600, "IN", "A", "5.6.7.8");
        zone.add_rr_from_parts("example.com.", 3600, "IN", "NS", "ns1.example.com.");

        expect(zone.find_rr("example.com.", 1)).not.toBeNull();
        expect(zone.find_rr("example.com.", 1)!.value).toBe("1.2.3.4");
        expect(zone.find_rrset("example.com.", 1).length).toBe(2);
        expect(zone.find_rrset("example.com.", 2).length).toBe(1); // NS
        expect(zone.find_rr("notexist.com.", 1)).toBeNull();
    });

    it("can parse a zone file string", () => {
        const zone_text = `
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
example.com. 3600 IN A 93.184.216.34
example.com. 3600 IN AAAA 2606:2800:220:1:248:1893:25c8:1946
www.example.com. 300 IN CNAME example.com.
`;
        const zone = new Zone();
        zone.read_string(zone_text);

        expect(zone.find_rr("example.com.", 6)).not.toBeNull(); // SOA
        expect(zone.find_rrset("example.com.", 2).length).toBe(2); // 2 NS records
        expect(zone.find_rr("example.com.", 1)!.value).toBe("93.184.216.34");
        expect(zone.find_rr("www.example.com.", 5)!.value).toBe("example.com.");
    });

    it("handles comments", () => {
        const zone_text = `
example.com. 3600 IN A 1.2.3.4 ; this is a comment
; this entire line is a comment
example.com. 3600 IN NS ns1.example.com.
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 1)!.value).toBe("1.2.3.4");
        expect(zone.find_rr("example.com.", 2)).not.toBeNull();
    });

    it("handles continuation lines with parentheses", () => {
        const zone_text = `example.com. 3600 IN SOA ns1.example.com. admin.example.com. (
    2021010101
    3600
    900
    604800
    86400
)
example.com. 3600 IN A 1.2.3.4
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 6)).not.toBeNull(); // SOA
        expect(zone.find_rr("example.com.", 1)).not.toBeNull(); // A
    });

    it("handles implicit label from leading whitespace", () => {
        const zone_text = `example.com. 3600 IN A 1.2.3.4
                 3600 IN A 5.6.7.8
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rrset("example.com.", 1).length).toBe(2);
    });

    it("handles implicit class (no IN)", () => {
        const zone_text = `example.com. 3600 A 1.2.3.4
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 1)!.value).toBe("1.2.3.4");
        expect(zone.find_rr("example.com.", 1)!.rrclass).toBe(1); // IN
    });
});
