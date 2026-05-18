// DNS Zone and ResourceRecord tests

import { ResourceRecord, Zone, has_encoder } from "../../src/zone/dns_zone";
import { WireBuilder } from "../../src/wire/dns_wire_util";
import { DNSZoneRDataFormatError } from "../../src/dns_exception";

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

    it("builds MX record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "MX", "10 mail.example.com.");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // rdlength(2) + preference(2) + wire name of mail.example.com.
        // mail.example.com. = 1+4 + 1+7 + 1+3 + 1 = 18 bytes
        expect(result[0]).toBe(0x00);
        expect(result[1]).toBe(20); // 2 + 18
        expect(result[2]).toBe(0x00); // preference high
        expect(result[3]).toBe(10);   // preference low
    });

    it("builds TXT record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "TXT", '"v=spf1 include:example.com ~all"');
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        const rdlen = (result[0] << 8) | result[1];
        const txt_str = "v=spf1 include:example.com ~all";
        // rdlen should be 1 (length byte) + string length
        expect(rdlen).toBe(1 + txt_str.length);
        expect(result[2]).toBe(txt_str.length); // character-string length
    });

    it("builds SRV record wire body", () => {
        const rr = new ResourceRecord("_sip._tcp.example.com.", 3600, "IN", "SRV", "10 60 5060 sip.example.com.");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // rdlength(2) + priority(2) + weight(2) + port(2) + wire name
        // sip.example.com. = 1+3 + 1+7 + 1+3 + 1 = 17 bytes
        const rdlen = (result[0] << 8) | result[1];
        expect(rdlen).toBe(6 + 17); // 23
        expect(result[2]).toBe(0x00); expect(result[3]).toBe(10);   // priority
        expect(result[4]).toBe(0x00); expect(result[5]).toBe(60);   // weight
        expect(result[6]).toBe(0x13); expect(result[7]).toBe(0xc4); // port 5060
    });

    it("builds CAA record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "CAA", '0 issue "letsencrypt.org"');
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        const rdlen = (result[0] << 8) | result[1];
        // flags(1) + tag_len(1) + "issue"(5) + "letsencrypt.org"(15) = 22
        expect(rdlen).toBe(22);
        expect(result[2]).toBe(0);   // flags
        expect(result[3]).toBe(5);   // tag length
    });

    // RFC 1035 §3.3.1: CNAME RDATA = single <domain-name>
    // Uses same wire encoding as NS (§3.3.11)
    it("builds CNAME record wire body", () => {
        const rr = new ResourceRecord("www.example.com.", 3600, "IN", "CNAME", "example.com.");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // rdlength(2) + wire name of example.com.
        // example.com. = 1+7(example) + 1+3(com) + 1(root) = 13
        expect(result[0]).toBe(0x00);
        expect(result[1]).toBe(13);
    });

    // RFC 6672 §2.1: DNAME RDATA = single <target> domain name
    // Uses same wire encoding as NS (RFC 1035 §3.3.11)
    it("builds DNAME record wire body", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "DNAME", "example.net.");
        const wb = new WireBuilder();
        rr.get_wire_body(wb);
        const result = wb.build();
        // rdlength(2) + wire name of example.net.
        // example.net. = 1+7(example) + 1+3(net) + 1(root) = 13
        expect(result[0]).toBe(0x00);
        expect(result[1]).toBe(13);
    });

    it("renders to_string correctly", () => {
        const rr = new ResourceRecord("example.com.", 3600, "IN", "A", "1.2.3.4");
        expect(rr.to_string()).toBe("example.com. 3600 IN A 1.2.3.4");
    });

    // UF-004: malformed RDATA used to silently produce a 0-byte body. The
    // built-in encoders now throw DNSZoneRDataFormatError so callers can
    // distinguish a missing encoder from a bad presentation value.
    describe("get_wire_body error handling (UF-004)", () => {
        it("throws DNSZoneRDataFormatError for malformed A RDATA", () => {
            const rr = new ResourceRecord("x.net.", 3600, "IN", "A", "not-an-ip");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
            expect(() => rr.get_wire_body(wb)).toThrow(/A:/);
        });

        it("throws DNSZoneRDataFormatError for out-of-range A octets", () => {
            const rr = new ResourceRecord("x.net.", 3600, "IN", "A", "256.0.0.1");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
        });

        it("throws DNSZoneRDataFormatError for malformed AAAA RDATA", () => {
            const rr = new ResourceRecord("x.net.", 3600, "IN", "AAAA", "not-an-ipv6");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
            expect(() => rr.get_wire_body(wb)).toThrow(/AAAA:/);
        });

        it("throws DNSZoneRDataFormatError for malformed MX RDATA", () => {
            const rr = new ResourceRecord("example.com.", 3600, "IN", "MX", "foo bar");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
            expect(() => rr.get_wire_body(wb)).toThrow(/MX:/);
        });

        it("throws DNSZoneRDataFormatError for malformed SRV RDATA", () => {
            const rr = new ResourceRecord("_sip._tcp.example.com.", 3600, "IN", "SRV", "missing fields");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
        });

        it("throws DNSZoneRDataFormatError for malformed CAA RDATA", () => {
            const rr = new ResourceRecord("example.com.", 3600, "IN", "CAA", "no-flags-here");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
        });

        it("throws DNSZoneRDataFormatError for malformed SOA RDATA", () => {
            const rr = new ResourceRecord("example.com.", 3600, "IN", "SOA", "missing fields");
            const wb = new WireBuilder();
            expect(() => rr.get_wire_body(wb)).toThrow(DNSZoneRDataFormatError);
        });

        it("get_wire_body is a no-op for types without an encoder", () => {
            // HS class type with no encoder (numeric type 999 — not assigned).
            const rr = new ResourceRecord("x.net.", 3600, 1, 999, "anything");
            const wb = new WireBuilder();
            // Should NOT throw — back-compat for "unsupported type".
            expect(() => rr.get_wire_body(wb)).not.toThrow();
            expect(wb.build().length).toBe(0);
        });

        it("has_encoder reports built-in encoder types", () => {
            expect(has_encoder(1)).toBe(true);    // A
            expect(has_encoder(28)).toBe(true);   // AAAA
            expect(has_encoder(15)).toBe(true);   // MX
            expect(has_encoder(33)).toBe(true);   // SRV
            expect(has_encoder(257)).toBe(true);  // CAA
        });

        it("has_encoder reports false for unknown types", () => {
            expect(has_encoder(999)).toBe(false);
        });
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

    it("handles $ORIGIN directive", () => {
        const zone_text = `$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
@ 3600 IN A 1.2.3.4
www 3600 IN A 5.6.7.8
ns1 3600 IN A 10.0.0.1
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 6)).not.toBeNull(); // SOA via @
        expect(zone.find_rr("example.com.", 1)!.value).toBe("1.2.3.4"); // @ -> example.com.
        expect(zone.find_rr("www.example.com.", 1)!.value).toBe("5.6.7.8"); // relative name
        expect(zone.find_rr("ns1.example.com.", 1)!.value).toBe("10.0.0.1");
    });

    it("handles $TTL directive", () => {
        const zone_text = `$TTL 86400
example.com. IN SOA ns1.example.com. admin.example.com. 2021010101 3600 900 604800 86400
example.com. IN A 1.2.3.4
example.com. 300 IN A 5.6.7.8
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 6)!.ttl).toBe(86400); // uses $TTL
        const a_records = zone.find_rrset("example.com.", 1);
        expect(a_records.length).toBe(2);
        expect(a_records[0].ttl).toBe(86400); // uses $TTL
        expect(a_records[1].ttl).toBe(300);   // explicit TTL overrides
    });

    it("handles $ORIGIN with $TTL together", () => {
        const zone_text = `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin 2021010101 3600 900 604800 86400
@ IN NS ns1
@ IN A 93.184.216.34
www IN A 93.184.216.35
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("example.com.", 6)).not.toBeNull();
        expect(zone.find_rr("example.com.", 1)!.ttl).toBe(3600);
        expect(zone.find_rr("www.example.com.", 1)!.value).toBe("93.184.216.35");
    });

    it("FQDN names are not affected by $ORIGIN", () => {
        const zone_text = `$ORIGIN example.com.
other.net. 3600 IN A 1.2.3.4
`;
        const zone = new Zone();
        zone.read_string(zone_text);
        expect(zone.find_rr("other.net.", 1)!.value).toBe("1.2.3.4");
    });
});
