import { ResourceRecord } from '../../../src/lib/dns_zone';
import { DNSRR_RP } from '../../../src/lib/rr/rp_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table RP', () => {
    it('should convert RP type', () => {
        expect(RRTypeToString(17)).toBe('RP');
        expect(StringToRRType('RP')).toBe(17);
    });
});

describe('DNSRR_RP (RFC 1183 §2.2)', () => {
    // RFC 1183 §2.2: RP RDATA = mbox-dname + txt-dname (two domain names)

    it('should parse RP presentation format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'RP', 'admin.example.com. info.example.com.');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_RP);

        const rp = handler as DNSRR_RP;
        expect(rp.mbox).toBe('admin.example.com.');
        expect(rp.txt_dname).toBe('info.example.com.');
    });

    it('should parse RP with root domain names', () => {
        // RFC 1183 §2.2: "." means no mailbox / no TXT records
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'RP', '. .');
        const handler = rr.get_handler() as DNSRR_RP;
        expect(handler.mbox).toBe('.');
        expect(handler.txt_dname).toBe('.');
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'RP', 'admin.example.com. info.example.com.');
        const handler = rr.get_handler() as DNSRR_RP;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + mbox_wire + txt_wire
        // "admin.example.com." => 5+admin + 7+example + 3+com + 0 = 6+8+4+1 = 19
        // "info.example.com."  => 4+info  + 7+example + 3+com + 0 = 5+8+4+1 = 18
        const expectedRdlen = 19 + 18;
        expect((wire[0] << 8) | wire[1]).toBe(expectedRdlen);
        expect(wire.length).toBe(2 + expectedRdlen);

        // First label of mbox: length=5, "admin"
        expect(wire[2]).toBe(5);
        expect(wire[3]).toBe(0x61);  // 'a'
    });

    it('should build wire format with root domains', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'RP', '. .');
        const handler = rr.get_handler() as DNSRR_RP;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + root(1) + root(1) = 4
        expect(wire.length).toBe(4);
        expect((wire[0] << 8) | wire[1]).toBe(2);  // rdlen = 1+1
        expect(wire[2]).toBe(0);  // root label
        expect(wire[3]).toBe(0);  // root label
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'RP', 'admin.example.com. info.example.com.');
        const handler = rr.get_handler() as DNSRR_RP;
        const cloned = handler.clone();
        expect(cloned.mbox).toBe(handler.mbox);
        expect(cloned.txt_dname).toBe(handler.txt_dname);
    });

    it('should reject invalid format', () => {
        // Missing txt-dname
        expect(() => new DNSRR_RP(null, 'admin.example.com.')).toThrow();
    });
});

describe('Zone file parsing with RP records', () => {
    it('should parse RP records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  RP  admin.example.com. info.example.com.
`);
        const rr = zone.find_rr('example.com.', StringToRRType('RP'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_RP;
        expect(handler.mbox).toBe('admin.example.com.');
        expect(handler.txt_dname).toBe('info.example.com.');
    });
});
