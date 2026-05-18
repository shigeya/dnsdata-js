import { ResourceRecord } from '../../../src/lib/dns_zone';
import { DNSRR_CSYNC } from '../../../src/lib/rr/csync_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table CSYNC', () => {
    it('should convert CSYNC type', () => {
        expect(RRTypeToString(62)).toBe('CSYNC');
        expect(StringToRRType('CSYNC')).toBe(62);
    });
});

describe('DNSRR_CSYNC (RFC 7477)', () => {
    // RFC 7477 §2: SOA_Serial(4) + Flags(2) + Type_Bit_Map(variable)

    it('should parse CSYNC with type list', () => {
        // serial=66, flags=3 (immediate+soaminimum), types: A NS AAAA
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CSYNC', '66 3 A NS AAAA');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_CSYNC);

        const csync = handler as DNSRR_CSYNC;
        expect(csync.soa_serial).toBe(66);
        expect(csync.flags).toBe(3);
        expect(csync.covered_types).toContain(1);   // A
        expect(csync.covered_types).toContain(2);   // NS
        expect(csync.covered_types).toContain(28);  // AAAA
    });

    it('should parse CSYNC without types', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CSYNC', '100 1');
        const handler = rr.get_handler() as DNSRR_CSYNC;
        expect(handler.soa_serial).toBe(100);
        expect(handler.flags).toBe(1);
        expect(handler.covered_types.length).toBe(0);
        expect(handler.type_bitmap.length).toBe(0);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CSYNC', '66 3 A NS AAAA');
        const handler = rr.get_handler() as DNSRR_CSYNC;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + serial(4) + flags(2) + type_bitmap(variable)
        const rdlen = (wire[0] << 8) | wire[1];
        expect(rdlen).toBe(4 + 2 + handler.type_bitmap.length);

        // SOA Serial = 66 = 0x00000042
        expect(wire[2]).toBe(0x00);
        expect(wire[3]).toBe(0x00);
        expect(wire[4]).toBe(0x00);
        expect(wire[5]).toBe(0x42);

        // Flags = 3 = 0x0003
        expect(wire[6]).toBe(0x00);
        expect(wire[7]).toBe(0x03);

        // Type bitmap follows (RFC 4034 §4.1.2 encoding)
        // A(1), NS(2), AAAA(28) are all in window block 0
        expect(wire[8]).toBe(0);  // window block 0
    });

    it('should build empty bitmap when no types', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CSYNC', '100 1');
        const handler = rr.get_handler() as DNSRR_CSYNC;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + serial(4) + flags(2) = 8, no bitmap
        expect(wire.length).toBe(2 + 4 + 2);
        expect((wire[0] << 8) | wire[1]).toBe(6);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CSYNC', '66 3 A NS AAAA');
        const handler = rr.get_handler() as DNSRR_CSYNC;
        const cloned = handler.clone();
        expect(cloned.soa_serial).toBe(handler.soa_serial);
        expect(cloned.flags).toBe(handler.flags);
        expect(cloned.covered_types).toEqual(handler.covered_types);
    });

    it('should reject invalid format', () => {
        expect(() => new DNSRR_CSYNC(null, '66')).toThrow();
    });
});

describe('Zone file parsing with CSYNC records', () => {
    it('should parse CSYNC records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  CSYNC  66 3 A NS AAAA
`);
        const rr = zone.find_rr('example.com.', StringToRRType('CSYNC'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_CSYNC;
        expect(handler.soa_serial).toBe(66);
        expect(handler.flags).toBe(3);
    });
});
