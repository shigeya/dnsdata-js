import { ResourceRecord } from '../../src/lib/dns_zone';
import { DNSRR_EUI } from '../../src/lib/eui_rr';
import { StringToRRType, RRTypeToString } from '../../src/lib/dns_type_table';
import { WireBuilder } from '../../src/lib/dns_wire_util';

describe('dns_type_table EUI48/EUI64', () => {
    it('should convert EUI48 type', () => {
        expect(RRTypeToString(108)).toBe('EUI48');
        expect(StringToRRType('EUI48')).toBe(108);
    });

    it('should convert EUI64 type', () => {
        expect(RRTypeToString(109)).toBe('EUI64');
        expect(StringToRRType('EUI64')).toBe(109);
    });
});

describe('EUI48 (RFC 7043 §3)', () => {
    // RFC 7043 §3.1: RDATA = 6-octet address in network byte order
    // RFC 7043 §3.3: Presentation = six hex octets separated by hyphens

    it('should parse EUI48 presentation format', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI48', '00-00-5e-00-53-2a');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_EUI);

        const eui = handler as DNSRR_EUI;
        expect(eui.address.length).toBe(6);
        expect(eui.address[0]).toBe(0x00);
        expect(eui.address[1]).toBe(0x00);
        expect(eui.address[2]).toBe(0x5e);
        expect(eui.address[3]).toBe(0x00);
        expect(eui.address[4]).toBe(0x53);
        expect(eui.address[5]).toBe(0x2a);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI48', '00-00-5e-00-53-2a');
        const handler = rr.get_handler() as DNSRR_EUI;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + address(6)
        expect(wire.length).toBe(2 + 6);
        expect((wire[0] << 8) | wire[1]).toBe(6);  // rdlen
        expect(wire[2]).toBe(0x00);
        expect(wire[3]).toBe(0x00);
        expect(wire[4]).toBe(0x5e);
        expect(wire[5]).toBe(0x00);
        expect(wire[6]).toBe(0x53);
        expect(wire[7]).toBe(0x2a);
    });

    it('should handle uppercase hex digits', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI48', 'AA-BB-CC-DD-EE-FF');
        const handler = rr.get_handler() as DNSRR_EUI;
        expect(handler.address[0]).toBe(0xaa);
        expect(handler.address[5]).toBe(0xff);
    });

    it('should reject invalid format', () => {
        // Wrong number of octets
        expect(() => new DNSRR_EUI(null, '00-00-5e-00-53', 6)).toThrow();
        // Too many octets
        expect(() => new DNSRR_EUI(null, '00-00-5e-00-53-2a-ff', 6)).toThrow();
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI48', '00-00-5e-00-53-2a');
        const handler = rr.get_handler() as DNSRR_EUI;
        const cloned = handler.clone();
        expect(Buffer.from(cloned.address)).toEqual(Buffer.from(handler.address));
    });
});

describe('EUI64 (RFC 7043 §4)', () => {
    // RFC 7043 §4.1: RDATA = 8-octet address in network byte order
    // RFC 7043 §4.3: Presentation = eight hex octets separated by hyphens

    it('should parse EUI64 presentation format', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI64', '00-00-5e-ef-10-00-00-2a');
        const handler = rr.get_handler() as DNSRR_EUI;
        expect(handler.address.length).toBe(8);
        expect(handler.address[0]).toBe(0x00);
        expect(handler.address[3]).toBe(0xef);
        expect(handler.address[7]).toBe(0x2a);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('host.example.com.', 86400, 'IN', 'EUI64', '00-00-5e-ef-10-00-00-2a');
        const handler = rr.get_handler() as DNSRR_EUI;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + address(8)
        expect(wire.length).toBe(2 + 8);
        expect((wire[0] << 8) | wire[1]).toBe(8);  // rdlen
    });

    it('should reject invalid format', () => {
        expect(() => new DNSRR_EUI(null, '00-00-5e-ef-10-00-00', 8)).toThrow();
    });
});

describe('Zone file parsing with EUI48/EUI64 records', () => {
    it('should parse EUI48 records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 86400
host  IN  EUI48  00-00-5e-00-53-2a
`);
        const rr = zone.find_rr('host.example.com.', StringToRRType('EUI48'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_EUI;
        expect(handler.address.length).toBe(6);
    });

    it('should parse EUI64 records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 86400
host  IN  EUI64  00-00-5e-ef-10-00-00-2a
`);
        const rr = zone.find_rr('host.example.com.', StringToRRType('EUI64'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_EUI;
        expect(handler.address.length).toBe(8);
    });
});
