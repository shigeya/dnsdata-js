import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_HINFO } from '../../../src/zone/rr/hinfo_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table HINFO', () => {
    it('should convert HINFO type', () => {
        expect(RRTypeToString(13)).toBe('HINFO');
        expect(StringToRRType('HINFO')).toBe(13);
    });
});

describe('DNSRR_HINFO (RFC 1035 §3.3.2)', () => {
    // RFC 1035 §3.3.2: HINFO RDATA = cpu<character-string> + os<character-string>

    it('should parse quoted strings', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'HINFO', '"INTEL-386" "UNIX"');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_HINFO);

        const hinfo = handler as DNSRR_HINFO;
        expect(hinfo.cpu).toBe('INTEL-386');
        expect(hinfo.os).toBe('UNIX');
    });

    it('should parse unquoted strings', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'HINFO', 'INTEL-386 UNIX');
        const handler = rr.get_handler() as DNSRR_HINFO;
        expect(handler.cpu).toBe('INTEL-386');
        expect(handler.os).toBe('UNIX');
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'HINFO', '"CPU" "OS"');
        const handler = rr.get_handler() as DNSRR_HINFO;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + len(1)+"CPU"(3) + len(1)+"OS"(2) = 2 + 4 + 3 = 9
        expect(wire.length).toBe(9);
        expect((wire[0] << 8) | wire[1]).toBe(7);  // rdlen = 1+3+1+2
        expect(wire[2]).toBe(3);     // cpu length
        expect(wire[3]).toBe(0x43);  // 'C'
        expect(wire[4]).toBe(0x50);  // 'P'
        expect(wire[5]).toBe(0x55);  // 'U'
        expect(wire[6]).toBe(2);     // os length
        expect(wire[7]).toBe(0x4f);  // 'O'
        expect(wire[8]).toBe(0x53);  // 'S'
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'HINFO', '"CPU" "OS"');
        const handler = rr.get_handler() as DNSRR_HINFO;
        const cloned = handler.clone();
        expect(cloned.cpu).toBe(handler.cpu);
        expect(cloned.os).toBe(handler.os);
    });

    it('should reject invalid format', () => {
        // Only one string
        expect(() => new DNSRR_HINFO(null, 'CPU')).toThrow();
    });
});

describe('Zone file parsing with HINFO records', () => {
    it('should parse HINFO records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/dnssec/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
host  IN  HINFO  INTEL-386 UNIX
`);
        const rr = zone.find_rr('host.example.com.', StringToRRType('HINFO'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_HINFO;
        expect(handler.cpu).toBe('INTEL-386');
        expect(handler.os).toBe('UNIX');
    });
});
