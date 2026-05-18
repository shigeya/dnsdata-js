import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_TLSA, DNSRR_SMIMEA } from '../../../src/zone/rr/dane_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table DANE types', () => {
    it('should convert TLSA type', () => {
        expect(RRTypeToString(52)).toBe('TLSA');
        expect(StringToRRType('TLSA')).toBe(52);
    });

    it('should convert SMIMEA type', () => {
        expect(RRTypeToString(53)).toBe('SMIMEA');
        expect(StringToRRType('SMIMEA')).toBe(53);
    });
});

describe('DNSRR_TLSA', () => {
    // Example: _443._tcp.example.com. IN TLSA 3 1 1 <sha256hex>
    const sha256hex = 'aabbccdd' + '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'.slice(0, 56);
    const tlsaValue = `3 1 1 ${sha256hex}`;

    it('should parse TLSA presentation format', () => {
        const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', tlsaValue);
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_TLSA);

        const tlsa = handler as DNSRR_TLSA;
        expect(tlsa.usage).toBe(3);          // DANE-EE
        expect(tlsa.selector).toBe(1);       // SPKI
        expect(tlsa.matching_type).toBe(1);  // SHA-256
        expect(Buffer.from(tlsa.certificate_association_data).toString('hex')).toBe(sha256hex);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', tlsaValue);
        const handler = rr.get_handler() as DNSRR_TLSA;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + usage(1) + selector(1) + matching_type(1) + data
        const dataLen = sha256hex.length / 2;
        expect(wire.length).toBe(2 + 3 + dataLen);
        // rdlen = 3 + dataLen
        expect((wire[0] << 8) | wire[1]).toBe(3 + dataLen);
        expect(wire[2]).toBe(3);  // usage
        expect(wire[3]).toBe(1);  // selector
        expect(wire[4]).toBe(1);  // matching_type
    });

    it('should parse TLSA with whitespace in hex data', () => {
        const hexWithSpaces = 'aabb ccdd eeff 0011';
        const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', `3 0 1 ${hexWithSpaces}`);
        const handler = rr.get_handler() as DNSRR_TLSA;
        expect(Buffer.from(handler.certificate_association_data).toString('hex')).toBe('aabbccddeeff0011');
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', tlsaValue);
        const handler = rr.get_handler() as DNSRR_TLSA;
        const cloned = handler.clone();
        expect(cloned.usage).toBe(handler.usage);
        expect(cloned.selector).toBe(handler.selector);
        expect(cloned.matching_type).toBe(handler.matching_type);
        expect(Buffer.from(cloned.certificate_association_data)).toEqual(Buffer.from(handler.certificate_association_data));
    });

    it('should reject invalid presentation format', () => {
        expect(() => {
            new DNSRR_TLSA(null, 'invalid');
        }).toThrow();
    });

    it('should handle all certificate usage values', () => {
        for (const usage of [0, 1, 2, 3]) {
            const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', `${usage} 0 1 aabbccdd`);
            const handler = rr.get_handler() as DNSRR_TLSA;
            expect(handler.usage).toBe(usage);
        }
    });

    it('should handle full certificate (matching_type=0)', () => {
        // matching_type 0 means full certificate data, can be longer
        const longHex = 'aa'.repeat(128);
        const rr = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', `3 0 0 ${longHex}`);
        const handler = rr.get_handler() as DNSRR_TLSA;
        expect(handler.matching_type).toBe(0);
        expect(handler.certificate_association_data.length).toBe(128);
    });
});

describe('DNSRR_SMIMEA', () => {
    const sha256hex = 'aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb';
    const smimeaValue = `3 1 1 ${sha256hex}`;

    it('should parse SMIMEA presentation format', () => {
        const rr = new ResourceRecord('abcdef._smimecert.example.com.', 3600, 'IN', 'SMIMEA', smimeaValue);
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_SMIMEA);

        const smimea = handler as DNSRR_SMIMEA;
        expect(smimea.usage).toBe(3);
        expect(smimea.selector).toBe(1);
        expect(smimea.matching_type).toBe(1);
        expect(Buffer.from(smimea.certificate_association_data).toString('hex')).toBe(sha256hex);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('abcdef._smimecert.example.com.', 3600, 'IN', 'SMIMEA', smimeaValue);
        const handler = rr.get_handler() as DNSRR_SMIMEA;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        const dataLen = sha256hex.length / 2;
        expect(wire.length).toBe(2 + 3 + dataLen);
        expect((wire[0] << 8) | wire[1]).toBe(3 + dataLen);
        expect(wire[2]).toBe(3);
        expect(wire[3]).toBe(1);
        expect(wire[4]).toBe(1);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('abcdef._smimecert.example.com.', 3600, 'IN', 'SMIMEA', smimeaValue);
        const handler = rr.get_handler() as DNSRR_SMIMEA;
        const cloned = handler.clone();
        expect(cloned.usage).toBe(handler.usage);
        expect(cloned.selector).toBe(handler.selector);
        expect(cloned.matching_type).toBe(handler.matching_type);
    });

    it('should have same wire format as equivalent TLSA', () => {
        const value = '3 1 1 aabbccdd';
        const tlsaRR = new ResourceRecord('_443._tcp.example.com.', 3600, 'IN', 'TLSA', value);
        const smimeaRR = new ResourceRecord('hash._smimecert.example.com.', 3600, 'IN', 'SMIMEA', value);

        const tlsaBuilder = new WireBuilder();
        (tlsaRR.get_handler() as DNSRR_TLSA).get_wire_body(tlsaBuilder);

        const smimeaBuilder = new WireBuilder();
        (smimeaRR.get_handler() as DNSRR_SMIMEA).get_wire_body(smimeaBuilder);

        expect(tlsaBuilder.build()).toEqual(smimeaBuilder.build());
    });
});

describe('Zone file parsing with DANE records', () => {
    it('should parse TLSA records from zone file text', () => {
        // Import DNSSecZone to trigger handler registration
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
_443._tcp  IN  TLSA  3 1 1 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
`);
        const rr = zone.find_rr('_443._tcp.example.com.', StringToRRType('TLSA'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_TLSA;
        expect(handler.usage).toBe(3);
        expect(handler.selector).toBe(1);
        expect(handler.matching_type).toBe(1);
    });
});
