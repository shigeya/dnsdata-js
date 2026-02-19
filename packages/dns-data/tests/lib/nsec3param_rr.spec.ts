import { ResourceRecord } from '../../src/lib/dns_zone';
import { DNSRR_NSEC3PARAM } from '../../src/lib/dnssec_rr';
import { StringToRRType, RRTypeToString } from '../../src/lib/dns_type_table';
import { WireBuilder } from '../../src/lib/dns_wire_util';

describe('dns_type_table NSEC3PARAM', () => {
    it('should convert NSEC3PARAM type', () => {
        expect(RRTypeToString(51)).toBe('NSEC3PARAM');
        expect(StringToRRType('NSEC3PARAM')).toBe(51);
    });
});

describe('DNSRR_NSEC3PARAM', () => {
    // RFC 5155 §4.2: hash_algorithm(1) + flags(1) + iterations(2) + salt_length(1) + salt(variable)

    it('should parse NSEC3PARAM with salt', () => {
        // hash_algo=1 (SHA-1), flags=0, iterations=10, salt=aabbccdd
        const rr = new ResourceRecord('example.com.', 0, 'IN', 'NSEC3PARAM', '1 0 10 aabbccdd');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_NSEC3PARAM);

        const param = handler as DNSRR_NSEC3PARAM;
        expect(param.hash_algorithm).toBe(1);
        expect(param.flags).toBe(0);
        expect(param.iterations).toBe(10);
        expect(Buffer.from(param.salt).toString('hex')).toBe('aabbccdd');
    });

    it('should parse NSEC3PARAM with empty salt (dash)', () => {
        // RFC 5155 §4.2: salt of "-" means zero-length salt
        const rr = new ResourceRecord('example.com.', 0, 'IN', 'NSEC3PARAM', '1 0 0 -');
        const handler = rr.get_handler() as DNSRR_NSEC3PARAM;
        expect(handler.hash_algorithm).toBe(1);
        expect(handler.flags).toBe(0);
        expect(handler.iterations).toBe(0);
        expect(handler.salt.length).toBe(0);
    });

    it('should build correct wire format with salt', () => {
        const rr = new ResourceRecord('example.com.', 0, 'IN', 'NSEC3PARAM', '1 0 10 aabbccdd');
        const handler = rr.get_handler() as DNSRR_NSEC3PARAM;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + hash_algo(1) + flags(1) + iterations(2) + salt_len(1) + salt(4)
        expect(wire.length).toBe(2 + 1 + 1 + 2 + 1 + 4);
        expect((wire[0] << 8) | wire[1]).toBe(5 + 4);  // rdlen = 5 + salt_length
        expect(wire[2]).toBe(1);   // hash_algorithm = SHA-1
        expect(wire[3]).toBe(0);   // flags
        expect((wire[4] << 8) | wire[5]).toBe(10);  // iterations
        expect(wire[6]).toBe(4);   // salt_length
        expect(wire[7]).toBe(0xaa);
        expect(wire[8]).toBe(0xbb);
        expect(wire[9]).toBe(0xcc);
        expect(wire[10]).toBe(0xdd);
    });

    it('should build correct wire format with empty salt', () => {
        const rr = new ResourceRecord('example.com.', 0, 'IN', 'NSEC3PARAM', '1 0 0 -');
        const handler = rr.get_handler() as DNSRR_NSEC3PARAM;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + hash_algo(1) + flags(1) + iterations(2) + salt_len(1) + no salt
        expect(wire.length).toBe(2 + 5);
        expect((wire[0] << 8) | wire[1]).toBe(5);  // rdlen = 5
        expect(wire[6]).toBe(0);   // salt_length = 0
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 0, 'IN', 'NSEC3PARAM', '1 0 10 aabbccdd');
        const handler = rr.get_handler() as DNSRR_NSEC3PARAM;
        const cloned = handler.clone();
        expect(cloned.hash_algorithm).toBe(handler.hash_algorithm);
        expect(cloned.flags).toBe(handler.flags);
        expect(cloned.iterations).toBe(handler.iterations);
        expect(Buffer.from(cloned.salt)).toEqual(Buffer.from(handler.salt));
    });

    it('should reject invalid presentation format', () => {
        expect(() => new DNSRR_NSEC3PARAM(null, 'invalid')).toThrow();
    });
});

describe('Zone file parsing with NSEC3PARAM records', () => {
    it('should parse NSEC3PARAM records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  NSEC3PARAM  1 0 10 aabbccdd
`);
        const rr = zone.find_rr('example.com.', StringToRRType('NSEC3PARAM'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_NSEC3PARAM;
        expect(handler.hash_algorithm).toBe(1);
        expect(handler.iterations).toBe(10);
    });
});
