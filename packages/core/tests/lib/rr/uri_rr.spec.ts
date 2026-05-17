import { ResourceRecord } from '../../../src/lib/dns_zone';
import { DNSRR_URI } from '../../../src/lib/rr/uri_rr';
import { StringToRRType, RRTypeToString } from '../../../src/lib/dns_type_table';
import { WireBuilder } from '../../../src/lib/dns_wire_util';

describe('dns_type_table URI', () => {
    it('should convert URI type', () => {
        expect(RRTypeToString(256)).toBe('URI');
        expect(StringToRRType('URI')).toBe(256);
    });
});

describe('DNSRR_URI (RFC 7553)', () => {
    // RFC 7553 §4.5: priority(2) + weight(2) + target(raw octets)

    it('should parse URI with HTTP target', () => {
        const rr = new ResourceRecord('_http._tcp.example.com.', 3600, 'IN', 'URI',
            '10 1 "http://www.example.com/path"');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_URI);

        const uri = handler as DNSRR_URI;
        expect(uri.priority).toBe(10);
        expect(uri.weight).toBe(1);
        expect(uri.target).toBe('http://www.example.com/path');
    });

    it('should parse URI with FTP target', () => {
        const rr = new ResourceRecord('_ftp._tcp.example.com.', 3600, 'IN', 'URI',
            '20 10 "ftp://ftp.example.com/public"');
        const handler = rr.get_handler() as DNSRR_URI;
        expect(handler.priority).toBe(20);
        expect(handler.weight).toBe(10);
        expect(handler.target).toBe('ftp://ftp.example.com/public');
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('_http._tcp.example.com.', 3600, 'IN', 'URI',
            '10 1 "http://www.example.com/"');
        const handler = rr.get_handler() as DNSRR_URI;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        const targetBytes = Buffer.from('http://www.example.com/', 'utf-8');
        const expectedRdlen = 2 + 2 + targetBytes.length;

        // rdlen
        expect((wire[0] << 8) | wire[1]).toBe(expectedRdlen);
        // priority
        expect((wire[2] << 8) | wire[3]).toBe(10);
        // weight
        expect((wire[4] << 8) | wire[5]).toBe(1);
        // target (raw octets, no length prefix)
        expect(wire[6]).toBe(0x68);  // 'h'
        expect(wire[7]).toBe(0x74);  // 't'
        expect(wire[8]).toBe(0x74);  // 't'
        expect(wire[9]).toBe(0x70);  // 'p'

        // Total length
        expect(wire.length).toBe(2 + expectedRdlen);
    });

    it('should compute correct rdlength', () => {
        const rr = new ResourceRecord('_http._tcp.example.com.', 3600, 'IN', 'URI',
            '10 1 "http://www.example.com/"');
        const handler = rr.get_handler() as DNSRR_URI;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        const rdlen = (wire[0] << 8) | wire[1];
        const targetLen = Buffer.from('http://www.example.com/', 'utf-8').length;
        expect(rdlen).toBe(2 + 2 + targetLen);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('_http._tcp.example.com.', 3600, 'IN', 'URI',
            '10 1 "http://www.example.com/"');
        const handler = rr.get_handler() as DNSRR_URI;
        const cloned = handler.clone();
        expect(cloned.priority).toBe(handler.priority);
        expect(cloned.weight).toBe(handler.weight);
        expect(cloned.target).toBe(handler.target);
    });

    it('should reject invalid format (missing quotes)', () => {
        expect(() => new DNSRR_URI(null, '10 1 http://example.com')).toThrow();
    });

    it('should reject invalid format (missing weight)', () => {
        expect(() => new DNSRR_URI(null, '10 "http://example.com"')).toThrow();
    });
});

describe('Zone file parsing with URI records', () => {
    it('should parse URI records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
_http._tcp  IN  URI  10 1 "http://www.example.com/"
`);
        const rr = zone.find_rr('_http._tcp.example.com.', StringToRRType('URI'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_URI;
        expect(handler.priority).toBe(10);
        expect(handler.weight).toBe(1);
        expect(handler.target).toBe('http://www.example.com/');
    });
});
