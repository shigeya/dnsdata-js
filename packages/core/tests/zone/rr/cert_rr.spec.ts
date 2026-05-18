import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_CERT } from '../../../src/zone/rr/cert_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table CERT', () => {
    it('should convert CERT type', () => {
        expect(RRTypeToString(37)).toBe('CERT');
        expect(StringToRRType('CERT')).toBe(37);
    });
});

describe('DNSRR_CERT (RFC 4398)', () => {
    // RFC 4398 §2: type(2) + key_tag(2) + algorithm(1) + certificate(variable)

    // Test data: PKIX cert type, key_tag=12345, algo=8(RSASHA256), small base64 cert
    const testCertBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
    const testCertB64 = Buffer.from(testCertBytes).toString('base64');

    it('should parse CERT with numeric type', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CERT', `1 12345 8 ${testCertB64}`);
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_CERT);

        const cert = handler as DNSRR_CERT;
        expect(cert.cert_type).toBe(1);  // PKIX
        expect(cert.key_tag).toBe(12345);
        expect(cert.algorithm).toBe(8);
        expect(cert.certificate.length).toBe(6);
    });

    it('should parse CERT with mnemonic type', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CERT', `PKIX 12345 8 ${testCertB64}`);
        const handler = rr.get_handler() as DNSRR_CERT;
        expect(handler.cert_type).toBe(1);
    });

    it('should parse PGP type mnemonic', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CERT', `PGP 54321 0 ${testCertB64}`);
        const handler = rr.get_handler() as DNSRR_CERT;
        expect(handler.cert_type).toBe(3);
        expect(handler.algorithm).toBe(0);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CERT', `1 12345 8 ${testCertB64}`);
        const handler = rr.get_handler() as DNSRR_CERT;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + type(2) + key_tag(2) + algorithm(1) + cert(6)
        expect(wire.length).toBe(2 + 2 + 2 + 1 + 6);
        expect((wire[0] << 8) | wire[1]).toBe(2 + 2 + 1 + 6);  // rdlen = 11
        expect((wire[2] << 8) | wire[3]).toBe(1);      // cert_type = PKIX
        expect((wire[4] << 8) | wire[5]).toBe(12345);  // key_tag
        expect(wire[6]).toBe(8);                        // algorithm
        expect(wire[7]).toBe(0xde);                     // cert data
        expect(wire[12]).toBe(0xfe);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CERT', `1 12345 8 ${testCertB64}`);
        const handler = rr.get_handler() as DNSRR_CERT;
        const cloned = handler.clone();
        expect(cloned.cert_type).toBe(handler.cert_type);
        expect(cloned.key_tag).toBe(handler.key_tag);
        expect(cloned.algorithm).toBe(handler.algorithm);
        expect(Buffer.from(cloned.certificate)).toEqual(Buffer.from(handler.certificate));
    });

    it('should reject invalid format', () => {
        expect(() => new DNSRR_CERT(null, '1 2')).toThrow();
    });
});

describe('Zone file parsing with CERT records', () => {
    it('should parse CERT records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/dnssec/dnssec_zone');
        const zone = new DNSSecZone();
        const b64 = Buffer.from([0x01, 0x02, 0x03]).toString('base64');
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  CERT  PKIX 12345 8 ${b64}
`);
        const rr = zone.find_rr('example.com.', StringToRRType('CERT'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_CERT;
        expect(handler.cert_type).toBe(1);
        expect(handler.key_tag).toBe(12345);
    });
});
