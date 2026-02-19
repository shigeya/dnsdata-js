import { ResourceRecord } from '../../src/lib/dns_zone';
import { DNSRR_SSHFP } from '../../src/lib/sshfp_rr';
import { StringToRRType, RRTypeToString } from '../../src/lib/dns_type_table';
import { WireBuilder } from '../../src/lib/dns_wire_util';

describe('dns_type_table SSHFP', () => {
    it('should convert SSHFP type', () => {
        expect(RRTypeToString(44)).toBe('SSHFP');
        expect(StringToRRType('SSHFP')).toBe(44);
    });
});

describe('DNSRR_SSHFP', () => {
    // RFC 4255 §3.1: algorithm(1) + fp_type(1) + fingerprint
    // Example: RSA key with SHA-1 fingerprint
    const sha1hex = '123456789abcdef67890123456789abcdef67890';
    const sshfpValue = `1 1 ${sha1hex}`;

    it('should parse SSHFP presentation format', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', sshfpValue);
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_SSHFP);

        const sshfp = handler as DNSRR_SSHFP;
        expect(sshfp.algorithm).toBe(1);   // RSA
        expect(sshfp.fp_type).toBe(1);     // SHA-1
        expect(Buffer.from(sshfp.fingerprint).toString('hex')).toBe(sha1hex);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', sshfpValue);
        const handler = rr.get_handler() as DNSRR_SSHFP;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + algorithm(1) + fp_type(1) + fingerprint(20 bytes for SHA-1)
        const fpLen = sha1hex.length / 2;
        expect(wire.length).toBe(2 + 2 + fpLen);
        expect((wire[0] << 8) | wire[1]).toBe(2 + fpLen);  // rdlen
        expect(wire[2]).toBe(1);  // algorithm = RSA
        expect(wire[3]).toBe(1);  // fp_type = SHA-1
    });

    it('should handle SHA-256 fingerprint (RFC 6594)', () => {
        const sha256hex = 'aa'.repeat(32);
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', `3 2 ${sha256hex}`);
        const handler = rr.get_handler() as DNSRR_SSHFP;
        expect(handler.algorithm).toBe(3);   // ECDSA
        expect(handler.fp_type).toBe(2);     // SHA-256
        expect(handler.fingerprint.length).toBe(32);
    });

    it('should handle Ed25519 algorithm (RFC 7479)', () => {
        const sha256hex = 'bb'.repeat(32);
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', `4 2 ${sha256hex}`);
        const handler = rr.get_handler() as DNSRR_SSHFP;
        expect(handler.algorithm).toBe(4);   // Ed25519
        expect(handler.fp_type).toBe(2);     // SHA-256
    });

    it('should parse fingerprint with whitespace', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', '1 1 aabb ccdd eeff');
        const handler = rr.get_handler() as DNSRR_SSHFP;
        expect(Buffer.from(handler.fingerprint).toString('hex')).toBe('aabbccddeeff');
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('host.example.com.', 3600, 'IN', 'SSHFP', sshfpValue);
        const handler = rr.get_handler() as DNSRR_SSHFP;
        const cloned = handler.clone();
        expect(cloned.algorithm).toBe(handler.algorithm);
        expect(cloned.fp_type).toBe(handler.fp_type);
        expect(Buffer.from(cloned.fingerprint)).toEqual(Buffer.from(handler.fingerprint));
    });

    it('should reject invalid presentation format', () => {
        expect(() => new DNSRR_SSHFP(null, 'invalid')).toThrow();
    });
});

describe('Zone file parsing with SSHFP records', () => {
    it('should parse SSHFP records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
host  IN  SSHFP  1 1 123456789abcdef67890123456789abcdef67890
`);
        const rr = zone.find_rr('host.example.com.', StringToRRType('SSHFP'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_SSHFP;
        expect(handler.algorithm).toBe(1);
        expect(handler.fp_type).toBe(1);
    });
});
