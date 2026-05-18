import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_OPENPGPKEY } from '../../../src/zone/rr/openpgpkey_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table OPENPGPKEY', () => {
    it('should convert OPENPGPKEY type', () => {
        expect(RRTypeToString(61)).toBe('OPENPGPKEY');
        expect(StringToRRType('OPENPGPKEY')).toBe(61);
    });
});

describe('DNSRR_OPENPGPKEY (RFC 7929)', () => {
    // RFC 7929 §2.1: RDATA = raw OpenPGP Transferable Public Key
    // RFC 7929 §2.2: Presentation = base64-encoded key

    // Small test key (not a real PGP key, just test bytes)
    const testBytes = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const testB64 = Buffer.from(testBytes).toString('base64');

    it('should parse base64-encoded key data', () => {
        const rr = new ResourceRecord('abc._openpgpkey.example.com.', 3600, 'IN', 'OPENPGPKEY', testB64);
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_OPENPGPKEY);

        const pgp = handler as DNSRR_OPENPGPKEY;
        expect(pgp.key_data.length).toBe(5);
        expect(pgp.key_data[0]).toBe(0x01);
        expect(pgp.key_data[4]).toBe(0x05);
    });

    it('should handle base64 with whitespace', () => {
        // Zone files may have base64 split across lines
        const b64WithSpaces = testB64.substring(0, 4) + ' ' + testB64.substring(4);
        const rr = new ResourceRecord('abc._openpgpkey.example.com.', 3600, 'IN', 'OPENPGPKEY', b64WithSpaces);
        const handler = rr.get_handler() as DNSRR_OPENPGPKEY;
        expect(handler.key_data.length).toBe(5);
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('abc._openpgpkey.example.com.', 3600, 'IN', 'OPENPGPKEY', testB64);
        const handler = rr.get_handler() as DNSRR_OPENPGPKEY;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + key_data(5)
        expect(wire.length).toBe(2 + 5);
        expect((wire[0] << 8) | wire[1]).toBe(5);  // rdlen
        expect(wire[2]).toBe(0x01);
        expect(wire[6]).toBe(0x05);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('abc._openpgpkey.example.com.', 3600, 'IN', 'OPENPGPKEY', testB64);
        const handler = rr.get_handler() as DNSRR_OPENPGPKEY;
        const cloned = handler.clone();
        expect(Buffer.from(cloned.key_data)).toEqual(Buffer.from(handler.key_data));
    });

    it('should reject empty key data', () => {
        expect(() => new DNSRR_OPENPGPKEY(null, '')).toThrow();
        expect(() => new DNSRR_OPENPGPKEY(null, '   ')).toThrow();
    });
});

describe('Zone file parsing with OPENPGPKEY records', () => {
    it('should parse OPENPGPKEY records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        const testB64 = Buffer.from([0xde, 0xad, 0xbe, 0xef]).toString('base64');
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
abc._openpgpkey  IN  OPENPGPKEY  ${testB64}
`);
        const rr = zone.find_rr('abc._openpgpkey.example.com.', StringToRRType('OPENPGPKEY'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_OPENPGPKEY;
        expect(handler.key_data.length).toBe(4);
    });
});
