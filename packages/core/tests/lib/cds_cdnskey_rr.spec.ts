import { ResourceRecord } from '../../src/zone/dns_zone';
import { DNSRR_DS, DNSKey } from '../../src/lib/dnssec_rr';
import { StringToRRType, RRTypeToString } from '../../src/types/dns_type_table';
import { WireBuilder } from '../../src/wire/dns_wire_util';

describe('dns_type_table CDS/CDNSKEY', () => {
    it('should convert CDS type', () => {
        expect(RRTypeToString(59)).toBe('CDS');
        expect(StringToRRType('CDS')).toBe(59);
    });

    it('should convert CDNSKEY type', () => {
        expect(RRTypeToString(60)).toBe('CDNSKEY');
        expect(StringToRRType('CDNSKEY')).toBe(60);
    });
});

describe('CDS (RFC 7344 §3.1)', () => {
    // RFC 7344 §3.1: CDS wire and presentation format is identical to DS (RFC 4034).
    // The DNSRR_DS handler class is reused.

    // DS presentation: keytag(uint16) algorithm(uint8) digest_type(uint8) digest(hex)
    const cdsValue = '12345 8 2 ' + 'ab'.repeat(32);

    it('should parse CDS using DS handler', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CDS', cdsValue);
        const handler = rr.get_handler();
        // RFC 7344 §3.1: reuses DNSRR_DS handler
        expect(handler).toBeInstanceOf(DNSRR_DS);

        const cds = handler as DNSRR_DS;
        expect(cds.key_tag).toBe(12345);
        expect(cds.algorithm).toBe(8);
        expect(cds.digest_type).toBe(2);
    });

    it('should build identical wire format to DS', () => {
        const cdsRR = new ResourceRecord('example.com.', 3600, 'IN', 'CDS', cdsValue);
        const dsRR = new ResourceRecord('example.com.', 3600, 'IN', 'DS', cdsValue);

        const cdsBuilder = new WireBuilder();
        (cdsRR.get_handler() as DNSRR_DS).get_wire_body(cdsBuilder);
        const cdsWire = cdsBuilder.build();

        const dsBuilder = new WireBuilder();
        (dsRR.get_handler() as DNSRR_DS).get_wire_body(dsBuilder);
        const dsWire = dsBuilder.build();

        // RFC 7344 §3.1: wire format identical to DS
        expect(cdsWire).toEqual(dsWire);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CDS', cdsValue);
        const handler = rr.get_handler() as DNSRR_DS;
        const cloned = handler.clone();
        expect(cloned.key_tag).toBe(handler.key_tag);
        expect(cloned.algorithm).toBe(handler.algorithm);
        expect(cloned.digest_type).toBe(handler.digest_type);
    });
});

describe('CDNSKEY (RFC 7344 §3.2)', () => {
    // RFC 7344 §3.2: CDNSKEY wire and presentation format is identical to DNSKEY (RFC 4034).
    // The DNSKey handler class is reused.

    // DNSKEY presentation: flags(uint16) protocol(uint8) algorithm(uint8) public_key(base64)
    const cdnskeyValue = '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=';

    it('should parse CDNSKEY using DNSKEY handler', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'CDNSKEY', cdnskeyValue);
        const handler = rr.get_handler();
        // RFC 7344 §3.2: reuses DNSKey handler
        expect(handler).toBeInstanceOf(DNSKey);

        const cdnskey = handler as DNSKey;
        expect(cdnskey.flags).toBe(257);
        expect(cdnskey.protocol).toBe(3);
        expect(cdnskey.algorithm).toBe(8);
    });

    it('should build identical wire format to DNSKEY', () => {
        const cdnskeyRR = new ResourceRecord('example.com.', 3600, 'IN', 'CDNSKEY', cdnskeyValue);
        const dnskeyRR = new ResourceRecord('example.com.', 3600, 'IN', 'DNSKEY', cdnskeyValue);

        const cdnskeyBuilder = new WireBuilder();
        (cdnskeyRR.get_handler() as DNSKey).get_wire_body(cdnskeyBuilder);
        const cdnskeyWire = cdnskeyBuilder.build();

        const dnskeyBuilder = new WireBuilder();
        (dnskeyRR.get_handler() as DNSKey).get_wire_body(dnskeyBuilder);
        const dnskeyWire = dnskeyBuilder.build();

        // RFC 7344 §3.2: wire format identical to DNSKEY
        expect(cdnskeyWire).toEqual(dnskeyWire);
    });
});

describe('Zone file parsing with CDS/CDNSKEY records', () => {
    it('should parse CDS records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  CDS  12345 8 2 ${'ab'.repeat(32)}
`);
        const rr = zone.find_rr('example.com.', StringToRRType('CDS'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_DS;
        expect(handler.key_tag).toBe(12345);
    });

    it('should parse CDNSKEY records from zone file text', () => {
        const { DNSSecZone } = require('../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  CDNSKEY  257 3 8 AwEAAQ==
`);
        const rr = zone.find_rr('example.com.', StringToRRType('CDNSKEY'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSKey;
        expect(handler.flags).toBe(257);
        expect(handler.algorithm).toBe(8);
    });
});
