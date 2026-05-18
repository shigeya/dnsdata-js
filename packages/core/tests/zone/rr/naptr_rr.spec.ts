import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_NAPTR } from '../../../src/zone/rr/naptr_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table NAPTR', () => {
    it('should convert NAPTR type', () => {
        expect(RRTypeToString(35)).toBe('NAPTR');
        expect(StringToRRType('NAPTR')).toBe(35);
    });
});

describe('DNSRR_NAPTR (RFC 3403)', () => {
    // RFC 3403 §4.1: order(2) + preference(2) + flags(char-string) + services(char-string)
    //                + regexp(char-string) + replacement(domain-name)

    it('should parse NAPTR with ENUM example', () => {
        // RFC 6116 ENUM example
        const rr = new ResourceRecord('2.1.2.1.5.5.5.0.0.8.1.e164.arpa.', 3600, 'IN', 'NAPTR',
            '100 10 "u" "E2U+sip" "!^\\\\+(.*)$!sip:\\\\1@example.com!" .');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_NAPTR);

        const naptr = handler as DNSRR_NAPTR;
        expect(naptr.order).toBe(100);
        expect(naptr.preference).toBe(10);
        expect(naptr.flags).toBe('u');
        expect(naptr.services).toBe('E2U+sip');
        expect(naptr.regexp).toBe('!^\\+(.*)$!sip:\\1@example.com!');
        expect(naptr.replacement).toBe('.');
    });

    it('should parse NAPTR with SIP example', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'NAPTR',
            '10 100 "s" "SIP+D2U" "" _sip._udp.example.com.');
        const handler = rr.get_handler() as DNSRR_NAPTR;
        expect(handler.order).toBe(10);
        expect(handler.preference).toBe(100);
        expect(handler.flags).toBe('s');
        expect(handler.services).toBe('SIP+D2U');
        expect(handler.regexp).toBe('');
        expect(handler.replacement).toBe('_sip._udp.example.com.');
    });

    it('should parse NAPTR with empty flags', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'NAPTR',
            '100 50 "" "http+N2L+N2C+N2R" "" www.example.com.');
        const handler = rr.get_handler() as DNSRR_NAPTR;
        expect(handler.flags).toBe('');
        expect(handler.services).toBe('http+N2L+N2C+N2R');
        expect(handler.replacement).toBe('www.example.com.');
    });

    it('should build correct wire format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'NAPTR',
            '10 100 "s" "SIP+D2U" "" _sip._udp.example.com.');
        const handler = rr.get_handler() as DNSRR_NAPTR;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // Skip rdlen(2), check order and preference
        expect((wire[2] << 8) | wire[3]).toBe(10);   // order
        expect((wire[4] << 8) | wire[5]).toBe(100);   // preference

        // flags: character-string "s" => length(1)=1, data='s'
        expect(wire[6]).toBe(1);       // flags length
        expect(wire[7]).toBe(0x73);    // 's'

        // services: character-string "SIP+D2U" => length(1)=7, data='SIP+D2U'
        expect(wire[8]).toBe(7);       // services length
        expect(wire[9]).toBe(0x53);    // 'S'
        expect(wire[10]).toBe(0x49);   // 'I'
        expect(wire[11]).toBe(0x50);   // 'P'

        // regexp: character-string "" => length(1)=0
        expect(wire[16]).toBe(0);      // regexp length (empty)
    });

    it('should compute correct rdlength', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'NAPTR',
            '10 100 "s" "SIP+D2U" "" _sip._udp.example.com.');
        const handler = rr.get_handler() as DNSRR_NAPTR;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        const rdlen = (wire[0] << 8) | wire[1];
        // order(2) + preference(2) + flags(1+1) + services(1+7) + regexp(1+0) + replacement
        // replacement: _sip(4+1) + _udp(4+1) + example(7+1) + com(3+1) + root(1) = 23
        const expectedReplacementLen = 1 + 4 + 1 + 4 + 1 + 7 + 1 + 3 + 1;  // labels with length prefix + root
        const expectedRdlen = 2 + 2 + (1 + 1) + (1 + 7) + (1 + 0) + expectedReplacementLen;
        expect(rdlen).toBe(expectedRdlen);
        // Total wire length = 2(rdlen field) + rdlen
        expect(wire.length).toBe(2 + rdlen);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'NAPTR',
            '10 100 "s" "SIP+D2U" "" _sip._udp.example.com.');
        const handler = rr.get_handler() as DNSRR_NAPTR;
        const cloned = handler.clone();
        expect(cloned.order).toBe(handler.order);
        expect(cloned.preference).toBe(handler.preference);
        expect(cloned.flags).toBe(handler.flags);
        expect(cloned.services).toBe(handler.services);
        expect(cloned.regexp).toBe(handler.regexp);
        expect(cloned.replacement).toBe(handler.replacement);
    });

    it('should reject invalid format', () => {
        expect(() => new DNSRR_NAPTR(null, '10')).toThrow();
    });

    it('should reject missing quoted string', () => {
        expect(() => new DNSRR_NAPTR(null, '10 100 s SIP+D2U "" .')).toThrow();
    });
});

describe('Zone file parsing with NAPTR records', () => {
    it('should parse NAPTR records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  NAPTR  10 100 "s" "SIP+D2U" "" _sip._udp.example.com.
`);
        const rr = zone.find_rr('example.com.', StringToRRType('NAPTR'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_NAPTR;
        expect(handler.order).toBe(10);
        expect(handler.preference).toBe(100);
        expect(handler.flags).toBe('s');
        expect(handler.services).toBe('SIP+D2U');
    });
});
