import { ResourceRecord } from '../../../src/lib/dns_zone';
import { DNSRR_SVCB } from '../../../src/lib/rr/svcb_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table SVCB/HTTPS', () => {
    it('should convert SVCB type', () => {
        expect(RRTypeToString(64)).toBe('SVCB');
        expect(StringToRRType('SVCB')).toBe(64);
    });

    it('should convert HTTPS type', () => {
        expect(RRTypeToString(65)).toBe('HTTPS');
        expect(StringToRRType('HTTPS')).toBe(65);
    });
});

describe('DNSRR_SVCB', () => {
    // RFC 9460 §2.2: SvcPriority(2) + TargetName(domain) + SvcParams

    it('should parse AliasMode (priority=0)', () => {
        // RFC 9460 §2.4.2: AliasMode has priority 0 and a target
        const rr = new ResourceRecord('_https._tcp.example.com.', 3600, 'IN', 'SVCB', '0 svc.example.com.');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_SVCB);

        const svcb = handler as DNSRR_SVCB;
        expect(svcb.priority).toBe(0);
        expect(svcb.target).toBe('svc.example.com.');
        expect(svcb.params.length).toBe(0);
    });

    it('should parse ServiceMode with alpn param', () => {
        // RFC 9460 §7.1: alpn parameter
        const rr = new ResourceRecord('_https._tcp.example.com.', 3600, 'IN', 'SVCB', '1 . alpn=h2,h3');
        const handler = rr.get_handler() as DNSRR_SVCB;
        expect(handler.priority).toBe(1);
        expect(handler.target).toBe('.');
        expect(handler.params.length).toBe(1);
        expect(handler.params[0].key).toBe(1);  // alpn
    });

    it('should parse ServiceMode with port param', () => {
        // RFC 9460 §7.2: port parameter
        const rr = new ResourceRecord('_https._tcp.example.com.', 3600, 'IN', 'SVCB', '1 svc.example.com. port=8443');
        const handler = rr.get_handler() as DNSRR_SVCB;
        expect(handler.priority).toBe(1);
        expect(handler.params.length).toBe(1);
        expect(handler.params[0].key).toBe(3);  // port
        // port wire value: 8443 = 0x20FB
        expect(handler.params[0].value[0]).toBe(0x20);
        expect(handler.params[0].value[1]).toBe(0xFB);
    });

    it('should parse ServiceMode with multiple params', () => {
        const rr = new ResourceRecord('_https._tcp.example.com.', 3600, 'IN', 'SVCB',
            '1 svc.example.com. alpn=h2 port=443');
        const handler = rr.get_handler() as DNSRR_SVCB;
        expect(handler.params.length).toBe(2);
        // RFC 9460 §2.2: params must be in increasing key order
        expect(handler.params[0].key).toBe(1);  // alpn
        expect(handler.params[1].key).toBe(3);  // port
    });

    it('should sort params by key order', () => {
        // Even if presentation has them out of order, wire must be sorted
        const rr = new ResourceRecord('_https._tcp.example.com.', 3600, 'IN', 'SVCB',
            '1 svc.example.com. port=443 alpn=h2');
        const handler = rr.get_handler() as DNSRR_SVCB;
        expect(handler.params[0].key).toBe(1);  // alpn first
        expect(handler.params[1].key).toBe(3);  // port second
    });

    it('should build correct wire format for AliasMode', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB', '0 svc.example.com.');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + priority(2) + target(wire-encoded "svc.example.com.")
        // target: 3 "svc" + 7 "example" + 3 "com" + 0 = 3+1+7+1+3+1+1 = 17 bytes
        const targetLen = 17;
        expect((wire[0] << 8) | wire[1]).toBe(2 + targetLen);  // rdlen
        expect((wire[2] << 8) | wire[3]).toBe(0);  // priority = 0
        // First label: length=3, then "svc"
        expect(wire[4]).toBe(3);
        expect(wire[5]).toBe(0x73);  // 's'
        expect(wire[6]).toBe(0x76);  // 'v'
        expect(wire[7]).toBe(0x63);  // 'c'
    });

    it('should build correct wire format for root target (.)', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB', '1 . alpn=h2');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // After rdlen(2): priority(2) + root name(1 byte: 0x00) + alpn param
        expect((wire[2] << 8) | wire[3]).toBe(1);  // priority = 1
        expect(wire[4]).toBe(0);  // root label (just terminator)
        // alpn param: key(2)=0x0001, length(2), value
        expect((wire[5] << 8) | wire[6]).toBe(1);  // SvcParamKey = alpn
    });

    it('should encode alpn wire format correctly', () => {
        // RFC 9460 §7.1.1: alpn wire = repeated (length(1) + alpn-id)
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB', '1 . alpn=h2,h3');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const alpnParam = handler.params[0];
        expect(alpnParam.key).toBe(1);
        // h2: length=2, 'h','2'  h3: length=2, 'h','3'  => total 6 bytes
        expect(alpnParam.value.length).toBe(6);
        expect(alpnParam.value[0]).toBe(2);   // length of "h2"
        expect(alpnParam.value[1]).toBe(0x68); // 'h'
        expect(alpnParam.value[2]).toBe(0x32); // '2'
        expect(alpnParam.value[3]).toBe(2);   // length of "h3"
        expect(alpnParam.value[4]).toBe(0x68); // 'h'
        expect(alpnParam.value[5]).toBe(0x33); // '3'
    });

    it('should encode ipv4hint wire format correctly', () => {
        // RFC 9460 §7.4: ipv4hint = concatenated 4-byte addresses
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB',
            '1 . ipv4hint=192.0.2.1,192.0.2.2');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const param = handler.params[0];
        expect(param.key).toBe(4);  // ipv4hint
        expect(param.value.length).toBe(8);  // 2 addresses * 4 bytes
        expect(param.value[0]).toBe(192);
        expect(param.value[1]).toBe(0);
        expect(param.value[2]).toBe(2);
        expect(param.value[3]).toBe(1);
        expect(param.value[4]).toBe(192);
        expect(param.value[5]).toBe(0);
        expect(param.value[6]).toBe(2);
        expect(param.value[7]).toBe(2);
    });

    it('should encode ipv6hint wire format correctly', () => {
        // RFC 9460 §7.4: ipv6hint = concatenated 16-byte addresses
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB',
            '1 . ipv6hint=2001:db8::1');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const param = handler.params[0];
        expect(param.key).toBe(6);  // ipv6hint
        expect(param.value.length).toBe(16);
        expect(param.value[0]).toBe(0x20);  // 2001
        expect(param.value[1]).toBe(0x01);
        expect(param.value[2]).toBe(0x0d);  // 0db8
        expect(param.value[3]).toBe(0xb8);
        // bytes 4-14 are zeros (::)
        for (let i = 4; i < 15; i++) expect(param.value[i]).toBe(0);
        expect(param.value[15]).toBe(1);  // ::1
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB', '1 svc.example.com. alpn=h2 port=443');
        const handler = rr.get_handler() as DNSRR_SVCB;
        const cloned = handler.clone();
        expect(cloned.priority).toBe(handler.priority);
        expect(cloned.target).toBe(handler.target);
        expect(cloned.params.length).toBe(handler.params.length);
    });

    it('should reject invalid presentation format', () => {
        expect(() => new DNSRR_SVCB(null, 'invalid')).toThrow();
    });
});

describe('HTTPS RR (type 65)', () => {
    // RFC 9460 §9.1: HTTPS uses identical wire format to SVCB (type 64).
    // The handler class DNSRR_SVCB is shared; only the RR type code differs.

    it('should parse HTTPS record using shared SVCB handler', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'HTTPS', '1 . alpn=h2,h3');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_SVCB);

        const https = handler as DNSRR_SVCB;
        expect(https.priority).toBe(1);
        expect(https.target).toBe('.');
        expect(https.params.length).toBe(1);
    });

    it('should build identical wire format as SVCB', () => {
        const svcbRR = new ResourceRecord('example.com.', 3600, 'IN', 'SVCB', '1 . alpn=h2');
        const httpsRR = new ResourceRecord('example.com.', 3600, 'IN', 'HTTPS', '1 . alpn=h2');

        const svcbBuilder = new WireBuilder();
        (svcbRR.get_handler() as DNSRR_SVCB).get_wire_body(svcbBuilder);
        const svcbWire = svcbBuilder.build();

        const httpsBuilder = new WireBuilder();
        (httpsRR.get_handler() as DNSRR_SVCB).get_wire_body(httpsBuilder);
        const httpsWire = httpsBuilder.build();

        // RFC 9460 §9.1: Wire format is identical
        expect(httpsWire).toEqual(svcbWire);
    });
});

describe('Zone file parsing with SVCB/HTTPS records', () => {
    it('should parse SVCB records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
_https._tcp  IN  SVCB  1 svc.example.com. alpn=h2
`);
        const rr = zone.find_rr('_https._tcp.example.com.', StringToRRType('SVCB'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_SVCB;
        expect(handler.priority).toBe(1);
        expect(handler.target).toBe('svc.example.com.');
    });

    it('should parse HTTPS records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/lib/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  HTTPS  1 . alpn=h2,h3 port=443
`);
        const rr = zone.find_rr('example.com.', StringToRRType('HTTPS'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_SVCB;
        expect(handler.priority).toBe(1);
        expect(handler.params.length).toBe(2);
    });
});
