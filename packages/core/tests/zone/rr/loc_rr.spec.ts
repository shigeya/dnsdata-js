import { ResourceRecord } from '../../../src/zone/dns_zone';
import { DNSRR_LOC } from '../../../src/zone/rr/loc_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/wire/dns_wire_util';

describe('dns_type_table LOC', () => {
    it('should convert LOC type', () => {
        expect(RRTypeToString(29)).toBe('LOC');
        expect(StringToRRType('LOC')).toBe(29);
    });
});

describe('DNSRR_LOC (RFC 1876)', () => {
    // RFC 1876 §2: VERSION(1) + SIZE(1) + HORIZ_PRE(1) + VERT_PRE(1)
    //              + LATITUDE(4) + LONGITUDE(4) + ALTITUDE(4) = 16 bytes

    const EQUATOR = 2147483648;  // 2^31
    const ALT_OFFSET = 10000000; // 100,000m in cm

    it('should parse full presentation format with d m s', () => {
        // RFC 1876 §3 example: 42 21 54 N 71 06 18 W -24m 30m
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '42 21 54 N 71 06 18 W -24m 30m');
        const handler = rr.get_handler();
        expect(handler).toBeInstanceOf(DNSRR_LOC);

        const loc = handler as DNSRR_LOC;
        expect(loc.version).toBe(0);

        // Latitude: 42°21'54" N = (42*3600 + 21*60 + 54) * 1000 = 152514000 thousandths
        // Wire: EQUATOR + 152514000
        expect(loc.latitude).toBe(EQUATOR + 152514000);

        // Longitude: 71°06'18" W = (71*3600 + 6*60 + 18) * 1000 = 255978000 thousandths
        // Wire: EQUATOR - 255978000
        expect(loc.longitude).toBe(EQUATOR - 255978000);

        // Altitude: -24m = -2400cm + 10000000 = 9997600
        expect(loc.altitude).toBe(ALT_OFFSET - 2400);
    });

    it('should parse degrees-only format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '42 N 71 W 0m');
        const handler = rr.get_handler() as DNSRR_LOC;
        // 42° = 42 * 3600 * 1000 = 151200000
        expect(handler.latitude).toBe(EQUATOR + 151200000);
    });

    it('should parse degrees-minutes format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '42 21 N 71 06 W 100m');
        const handler = rr.get_handler() as DNSRR_LOC;
        // 42°21' = (42*3600 + 21*60) * 1000 = 152460000
        expect(handler.latitude).toBe(EQUATOR + 152460000);
    });

    it('should use default values for optional fields', () => {
        // RFC 1876 §3: defaults: size=1m, hp=10000m, vp=10m
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '0 N 0 E 0m');
        const handler = rr.get_handler() as DNSRR_LOC;

        // size=1m -> 100cm -> 1e2 -> 0x12
        expect(handler.size).toBe(0x12);
        // hp=10000m -> 1000000cm -> 1e6 -> 0x16
        expect(handler.horiz_pre).toBe(0x16);
        // vp=10m -> 1000cm -> 1e3 -> 0x13
        expect(handler.vert_pre).toBe(0x13);
    });

    it('should build correct 16-byte wire format', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '0 N 0 E 0m 1m 10000m 10m');
        const handler = rr.get_handler() as DNSRR_LOC;
        const builder = new WireBuilder();
        handler.get_wire_body(builder);
        const wire = builder.build();

        // rdlen(2) + 16 bytes RDATA
        expect(wire.length).toBe(2 + 16);
        expect((wire[0] << 8) | wire[1]).toBe(16);  // rdlen

        // VERSION = 0
        expect(wire[2]).toBe(0);

        // SIZE, HORIZ_PRE, VERT_PRE
        expect(wire[3]).toBe(0x12);  // size = 1m
        expect(wire[4]).toBe(0x16);  // hp = 10000m
        expect(wire[5]).toBe(0x13);  // vp = 10m

        // LATITUDE at equator: 2^31 = 0x80000000
        expect(wire[6]).toBe(0x80);
        expect(wire[7]).toBe(0x00);
        expect(wire[8]).toBe(0x00);
        expect(wire[9]).toBe(0x00);

        // LONGITUDE at prime meridian: 2^31
        expect(wire[10]).toBe(0x80);
        expect(wire[11]).toBe(0x00);
        expect(wire[12]).toBe(0x00);
        expect(wire[13]).toBe(0x00);

        // ALTITUDE at 0m: 10000000 = 0x00989680
        expect(wire[14]).toBe(0x00);
        expect(wire[15]).toBe(0x98);
        expect(wire[16]).toBe(0x96);
        expect(wire[17]).toBe(0x80);
    });

    it('should handle south latitude and east longitude', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '33 51 36 S 151 12 40 E 50m');
        const handler = rr.get_handler() as DNSRR_LOC;

        // 33°51'36" S -> EQUATOR - (33*3600+51*60+36)*1000 = EQUATOR - 121896000
        expect(handler.latitude).toBe(EQUATOR - 121896000);

        // 151°12'40" E -> EQUATOR + (151*3600+12*60+40)*1000 = EQUATOR + 544360000
        expect(handler.longitude).toBe(EQUATOR + 544360000);
    });

    it('should clone correctly', () => {
        const rr = new ResourceRecord('example.com.', 3600, 'IN', 'LOC',
            '42 21 54 N 71 06 18 W -24m 30m');
        const handler = rr.get_handler() as DNSRR_LOC;
        const cloned = handler.clone();
        expect(cloned.latitude).toBe(handler.latitude);
        expect(cloned.longitude).toBe(handler.longitude);
        expect(cloned.altitude).toBe(handler.altitude);
        expect(cloned.size).toBe(handler.size);
    });
});

describe('Zone file parsing with LOC records', () => {
    it('should parse LOC records from zone file text', () => {
        const { DNSSecZone } = require('../../../src/dnssec/dnssec_zone');
        const zone = new DNSSecZone();
        zone.read_string(`
$ORIGIN example.com.
$TTL 3600
@  IN  LOC  42 21 54 N 71 06 18 W -24m 30m
`);
        const rr = zone.find_rr('example.com.', StringToRRType('LOC'));
        expect(rr).not.toBeNull();
        const handler = rr!.get_handler() as DNSRR_LOC;
        expect(handler.version).toBe(0);
    });
});
