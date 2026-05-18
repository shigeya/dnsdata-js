import { DNSRR_OPT, EDNS_OPTION_NSID, EDNS_OPTION_COOKIE } from '../../../src/lib/rr/opt_rr';
import { StringToRRType, RRTypeToString } from '../../../src/types/dns_type_table';
import { WireBuilder } from '../../../src/lib/dns_wire_util';

describe('dns_type_table OPT', () => {
    it('should convert OPT type', () => {
        expect(RRTypeToString(41)).toBe('OPT');
        expect(StringToRRType('OPT')).toBe(41);
    });
});

describe('DNSRR_OPT (RFC 6891)', () => {
    // RFC 6891 §6.1.2: OPT pseudo-RR wire format

    it('should create default OPT record', () => {
        const opt = new DNSRR_OPT();
        expect(opt.udp_payload_size).toBe(4096);
        expect(opt.extended_rcode).toBe(0);
        expect(opt.version).toBe(0);
        expect(opt.do_bit).toBe(false);
        expect(opt.z).toBe(0);
        expect(opt.options.length).toBe(0);
    });

    it('should create OPT with custom parameters', () => {
        const opt = new DNSRR_OPT({
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: [],
        });
        expect(opt.udp_payload_size).toBe(1232);
        expect(opt.do_bit).toBe(true);
    });

    it('should build correct wire format with no options', () => {
        const opt = new DNSRR_OPT({ udp_payload_size: 4096, do_bit: false });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        // NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 11 bytes
        expect(wire.length).toBe(11);

        // NAME: root (0x00)
        expect(wire[0]).toBe(0);

        // TYPE: 41 (OPT)
        expect((wire[1] << 8) | wire[2]).toBe(41);

        // CLASS: UDP payload size = 4096
        expect((wire[3] << 8) | wire[4]).toBe(4096);

        // TTL: extended_rcode=0, version=0, DO=0, Z=0
        expect(wire[5]).toBe(0);  // extended_rcode
        expect(wire[6]).toBe(0);  // version
        expect(wire[7]).toBe(0);  // DO=0, Z high byte
        expect(wire[8]).toBe(0);  // Z low byte

        // RDLEN: 0 (no options)
        expect((wire[9] << 8) | wire[10]).toBe(0);
    });

    it('should encode DO bit correctly', () => {
        const opt = new DNSRR_OPT({ do_bit: true });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        // TTL byte 2 (wire[7]) should have DO bit set (0x80)
        expect(wire[7] & 0x80).toBe(0x80);
    });

    it('should encode extended RCODE and version', () => {
        const opt = new DNSRR_OPT({
            extended_rcode: 1,
            version: 2,
            do_bit: true,
        });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        expect(wire[5]).toBe(1);        // extended_rcode
        expect(wire[6]).toBe(2);        // version
        expect(wire[7] & 0x80).toBe(0x80);  // DO bit
    });

    it('should build wire format with EDNS options', () => {
        const nsidData = new Uint8Array([0x6e, 0x73, 0x31]);  // "ns1"
        const opt = new DNSRR_OPT({
            options: [
                { code: EDNS_OPTION_NSID, data: nsidData },
            ],
        });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        // NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) + option-code(2) + option-len(2) + data(3)
        expect(wire.length).toBe(11 + 4 + 3);

        // RDLEN = 4 + 3 = 7
        expect((wire[9] << 8) | wire[10]).toBe(7);

        // Option code: NSID = 3
        expect((wire[11] << 8) | wire[12]).toBe(EDNS_OPTION_NSID);

        // Option length: 3
        expect((wire[13] << 8) | wire[14]).toBe(3);

        // Option data: "ns1"
        expect(wire[15]).toBe(0x6e);  // 'n'
        expect(wire[16]).toBe(0x73);  // 's'
        expect(wire[17]).toBe(0x31);  // '1'
    });

    it('should build wire format with multiple options', () => {
        const opt = new DNSRR_OPT({
            options: [
                { code: EDNS_OPTION_NSID, data: new Uint8Array([0x6e, 0x73, 0x31]) },
                { code: EDNS_OPTION_COOKIE, data: new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]) },
            ],
        });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        // RDLEN = (4+3) + (4+8) = 19
        expect((wire[9] << 8) | wire[10]).toBe(19);
    });
});

describe('DNSRR_OPT.from_wire', () => {
    it('should parse OPT from wire format with no options', () => {
        const opt = new DNSRR_OPT({ udp_payload_size: 4096, do_bit: true });
        const builder = new WireBuilder();
        opt.get_wire(builder);
        const wire = builder.build();

        // Skip NAME byte (1), parse from TYPE onwards
        const parsed = DNSRR_OPT.from_wire(wire, 1);
        expect(parsed.udp_payload_size).toBe(4096);
        expect(parsed.do_bit).toBe(true);
        expect(parsed.extended_rcode).toBe(0);
        expect(parsed.version).toBe(0);
        expect(parsed.options.length).toBe(0);
    });

    it('should parse OPT from wire format with options', () => {
        const nsidData = new Uint8Array([0x6e, 0x73, 0x31]);
        const original = new DNSRR_OPT({
            udp_payload_size: 1232,
            do_bit: true,
            options: [
                { code: EDNS_OPTION_NSID, data: nsidData },
            ],
        });
        const builder = new WireBuilder();
        original.get_wire(builder);
        const wire = builder.build();

        const parsed = DNSRR_OPT.from_wire(wire, 1);
        expect(parsed.udp_payload_size).toBe(1232);
        expect(parsed.do_bit).toBe(true);
        expect(parsed.options.length).toBe(1);
        expect(parsed.options[0].code).toBe(EDNS_OPTION_NSID);
        expect(parsed.options[0].data).toEqual(nsidData);
    });

    it('should parse extended RCODE and version', () => {
        const original = new DNSRR_OPT({
            extended_rcode: 5,
            version: 1,
            do_bit: false,
        });
        const builder = new WireBuilder();
        original.get_wire(builder);
        const wire = builder.build();

        const parsed = DNSRR_OPT.from_wire(wire, 1);
        expect(parsed.extended_rcode).toBe(5);
        expect(parsed.version).toBe(1);
        expect(parsed.do_bit).toBe(false);
    });

    it('should reject insufficient data', () => {
        expect(() => DNSRR_OPT.from_wire(new Uint8Array(5))).toThrow();
    });

    it('should reject wrong type', () => {
        const data = new Uint8Array(10);
        data[0] = 0; data[1] = 1;  // type = 1 (A), not 41
        expect(() => DNSRR_OPT.from_wire(data)).toThrow(/expected type 41/);
    });
});

describe('DNSRR_OPT.find_option', () => {
    it('should find existing option', () => {
        const opt = new DNSRR_OPT({
            options: [
                { code: EDNS_OPTION_NSID, data: new Uint8Array([0x6e, 0x73, 0x31]) },
                { code: EDNS_OPTION_COOKIE, data: new Uint8Array([0x01, 0x02, 0x03, 0x04]) },
            ],
        });
        const nsid = opt.find_option(EDNS_OPTION_NSID);
        expect(nsid).toBeDefined();
        expect(nsid!.code).toBe(EDNS_OPTION_NSID);
    });

    it('should return undefined for missing option', () => {
        const opt = new DNSRR_OPT();
        expect(opt.find_option(EDNS_OPTION_NSID)).toBeUndefined();
    });
});

describe('OPT round-trip', () => {
    it('should round-trip with complex configuration', () => {
        const cookieData = new Uint8Array(24);
        for (let i = 0; i < 24; i++) cookieData[i] = i;

        const original = new DNSRR_OPT({
            udp_payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            do_bit: true,
            options: [
                { code: EDNS_OPTION_NSID, data: new Uint8Array([0x6e, 0x73, 0x31]) },
                { code: EDNS_OPTION_COOKIE, data: cookieData },
            ],
        });

        const builder = new WireBuilder();
        original.get_wire(builder);
        const wire = builder.build();

        const parsed = DNSRR_OPT.from_wire(wire, 1);
        expect(parsed.udp_payload_size).toBe(1232);
        expect(parsed.do_bit).toBe(true);
        expect(parsed.options.length).toBe(2);
        expect(parsed.options[0].code).toBe(EDNS_OPTION_NSID);
        expect(parsed.options[0].data).toEqual(new Uint8Array([0x6e, 0x73, 0x31]));
        expect(parsed.options[1].code).toBe(EDNS_OPTION_COOKIE);
        expect(parsed.options[1].data).toEqual(cookieData);
    });
});
