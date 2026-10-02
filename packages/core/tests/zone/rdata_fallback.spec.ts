// Ports dnsdata-go `zone/rdata_fallback_test.go`: a record read off the
// wire keeps its RDATA octets, which get_wire_body writes when no
// handler or built-in encoder exists for the type.

import { DNSZoneRDataFormatError } from '../../src/dns_exception';
import { WireBuilder } from '../../src/wire/dns_wire_util';
import { ResourceRecord, new_resource_record_with_rdata } from '../../src/zone/dns_zone';

// NO_ENCODER_TYPE has neither a built-in encoder nor a registered handler.
const NO_ENCODER_TYPE = 65400;
const IN = 1;

function wire_body(rr: ResourceRecord): number[] {
    const b = new WireBuilder();
    rr.get_wire_body(b);
    return Array.from(b.build());
}

describe('new_resource_record_with_rdata', () => {
    it('falls back to the received octets', () => {
        const rdata = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
        const rr = new_resource_record_with_rdata('x.test.', 60, IN, NO_ENCODER_TYPE, 'a presentation form', rdata);
        rdata[0] = 0; // the record keeps its own copy
        expect(wire_body(rr)).toEqual([0, 4, 0xde, 0xad, 0xbe, 0xef]);
        expect(rr.value).toBe('a presentation form');
    });

    it('writes empty RDATA', () => {
        const rr = new_resource_record_with_rdata('x.test.', 60, IN, NO_ENCODER_TYPE, '', new Uint8Array(0));
        expect(wire_body(rr)).toEqual([0, 0]);
    });

    // An encoder, when there is one, still writes the RDATA: the received
    // octets are only a fallback.
    it('lets an encoder win', () => {
        const rr = new_resource_record_with_rdata('x.test.', 60, IN, 'A', '192.0.2.1', Uint8Array.from([1, 2, 3, 4]));
        expect(wire_body(rr)).toEqual([0, 4, 192, 0, 2, 1]);
    });

    it('rejects RDATA longer than 65535 octets', () => {
        expect(() => new_resource_record_with_rdata('x.test.', 60, IN, NO_ENCODER_TYPE, '', new Uint8Array(0x10000)))
            .toThrow(DNSZoneRDataFormatError);
    });

    it('a record without received octets writes nothing for a type with no encoder', () => {
        expect(wire_body(new ResourceRecord('x.test.', 60, IN, NO_ENCODER_TYPE, 'a presentation form'))).toEqual([]);
    });
});
