// WireBuilder tests

import { WireBuilder, compare_uint8arrays } from "../../src/wire/dns_wire_util";

describe("WireBuilder", () => {
    it("can append uint8", () => {
        const wb = new WireBuilder();
        wb.append_uint8(0x42);
        expect(wb.build()).toEqual(new Uint8Array([0x42]));
    });

    it("can append uint16 in big-endian", () => {
        const wb = new WireBuilder();
        wb.append_uint16(0x0102);
        expect(wb.build()).toEqual(new Uint8Array([0x01, 0x02]));
    });

    it("can append uint32 in big-endian", () => {
        const wb = new WireBuilder();
        wb.append_uint32(0x01020304);
        expect(wb.build()).toEqual(new Uint8Array([0x01, 0x02, 0x03, 0x04]));
    });

    it("can append bytes", () => {
        const wb = new WireBuilder();
        wb.append_bytes(new Uint8Array([0xaa, 0xbb]));
        wb.append_uint8(0xcc);
        expect(wb.build()).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
    });

    it("tracks length correctly", () => {
        const wb = new WireBuilder();
        expect(wb.length).toBe(0);
        wb.append_uint16(0x0001);
        expect(wb.length).toBe(2);
        wb.append_uint32(0x00000001);
        expect(wb.length).toBe(6);
    });

    it("can build RRSIG-style header fields", () => {
        const wb = new WireBuilder();
        wb.append_uint16(1);    // type covered: A
        wb.append_uint8(8);     // algorithm: RSASHA256
        wb.append_uint8(2);     // labels
        wb.append_uint32(86400); // original TTL
        expect(wb.build()).toEqual(new Uint8Array([
            0x00, 0x01,         // type covered
            0x08,               // algorithm
            0x02,               // labels
            0x00, 0x01, 0x51, 0x80 // TTL = 86400
        ]));
    });
});

describe("compare_uint8arrays", () => {
    it("compares equal arrays", () => {
        expect(compare_uint8arrays(
            new Uint8Array([1, 2, 3]),
            new Uint8Array([1, 2, 3])
        )).toBe(0);
    });

    it("compares by first differing byte", () => {
        expect(compare_uint8arrays(
            new Uint8Array([1, 2, 3]),
            new Uint8Array([1, 2, 4])
        )).toBeLessThan(0);
    });

    it("shorter array is less when prefix matches", () => {
        expect(compare_uint8arrays(
            new Uint8Array([1, 2]),
            new Uint8Array([1, 2, 3])
        )).toBeLessThan(0);
    });
});
