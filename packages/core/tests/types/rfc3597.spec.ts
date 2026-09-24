// RFC 3597 §5: TYPEnnn / CLASSnnn generic mnemonics.
// Ports dnsdata-go types/rfc3597_test.go.

import {
    StringToRRType,
    StringToRRClass,
    RRTypeName,
    RRClassName,
} from "../../src/types/dns_type_table";
import { UnknownRRTypeError, UnknownRRClassError } from "../../src/dns_exception";

const TYPE_A = 1;
const TYPE_TLSA = 52;
const CLASS_IN = 1;
const CLASS_CHAOS = 3;

describe("StringToRRType generic", () => {
    const cases: Array<[string, number]> = [
        ["TYPE65400", 65400],
        ["type65400", 65400],
        ["Type1", TYPE_A],
        ["TYPE0", 0],
        ["TYPE65535", 65535],
        ["TYPE52", TYPE_TLSA],
    ];
    it.each(cases)("%s -> %d", (input, want) => {
        expect(StringToRRType(input)).toBe(want);
    });
});

describe("StringToRRType generic rejects", () => {
    it.each(["TYPE", "TYPE65536", "TYPE-1", "TYPE1x", "TYPE 1", "TYPE+1"])("%s", (input) => {
        expect(() => StringToRRType(input)).toThrow(UnknownRRTypeError);
    });
});

describe("StringToRRClass generic", () => {
    const cases: Array<[string, number]> = [
        ["CLASS1", CLASS_IN],
        ["class3", CLASS_CHAOS],
        ["CLASS65280", 65280],
    ];
    it.each(cases)("%s -> %d", (input, want) => {
        expect(StringToRRClass(input)).toBe(want);
    });

    it("rejects CLASS70000", () => {
        expect(() => StringToRRClass("CLASS70000")).toThrow(UnknownRRClassError);
    });
});

describe("RRTypeName", () => {
    it("returns the mnemonic for a known type", () => {
        expect(RRTypeName(TYPE_TLSA)).toBe("TLSA");
    });
    it("falls back to TYPE<n>", () => {
        expect(RRTypeName(65400)).toBe("TYPE65400");
    });
});

describe("RRClassName", () => {
    it("returns the mnemonic for a known class", () => {
        expect(RRClassName(CLASS_IN)).toBe("IN");
    });
    it("falls back to CLASS<n>", () => {
        expect(RRClassName(65280)).toBe("CLASS65280");
    });
});
