// Type Table test code

import {
    OpCodeToString,
    StringToOpCode,
    RCodeToString,
    StringToRCode,
    RRTypeToString,
    StringToRRType,
    RRClassToString,
    StringToRRClass
} from "../../src/lib/dns_type_table";

//

const opcode_test_vector : Array<[number, string]> = [
    [0, "Query"],
    [1, "IQuery"],
    [2, "Status"],
    [4, "Notify"],
    [5, "Update"],
];

describe("OpCodeToString", () => {
    it("can translate among opcode and printable string", () => {
        opcode_test_vector.forEach(async ([opcode, printable]) => {
            expect(OpCodeToString(opcode)).toBe(printable);
        })
    });

    it("can detect illegal opcode string", () => {
        expect( () => { OpCodeToString(3) } ).toThrow("OpCodeToString: unknown ns_opcode <3>");
    });
});


describe("StringToOpCode", () => {
    it("can translate among opcode and printable string", () => {
        opcode_test_vector.forEach(async ([opcode, printable]) => {
            expect(StringToOpCode(printable)).toBe(opcode);
        })
    });

    it("can detect illegal opcode string", () => {
        expect( () => { StringToOpCode("XXX") } ).toThrow(RangeError);
    });
});

//

const rcode_test_vector : Array<[number, string]> = [
    [0, "NOERROR"],
    [1, "FORMERR"],
    [2, "SERVFAIL"],
    [3, "NXDOMAIN"],
    [4, "NOTIMPL"],
    [5, "REFUSED"],
    [6, "YXDOMAIN"],
    [7, "YXRRSET"],
    [8, "NXRRSET"],
    [9, "NOTAUTH"],
    [10, "NOTZONE"],
    [16, "BADVERS/SIG"],
    [17, "BADKEY"],
    [18, "BADTIME"],
];

describe("RCodeToString", () => {
    it("can translate among rcode and printable string", () => {
        rcode_test_vector.forEach(async ([rcode, printable]) => {
            expect(RCodeToString(rcode)).toBe(printable);
        })
    });

    it("can detect illegal rcode", () => {
        expect( () => { RCodeToString(11) } ).toThrow("RCodeToString: unknown ns_rcode <11>");
    });
});

describe("StringToRCode", () => {
    it("can translate among rcode and printable string", () => {
        rcode_test_vector.forEach(async ([rcode, printable]) => {
            expect(StringToRCode(printable)).toBe(rcode);
        })
    });

    it("can detect illegal rcode", () => {
        expect( () => { StringToRCode("XXX") } ).toThrow(RangeError);
    });
});

//
const rrtype_test_vector : Array<[number, string]> = [
    [0, "INVALID"],
    [1, "A"],
    [2, "NS"],
    [5, "CNAME"],
    [6, "SOA"],
    [12, "PTR"],
    [16, "TXT"],
    [28, "AAAA"],
    [33, "SRV"],
    [35, "NAPTR"],
    [43, "DS"],
    [46, "RRSIG"],
    [47, "NSEC"],
    [48, "DNSKEY"],
    [50, "NSEC3"],
    [256, "URI"]
];

describe("RRTypeToString", () => {
    it("can translate between rrtype and printable string", () => {
        rrtype_test_vector.forEach(async ([rrtype, printable]) => {
            expect(RRTypeToString(rrtype)).toBe(printable);
        })
    });

    it("can detect illegal RR type", () => {
        expect( () => { RRTypeToString(999) } ).toThrow("RRTypeToString: unknown ns_type: <999>");
    });
    
});

describe("StringToRRType", () => {
    it("can translate between rrtype and printable string", () => {
        rrtype_test_vector.forEach(async ([rrtype, printable]) => {
            expect(StringToRRType(printable)).toBe(rrtype);
        })
    });

    it("can detect illegal rrtype string", () => {
        expect( () => { StringToRRType("XXX") } ).toThrow(RangeError);
    });
});

//

const rrclass_test_vector : Array<[number, string]> = [
    [0, "INVALID"],
    [1, "IN"],
    [2, "UNALLOC_2"],
    [3, "CHAOS"],
    [4, "HS"],
    [254, "NONE"],
    [255, "ANY"],
];

describe("RRClassToString", () => {
    it("can translate between rrtype and printable string", () => {
        rrclass_test_vector.forEach(async ([rrtype, printable]) => {
            expect(RRClassToString(rrtype)).toBe(printable);
        })
    });

    it("can detect illegal　RR class", () => {
        expect( () => { RRClassToString(999) } ).toThrow("RRClassToString: unknown ns_class: <999>");
    });
});

describe("RRClassToString", () => {
    it("can translate between qclass and printable string", () => {
        rrclass_test_vector.forEach(async ([rrclass, printable]) => {
            expect(StringToRRClass(printable)).toBe(rrclass);
        })
    });
    it("can detect illegal qclass string", () => {
        expect( () => { StringToRRClass("XXX") } ).toThrow(RangeError);
    });
});
