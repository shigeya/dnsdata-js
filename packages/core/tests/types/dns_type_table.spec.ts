// Type Table test code

import {
    OpCodeToString,
    StringToOpCode,
    RCodeToString,
    StringToRCode,
    RRTypeToString,
    StringToRRType,
    RRClassToString,
    StringToRRClass,
    QTypeValidForRequest,
    QClassValidForRequest
} from "../../src/types/dns_type_table";
import {
    UnknownOpCodeError,
    UnknownRCodeError,
    UnknownRRTypeError,
    UnknownRRClassError,
} from "../../src/lib/dns_exception";

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

describe("StringToRRClass", () => {
    it("can translate between qclass and printable string", () => {
        rrclass_test_vector.forEach(async ([rrclass, printable]) => {
            expect(StringToRRClass(printable)).toBe(rrclass);
        })
    });
    it("can detect illegal qclass string", () => {
        expect( () => { StringToRRClass("XXX") } ).toThrow(RangeError);
    });
});

//

describe("QTypeValidForRequest", () => {
    it("returns true for valid query types", () => {
        [1, 2, 5, 6, 12, 16, 28, 33, 35, 43, 46, 47, 48, 50, 256].forEach(t => {
            expect(QTypeValidForRequest(t)).toBe(true);
        });
    });
    it("returns false for invalid/unknown types", () => {
        [0, 999, 3, 4].forEach(t => {
            expect(QTypeValidForRequest(t)).toBe(false);
        });
    });
});

describe("QClassValidForRequest", () => {
    it("returns true for valid query classes", () => {
        [1, 3, 4, 255].forEach(c => {
            expect(QClassValidForRequest(c)).toBe(true);
        });
    });
    it("returns false for invalid query classes", () => {
        [0, 254, 999].forEach(c => {
            expect(QClassValidForRequest(c)).toBe(false);
        });
    });
});

// UF-003: typed enum-classification errors so callers can discriminate
// "unknown opcode" from "unknown rrtype" via instanceof instead of message
// matching, and read the offending value off the .value field.
describe("typed enum errors (UF-003)", () => {
    it("OpCodeToString throws UnknownOpCodeError with the numeric value", () => {
        try {
            OpCodeToString(3);
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownOpCodeError);
            expect(err).toBeInstanceOf(RangeError); // back-compat
            expect((err as UnknownOpCodeError).value).toBe(3);
        }
    });

    it("StringToOpCode throws UnknownOpCodeError with the string value", () => {
        try {
            StringToOpCode("XXX");
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownOpCodeError);
            expect((err as UnknownOpCodeError).value).toBe("XXX");
        }
    });

    it("RCodeToString throws UnknownRCodeError with the numeric value", () => {
        try {
            RCodeToString(11);
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRCodeError);
            expect((err as UnknownRCodeError).value).toBe(11);
        }
    });

    it("StringToRCode throws UnknownRCodeError with the string value", () => {
        try {
            StringToRCode("XXX");
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRCodeError);
            expect((err as UnknownRCodeError).value).toBe("XXX");
        }
    });

    it("RRTypeToString throws UnknownRRTypeError with the numeric value", () => {
        try {
            RRTypeToString(999);
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRRTypeError);
            expect((err as UnknownRRTypeError).value).toBe(999);
        }
    });

    it("StringToRRType throws UnknownRRTypeError with the string value", () => {
        try {
            StringToRRType("XXX");
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRRTypeError);
            expect((err as UnknownRRTypeError).value).toBe("XXX");
        }
    });

    it("RRClassToString throws UnknownRRClassError with the numeric value", () => {
        try {
            RRClassToString(999);
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRRClassError);
            expect((err as UnknownRRClassError).value).toBe(999);
        }
    });

    it("StringToRRClass throws UnknownRRClassError with the string value", () => {
        try {
            StringToRRClass("XXX");
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRRClassError);
            expect((err as UnknownRRClassError).value).toBe("XXX");
        }
    });

    it("distinct categories do not cross-match (RRType vs OpCode)", () => {
        try {
            RRTypeToString(999);
            fail("expected throw");
        } catch (err) {
            expect(err).toBeInstanceOf(UnknownRRTypeError);
            expect(err).not.toBeInstanceOf(UnknownOpCodeError);
            expect(err).not.toBeInstanceOf(UnknownRCodeError);
            expect(err).not.toBeInstanceOf(UnknownRRClassError);
        }
    });
});
