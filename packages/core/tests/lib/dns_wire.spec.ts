// Spec on: Converting between DNS wire format and string(utf)

import { domain_name2wire, wire2domain_name, parse_domain_name } from "../../src/lib/dns_wire";
import {
    DNSWireError,
    DNSWirePointerLoopError,
    DNSWirePointerForwardError,
} from "../../src/lib/dns_exception";

describe("Domain name wire format conversion library", () => {
    const test_vector: Array<[string, Uint8Array]> = [
        ["xp.net.",        new Uint8Array([0x02, 0x78, 0x70, 0x03, 0x6e, 0x65, 0x74, 0x00])],
        ["Z.ISI.ARPA.",    new Uint8Array([0x01, 0x7a, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["FOO.ISI.ARPA.",  new Uint8Array([0x03, 0x66, 0x6f, 0x6f, 0x03, 0x69, 0x73, 0x69, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["ARPA.",          new Uint8Array([0x04, 0x61, 0x72, 0x70, 0x61, 0x00])],
        ["ARPA",           new Uint8Array([0x04, 0x61, 0x72, 0x70, 0x61])],
        ["sh.wide.xx.jp.", new Uint8Array([0x02, 0x73, 0x68, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70, 0x00])],
        ["ns.wide.xx.jp",  new Uint8Array([0x02, 0x6e, 0x73, 0x04, 0x77, 0x69, 0x64, 0x65, 0x02, 0x78, 0x78, 0x02, 0x6a, 0x70])],
    ];

    it("can translate to wire format", () => {
        test_vector.forEach(([domain_name, wire]) => {
            expect(domain_name2wire(domain_name)).toEqual(wire);
        })
    });

    it("can translate from wire format", () => {
        test_vector.forEach(([domain_name, wire]) => {
            expect(wire2domain_name(wire)).toBe(domain_name.toLowerCase());
        });
    });

    // UF-001: `| 0x20` lowercasing corrupted underscore (0x5F → 0x7F),
    // breaking DKIM / DMARC / TLSA / MTA-STS underscore-prefixed labels.
    describe("underscore-prefixed labels (UF-001)", () => {
        const underscore_vector: Array<[string, Uint8Array]> = [
            [
                "_dmarc.example.com.",
                new Uint8Array([
                    0x06, 0x5f, 0x64, 0x6d, 0x61, 0x72, 0x63,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
            [
                "_443._tcp.example.com.",
                new Uint8Array([
                    0x04, 0x5f, 0x34, 0x34, 0x33,
                    0x04, 0x5f, 0x74, 0x63, 0x70,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
            [
                "Selector._DomainKey.Example.Com.",
                new Uint8Array([
                    0x08, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x6f, 0x72,
                    0x0a, 0x5f, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x6b, 0x65, 0x79,
                    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d,
                    0x00,
                ]),
            ],
        ];

        it("encodes underscore-prefixed labels without corruption", () => {
            underscore_vector.forEach(([domain_name, wire]) => {
                expect(domain_name2wire(domain_name)).toEqual(wire);
            });
        });

        it("round-trips underscore-prefixed labels", () => {
            underscore_vector.forEach(([domain_name, wire]) => {
                expect(wire2domain_name(wire)).toBe(domain_name.toLowerCase());
            });
        });

        it("does not flip bit 5 of '_' (0x5F → 0x7F)", () => {
            const wire = domain_name2wire("_x.");
            expect(wire[1]).toBe(0x5f);
            expect(wire[1]).not.toBe(0x7f);
        });
    });

    // UF-002: RFC 1035 §2.3.4 / §4.1.4 length and structural validation.
    describe("length and structural validation (UF-002)", () => {
        describe("domain_name2wire", () => {
            it("accepts a 63-octet label (maximum)", () => {
                const label = "a".repeat(63);
                const name = `${label}.example.com.`;
                const wire = domain_name2wire(name);
                expect(wire[0]).toBe(63);
            });

            it("rejects a 64-octet label", () => {
                const label = "a".repeat(64);
                const name = `${label}.example.com.`;
                expect(() => domain_name2wire(name)).toThrow(DNSWireError);
                expect(() => domain_name2wire(name)).toThrow(/label too long/);
            });

            it("accepts a name encoding to exactly 255 octets", () => {
                // 4 labels of 63 + root: 4 * (1+63) + 1 = 257 octets — too long.
                // Use 3*63 + 1*61 + root: 3*64 + 62 + 1 = 255 exactly.
                const a63 = "a".repeat(63);
                const a61 = "a".repeat(61);
                const name = `${a63}.${a63}.${a63}.${a61}.`;
                const wire = domain_name2wire(name);
                expect(wire.length).toBe(255);
            });

            it("rejects a name encoding to 256 octets", () => {
                // 3*64 + 62 + 1 (a63 a63 a63 a62 root) = 256 octets exactly.
                const a63 = "a".repeat(63);
                const a62 = "a".repeat(62);
                const name = `${a63}.${a63}.${a63}.${a62}.`;
                expect(() => domain_name2wire(name)).toThrow(DNSWireError);
                expect(() => domain_name2wire(name)).toThrow(/name too long/);
            });

            it("rejects empty labels in the middle of a name", () => {
                expect(() => domain_name2wire("foo..bar.")).toThrow(DNSWireError);
                expect(() => domain_name2wire("foo..bar.")).toThrow(/empty label/);
            });
        });

        describe("wire2domain_name", () => {
            it("rejects length octet 0x40 (reserved)", () => {
                const wire = new Uint8Array([0x40, 0x61, 0x00]);
                expect(() => wire2domain_name(wire)).toThrow(DNSWireError);
                expect(() => wire2domain_name(wire)).toThrow(/invalid length octet/);
            });

            it("rejects length octet 0xC0 (compression pointer)", () => {
                // wire2domain_name does not decompress; pointers must be rejected.
                const wire = new Uint8Array([0xc0, 0x0c]);
                expect(() => wire2domain_name(wire)).toThrow(DNSWireError);
                expect(() => wire2domain_name(wire)).toThrow(/invalid length octet/);
            });

            it("rejects truncated input (declared label runs off the end)", () => {
                // Length octet says 5 bytes follow, but only 3 are present.
                const wire = new Uint8Array([0x05, 0x61, 0x62, 0x63]);
                expect(() => wire2domain_name(wire)).toThrow(DNSWireError);
                expect(() => wire2domain_name(wire)).toThrow(/truncated wire/);
            });
        });
    });

    // UP-002: parse_domain_name decodes possibly-compressed names from a
    // larger message buffer. Covers RFC 1035 §4.1.4 compression-pointer
    // semantics + the reserved 0x40 / 0x80 prefixes + hop-cap.
    describe("parse_domain_name (UP-002)", () => {
        it("decodes a simple uncompressed name", () => {
            // "example.com." starting at offset 0.
            const msg = new Uint8Array([
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d,
                0x00,
            ]);
            const { name, next } = parse_domain_name(msg, 0);
            expect(name).toBe("example.com.");
            expect(next).toBe(13);
        });

        it("decodes the root name", () => {
            const msg = new Uint8Array([0x00]);
            const { name, next } = parse_domain_name(msg, 0);
            expect(name).toBe(".");
            expect(next).toBe(1);
        });

        it("follows a backward compression pointer", () => {
            // [0..12]: example.com. (13 octets ending with 0x00).
            // [13]: 0xC0 0x00 → pointer back to offset 0.
            const msg = new Uint8Array([
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d,
                0x00,
                0xC0, 0x00,
            ]);
            const { name, next } = parse_domain_name(msg, 13);
            expect(name).toBe("example.com.");
            // Pointer advance is 2 bytes from the pointer location,
            // NOT the length of the pointed-to name.
            expect(next).toBe(15);
        });

        it("follows a partial-label + pointer combination", () => {
            // [0..12]: example.com.
            // [13]: 0x03 'w' 'w' 'w' 0xC0 0x00 → "www" + pointer to example.com.
            const msg = new Uint8Array([
                0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
                0x03, 0x63, 0x6f, 0x6d,
                0x00,
                0x03, 0x77, 0x77, 0x77,
                0xC0, 0x00,
            ]);
            const { name, next } = parse_domain_name(msg, 13);
            expect(name).toBe("www.example.com.");
            expect(next).toBe(19);
        });

        it("rejects a pointer that points at or past its own position", () => {
            // pointer at offset 0 pointing to offset 0 (self-reference).
            const msg = new Uint8Array([0xC0, 0x00]);
            expect(() => parse_domain_name(msg, 0)).toThrow(DNSWirePointerForwardError);

            // pointer at offset 0 pointing to offset 5 (forward).
            const msg2 = new Uint8Array([0xC0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            expect(() => parse_domain_name(msg2, 0)).toThrow(DNSWirePointerForwardError);
        });

        it("detects a compression-pointer loop", () => {
            // [0..3]: "abc" label then pointer back to offset 0 (self loop
            // via the visited set).
            const msg = new Uint8Array([
                0x03, 0x61, 0x62, 0x63,   // "abc"
                0xC0, 0x00,                // pointer to offset 0 (revisited on second pass)
            ]);
            // First pass: read "abc" (4 bytes), then pointer to 0 → visited[0]=true → jump.
            // Second pass: same path → pointer to 0 again → visited[0] already true → loop.
            expect(() => parse_domain_name(msg, 0)).toThrow(DNSWirePointerLoopError);
        });

        it("rejects reserved label-length prefix 0x40", () => {
            const msg = new Uint8Array([0x40, 0x00]);
            expect(() => parse_domain_name(msg, 0)).toThrow(DNSWireError);
        });

        it("rejects out-of-range starting offset", () => {
            const msg = new Uint8Array([0x00]);
            expect(() => parse_domain_name(msg, 99)).toThrow(DNSWireError);
            expect(() => parse_domain_name(msg, -1)).toThrow(DNSWireError);
        });

        it("rejects truncated label data", () => {
            // length 5 declared but only 3 octets follow + no terminator.
            const msg = new Uint8Array([0x05, 0x61, 0x62, 0x63]);
            expect(() => parse_domain_name(msg, 0)).toThrow(DNSWireError);
        });
    });
});
