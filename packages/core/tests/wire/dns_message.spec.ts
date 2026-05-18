// dns_message.ts tests — parse_message + Header / RawMessage / RawRR.
//
// Builds raw DNS message bytes by hand and asserts the parser
// recovers the structured shape (including compression-pointer
// follow-through for the answer-section owner name).

import { parse_message, Header } from '../../src/wire/dns_message';
import { DNSMessageMalformedError } from '../../src/lib/dns_exception';

// Helper: assemble a Uint8Array from a list of byte arrays / numbers.
function bytes(...parts: (number | number[] | Uint8Array)[]): Uint8Array {
    const out: number[] = [];
    for (const p of parts) {
        if (typeof p === 'number') out.push(p);
        else if (p instanceof Uint8Array) {
            for (let i = 0; i < p.length; i++) out.push(p[i]);
        } else {
            out.push(...p);
        }
    }
    return new Uint8Array(out);
}

// Encode "example.com." as a wire-form name (uncompressed).
const NAME_EXAMPLE_COM = [
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
    0x03, 0x63, 0x6f, 0x6d,                          // com
    0x00,
];

// Build a typical A-record response over example.com.
function make_a_response(): Uint8Array {
    return bytes(
        // Header (12 octets)
        0x12, 0x34,           // ID
        0x81, 0x80,           // Flags: QR=1, RD=1, RA=1
        0x00, 0x01,           // QDCount
        0x00, 0x01,           // ANCount
        0x00, 0x00,           // NSCount
        0x00, 0x00,           // ARCount
        // Question
        NAME_EXAMPLE_COM,
        0x00, 0x01,           // QType A
        0x00, 0x01,           // QClass IN
        // Answer: pointer to qname @ offset 12
        0xC0, 0x0C,
        0x00, 0x01,           // Type A
        0x00, 0x01,           // Class IN
        0x00, 0x00, 0x01, 0x2C, // TTL = 300
        0x00, 0x04,           // RDLEN
        93, 184, 216, 34,     // RDATA
    );
}

describe('parse_message', () => {
    it('parses header / question / answer for a simple A response', () => {
        const msg = make_a_response();
        const result = parse_message(msg);

        expect(result.header).toBeInstanceOf(Header);
        expect(result.header.id).toBe(0x1234);
        expect(result.header.qr()).toBe(true);
        expect(result.header.rd()).toBe(true);
        expect(result.header.ra()).toBe(true);
        expect(result.header.aa()).toBe(false);
        expect(result.header.tc()).toBe(false);
        expect(result.header.ad()).toBe(false);
        expect(result.header.cd()).toBe(false);
        expect(result.header.rcode()).toBe(0);
        expect(result.header.qdcount).toBe(1);
        expect(result.header.ancount).toBe(1);

        expect(result.question.name).toBe('example.com.');
        expect(result.question.type).toBe(1);
        expect(result.question.class).toBe(1);

        expect(result.answer).toHaveLength(1);
        const rr = result.answer[0];
        expect(rr.name).toBe('example.com.');
        expect(rr.type).toBe(1);
        expect(rr.class).toBe(1);
        expect(rr.ttl).toBe(300);
        expect(rr.rdata).toEqual(new Uint8Array([93, 184, 216, 34]));
        // rdataStart should point exactly to the RDATA octets.
        expect(rr.rdataStart).toBeGreaterThan(0);
        expect(result.raw[rr.rdataStart]).toBe(93);

        expect(result.authority).toEqual([]);
        expect(result.additional).toEqual([]);
    });

    it('rejects a header shorter than 12 octets', () => {
        expect(() => parse_message(new Uint8Array(5))).toThrow(DNSMessageMalformedError);
        expect(() => parse_message(new Uint8Array(5))).toThrow(/header truncated/);
    });

    it('rejects qdcount != 1', () => {
        const msg = bytes(
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,           // QDCount=2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        );
        expect(() => parse_message(msg)).toThrow(DNSMessageMalformedError);
        expect(() => parse_message(msg)).toThrow(/qdcount=2/);
    });

    it('rejects truncated question fields', () => {
        // Header says QD=1 but the question is just a name + 1 byte (need 4).
        const msg = bytes(
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            NAME_EXAMPLE_COM,
            0x00,
        );
        expect(() => parse_message(msg)).toThrow(DNSMessageMalformedError);
        expect(() => parse_message(msg)).toThrow(/question fields truncated/);
    });

    it('rejects truncated RDATA in an answer record', () => {
        // Header says AN=1 but the answer's RDATA length says 4 octets while
        // only 2 are present.
        const msg = bytes(
            0x12, 0x34, 0x81, 0x80,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            NAME_EXAMPLE_COM,
            0x00, 0x01, 0x00, 0x01,
            // Answer
            0xC0, 0x0C,           // pointer to qname
            0x00, 0x01,           // Type A
            0x00, 0x01,           // Class IN
            0x00, 0x00, 0x00, 0x60,
            0x00, 0x04,           // RDLEN=4
            0xAA, 0xBB,           // ...but only 2 octets follow.
        );
        expect(() => parse_message(msg)).toThrow(DNSMessageMalformedError);
        expect(() => parse_message(msg)).toThrow(/rdata truncated/);
    });

    it('decodes a multi-section response with authority + additional', () => {
        // Question + 0 answer + 1 NS in authority + 1 A in additional.
        const NAME_NS_EXAMPLE_COM = [
            0x02, 0x6e, 0x73,   // "ns"
            0xC0, 0x0C,         // pointer to "example.com." at offset 12
        ];
        const msg = bytes(
            0x12, 0x34, 0x80, 0x00, // QR set, NoError
            0x00, 0x01, 0x00, 0x00,  // QD=1, AN=0
            0x00, 0x01, 0x00, 0x01,  // NS=1, AR=1
            NAME_EXAMPLE_COM,
            0x00, 0x01, 0x00, 0x01,  // QType A, QClass IN
            // Authority: example.com. NS ns.example.com.
            0xC0, 0x0C,              // owner = example.com.
            0x00, 0x02, 0x00, 0x01,  // Type NS, Class IN
            0x00, 0x00, 0x01, 0x2C,  // TTL 300
            0x00, 0x05,              // RDLEN
            NAME_NS_EXAMPLE_COM,
            // Additional: ns.example.com. A 192.0.2.1
            NAME_NS_EXAMPLE_COM,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x01, 0x2C,
            0x00, 0x04,
            192, 0, 2, 1,
        );
        const result = parse_message(msg);
        expect(result.answer).toEqual([]);
        expect(result.authority).toHaveLength(1);
        expect(result.additional).toHaveLength(1);
        expect(result.authority[0].name).toBe('example.com.');
        expect(result.authority[0].type).toBe(2);
        expect(result.additional[0].name).toBe('ns.example.com.');
        expect(result.additional[0].type).toBe(1);
    });
});
