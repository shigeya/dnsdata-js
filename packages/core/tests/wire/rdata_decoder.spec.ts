// rdata_decoder.ts tests — RDATA wire → presentation string.
//
// Exercises every type listed in the public surface, plus the
// RFC 3597 §5 fallback for unknown types. RDATA values that embed
// compressed domain names (NS, CNAME, PTR, DNAME, MX, SOA, SRV,
// RRSIG signer, NSEC next) are run through messages that actually
// use a compression pointer, so the (msg, rdataStart) plumbing is
// exercised rather than just the in-rdata path.

import { rdata_to_string, rfc3597 } from '../../src/wire/rdata_decoder';
import { parse_message } from '../../src/wire/dns_message';
import { StringToRRType } from '../../src/types/dns_type_table';
import { DNSRDataDecodeError } from '../../src/dns_exception';

const TYPE_A     = StringToRRType('A');
const TYPE_AAAA  = StringToRRType('AAAA');
const TYPE_NS    = StringToRRType('NS');
const TYPE_CNAME = StringToRRType('CNAME');
const TYPE_PTR   = StringToRRType('PTR');
const TYPE_DNAME = StringToRRType('DNAME');
const TYPE_MX    = StringToRRType('MX');
const TYPE_TXT   = StringToRRType('TXT');
const TYPE_SOA   = StringToRRType('SOA');
const TYPE_SRV   = StringToRRType('SRV');
const TYPE_CAA   = StringToRRType('CAA');
const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS    = StringToRRType('DS');
const TYPE_RRSIG = StringToRRType('RRSIG');
const TYPE_NSEC  = StringToRRType('NSEC');
const TYPE_NSEC3 = StringToRRType('NSEC3');
const TYPE_NSEC3PARAM = StringToRRType('NSEC3PARAM');

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

const NAME_EXAMPLE_COM = [
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00,
];

// Build a message whose answer rrset of type `qtype` contains the
// given rdata bytes. Returns the parsed RawRR plus the whole message
// so the test can call rdata_to_string with the right context.
function single_answer_message(qtype: number, rdata: Uint8Array): { msg: Uint8Array; rdata: Uint8Array; rdataStart: number; } {
    const msg = bytes(
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        NAME_EXAMPLE_COM,
        (qtype >> 8) & 0xff, qtype & 0xff,
        0x00, 0x01,
        0xC0, 0x0C,
        (qtype >> 8) & 0xff, qtype & 0xff,
        0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C,
        (rdata.length >> 8) & 0xff, rdata.length & 0xff,
        rdata,
    );
    const parsed = parse_message(msg);
    const rr = parsed.answer[0];
    return { msg, rdata: rr.rdata, rdataStart: rr.rdataStart };
}

describe('rdata_to_string', () => {
    it('decodes A', () => {
        const { msg, rdata, rdataStart } = single_answer_message(TYPE_A, new Uint8Array([192, 0, 2, 1]));
        expect(rdata_to_string(msg, TYPE_A, rdata, rdataStart)).toBe('192.0.2.1');
    });

    it('decodes AAAA with RFC 5952-style :: collapse', () => {
        const { msg, rdata, rdataStart } = single_answer_message(TYPE_AAAA, new Uint8Array([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]));
        expect(rdata_to_string(msg, TYPE_AAAA, rdata, rdataStart)).toBe('2001:db8::1');
    });

    it('decodes AAAA picking the longest zero-run for ::', () => {
        const { msg, rdata, rdataStart } = single_answer_message(TYPE_AAAA, new Uint8Array([
            0x20, 0x01, 0x00, 0x00, 0x0d, 0xb8, 0x00, 0x01,
            0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x56, 0x78,
        ]));
        // Groups: 2001 0 db8 1 0 1234 0 5678 — longest run of zeros is
        // a single 0 (none of length >= 2), so no `::` collapse fires.
        expect(rdata_to_string(msg, TYPE_AAAA, rdata, rdataStart))
            .toBe('2001:0:db8:1:0:1234:0:5678');
    });

    it('decodes single-name types (NS / CNAME / PTR / DNAME) via compression', () => {
        // RDATA is just a pointer to "example.com." at offset 12.
        const rdata = new Uint8Array([0xC0, 0x0C]);
        for (const t of [TYPE_NS, TYPE_CNAME, TYPE_PTR, TYPE_DNAME]) {
            const { msg, rdata: r, rdataStart } = single_answer_message(t, rdata);
            expect(rdata_to_string(msg, t, r, rdataStart)).toBe('example.com.');
        }
    });

    it('decodes MX with a compressed exchange', () => {
        // RDATA = preference(2) + "mail" + pointer to "example.com."
        const rdata = bytes(
            0x00, 0x0A,                     // pref 10
            0x04, 0x6d, 0x61, 0x69, 0x6c,   // "mail"
            0xC0, 0x0C,                     // ptr → "example.com."
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_MX, rdata);
        expect(rdata_to_string(msg, TYPE_MX, r, rdataStart)).toBe('10 mail.example.com.');
    });

    it('decodes TXT with multiple character-strings, quoting "\\" and ""', () => {
        const rdata = bytes(
            0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,  // "hello"
            0x03, 0x22, 0x5c, 0x21,              // `"\!`
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_TXT, rdata);
        expect(rdata_to_string(msg, TYPE_TXT, r, rdataStart)).toBe(`"hello" "\\"\\\\!"`);
    });

    it('throws on truncated TXT character-string', () => {
        // Length 5 declared but only 3 octets follow.
        const rdata = bytes(0x05, 0x61, 0x62, 0x63);
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_TXT, rdata);
        expect(() => rdata_to_string(msg, TYPE_TXT, r, rdataStart)).toThrow(DNSRDataDecodeError);
    });

    it('decodes SOA with compressed mname/rname', () => {
        // mname = "ns" + ptr → example.com., rname = "hostmaster" + ptr → example.com.
        const rdata = bytes(
            0x02, 0x6e, 0x73,                                                   // "ns"
            0xC0, 0x0C,
            0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72,   // "hostmaster"
            0xC0, 0x0C,
            0x00, 0x00, 0x00, 0x01,   // serial=1
            0x00, 0x00, 0x0e, 0x10,   // refresh=3600
            0x00, 0x00, 0x03, 0x84,   // retry=900
            0x00, 0x09, 0x3a, 0x80,   // expire=604800
            0x00, 0x00, 0x01, 0x51,   // minimum=337
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_SOA, rdata);
        expect(rdata_to_string(msg, TYPE_SOA, r, rdataStart))
            .toBe('ns.example.com. hostmaster.example.com. 1 3600 900 604800 337');
    });

    it('decodes SRV', () => {
        const rdata = bytes(
            0x00, 0x0A,            // priority 10
            0x00, 0x14,            // weight 20
            0x00, 0x50,            // port 80
            0x04, 0x68, 0x74, 0x74, 0x70, 0xC0, 0x0C,  // "http" + ptr to example.com.
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_SRV, rdata);
        expect(rdata_to_string(msg, TYPE_SRV, r, rdataStart))
            .toBe('10 20 80 http.example.com.');
    });

    it('decodes CAA', () => {
        const rdata = bytes(
            0,                                  // flags
            5, 0x69, 0x73, 0x73, 0x75, 0x65,    // tag = "issue"
            0x6c, 0x65, 0x74, 0x73, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2e, 0x6f, 0x72, 0x67, // "letsencrypt.org"
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_CAA, rdata);
        expect(rdata_to_string(msg, TYPE_CAA, r, rdataStart))
            .toBe('0 issue "letsencrypt.org"');
    });

    it('decodes DNSKEY', () => {
        const keyData = new Uint8Array([0xAA, 0xBB, 0xCC]);
        const rdata = bytes(
            0x01, 0x01,           // flags = 257
            0x03,                  // protocol = 3
            0x08,                  // algorithm = 8
            keyData,
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_DNSKEY, rdata);
        const expectedB64 = Buffer.from(keyData).toString('base64');
        expect(rdata_to_string(msg, TYPE_DNSKEY, r, rdataStart)).toBe(`257 3 8 ${expectedB64}`);
    });

    it('decodes DS with lower-case hex digest', () => {
        const digest = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
        const rdata = bytes(
            0x4F, 0x66,    // keyTag 20326
            0x08,           // algorithm 8
            0x02,           // digestType 2
            digest,
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_DS, rdata);
        expect(rdata_to_string(msg, TYPE_DS, r, rdataStart)).toBe('20326 8 2 deadbeef');
    });

    it('decodes RRSIG with a compressed signer name', () => {
        const sig = new Uint8Array([0x00, 0x11, 0x22]);
        const rdata = bytes(
            0x00, 0x01,                 // typeCovered = A
            0x08,                        // algorithm
            0x02,                        // labels
            0x00, 0x00, 0x0e, 0x10,      // originalTTL 3600
            0x66, 0x00, 0x00, 0x00,      // expire
            0x65, 0x00, 0x00, 0x00,      // inception
            0x4F, 0x66,                  // keyTag 20326
            0xC0, 0x0C,                  // signer = pointer to example.com.
            sig,
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_RRSIG, rdata);
        const expectedSig = Buffer.from(sig).toString('base64');
        const out = rdata_to_string(msg, TYPE_RRSIG, r, rdataStart);
        expect(out).toContain('A 8 2 3600 ');
        expect(out).toContain(' example.com. ');
        expect(out.endsWith(' ' + expectedSig)).toBe(true);
    });

    it('decodes NSEC with type bitmap', () => {
        // next = "next.example.com.", bitmap window 0 covering A (1) and NS (2)
        const rdata = bytes(
            0x04, 0x6e, 0x65, 0x78, 0x74, 0xC0, 0x0C, // "next." + ptr → example.com.
            0x00,           // window 0
            0x01,           // length 1
            0b01100000,     // bits 1 (A) and 2 (NS) set
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_NSEC, rdata);
        expect(rdata_to_string(msg, TYPE_NSEC, r, rdataStart)).toBe('next.example.com. A NS');
    });

    it('decodes NSEC3 with no salt and an empty type bitmap', () => {
        // hash algo 1, flags 0, iterations 10, salt = "-", nextHash = [0x00, 0x01]
        const nextHash = new Uint8Array([0x00, 0x01]);
        const rdata = bytes(
            0x01,                 // hash algo
            0x00,                 // flags
            0x00, 0x0a,           // iterations 10
            0x00,                 // saltLen 0
            nextHash.length, nextHash,
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_NSEC3, rdata);
        const out = rdata_to_string(msg, TYPE_NSEC3, r, rdataStart);
        expect(out.startsWith('1 0 10 - ')).toBe(true);
    });

    it('decodes NSEC3PARAM', () => {
        const rdata = bytes(
            0x01, 0x00, 0x00, 0x0a, // hashAlgo=1, flags=0, iterations=10
            0x02, 0xAB, 0xCD,        // saltLen=2, salt bytes
        );
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_NSEC3PARAM, rdata);
        expect(rdata_to_string(msg, TYPE_NSEC3PARAM, r, rdataStart)).toBe('1 0 10 ABCD');
    });

    it('falls back to RFC 3597 generic form for unknown types', () => {
        // Use type 65530 (private use range) which the table does not know.
        const rdata = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
        const out = rdata_to_string(new Uint8Array(0), 65530, rdata, 0);
        expect(out).toBe('\\# 4 deadbeef');
    });

    it('rfc3597 emits zero-length form correctly', () => {
        expect(rfc3597(new Uint8Array(0))).toBe('\\# 0');
    });

    it('throws on A with wrong length', () => {
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_A, new Uint8Array([1, 2, 3]));
        expect(() => rdata_to_string(msg, TYPE_A, r, rdataStart)).toThrow(DNSRDataDecodeError);
    });

    it('throws on AAAA with wrong length', () => {
        const { msg, rdata: r, rdataStart } = single_answer_message(TYPE_AAAA, new Uint8Array(15));
        expect(() => rdata_to_string(msg, TYPE_AAAA, r, rdataStart)).toThrow(DNSRDataDecodeError);
    });
});

// Same bytes and strings as dnsdata-go wire/rdata_svcb_test.go.
describe('rdata_to_string TLSA / SMIMEA / SVCB / HTTPS', () => {
    const TYPE_TLSA   = StringToRRType('TLSA');
    const TYPE_SMIMEA = StringToRRType('SMIMEA');
    const TYPE_SVCB   = StringToRRType('SVCB');
    const TYPE_HTTPS  = StringToRRType('HTTPS');
    const ALL_KEYS = '000100' +
        '0000000400010003' +
        '00010006026832026833' +
        '00020000' +
        '0003000220fb' +
        '00040008c0000201c0000202' +
        '00050003010203' +
        '0006001020010db8000000000000000000000001' +
        'fde80002abcd' +
        'fde90000';

    // [name, type, rdata hex, expected presentation]
    const cases: [string, number, string, string][] = [
        // RFC 6698 §2.2 / RFC 8162 §2. Empty certificate data stays generic.
        ['TLSA', TYPE_TLSA, '030101abcd', '3 1 1 abcd'],
        ['SMIMEA', TYPE_SMIMEA, '0300010A0B', '3 0 1 0a0b'],
        ['TLSA empty data', TYPE_TLSA, '030101', '\\# 3 030101'],
        // RFC 9460 §2.1, in the form DNSRR_SVCB reads.
        ['SVCB', TYPE_SVCB, '000103737663076578616d706c6503636f6d00000100030268320003000201bb',
            '1 svc.example.com. alpn=h2 port=443'],
        ['HTTPS', TYPE_HTTPS, '00010000010003026832', '1 . alpn=h2'],
        ['AliasMode', TYPE_HTTPS, '000003666f6f00', '0 foo.'],
        ['all keys', TYPE_SVCB, ALL_KEYS,
            '1 . mandatory=alpn,port alpn=h2,h3 no-default-alpn port=8443 ' +
            'ipv4hint=192.0.2.1,192.0.2.2 ech=AQID ipv6hint=2001:db8::1 key65000=abcd key65001'],
        // Values the parser would not read back to the same octets.
        ['unsorted keys', TYPE_SVCB, '0001000003000201bb00010003026832',
            '\\# 16 0001000003000201bb00010003026832'],
        ['alpn with comma', TYPE_SVCB, '0001000001000403612c62', '\\# 11 0001000001000403612c62'],
        ['alpn empty', TYPE_SVCB, '00010000010000', '\\# 7 00010000010000'],
        ['no-default-alpn with value', TYPE_SVCB, '0001000002000100', '\\# 8 0001000002000100'],
        ['port short', TYPE_SVCB, '0001000003000101', '\\# 8 0001000003000101'],
        ['ipv4hint ragged', TYPE_SVCB, '00010000040005c000020101', '\\# 12 00010000040005c000020101'],
        ['ipv6hint IPv4-mapped', TYPE_SVCB, '0001000006001000000000000000000000ffffc0000201',
            '\\# 23 0001000006001000000000000000000000ffffc0000201'],
        // The parser keeps the target's case (dnsdata-go UF-008).
        ['uppercase target', TYPE_SVCB, '000103464f4f00', '1 FOO.'],
        ['mandatory unsorted', TYPE_SVCB, '000100000000040003000100010003026832000300020035',
            '\\# 24 000100000000040003000100010003026832000300020035'],
        // Malformed RDATA stays generic, so one bad record does not fail a response.
        ['SVCB short', TYPE_SVCB, '0001', '\\# 2 0001'],
        ['SVCB bad target', TYPE_SVCB, '000105', '\\# 3 000105'],
        ['SVCB header truncated', TYPE_SVCB, '000100000100', '\\# 6 000100000100'],
        ['SVCB value truncated', TYPE_SVCB, '0001000001000502', '\\# 8 0001000001000502'],
        ['alpn id truncated', TYPE_SVCB, '000100000100020561', '\\# 9 000100000100020561'],
        ['TLSA short', TYPE_TLSA, '0301', '\\# 2 0301'],
    ];

    it.each(cases)('presents %s as dnsdata-go does', (_name, type, hex, want) => {
        const rdata = new Uint8Array(Buffer.from(hex, 'hex'));
        expect(rdata_to_string(rdata, type, rdata, 0)).toBe(want);
    });
});
