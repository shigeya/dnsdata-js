// Port of dnsdata-go zone/strict_test.go (UP-011). Handlers are
// registered by tests/jest.setup.ts (TLSA needs its handler).

import { Zone } from '../../src/zone/dns_zone';
import { WireBuilder } from '../../src/wire/dns_wire_util';
import { StringToRRType, RRTypeName } from '../../src/types/dns_type_table';
import {
    DNSZoneParseError,
    DNSZonePresentationFormatError,
    DNSZoneRDataFormatError,
} from '../../src/dns_exception';

const TYPE_UNKNOWN = 65400;

function catch_error(fn: () => void): unknown {
    try {
        fn();
    } catch (e) {
        return e;
    }
    return undefined;
}

describe('Zone.read_string_strict', () => {
    it('accepts a well-formed zone', () => {
        const text = `$ORIGIN example.test.
$TTL 3600
@        IN  SOA ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300
@           NS  ns1.example.test.
ns1      60 IN A 192.0.2.1
         IN 60 AAAA 2001:db8::1   ; class before TTL, inherited owner
key      TYPE65400 \\# 4 ( 0102
                         0304 )
txt      CLASS1 TXT "a;b" "c"      ; semicolon inside quotes is data
_443._tcp TLSA 3 1 1 00112233
`;
        const z = new Zone();
        z.read_string_strict(text);

        const checks: Array<[string, number, number, string]> = [
            ['example.test.', StringToRRType('SOA'), 3600,
                'ns1.example.test. hostmaster.example.test. 1 7200 3600 1209600 300'],
            ['example.test.', StringToRRType('NS'), 3600, 'ns1.example.test.'],
            ['ns1.example.test.', StringToRRType('A'), 60, '192.0.2.1'],
            ['ns1.example.test.', StringToRRType('AAAA'), 60, '2001:db8::1'],
            ['key.example.test.', TYPE_UNKNOWN, 3600, '\\# 4 0102 0304'],
            ['txt.example.test.', StringToRRType('TXT'), 3600, '"a;b" "c"'],
            ['_443._tcp.example.test.', StringToRRType('TLSA'), 3600, '3 1 1 00112233'],
        ];
        for (const [name, type, ttl, value] of checks) {
            const rr = z.find_rr(name, type);
            expect({ name, type: RRTypeName(type), found: rr !== null }).toEqual(
                { name, type: RRTypeName(type), found: true });
            expect(rr?.ttl).toBe(ttl);
            expect(rr?.value).toBe(value);
        }
        expect(z.find_rr('txt.example.test.', StringToRRType('TXT'))?.txt_strings()).toEqual(['a;b', 'c']);
    });

    const error_cases: Array<[string, string, number]> = [
        ['unknown type', '$ORIGIN example.test.\n$TTL 60\nok A 192.0.2.1\nbad NOSUCHTYPE 1 2 3\n', 4],
        ['generic length mismatch', '$TTL 60\nx.example. TYPE65400 \\# 3 0102\n', 2],
        ['relative owner without origin', '$TTL 60\nx A 192.0.2.1\n', 2],
        ['missing TTL', 'x.example. A 192.0.2.1\n', 1],
        ['malformed rdata', '$TTL 60\nx.example. A not-an-address\n', 2],
        ['missing rdata', '$TTL 60\nx.example. A\n', 2],
        ['type without encoder', '$TTL 60\nx.example. OPT 00\n', 2],
        ['unsupported directive', '$INCLUDE other.zone\n', 1],
        ['inherited owner with none before', '$TTL 60\n  A 192.0.2.1\n', 2],
        ['unclosed parenthesis', '$TTL 60\nx.example. TXT ( "a"\n"b"\n', 2],
        ['bad TTL directive', '$TTL forever\n', 1],
        ['bad owner', '$TTL 60\nx..example. A 192.0.2.1\n', 2],
    ];
    it.each(error_cases)('rejects: %s', (_name, text, want_line) => {
        const z = new Zone();
        const err = catch_error(() => z.read_string_strict(text));
        expect(err).toBeInstanceOf(DNSZoneParseError);
        const pe = err as DNSZoneParseError;
        expect(pe.line).toBe(want_line);
        expect(pe.cause instanceof DNSZonePresentationFormatError
            || pe.cause instanceof DNSZoneRDataFormatError).toBe(true);
        expect(pe.message).toMatch(new RegExp(`^zone line ${want_line}: `));
    });

    it('reports a record without encoder as an RDATA error', () => {
        const err = catch_error(() => new Zone().read_string_strict('$TTL 60\nx.example. OPT 00\n'));
        expect((err as DNSZoneParseError).cause).toBeInstanceOf(DNSZoneRDataFormatError);
    });

    it('leaves the zone untouched on error', () => {
        const z = new Zone();
        z.add_rr_from_parts('keep.example.', 60, 'IN', 'A', '192.0.2.9');
        expect(() => z.read_string_strict('$TTL 60\nnew.example. A 192.0.2.1\nbad.example. NOPE x\n'))
            .toThrow(DNSZoneParseError);
        expect(z.all_records()).toHaveLength(1);
    });
});

describe('Zone.read_string (lenient)', () => {
    // The lenient reader keeps dropping the same line silently (existing
    // behaviour); the strict reader is what surfaces it.
    it('still skips an unknown type', () => {
        const z = new Zone();
        expect(z.read_string('$TTL 60\nbad.example. NOPE x\nok.example. A 192.0.2.1\n')).toBe(true);
        expect(z.all_records()).toHaveLength(1);
    });

    it('accepts a generic type', () => {
        const z = new Zone();
        z.read_string('$TTL 60\nkey.example. TYPE65400 \\# 2 abcd\n');
        const rr = z.find_rr('key.example.', TYPE_UNKNOWN);
        expect(rr).not.toBeNull();
        const b = new WireBuilder();
        rr?.get_wire_body(b);
        expect(b.length).toBe(4);
    });
});
