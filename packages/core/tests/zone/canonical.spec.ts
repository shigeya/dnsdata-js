// Port of dnsdata-go zone/canonical_test.go (UP-012).

import { Zone } from '../../src/zone/dns_zone';
import { compare_canonical_names } from '../../src/zone/canonical';
import { compare_canonical_names as dnssec_compare_canonical_names } from '../../src/dnssec/dnssec_util';
import { StringToRRType } from '../../src/types/dns_type_table';
import { DNSZoneRDataFormatError } from '../../src/dns_exception';

const DETERMINISM_RUNS = 20;

describe('compare_canonical_names', () => {
    it('orders the RFC 4034 §6.1 example', () => {
        // RFC 4034 §6.1 example, in order (escapes omitted).
        const ordered = [
            'example.', 'a.example.', 'yljkjljk.a.example.', 'Z.a.example.',
            'zABC.a.EXAMPLE.', 'z.example.', '*.z.example.',
        ];
        for (let i = 0; i + 1 < ordered.length; i++) {
            expect(compare_canonical_names(ordered[i], ordered[i + 1])).toBeLessThan(0);
            expect(compare_canonical_names(ordered[i + 1], ordered[i])).toBeGreaterThan(0);
        }
    });

    it('ignores case and the trailing dot', () => {
        expect(compare_canonical_names('Example.', 'example')).toBe(0);
    });

    it('sorts the root first', () => {
        expect(compare_canonical_names('.', 'com.')).toBeLessThan(0);
    });

    it('matches the dnssec helper, which delegates to it', () => {
        const names = ['.', 'com.', 'example.', 'a.example.', 'Z.a.example.', '*.z.example.'];
        for (const a of names) {
            for (const b of names) {
                expect(dnssec_compare_canonical_names(a, b)).toBe(compare_canonical_names(a, b));
            }
        }
    });
});

describe('Zone.records_canonical', () => {
    it('orders by owner, type, class and RDATA and drops duplicates', () => {
        const text = `$TTL 60
b.example. A 192.0.2.2
example. NS ns2.example.
a.example. TXT "x"
example. SOA ns1.example. h.example. 1 2 3 4 5
b.example. A 192.0.2.1
example. NS NS1.example.
a.example. A 192.0.2.3
a.example. TYPE65400 \\# 1 00
b.example. A 192.0.2.1
`;
        const z = new Zone();
        z.read_string_strict(text);
        expect(z.print_canonical()).toBe([
            'example. 60 IN NS NS1.example.',
            'example. 60 IN NS ns2.example.',
            'example. 60 IN SOA ns1.example. h.example. 1 2 3 4 5',
            'a.example. 60 IN A 192.0.2.3',
            'a.example. 60 IN TXT "x"',
            'a.example. 60 IN TYPE65400 \\# 1 00',
            'b.example. 60 IN A 192.0.2.1',
            'b.example. 60 IN A 192.0.2.2',
        ].join('\n'));
        expect(z.print_canonical(0)).toBe(z.print_canonical());

        const only_a = z.print_canonical(StringToRRType('A'));
        expect(only_a.split('\n')).toHaveLength(3);
        expect(only_a).not.toContain('NS');
    });

    it('does not depend on insertion order', () => {
        const build = (values: string[]): string => {
            const z = new Zone();
            for (const v of values) {
                z.add_rr_from_parts('x.example.', 60, 'IN', 'A', v);
            }
            z.add_rr_from_parts('y.example.', 60, 'IN', 'A', '192.0.2.1');
            return z.print_canonical();
        };
        const values = ['192.0.2.9', '192.0.2.1', '192.0.2.5'];
        const first = build(values);
        for (let i = 0; i < DETERMINISM_RUNS; i++) {
            expect(build(i % 2 === 0 ? values : [...values].reverse())).toBe(first);
        }
    });

    it('reports a record that does not encode', () => {
        const z = new Zone();
        z.add_rr_from_parts('x.example.', 60, 'IN', 'A', 'not-an-address');
        expect(() => z.records_canonical()).toThrow(DNSZoneRDataFormatError);
    });

    it('returns nothing for an empty zone', () => {
        expect(new Zone().records_canonical()).toEqual([]);
    });

    it('leaves print unchanged', () => {
        const z = new Zone();
        z.add_rr_from_parts('b.example.', 60, 'IN', 'A', '192.0.2.2');
        z.add_rr_from_parts('a.example.', 60, 'IN', 'A', '192.0.2.1');
        expect(z.print()).toBe('b.example. 60 IN A 192.0.2.2\na.example. 60 IN A 192.0.2.1');
    });
});
