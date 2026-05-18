// Tests for DNSSEC canonical-name helpers (UP-004 / #8).

import {
    compare_canonical_names,
    equal_canonical_names,
    label_count,
    last_n_labels,
} from '../../src/dnssec/dnssec_util';

describe('compare_canonical_names', () => {
    // RFC 4034 §6.1 ordering examples.
    const sortedExamples: string[] = [
        'example.',
        'a.example.',
        'yljkjljk.a.example.',
        'Z.a.example.',
        'zABC.a.EXAMPLE.',
        'z.example.',
        '.z.example.',
        '*.z.example.',
        'Ȁ.z.example.',
    ];

    it('matches the RFC 4034 §6.1 ordering', () => {
        for (let i = 0; i + 1 < sortedExamples.length; i++) {
            const lo = sortedExamples[i];
            const hi = sortedExamples[i + 1];
            expect(compare_canonical_names(lo, hi)).toBeLessThan(0);
            expect(compare_canonical_names(hi, lo)).toBeGreaterThan(0);
        }
    });

    it('returns 0 for equal names ignoring case and trailing dot', () => {
        expect(compare_canonical_names('Com.', 'com')).toBe(0);
        expect(compare_canonical_names('example.COM.', 'EXAMPLE.com')).toBe(0);
    });

    it('treats root as the lowest name', () => {
        expect(compare_canonical_names('.', 'com.')).toBeLessThan(0);
        expect(compare_canonical_names('', 'com.')).toBeLessThan(0);
        expect(compare_canonical_names('com.', '.')).toBeGreaterThan(0);
    });

    it('shorter ordered-prefix sorts lower', () => {
        // example. < a.example.
        expect(compare_canonical_names('example.', 'a.example.')).toBeLessThan(0);
    });
});

describe('equal_canonical_names', () => {
    it('ignores case and trailing dot', () => {
        expect(equal_canonical_names('Example.COM.', 'example.com')).toBe(true);
        expect(equal_canonical_names('foo.bar.', 'foo.baz.')).toBe(false);
    });

    it('treats "" and "." as equal (both root)', () => {
        expect(equal_canonical_names('', '.')).toBe(true);
    });
});

describe('label_count', () => {
    it('counts labels excluding root', () => {
        expect(label_count('.')).toBe(0);
        expect(label_count('')).toBe(0);
        expect(label_count('com.')).toBe(1);
        expect(label_count('example.com')).toBe(2);
        expect(label_count('www.example.com.')).toBe(3);
    });
});

describe('last_n_labels', () => {
    it('returns the right-most n labels with trailing dot', () => {
        expect(last_n_labels('www.example.com.', 1)).toBe('com.');
        expect(last_n_labels('www.example.com.', 2)).toBe('example.com.');
        expect(last_n_labels('www.example.com.', 3)).toBe('www.example.com.');
    });

    it('returns "." when n is zero or out of range', () => {
        expect(last_n_labels('www.example.com.', 0)).toBe('.');
        expect(last_n_labels('www.example.com.', 4)).toBe('.');
        expect(last_n_labels('.', 1)).toBe('.');
    });
});
