// RFC 4034 §6 canonical ordering helpers.
//
// Ports dnsdata-go `zone/canonical.go` (UP-012). The Zone methods that
// use these helpers (records_canonical, print_canonical) live in
// dns_zone.ts; this module stays free of zone imports so that both
// dns_zone.ts and dnssec/dnssec_util.ts can depend on it without an
// import cycle.

import { compare_uint8arrays } from '../wire/dns_wire_util';

// compare_canonical_names compares a and b in DNSSEC canonical name
// order (RFC 4034 §6.1): labels compared right to left, case-folded to
// lower case, a name sorting before its own descendants. The trailing
// dot is optional; "" and "." both mean the root. Returns -1, 0 or 1.
export function compare_canonical_names(a: string, b: string): number {
    const la = canonical_labels(a);
    const lb = canonical_labels(b);
    for (let i = 0; i < la.length && i < lb.length; i++) {
        const c = compare_values(la[la.length - 1 - i], lb[lb.length - 1 - i]);
        if (c !== 0) return c;
    }
    return compare_values(la.length, lb.length);
}

// canonical_labels lower-cases name and splits it into labels, left-most
// first. The root yields no labels.
function canonical_labels(name: string): string[] {
    const trimmed = (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();
    return trimmed === '' ? [] : trimmed.split('.');
}

function compare_values<T extends string | number>(a: T, b: T): number {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

// CanonicalEntry is the sort key of one record: owner, type, class and
// the RDATA octets (without the RDLENGTH prefix).
export interface CanonicalEntry {
    readonly label: string;
    readonly type: number;
    readonly rrclass: number;
    readonly rdata: Uint8Array;
}

// compare_canonical_entries orders records per RFC 4034 §6: owner name
// (§6.1), then type, then class, then the canonical RDATA octets (§6.3).
// Returns 0 exactly for duplicates in the §6.3 sense.
export function compare_canonical_entries(a: CanonicalEntry, b: CanonicalEntry): number {
    return compare_canonical_names(a.label, b.label)
        || compare_values(a.type, b.type)
        || compare_values(a.rrclass, b.rrclass)
        || Math.sign(compare_uint8arrays(a.rdata, b.rdata));
}

// sort_canonical returns entries in canonical order with exact
// duplicates removed (the first of each run is kept). The input array is
// not modified.
export function sort_canonical<T extends CanonicalEntry>(entries: readonly T[]): T[] {
    const sorted = [...entries].sort(compare_canonical_entries);
    return sorted.filter((e, i) => i === 0 || compare_canonical_entries(sorted[i - 1], e) !== 0);
}
