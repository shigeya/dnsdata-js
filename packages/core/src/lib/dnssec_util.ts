// DNSSEC canonical-name helpers
//
// Ported from dnsdata-go `dnssec/canon.go` (Go → TS feedback channel,
// tracked as UPSTREAM_FEEDBACK.md UP-004 in the Go repo and
// shigeya/dnsdata-js#8 here).
//
// RFC 4034 §6.1 fixes "canonical DNS name order": labels are compared
// right-to-left, case-folded to lower case, and a shorter ordered-prefix
// sorts lower than its extension. The RFC leaves the choice of trailing
// dot up to implementations, so we strip it as decoration: "com." and
// "com" compare equal, and both "" and "." represent the root.

// CompareCanonicalNames returns -1 / 0 / 1 when a sorts before, equal
// to, or after b in canonical-name order.
//
// Examples (RFC 4034 §6.1):
//
//   example       < a.example
//   a.example     < yljkjljk.a.example
//   yljkjljk.a.example < Z.a.example     (case-folded the same)
//   Z.a.example   < zABC.a.EXAMPLE
//   zABC.a.EXAMPLE < z.example
//   z.example     < \001.z.example
//   \001.z.example < *.z.example
//   *.z.example   < \200.z.example
export function compare_canonical_names(a: string, b: string): number {
    const la = canon_labels(a);
    const lb = canon_labels(b);

    // Compare right-to-left (the rightmost label is most significant).
    for (let i = 0; i < la.length && i < lb.length; i++) {
        const ai = la[la.length - 1 - i];
        const bi = lb[lb.length - 1 - i];
        if (ai < bi) return -1;
        if (ai > bi) return 1;
    }
    if (la.length < lb.length) return -1;
    if (la.length > lb.length) return 1;
    return 0;
}

// equal_canonical_names is the allocation-free fast path for the
// "matching denial" case in NSEC lookups, where the question is purely
// "is owner == qname after case folding and trailing-dot stripping?".
export function equal_canonical_names(a: string, b: string): boolean {
    const sa = strip_trailing_dot(a).toLowerCase();
    const sb = strip_trailing_dot(b).toLowerCase();
    return sa === sb;
}

// label_count counts labels in name, excluding the root label. Both
// "example.com." and "example.com" return 2; "." returns 0. Used by
// wildcard handling (RFC 4034 §3.1.3) and ancestor walks.
export function label_count(name: string): number {
    return canon_labels(name).length;
}

// last_n_labels returns the right-most n labels of name as a
// fully-qualified domain name (with trailing dot). Returns "." if n is
// zero or larger than the label count of name.
export function last_n_labels(name: string, n: number): string {
    const labels = canon_labels(name);
    if (n <= 0 || n > labels.length) return '.';
    return labels.slice(labels.length - n).join('.') + '.';
}

// canon_labels splits name on "." after lower-casing and trimming the
// trailing root dot, returning labels left-to-right. An empty name or
// bare "." returns an empty array.
function canon_labels(name: string): string[] {
    const cleaned = strip_trailing_dot(name).toLowerCase();
    if (cleaned === '') return [];
    return cleaned.split('.');
}

function strip_trailing_dot(s: string): string {
    return s.endsWith('.') ? s.slice(0, -1) : s;
}
