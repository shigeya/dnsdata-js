// Domain-name helpers of the zone signer (dnsdata-go
// `dnssec/signer/nsec.go` labelsOf / isAtOrBelow / sameName and
// `sign.go` rrsigLabels).

// labels_of returns name's labels, lower-cased, right-most last; the
// root has none.
export function labels_of(name: string): string[] {
    const trimmed = (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();
    return trimmed === '' ? [] : trimmed.split('.');
}

// is_at_or_below reports whether name equals ancestor or is a
// descendant of it.
export function is_at_or_below(name: string, ancestor: string): boolean {
    const n = labels_of(name);
    const a = labels_of(ancestor);
    if (n.length < a.length) return false;
    const tail = n.slice(n.length - a.length);
    return tail.every((label, i) => label === a[i]);
}

// same_name reports whether a and b are the same name, ignoring case
// and the trailing dot.
export function same_name(a: string, b: string): boolean {
    const la = labels_of(a);
    const lb = labels_of(b);
    return la.length === lb.length && la.every((label, i) => label === lb[i]);
}

// is_fqdn reports whether name ends with the root dot.
export function is_fqdn(name: string): boolean {
    return name.endsWith('.');
}

// rrsig_labels is the RRSIG Labels field for owner (RFC 4034 §3.1.3):
// the label count without the root, and without a leading wildcard.
// Unlike the dot-counting RRSig signing constructor, it is right for the
// root (0) and for wildcard owners.
export function rrsig_labels(owner: string): number {
    const labels = labels_of(owner);
    return labels.length > 0 && labels[0] === '*' ? labels.length - 1 : labels.length;
}
