// Domain-name helpers of the in-memory authority (dnsdata-go
// `resolver/memory/index.go` normalize / labels / isAtOrBelow / parent /
// wildcardOf / nextCloser). Every name here is normalized: lower-cased
// and fully qualified.

// normalize lower-cases name and makes it fully qualified.
export function normalize(name: string): string {
    const trimmed = name.trim().toLowerCase();
    return trimmed.endsWith('.') ? trimmed : trimmed + '.';
}

// labels returns name's labels, left-most first; the root has none.
export function labels(name: string): string[] {
    const trimmed = name.endsWith('.') ? name.slice(0, -1) : name;
    return trimmed === '' ? [] : trimmed.split('.');
}

// is_at_or_below reports whether name equals ancestor or descends from
// it. Both must be normalized.
export function is_at_or_below(name: string, ancestor: string): boolean {
    const n = labels(name);
    const a = labels(ancestor);
    if (n.length < a.length) return false;
    const tail = n.slice(n.length - a.length);
    return tail.every((label, i) => label === a[i]);
}

// parent returns the name one label shorter; the root is its own parent.
export function parent(name: string): string {
    const l = labels(name);
    return l.length <= 1 ? '.' : l.slice(1).join('.') + '.';
}

// wildcard_of returns `*.<name>`.
export function wildcard_of(name: string): string {
    return name === '.' ? '*.' : '*.' + name;
}

// next_closer returns the ancestor of name one label below ce.
export function next_closer(name: string, ce: string): string {
    const l = labels(name);
    const keep = labels(ce).length + 1;
    return l.slice(l.length - keep).join('.') + '.';
}
