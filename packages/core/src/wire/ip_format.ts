// Presentation strings for IP address octets, shared by the RDATA
// decoders (AAAA, SVCB ipv4hint / ipv6hint).

export const IPV4_LENGTH = 4;
export const IPV6_LENGTH = 16;

// format_ipv4 writes 4 octets as a dotted quad.
export function format_ipv4(b: Uint8Array): string {
    return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

// format_ipv6 writes 16 octets in RFC 5952 style, as Go's
// net.IP.String() does for an address that is not IPv4-mapped.
export function format_ipv6(b: Uint8Array): string {
    const groups: string[] = [];
    for (let i = 0; i < IPV6_LENGTH; i += 2) {
        groups.push(((b[i] << 8) | b[i + 1]).toString(16));
    }
    return collapse_ipv6(groups);
}

// is_ipv4_mapped reports whether 16 octets are ::ffff:a.b.c.d.
export function is_ipv4_mapped(b: Uint8Array): boolean {
    for (let i = 0; i < 10; i++) {
        if (b[i] !== 0) return false;
    }
    return b[10] === 0xff && b[11] === 0xff;
}

// RFC 5952-style IPv6 string: collapse the longest run of consecutive
// `0` groups to `::`. Single-zero runs are NOT collapsed (RFC 5952
// §4.2.2). Matches Go's net.IP.To16().String() output for well-formed
// inputs.
function collapse_ipv6(groups: string[]): string {
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < groups.length; i++) {
        if (groups[i] === '0') {
            if (curStart < 0) curStart = i;
            curLen++;
            if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
        } else {
            curStart = -1; curLen = 0;
        }
    }
    if (bestLen < 2) return groups.join(':');
    const head = groups.slice(0, bestStart).join(':');
    const tail = groups.slice(bestStart + bestLen).join(':');
    return `${head}::${tail}`;
}
