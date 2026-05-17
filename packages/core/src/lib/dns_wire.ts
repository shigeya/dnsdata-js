// Converting between DNS wire format and string(utf)

// RFC 4034 §6.2 canonical-form: lowercase A-Z only, leave everything else
// (including '_' 0x5F) untouched. The naive `b | 0x20` shortcut also flips
// bit 5 of '_', corrupting it to 0x7F (DEL) and breaking DKIM / DMARC /
// TLSA / MTA-STS lookups that rely on underscore-prefixed labels.
function ascii_to_lower(c: number): number {
    return (c >= 0x41 && c <= 0x5A) ? c + 0x20 : c;
}

export function domain_name2wire(domain_name: string): Uint8Array {
    const bytes: number[] = [];
    const d = domain_name;
    const l = d.length;

    for (let i = 0, j = 0; i < l;) {
        for (j = i; j < l && d[j] != '.'; ++j) {
            ;
        }

        if (j - i != 0) { // if there is text to copy
            bytes.push(j - i); // length
            for (let k = i; k < j; k++) {
                bytes.push(ascii_to_lower(d.charCodeAt(k)));
            }
        }

        if (j < l) {
            i = j + 1;
            if (i == l) {
                bytes.push(0x00);
            }
        }
        else {
            i = j;
        }
    }

    return new Uint8Array(bytes);
}

export function wire2domain_name(wire: Uint8Array): string {
    let x = "";
    const l = wire.length;

    for (let i = 0; i < l;) {
        const s = wire[i];
        if (s != 0x00) {
            if (i != 0) {
                x += ".";
            }
            ++i;
            for (let k = 0; k < s; k++) {
                x += String.fromCharCode(wire[i + k]);
            }
            i += s;
        }
        else { // terminal dot
            ++i;
            x += ".";
        }
    }
    return x;
}
