// Converting between DNS wire format and string(utf)

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
                bytes.push(d.charCodeAt(k) | 0x20); // lowercase
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
