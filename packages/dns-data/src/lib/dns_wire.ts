// Converting between DNS wire format and string(utf)

export function domain_name2wire(domain_name: string): string {
    var x = "";
    let d = domain_name;
    let l = d.length;

    for (var i = 0, j = 0; i < l;) {
        for (j = i; j < l && d[j] != '.'; ++j) {
            ;
        }

        if (j - i != 0) { // if there is text to copy
            x += String.fromCharCode(j - i); // length
            x += d.substring(i, j).toLowerCase();
        }

        if (j < l) {
            i = j + 1;
            if (i == l) {
                x += String.fromCharCode(0);
            }
        }
        else {
            i = j;
        }
    }
    
    return x;
};

export function wire2domain_name(wire: string): string {
    var x = "";
    let w = wire;
    let l = w.length;

    for (var i = 0; i < l;) {
        let s = w.charCodeAt(i);
        if (s != 0x00) {
            if (i != 0) {
                x += ".";
            }
            ++i;
            x += w.substring(i, i + s);
            i += s;
        }
        else { // terminal dot
            ++i;
            x += ".";
        }
    }
    return x;
};
