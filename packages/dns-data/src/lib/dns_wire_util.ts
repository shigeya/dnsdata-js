// Wire format buffer builder utility

export class WireBuilder {
    private buf: number[] = [];

    get length(): number {
        return this.buf.length;
    }

    append_uint8(v: number): void {
        this.buf.push(v & 0xff);
    }

    append_uint16(v: number): void {
        this.buf.push((v >> 8) & 0xff);
        this.buf.push(v & 0xff);
    }

    append_uint32(v: number): void {
        this.buf.push((v >> 24) & 0xff);
        this.buf.push((v >> 16) & 0xff);
        this.buf.push((v >> 8) & 0xff);
        this.buf.push(v & 0xff);
    }

    append_bytes(v: Uint8Array): void {
        for (let i = 0; i < v.length; i++) {
            this.buf.push(v[i]);
        }
    }

    build(): Uint8Array {
        return new Uint8Array(this.buf);
    }
}

export function compare_uint8arrays(a: Uint8Array, b: Uint8Array): number {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
}
