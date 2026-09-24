// Strict RFC 1035 master-file reader.
//
// Ports dnsdata-go `zone/strict.go` (UP-011). Zone.read_string_strict in
// dns_zone.ts drives parse_zone_strict; this module stays free of zone
// imports (the caller builds each record) so that dns_zone.ts can depend
// on it without an import cycle.

import { domain_name2wire } from '../wire/dns_wire';
import { WireBuilder } from '../wire/dns_wire_util';
import { StringToRRType, StringToRRClass, RRTypeName } from '../types/dns_type_table';
import {
    DNSZoneParseError,
    DNSZonePresentationFormatError,
    DNSZoneRDataFormatError,
} from '../dns_exception';

const CLASS_IN = 1;
const MAX_UINT32 = 0xFFFFFFFF;
// A logical line may start with at most TTL and class, in either order.
const MAX_TTL_CLASS_FIELDS = 2;

// StrictRecordParts is one parsed record before it becomes a
// ResourceRecord: an absolute owner and numeric TTL / class / type.
export interface StrictRecordParts {
    readonly label: string;
    readonly ttl: number;
    readonly rrclass: number;
    readonly type: number;
    readonly value: string;
}

// WireEncodable is the part of ResourceRecord the encode check needs.
export interface WireEncodable {
    readonly type: number;
    get_wire_body(builder: WireBuilder): void;
}

// parse_zone_strict parses master-file text, calling build for every
// record and encoding the result once as a check. It returns the built
// records in file order, or throws DNSZoneParseError for the first line
// it rejects. See Zone.read_string_strict for the accepted syntax.
export function parse_zone_strict<T extends WireEncodable>(
    text: string, build: (parts: StrictRecordParts) => T): T[] {
    const state = new StrictState();
    const out: T[] = [];
    for (const ll of strict_logical_lines(text)) {
        try {
            const parts = state.parse(ll);
            if (parts !== null) {
                const rr = build(parts);
                check_encodes(rr);
                out.push(rr);
            }
        } catch (e) {
            throw new DNSZoneParseError(ll.num, ll.text, as_zone_error(e));
        }
    }
    return out;
}

// LogicalLine is one record or directive after comment removal and
// parenthesis joining.
interface LogicalLine {
    readonly num: number;       // first physical line, 1-based
    readonly text: string;      // joined text, parentheses removed, trimmed
    readonly inherits: boolean; // first physical line starts with a blank: owner is inherited
}

// strict_logical_lines strips comments and joins parenthesised
// continuations. Quotes protect `;`, `(` and `)`.
function strict_logical_lines(text: string): LogicalLine[] {
    const out: LogicalLine[] = [];
    let cur: { num: number; text: string; inherits: boolean } | null = null;
    let depth = 0;
    const raws = text.split('\n');
    for (let i = 0; i < raws.length; i++) {
        const raw = raws[i];
        const stripped = strip_strict_line(raw, depth, i + 1);
        depth = stripped.depth;
        if (cur === null) {
            if (stripped.body.trim() === '') continue;
            cur = { num: i + 1, text: '', inherits: raw[0] === ' ' || raw[0] === '\t' };
        }
        cur.text += ' ' + stripped.body;
        if (depth === 0) {
            out.push({ ...cur, text: cur.text.trim() });
            cur = null;
        }
    }
    if (cur !== null) {
        throw new DNSZoneParseError(cur.num, cur.text,
            new DNSZonePresentationFormatError('unclosed parenthesis'));
    }
    return out;
}

// strip_strict_line removes a trailing comment and the parentheses from
// one physical line, returning the new parenthesis depth.
function strip_strict_line(line: string, depth: number, num: number): { body: string; depth: number } {
    let body = '';
    let in_quote = false;
    for (let i = 0; i < line.length; i++) {
        let c = line[i];
        if (c === '\\' && i + 1 < line.length) {
            body += c;
            i++;
            c = line[i];
        } else if (c === '"') {
            in_quote = !in_quote;
        } else if (!in_quote && c === ';') {
            return { body, depth };
        } else if (!in_quote && (c === '(' || c === ')')) {
            depth += c === '(' ? 1 : -1;
            if (depth < 0) {
                throw new DNSZoneParseError(num, line,
                    new DNSZonePresentationFormatError("unbalanced ')'"));
            }
            c = ' ';
        }
        body += c;
    }
    return { body, depth };
}

// StrictState carries the directives and inherited owner across lines.
class StrictState {
    private origin = '';
    private default_ttl = 0;
    private has_ttl = false;
    private prev_owner = '';

    // parse handles one logical line. It returns null for a directive.
    parse(ll: LogicalLine): StrictRecordParts | null {
        if (!ll.inherits && ll.text.startsWith('$')) {
            this.directive(ll.text);
            return null;
        }
        let spans = field_spans(ll.text);
        let owner = this.prev_owner;
        if (!ll.inherits) {
            owner = this.qualify(ll.text.slice(spans[0][0], spans[0][1]));
            spans = spans.slice(1);
        }
        if (owner === '') {
            throw new DNSZonePresentationFormatError('no owner to inherit');
        }
        const parts = this.record(owner, ll.text, spans);
        this.prev_owner = owner;
        return parts;
    }

    private directive(text: string): void {
        const fields = text.split(/\s+/);
        switch (fields[0].toUpperCase()) {
        case '$ORIGIN':
            if (fields.length !== 2 || !fields[1].endsWith('.')) {
                throw new DNSZonePresentationFormatError('$ORIGIN needs one absolute name');
            }
            this.origin = fields[1];
            return;
        case '$TTL': {
            if (fields.length !== 2) {
                throw new DNSZonePresentationFormatError('$TTL needs one value');
            }
            const ttl = parse_uint32(fields[1]);
            if (ttl === null) {
                throw new DNSZonePresentationFormatError(`$TTL "${fields[1]}"`);
            }
            this.default_ttl = ttl;
            this.has_ttl = true;
            return;
        }
        default:
            throw new DNSZonePresentationFormatError(`unsupported directive ${fields[0]}`);
        }
    }

    // qualify turns an owner token into an absolute name and checks that
    // it encodes.
    private qualify(token: string): string {
        const name = this.absolute(token);
        if (name !== '.' && name.slice(0, -1).split('.').includes('')) {
            throw new DNSZonePresentationFormatError(`owner "${name}" has an empty label`);
        }
        try {
            domain_name2wire(name);
        } catch (e) {
            throw new DNSZonePresentationFormatError(`owner "${name}": ${error_message(e)}`);
        }
        return name;
    }

    private absolute(token: string): string {
        if (token === '@') {
            if (this.origin === '') {
                throw new DNSZonePresentationFormatError('@ without $ORIGIN');
            }
            return this.origin;
        }
        if (token.endsWith('.')) return token;
        if (this.origin === '') {
            throw new DNSZonePresentationFormatError(`relative owner "${token}" without $ORIGIN`);
        }
        return this.origin === '.' ? token + '.' : token + '.' + this.origin;
    }

    // record parses `[ttl] [class] type rdata` (TTL and class in either
    // order) from the fields at spans.
    private record(owner: string, text: string, spans: ReadonlyArray<readonly [number, number]>): StrictRecordParts {
        let ttl = this.default_ttl;
        let has_ttl = this.has_ttl;
        let rrclass = CLASS_IN;
        let i = 0;
        for (; i < spans.length && i < MAX_TTL_CLASS_FIELDS; i++) {
            const tok = text.slice(spans[i][0], spans[i][1]);
            const n = parse_uint32(tok);
            if (n !== null) {
                ttl = n;
                has_ttl = true;
                continue;
            }
            const c = try_class(tok);
            if (c === null) break;
            rrclass = c;
        }
        if (i >= spans.length) {
            throw new DNSZonePresentationFormatError('missing type');
        }
        const type = parse_type(text.slice(spans[i][0], spans[i][1]));
        if (!has_ttl) {
            throw new DNSZonePresentationFormatError('no TTL and no $TTL');
        }
        const value = collapse_blanks(text.slice(spans[i][1]));
        if (value === '') {
            throw new DNSZonePresentationFormatError('missing RDATA');
        }
        return { label: owner, ttl, rrclass, type, value };
    }
}

function parse_uint32(tok: string): number | null {
    if (!/^[0-9]+$/.test(tok)) return null;
    const n = Number(tok);
    return n <= MAX_UINT32 ? n : null;
}

function try_class(tok: string): number | null {
    try {
        return StringToRRClass(tok);
    } catch {
        return null;
    }
}

function parse_type(tok: string): number {
    try {
        return StringToRRType(tok);
    } catch (e) {
        throw new DNSZonePresentationFormatError(error_message(e));
    }
}

// field_spans returns the [start, end) offsets of the blank-separated
// fields of s. Only the leading owner / TTL / class / type fields are
// read through it; the RDATA is taken as the rest of the text.
function field_spans(s: string): Array<[number, number]> {
    const out: Array<[number, number]> = [];
    let start = -1;
    for (let i = 0; i <= s.length; i++) {
        const blank = i === s.length || s[i] === ' ' || s[i] === '\t';
        if (blank && start >= 0) {
            out.push([start, i]);
            start = -1;
        } else if (!blank && start < 0) {
            start = i;
        }
    }
    return out;
}

// collapse_blanks trims s and turns every run of blanks outside double
// quotes into one space.
function collapse_blanks(s: string): string {
    let out = '';
    let in_quote = false;
    let pending_space = false;
    for (let i = 0; i < s.length; i++) {
        let c = s[i];
        if (!in_quote && (c === ' ' || c === '\t')) {
            pending_space = out.length > 0;
            continue;
        }
        if (pending_space) {
            out += ' ';
            pending_space = false;
        }
        if (c === '\\' && i + 1 < s.length) {
            out += c;
            i++;
            c = s[i];
        } else if (c === '"') {
            in_quote = !in_quote;
        }
        out += c;
    }
    return out;
}

// check_encodes encodes rr once; an error or an empty encoding (no
// encoder for the type) rejects the record.
function check_encodes(rr: WireEncodable): void {
    const builder = new WireBuilder();
    try {
        rr.get_wire_body(builder);
    } catch (e) {
        if (e instanceof DNSZonePresentationFormatError || e instanceof DNSZoneRDataFormatError) throw e;
        throw new DNSZoneRDataFormatError(error_message(e));
    }
    if (builder.length === 0) {
        throw new DNSZoneRDataFormatError(
            `no encoder for type ${RRTypeName(rr.type)} (register handlers or use the \\# form)`);
    }
}

// as_zone_error keeps the two zone error categories and folds anything
// else into DNSZonePresentationFormatError.
function as_zone_error(e: unknown): DNSZonePresentationFormatError | DNSZoneRDataFormatError {
    if (e instanceof DNSZonePresentationFormatError || e instanceof DNSZoneRDataFormatError) return e;
    return new DNSZonePresentationFormatError(error_message(e));
}

function error_message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
}
