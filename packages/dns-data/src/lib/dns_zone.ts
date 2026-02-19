// DNS Zone and Resource Record
//
// Ported from wide-cpp-lib/wide/dns/dns_zone.hpp / dns_zone.cpp

import { WireBuilder } from './dns_wire_util';
import { domain_name2wire } from './dns_wire';
import { StringToRRType, StringToRRClass, RRTypeToString, RRClassToString } from './dns_type_table';

// Type aliases
export type ns_type = number;
export type ns_class = number;

// Handler registry for extensible RR type handling (used by dnssec_rr.ts)
type HandlerFactory = (rr: ResourceRecord, value: string) => ResourceRecordHandler;
const handler_registry = new Map<ns_type, HandlerFactory>();

export function register_rr_handler(type: ns_type, factory: HandlerFactory): void {
    handler_registry.set(type, factory);
}

// Abstract base class for resource record data handlers
export abstract class ResourceRecordHandler {
    protected _rr: ResourceRecord | null;

    constructor(rr: ResourceRecord | null) {
        this._rr = rr;
    }

    get label(): string {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        return this._rr.label;
    }

    get ttl(): number {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        return this._rr.ttl;
    }

    get type(): ns_type {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        return this._rr.type;
    }

    get rrclass(): ns_class {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        return this._rr.rrclass;
    }

    get value(): string {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        return this._rr.value;
    }

    abstract get_wire_body(builder: WireBuilder): void;
    abstract clone(): ResourceRecordHandler;
}

// Parse IPv4 address string to 4 bytes
function parse_ipv4(addr: string): Uint8Array | null {
    const m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return null;
    const bytes = [parseInt(m[1]), parseInt(m[2]), parseInt(m[3]), parseInt(m[4])];
    if (bytes.some(b => b < 0 || b > 255)) return null;
    return new Uint8Array(bytes);
}

// Parse IPv6 address string to 16 bytes
function parse_ipv6(addr: string): Uint8Array | null {
    let groups: string[];

    if (addr.indexOf('::') !== -1) {
        const [left, right] = addr.split('::');
        const left_groups = left ? left.split(':') : [];
        const right_groups = right ? right.split(':') : [];
        const fill_count = 8 - left_groups.length - right_groups.length;
        if (fill_count < 0) return null;
        groups = [...left_groups, ...Array(fill_count).fill('0'), ...right_groups];
    } else {
        groups = addr.split(':');
    }

    if (groups.length !== 8) return null;

    const bytes = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
        const v = parseInt(groups[i], 16);
        if (isNaN(v) || v < 0 || v > 0xffff) return null;
        bytes[i * 2] = (v >> 8) & 0xff;
        bytes[i * 2 + 1] = v & 0xff;
    }
    return bytes;
}

// Parse TXT value: handles quoted strings and bare strings
function parse_txt_value(value: string): string[] {
    const result: string[] = [];
    let i = 0;
    while (i < value.length) {
        // Skip whitespace
        while (i < value.length && /\s/.test(value[i])) i++;
        if (i >= value.length) break;

        if (value[i] === '"') {
            // Quoted string
            i++; // skip opening quote
            let s = '';
            while (i < value.length && value[i] !== '"') {
                if (value[i] === '\\' && i + 1 < value.length) {
                    i++;
                    s += value[i];
                } else {
                    s += value[i];
                }
                i++;
            }
            if (i < value.length) i++; // skip closing quote
            result.push(s);
        } else {
            // Bare string (until whitespace)
            let s = '';
            while (i < value.length && !/\s/.test(value[i])) {
                s += value[i];
                i++;
            }
            result.push(s);
        }
    }
    return result;
}

// Resource Record
export class ResourceRecord {
    readonly label: string;
    readonly ttl: number;
    readonly rrclass: ns_class;
    readonly type: ns_type;
    readonly value: string;
    private handler: ResourceRecordHandler | null = null;

    constructor(label: string, ttl: number, rrclass: string | ns_class, type: string | ns_type, value: string) {
        this.label = label;
        this.ttl = ttl;
        this.rrclass = typeof rrclass === 'string' ? StringToRRClass(rrclass) : rrclass;
        this.type = typeof type === 'string' ? StringToRRType(type) : type;
        this.value = value;
    }

    get_handler(): ResourceRecordHandler | null {
        if (this.handler !== null) return this.handler;

        const factory = handler_registry.get(this.type);
        if (factory) {
            this.handler = factory(this, this.value);
        }
        return this.handler;
    }

    // Wire format: owner_name(wire) + type(2) + class(2)
    get_wire_header(builder: WireBuilder): void {
        const wire_name = domain_name2wire(this.label);
        builder.append_bytes(wire_name);
        builder.append_uint16(this.type);
        builder.append_uint16(this.rrclass);
    }

    // Wire format body: rdlength(2) + rdata
    // Delegates to handler if available, otherwise builds per-type
    get_wire_body(builder: WireBuilder): void {
        const h = this.get_handler();
        if (h !== null) {
            h.get_wire_body(builder);
            return;
        }

        switch (this.type) {
        case 1 /*A*/:       this._wire_body_a(builder); break;
        case 2 /*NS*/:      this._wire_body_ns(builder); break;
        // RFC 1035 §3.3.1: CNAME RDATA = single <domain-name>, same wire format as NS (§3.3.11)
        case 5 /*CNAME*/:   this._wire_body_ns(builder); break;
        case 6 /*SOA*/:     this._wire_body_soa(builder); break;
        // RFC 1035 §3.3.12: PTR RDATA = single <domain-name>, same wire format as NS (§3.3.11)
        case 12 /*PTR*/:    this._wire_body_ns(builder); break;
        case 15 /*MX*/:     this._wire_body_mx(builder); break;
        case 16 /*TXT*/:    this._wire_body_txt(builder); break;
        case 28 /*AAAA*/:   this._wire_body_aaaa(builder); break;
        case 33 /*SRV*/:    this._wire_body_srv(builder); break;
        case 257 /*CAA*/:   this._wire_body_caa(builder); break;
        default: break;
        }
    }

    private _wire_body_a(builder: WireBuilder): void {
        const ip = parse_ipv4(this.value);
        if (!ip) return;
        builder.append_uint16(4);
        builder.append_bytes(ip);
    }

    // RFC 1035: Wire format for single <domain-name> RDATA.
    // Shared by NS (§3.3.11), CNAME (§3.3.1), and PTR (§3.3.12).
    private _wire_body_ns(builder: WireBuilder): void {
        const name = this.value.trim().split(/\s+/)[0];
        const wire = domain_name2wire(name);
        builder.append_uint16(wire.length);
        builder.append_bytes(wire);
    }

    private _wire_body_soa(builder: WireBuilder): void {
        const m = this.value.match(/^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
        if (!m) return;
        const mname_wire = domain_name2wire(m[1]);
        const rname_wire = domain_name2wire(m[2]);
        const rdlen = mname_wire.length + rname_wire.length + 4 * 5;
        builder.append_uint16(rdlen);
        builder.append_bytes(mname_wire);
        builder.append_bytes(rname_wire);
        builder.append_uint32(parseInt(m[3])); // serial
        builder.append_uint32(parseInt(m[4])); // refresh
        builder.append_uint32(parseInt(m[5])); // retry
        builder.append_uint32(parseInt(m[6])); // expire
        builder.append_uint32(parseInt(m[7])); // minimum
    }

    private _wire_body_aaaa(builder: WireBuilder): void {
        const addr = this.value.trim().split(/\s+/)[0];
        const ip = parse_ipv6(addr);
        if (!ip) return;
        builder.append_uint16(16);
        builder.append_bytes(ip);
    }

    // MX: preference(2) + exchange(wire domain name)
    private _wire_body_mx(builder: WireBuilder): void {
        const m = this.value.match(/^(\d+)\s+(\S+)/);
        if (!m) return;
        const preference = parseInt(m[1]);
        const exchange_wire = domain_name2wire(m[2]);
        builder.append_uint16(2 + exchange_wire.length); // rdlength
        builder.append_uint16(preference);
        builder.append_bytes(exchange_wire);
    }

    // TXT: one or more character-strings, each prefixed by length byte
    private _wire_body_txt(builder: WireBuilder): void {
        const strings = parse_txt_value(this.value);
        let total_len = 0;
        const encoded: Uint8Array[] = [];
        for (const s of strings) {
            const bytes = Buffer.from(s, 'utf8');
            // Split into 255-byte chunks
            for (let off = 0; off < bytes.length || (off === 0 && bytes.length === 0); off += 255) {
                const chunk = bytes.slice(off, Math.min(off + 255, bytes.length));
                const entry = new Uint8Array(1 + chunk.length);
                entry[0] = chunk.length;
                entry.set(chunk, 1);
                encoded.push(entry);
                total_len += entry.length;
            }
        }
        builder.append_uint16(total_len);
        for (const e of encoded) {
            builder.append_bytes(e);
        }
    }

    // SRV: priority(2) + weight(2) + port(2) + target(wire domain name)
    private _wire_body_srv(builder: WireBuilder): void {
        const m = this.value.match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)/);
        if (!m) return;
        const priority = parseInt(m[1]);
        const weight = parseInt(m[2]);
        const port = parseInt(m[3]);
        const target_wire = domain_name2wire(m[4]);
        builder.append_uint16(6 + target_wire.length); // rdlength
        builder.append_uint16(priority);
        builder.append_uint16(weight);
        builder.append_uint16(port);
        builder.append_bytes(target_wire);
    }

    // CAA: flags(1) + tag_length(1) + tag + value
    private _wire_body_caa(builder: WireBuilder): void {
        const m = this.value.match(/^(\d+)\s+(\S+)\s+"([^"]*)"/);
        if (!m) return;
        const flags = parseInt(m[1]);
        const tag = Buffer.from(m[2], 'ascii');
        const caa_value = Buffer.from(m[3], 'utf8');
        builder.append_uint16(2 + tag.length + caa_value.length); // rdlength
        builder.append_uint8(flags);
        builder.append_uint8(tag.length);
        builder.append_bytes(tag);
        builder.append_bytes(caa_value);
    }

    to_string(): string {
        return `${this.label} ${this.ttl} ${RRClassToString(this.rrclass)} ${RRTypeToString(this.type)} ${this.value}`;
    }
}

// Zone: collection of resource records with zone file parsing
export class Zone {
    protected records: Map<string, ResourceRecord[]> = new Map();

    private _key(name: string, type: ns_type): string {
        return `${name}\0${type}`;
    }

    add_rr_from_parts(label: string, ttl: number, rrclass: string, type: string, value: string): ResourceRecord {
        const rr = new ResourceRecord(label, ttl, rrclass, type, value);
        return this.add_rr(rr);
    }

    add_rr(rr: ResourceRecord): ResourceRecord {
        const key = this._key(rr.label, rr.type);
        const list = this.records.get(key);
        if (list) {
            list.push(rr);
        } else {
            this.records.set(key, [rr]);
        }
        return rr;
    }

    find_rr(name: string, type: ns_type): ResourceRecord | null {
        const list = this.records.get(this._key(name, type));
        return list && list.length > 0 ? list[0] : null;
    }

    find_rrset(name: string, type: ns_type): ResourceRecord[] {
        return this.records.get(this._key(name, type)) || [];
    }

    // Iterate all records (for searching across types)
    all_records(): ResourceRecord[] {
        const result: ResourceRecord[] = [];
        for (const list of this.records.values()) {
            result.push(...list);
        }
        return result;
    }

    // Qualify a name relative to origin: if name doesn't end with '.', append origin
    private _qualify(name: string, origin: string): string {
        if (name === '@') return origin;
        if (name.endsWith('.')) return name;
        return name + '.' + origin;
    }

    // Parse zone file text
    read_string(text: string): boolean {
        const lines = text.split('\n');
        let continuation = '';
        let prev_label = '';
        let origin = '';
        let default_ttl = 0;

        for (let line of lines) {
            // Strip comments
            line = line.replace(/\s*;.*$/, '');

            // Skip blank lines
            if (/^\s*$/.test(line)) continue;

            // Handle continuation with parentheses
            if (continuation) {
                const close_match = line.match(/^(.*)\)(.*)$/);
                if (close_match) {
                    continuation += ' ' + close_match[1].trim();
                    if (close_match[2].trim()) {
                        continuation += ' ' + close_match[2].trim();
                    }
                    line = continuation;
                    continuation = '';
                } else {
                    continuation += ' ' + line.trim();
                    continue;
                }
            } else {
                const open_match = line.match(/^(.*)\((.*)$/);
                if (open_match) {
                    continuation = open_match[1].trim();
                    if (open_match[2].trim()) {
                        continuation += ' ' + open_match[2].trim();
                    }
                    continue;
                }
            }

            // Handle $ORIGIN directive
            const origin_match = line.match(/^\$ORIGIN\s+(\S+)/i);
            if (origin_match) {
                origin = origin_match[1];
                continue;
            }

            // Handle $TTL directive
            const ttl_match = line.match(/^\$TTL\s+(\d+)/i);
            if (ttl_match) {
                default_ttl = parseInt(ttl_match[1]);
                continue;
            }

            // Supplement label if line starts with whitespace
            if (/^\s+/.test(line)) {
                line = prev_label + line;
            }

            // Try parsing with explicit class: LABEL TTL CLASS TYPE VALUE
            let m = line.match(/^(\S+)\s+(\d+)\s+(IN)\s+(\S+)\s+(.*)$/);
            if (m) {
                const label = origin ? this._qualify(m[1], origin) : m[1];
                this.add_rr_from_parts(label, parseInt(m[2]), m[3], m[4], m[5]);
                prev_label = m[1];
                continue;
            }

            // Try parsing without class: LABEL TTL TYPE VALUE
            m = line.match(/^(\S+)\s+(\d+)\s+(\S+)\s+(.*)$/);
            if (m) {
                const label = origin ? this._qualify(m[1], origin) : m[1];
                this.add_rr_from_parts(label, parseInt(m[2]), 'IN', m[3], m[4]);
                prev_label = m[1];
                continue;
            }

            // Try parsing with $TTL default: LABEL CLASS TYPE VALUE
            if (default_ttl > 0) {
                m = line.match(/^(\S+)\s+(IN)\s+(\S+)\s+(.*)$/);
                if (m) {
                    const label = origin ? this._qualify(m[1], origin) : m[1];
                    this.add_rr_from_parts(label, default_ttl, m[2], m[3], m[4]);
                    prev_label = m[1];
                    continue;
                }

                // LABEL TYPE VALUE (no class, no TTL)
                m = line.match(/^(\S+)\s+(\S+)\s+(.*)$/);
                if (m) {
                    // Only match if the second field looks like an RR type
                    try {
                        StringToRRType(m[2]);
                        const label = origin ? this._qualify(m[1], origin) : m[1];
                        this.add_rr_from_parts(label, default_ttl, 'IN', m[2], m[3]);
                        prev_label = m[1];
                        continue;
                    } catch (_) {
                        // Not a valid type, skip
                    }
                }
            }
        }
        return true;
    }

    print(type?: ns_type): string {
        const lines: string[] = [];
        for (const list of this.records.values()) {
            for (const rr of list) {
                if (type === undefined || rr.type === type) {
                    lines.push(rr.to_string());
                }
            }
        }
        return lines.join('\n');
    }
}
