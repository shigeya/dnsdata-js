// DNS Zone and Resource Record
//
// Ported from wide-cpp-lib/wide/dns/dns_zone.hpp / dns_zone.cpp

import { WireBuilder } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { rdata_to_string, format_generic_rdata } from '../wire/rdata_decoder';
import { StringToRRType, StringToRRClass, RRTypeName, RRClassName } from '../types/dns_type_table';
import { DNSZoneRDataFormatError } from '../dns_exception';
import {
    GENERIC_RDATA_MARKER,
    MAX_RDATA_LENGTH,
    parse_generic_rdata,
    split_character_strings,
} from './generic';
import { parse_zone_strict } from './strict';
import { sort_canonical } from './canonical';
import { Registry, default_registry, type HandlerFactory } from './registry';

// Type aliases
export type ns_type = number;
export type ns_class = number;

const TYPE_TXT    = 16;

// Octets of RDLENGTH in front of the RDATA written by get_wire_body.
const RDLENGTH_OCTETS = 2;

// Handler registries for extensible RR type handling (see registry.ts).
export {
    Registry, default_registry, register_rr_handler,
    type HandlerFactory, type HandlerRDataFactory,
} from './registry';

// The handler cached on a ResourceRecord, with the Registry that built it.
interface HandlerEntry {
    registry: Registry;
    handler: ResourceRecordHandler;
}

// RR types that ResourceRecord encodes inline (no separate handler).
// Mirrors the switch in `get_wire_body` and powers `has_encoder`.
const BUILTIN_ENCODER_TYPES: ReadonlySet<ns_type> = new Set<ns_type>([
    1,   // A
    2,   // NS
    5,   // CNAME
    6,   // SOA
    12,  // PTR
    15,  // MX
    16,  // TXT
    28,  // AAAA
    33,  // SRV
    39,  // DNAME
    257, // CAA
]);

// True if this type has an encoder available — either a handler in
// registry (default: default_registry()) or one of the built-in
// `_wire_body_*` methods. Lets callers tell "encoder missing for this
// type" apart from "encoder threw on malformed RDATA" (the latter now
// surfaces as DNSZoneRDataFormatError).
export function has_encoder(type: ns_type, registry: Registry = default_registry()): boolean {
    return registry.lookup(type) !== undefined || BUILTIN_ENCODER_TYPES.has(type);
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

    // The presentation value this handler was parsed from. Differs from
    // value when the record holds RFC 3597 generic RDATA, so clone()
    // re-parses this rather than value.
    protected get source_value(): string {
        if (!this._rr) throw new Error("No parent ResourceRecord");
        const v = this._rr.handler_value();
        if (v === null) {
            throw new DNSZoneRDataFormatError(`no presentation form for ${RRTypeName(this._rr.type)}`);
        }
        return v;
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

function is_txt_space(ch: string): boolean {
    return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
}

// Returns the UTF-8 octets of the character at value[i] and its length
// in UTF-16 code units.
function char_octets(value: string, i: number): [Uint8Array, number] {
    const ch = String.fromCodePoint(value.codePointAt(i) ?? 0);
    return [Buffer.from(ch, 'utf8'), ch.length];
}

// Decodes the escape after a backslash at value[i]: three decimal digits
// are one octet (\DDD), anything else is taken literally. Returns the
// octets and the number of code units consumed.
function parse_txt_escape(value: string, i: number): [Uint8Array, number] {
    const ddd = value.substring(i, i + 3);
    if (/^\d{3}$/.test(ddd)) {
        const v = parseInt(ddd, 10);
        if (v > 255) throw new DNSZoneRDataFormatError(`\\${ddd} is not an octet`);
        return [Uint8Array.of(v), 3];
    }
    return char_octets(value, i);
}

// Tokenises a TXT presentation value into character-strings as octets:
// quoted strings and bare whitespace-delimited tokens, both with
// RFC 1035 §5.1 escapes (\DDD is one octet, \X is X). Matches
// dnsdata-go parseTXTValue. Throws DNSZoneRDataFormatError for a \DDD
// above 255.
function parse_txt_value(value: string): Uint8Array[] {
    const result: Uint8Array[] = [];
    let i = 0;
    while (i < value.length) {
        while (i < value.length && is_txt_space(value[i])) i++;
        if (i >= value.length) break;
        const quoted = value[i] === '"';
        if (quoted) i++;
        const octets: number[] = [];
        while (i < value.length) {
            const ch = value[i];
            if (quoted ? ch === '"' : is_txt_space(ch)) break;
            const [bytes, width] = ch === '\\' && i + 1 < value.length
                ? parse_txt_escape(value, i + 1)
                : char_octets(value, i);
            octets.push(...bytes);
            i += ch === '\\' && i + 1 < value.length ? 1 + width : width;
        }
        if (quoted && i < value.length) i++; // closing quote
        result.push(Uint8Array.from(octets));
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
    // See get_handler: one entry, tied to the registry that built it.
    private handler_entry: HandlerEntry | null = null;
    // The RDATA as received; see new_resource_record_with_rdata.
    private readonly received_rdata: Uint8Array | null;

    // rdata, when given, is the RDATA the record was read off the wire
    // as (copied); get_wire_body falls back to it. Prefer
    // new_resource_record_with_rdata, which checks its length.
    constructor(label: string, ttl: number, rrclass: string | ns_class, type: string | ns_type, value: string,
                rdata?: Uint8Array) {
        this.label = label;
        this.ttl = ttl;
        this.rrclass = typeof rrclass === 'string' ? StringToRRClass(rrclass) : rrclass;
        this.type = typeof type === 'string' ? StringToRRType(type) : type;
        this.value = value;
        this.received_rdata = rdata === undefined ? null : Uint8Array.from(rdata);
    }

    // Returns the type-specific handler built by registry's factory
    // (default: default_registry()), constructing it on first access, or
    // null when registry has no factory for the type.
    //
    // A value in RFC 3597 generic form (`\# <len> <hex>`) is decoded from
    // its octets by type, so a known type received as generic RDATA still
    // yields its structured handler (null when the octets do not decode).
    //
    // The handler is cached on the record together with the registry
    // that built it, and the cache is only returned for that same
    // registry: a record shared between users of different registries
    // (two Verifiers sharing one cache, say) never hands one registry's
    // handler to the other. The cache holds one entry; alternating
    // registries rebuild the handler.
    get_handler(registry: Registry = default_registry()): ResourceRecordHandler | null {
        const cached = this.handler_entry;
        if (cached !== null && cached.registry === registry) return cached.handler;

        const factory = registry.lookup(this.type);
        if (!factory) return null;

        let raw: Uint8Array | null;
        try {
            raw = this.generic_rdata();
        } catch {
            return null;
        }
        const handler = raw === null ? factory(this, this.value) : this._handler_from_generic(registry, factory, raw);
        if (handler === null) return null;
        this.handler_entry = { registry, handler };
        return handler;
    }

    // Returns the RDATA octets when value is in the RFC 3597 generic form,
    // null for any other value. Throws DNSZonePresentationFormatError for
    // malformed generic RDATA.
    generic_rdata(): Uint8Array | null {
        return parse_generic_rdata(this.value);
    }

    // Returns the character-strings of a TXT record, whether its value is
    // in presentation form or in RFC 3597 generic form.
    txt_strings(): string[] {
        if (this.type !== TYPE_TXT) {
            throw new DNSZoneRDataFormatError(`txt_strings on type ${RRTypeName(this.type)}`);
        }
        const raw = this.generic_rdata();
        if (raw !== null) return split_character_strings(raw);
        return parse_txt_value(this.value).map(s => Buffer.from(s).toString('utf8'));
    }

    // Returns the presentation value a handler factory parses: value
    // itself, or for a value in RFC 3597 generic form the presentation
    // decoded from its octets by type. Null when the octets have no
    // presentation form for this type. Throws for malformed generic RDATA.
    handler_value(): string | null {
        const raw = this.generic_rdata();
        return raw === null ? this.value : this._presentation_from_generic(raw);
    }

    private _presentation_from_generic(rdata: Uint8Array): string | null {
        const pres = rdata_to_string(rdata, this.type, rdata, 0);
        return pres.startsWith(GENERIC_RDATA_MARKER) ? null : pres;
    }

    // Builds the handler for a record held in generic form. Only consulted
    // when a factory is registered for the type, so handler registration
    // stays opt-in. Returns null when the octets do not decode.
    private _handler_from_generic(registry: Registry, factory: HandlerFactory,
                                  rdata: Uint8Array): ResourceRecordHandler | null {
        try {
            const rdata_factory = registry.lookup_rdata(this.type);
            if (rdata_factory) return rdata_factory(this, rdata);
            const pres = this._presentation_from_generic(rdata);
            return pres === null ? null : factory(this, pres);
        } catch {
            return null;
        }
    }

    // Wire format: owner_name(wire) + type(2) + class(2)
    get_wire_header(builder: WireBuilder): void {
        const wire_name = domain_name2wire(this.label);
        builder.append_bytes(wire_name);
        builder.append_uint16(this.type);
        builder.append_uint16(this.rrclass);
    }

    // Wire format body: rdlength(2) + rdata
    // Delegates to handler if available, otherwise builds per-type.
    //
    // A value in RFC 3597 generic form is written verbatim for any type,
    // ahead of any handler, so its octets (and hence its canonical form)
    // never pass through a re-encoding. Malformed generic RDATA throws
    // DNSZonePresentationFormatError.
    //
    // For types without a built-in or registered encoder, a record built
    // with new_resource_record_with_rdata writes the octets it was
    // received as; any other record writes nothing. The fallback serves
    // the types whose RDATA holds no compressible or case-folded names
    // (TLSA, SMIMEA, SVCB, HTTPS, ...), so the received octets are their
    // canonical form (RFC 4034 §6.2, RFC 3597 §4); the types that hold
    // such names have built-in encoders.
    //
    // The handler comes from registry (default: default_registry()).
    get_wire_body(builder: WireBuilder, registry: Registry = default_registry()): void {
        const raw = this.generic_rdata();
        if (raw !== null) {
            builder.append_uint16(raw.length);
            builder.append_bytes(raw);
            return;
        }

        const h = this.get_handler(registry);
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
        // RFC 6672 §2.1: DNAME RDATA = single <target> domain name, same wire format as NS
        case 39 /*DNAME*/:  this._wire_body_ns(builder); break;
        case 15 /*MX*/:     this._wire_body_mx(builder); break;
        case 16 /*TXT*/:    this._wire_body_txt(builder); break;
        case 28 /*AAAA*/:   this._wire_body_aaaa(builder); break;
        case 33 /*SRV*/:    this._wire_body_srv(builder); break;
        case 257 /*CAA*/:   this._wire_body_caa(builder); break;
        default:
            if (this.received_rdata !== null) {
                builder.append_uint16(this.received_rdata.length);
                builder.append_bytes(this.received_rdata);
            }
            break;
        }
    }

    private _wire_body_a(builder: WireBuilder): void {
        const ip = parse_ipv4(this.value);
        if (!ip) throw new DNSZoneRDataFormatError(`A: invalid IPv4 address "${this.value}"`);
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
        if (!m) throw new DNSZoneRDataFormatError(`SOA: invalid presentation "${this.value}"`);
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
        if (!ip) throw new DNSZoneRDataFormatError(`AAAA: invalid IPv6 address "${this.value}"`);
        builder.append_uint16(16);
        builder.append_bytes(ip);
    }

    // MX: preference(2) + exchange(wire domain name)
    private _wire_body_mx(builder: WireBuilder): void {
        const m = this.value.match(/^(\d+)\s+(\S+)/);
        if (!m) throw new DNSZoneRDataFormatError(`MX: invalid presentation "${this.value}"`);
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
        for (const bytes of strings) {
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
        if (!m) throw new DNSZoneRDataFormatError(`SRV: invalid presentation "${this.value}"`);
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

    // CAA: flags(1) + tag_length(1) + tag + value. The value is one
    // character-string, quoted or bare, with the same escapes as TXT.
    private _wire_body_caa(builder: WireBuilder): void {
        const m = this.value.match(/^(\d+)\s+(\S+)\s+(.*)$/);
        if (!m) throw new DNSZoneRDataFormatError(`CAA: invalid presentation "${this.value}"`);
        const flags = parseInt(m[1]);
        const tag = Buffer.from(m[2], 'ascii');
        const values = parse_txt_value(m[3]);
        if (values.length !== 1) {
            throw new DNSZoneRDataFormatError(`CAA: value is not one character-string "${this.value}"`);
        }
        const caa_value = values[0];
        builder.append_uint16(2 + tag.length + caa_value.length); // rdlength
        builder.append_uint8(flags);
        builder.append_uint8(tag.length);
        builder.append_bytes(tag);
        builder.append_bytes(caa_value);
    }

    to_string(): string {
        return `${this.label} ${this.ttl} ${RRClassName(this.rrclass)} ${RRTypeName(this.type)} ${this.value}`;
    }
}

// Builds a record whose value is the RFC 3597 generic form of rdata. The
// record's wire form is rdata verbatim for any type, which keeps the
// canonical form of received data intact. Throws DNSZoneRDataFormatError
// when rdata exceeds 65535 octets.
export function new_resource_record_from_rdata(label: string, ttl: number, rrclass: ns_class,
                                               type: ns_type, rdata: Uint8Array): ResourceRecord {
    if (rdata.length > MAX_RDATA_LENGTH) {
        throw new DNSZoneRDataFormatError(`RDATA length ${rdata.length}`);
    }
    return new ResourceRecord(label, ttl, rrclass, type, format_generic_rdata(rdata));
}

// new_resource_record_with_rdata builds a record read off the wire: value
// is its presentation form and rdata the RDATA octets it was decoded
// from. get_wire_body writes rdata when no handler or built-in encoder is
// available for the type, so a received record still encodes (and its
// RRSIG verifies) without the zone handlers registered. rdata is copied.
// Throws DNSZoneRDataFormatError when rdata exceeds 65535 octets.
// Ports dnsdata-go `zone.NewResourceRecordWithRData`.
export function new_resource_record_with_rdata(label: string, ttl: number, rrclass: string | ns_class,
                                               type: string | ns_type, value: string,
                                               rdata: Uint8Array): ResourceRecord {
    if (rdata.length > MAX_RDATA_LENGTH) {
        throw new DNSZoneRDataFormatError(`RDATA length ${rdata.length}`);
    }
    return new ResourceRecord(label, ttl, rrclass, type, value, rdata);
}

// canonical_rdata returns the RDATA octets of rr (without RDLENGTH), as
// records_canonical sorts them.
function canonical_rdata(rr: ResourceRecord): Uint8Array {
    const builder = new WireBuilder();
    try {
        rr.get_wire_body(builder);
    } catch (e) {
        const reason = e instanceof Error ? e.message : String(e);
        throw new DNSZoneRDataFormatError(`${rr.to_string()}: ${reason}`);
    }
    return builder.build().subarray(RDLENGTH_OCTETS);
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

    // read_string_strict parses RFC 1035 master-file text like
    // read_string but rejects, instead of skipping, anything it cannot
    // turn into a record: unknown types or classes, relative owners
    // without `$ORIGIN`, records without a TTL, malformed RDATA (including
    // RFC 3597 generic RDATA whose length does not match), types with no
    // encoder, and unsupported directives such as `$INCLUDE`.
    //
    // Every record is encoded once as a check, so a value that would
    // otherwise encode to nothing is caught here. The zone is only
    // modified when the whole text parses; on error it is left untouched
    // and DNSZoneParseError is thrown.
    //
    // Differences from read_string: `;` inside a quoted string is data,
    // the class may be any mnemonic or `CLASS<n>`, and TTL and class may
    // appear in either order. Domain names inside RDATA are not qualified
    // with `$ORIGIN`; write them fully qualified.
    read_string_strict(text: string): void {
        const parsed = parse_zone_strict(text,
            (p) => new ResourceRecord(p.label, p.ttl, p.rrclass, p.type, p.value));
        for (const rr of parsed) {
            this.add_rr(rr);
        }
    }

    // records_canonical returns every record of the zone in RFC 4034 §6
    // canonical order: owner name (§6.1), then type, then class, then the
    // canonical (wire) RDATA (§6.3). Exact duplicates (same owner, type,
    // class and RDATA octets) appear once. The order does not depend on
    // insertion order, so the output can be fixed in test vectors.
    //
    // Throws DNSZoneRDataFormatError if any record fails to encode; its
    // RDATA order would otherwise be undefined.
    records_canonical(): ResourceRecord[] {
        const entries = this.all_records().map((rr) => ({
            label: rr.label, type: rr.type, rrclass: rr.rrclass, rdata: canonical_rdata(rr), rr,
        }));
        return sort_canonical(entries).map((e) => e.rr);
    }

    // print_canonical is print in the order of records_canonical: one
    // record per line in presentation form, filtered to only_type when it
    // is given and non-zero (0 means every type, as in dnsdata-go).
    print_canonical(only_type?: ns_type): string {
        return this.records_canonical()
            .filter((rr) => !only_type || rr.type === only_type)
            .map((rr) => rr.to_string())
            .join('\n');
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
