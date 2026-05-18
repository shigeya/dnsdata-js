// RDATA presentation-form decoders.
//
// Ported from dnsdata-go `wire/rdata.go` (UPSTREAM_FEEDBACK.md
// UP-002, tracked in shigeya/dnsdata-js#6).
//
// rdata_to_string takes the per-type binary RDATA payload (typically
// produced by parse_message) and returns the same presentation-form
// value that ResourceRecord (dns_zone.ts) and the DNSSEC handlers
// (dnssec_rr.ts) consume. The decoder lives in the wire layer with
// NO dependency on dns_zone / dnssec_*: callers that need to lift
// the result into a ResourceRecord do so themselves.
//
// Types handled: A, AAAA, NS, CNAME, PTR, DNAME, MX, TXT, SOA, SRV,
// CAA, DNSKEY, CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3, NSEC3PARAM.
// Anything else returns the RFC 3597 §5 unknown-type generic form
// `\# <rdlen> <hex>`.

import { parse_domain_name } from './dns_wire';
import { RRTypeToString, StringToRRType } from './dns_type_table';
import { DNSRDataDecodeError } from './dns_exception';

const TYPE_A          = StringToRRType('A');
const TYPE_AAAA       = StringToRRType('AAAA');
const TYPE_NS         = StringToRRType('NS');
const TYPE_CNAME      = StringToRRType('CNAME');
const TYPE_PTR        = StringToRRType('PTR');
const TYPE_DNAME      = StringToRRType('DNAME');
const TYPE_MX         = StringToRRType('MX');
const TYPE_TXT        = StringToRRType('TXT');
const TYPE_SOA        = StringToRRType('SOA');
const TYPE_SRV        = StringToRRType('SRV');
const TYPE_CAA        = StringToRRType('CAA');
const TYPE_DNSKEY     = StringToRRType('DNSKEY');
const TYPE_CDNSKEY    = StringToRRType('CDNSKEY');
const TYPE_DS         = StringToRRType('DS');
const TYPE_CDS        = StringToRRType('CDS');
const TYPE_RRSIG      = StringToRRType('RRSIG');
const TYPE_NSEC       = StringToRRType('NSEC');
const TYPE_NSEC3      = StringToRRType('NSEC3');
const TYPE_NSEC3PARAM = StringToRRType('NSEC3PARAM');

// Converts the RDATA section of a resource record into its
// presentation-form value (the right-hand side of a zone-file line).
//
// msg is the full DNS message; rrtype is the RR-type code; rdata is
// a sub-view of msg and rdataStart its offset within msg. The
// (msg, rdataStart) pair lets per-type decoders follow compression
// pointers that escape rdata (RRSIG signer, SOA mname / rname, MX
// exchange, etc.).
export function rdata_to_string(msg: Uint8Array, rrtype: number, rdata: Uint8Array, rdataStart: number): string {
    switch (rrtype) {
        case TYPE_A:          return decode_a(rdata);
        case TYPE_AAAA:       return decode_aaaa(rdata);
        case TYPE_NS:
        case TYPE_CNAME:
        case TYPE_PTR:
        case TYPE_DNAME:      return decode_single_name(msg, rdataStart);
        case TYPE_MX:         return decode_mx(msg, rdata, rdataStart);
        case TYPE_TXT:        return decode_txt(rdata);
        case TYPE_SOA:        return decode_soa(msg, rdata, rdataStart);
        case TYPE_SRV:        return decode_srv(msg, rdata, rdataStart);
        case TYPE_CAA:        return decode_caa(rdata);
        case TYPE_DNSKEY:
        case TYPE_CDNSKEY:    return decode_dnskey(rdata);
        case TYPE_DS:
        case TYPE_CDS:        return decode_ds(rdata);
        case TYPE_RRSIG:      return decode_rrsig(msg, rdata, rdataStart);
        case TYPE_NSEC:       return decode_nsec(msg, rdata, rdataStart);
        case TYPE_NSEC3:      return decode_nsec3(rdata);
        case TYPE_NSEC3PARAM: return decode_nsec3param(rdata);
        default:              return rfc3597(rdata);
    }
}

// RFC 3597 §5 unknown-type generic form: `\# <rdlen> <hex>`.
// Exported so callers handling unknown types directly can reuse it.
export function rfc3597(rdata: Uint8Array): string {
    if (rdata.length === 0) return `\\# 0`;
    return `\\# ${rdata.length} ${to_hex_lower(rdata)}`;
}

function decode_a(rdata: Uint8Array): string {
    if (rdata.length !== 4) {
        throw new DNSRDataDecodeError(`A rdata length ${rdata.length}, want 4`);
    }
    return `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
}

function decode_aaaa(rdata: Uint8Array): string {
    if (rdata.length !== 16) {
        throw new DNSRDataDecodeError(`AAAA rdata length ${rdata.length}, want 16`);
    }
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
        groups.push(((rdata[i] << 8) | rdata[i + 1]).toString(16));
    }
    return collapse_ipv6(groups);
}

// RFC 5952 lossless-style IPv6 string: collapse the longest run of
// consecutive `0` groups to `::`. Single-zero runs are NOT collapsed
// (RFC 5952 §4.2.2). Matches net.IP.To16().String() output for
// well-formed inputs.
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

function decode_single_name(msg: Uint8Array, rdataStart: number): string {
    try {
        const { name } = parse_domain_name(msg, rdataStart);
        return name;
    } catch (err) {
        throw new DNSRDataDecodeError(`domain name: ${error_message(err)}`);
    }
}

function decode_mx(msg: Uint8Array, rdata: Uint8Array, rdataStart: number): string {
    if (rdata.length < 3) {
        throw new DNSRDataDecodeError(`MX rdata length ${rdata.length}`);
    }
    const pref = (rdata[0] << 8) | rdata[1];
    let name: string;
    try {
        ({ name } = parse_domain_name(msg, rdataStart + 2));
    } catch (err) {
        throw new DNSRDataDecodeError(`MX exchange: ${error_message(err)}`);
    }
    return `${pref} ${name}`;
}

function decode_txt(rdata: Uint8Array): string {
    const parts: string[] = [];
    let pos = 0;
    while (pos < rdata.length) {
        const len = rdata[pos];
        pos++;
        if (pos + len > rdata.length) {
            throw new DNSRDataDecodeError('TXT character-string truncated');
        }
        parts.push(txt_quote(rdata.subarray(pos, pos + len)));
        pos += len;
    }
    return parts.join(' ');
}

function txt_quote(s: Uint8Array): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === 0x22 /* " */ || c === 0x5C /* \ */) {
            out += '\\' + String.fromCharCode(c);
        } else {
            out += String.fromCharCode(c);
        }
    }
    out += '"';
    return out;
}

function decode_soa(msg: Uint8Array, rdata: Uint8Array, rdataStart: number): string {
    let mname: string, next: number;
    try {
        ({ name: mname, next } = parse_domain_name(msg, rdataStart));
    } catch (err) {
        throw new DNSRDataDecodeError(`SOA mname: ${error_message(err)}`);
    }
    let rname: string;
    try {
        ({ name: rname, next } = parse_domain_name(msg, next));
    } catch (err) {
        throw new DNSRDataDecodeError(`SOA rname: ${error_message(err)}`);
    }
    if (next + 20 > rdataStart + rdata.length) {
        throw new DNSRDataDecodeError('SOA fixed fields truncated');
    }
    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
    const serial  = view.getUint32(next);
    const refresh = view.getUint32(next + 4);
    const retry   = view.getUint32(next + 8);
    const expire  = view.getUint32(next + 12);
    const minimum = view.getUint32(next + 16);
    return `${mname} ${rname} ${serial} ${refresh} ${retry} ${expire} ${minimum}`;
}

function decode_srv(msg: Uint8Array, rdata: Uint8Array, rdataStart: number): string {
    if (rdata.length < 7) {
        throw new DNSRDataDecodeError(`SRV rdata length ${rdata.length}`);
    }
    const prio   = (rdata[0] << 8) | rdata[1];
    const weight = (rdata[2] << 8) | rdata[3];
    const port   = (rdata[4] << 8) | rdata[5];
    let target: string;
    try {
        ({ name: target } = parse_domain_name(msg, rdataStart + 6));
    } catch (err) {
        throw new DNSRDataDecodeError(`SRV target: ${error_message(err)}`);
    }
    return `${prio} ${weight} ${port} ${target}`;
}

function decode_caa(rdata: Uint8Array): string {
    if (rdata.length < 2) {
        throw new DNSRDataDecodeError(`CAA rdata length ${rdata.length}`);
    }
    const flags = rdata[0];
    const tagLen = rdata[1];
    if (2 + tagLen > rdata.length) {
        throw new DNSRDataDecodeError('CAA tag truncated');
    }
    let tag = '';
    for (let i = 0; i < tagLen; i++) tag += String.fromCharCode(rdata[2 + i]);
    let value = '';
    for (let i = 2 + tagLen; i < rdata.length; i++) value += String.fromCharCode(rdata[i]);
    return `${flags} ${tag} "${value}"`;
}

function decode_dnskey(rdata: Uint8Array): string {
    if (rdata.length < 4) {
        throw new DNSRDataDecodeError(`DNSKEY rdata length ${rdata.length}`);
    }
    const flags = (rdata[0] << 8) | rdata[1];
    const protocol = rdata[2];
    const algorithm = rdata[3];
    const keyData = Buffer.from(rdata.subarray(4)).toString('base64');
    return `${flags} ${protocol} ${algorithm} ${keyData}`;
}

function decode_ds(rdata: Uint8Array): string {
    if (rdata.length < 4) {
        throw new DNSRDataDecodeError(`DS rdata length ${rdata.length}`);
    }
    const keyTag = (rdata[0] << 8) | rdata[1];
    const algorithm = rdata[2];
    const digestType = rdata[3];
    const digest = to_hex_lower(rdata.subarray(4));
    return `${keyTag} ${algorithm} ${digestType} ${digest}`;
}

function decode_rrsig(msg: Uint8Array, rdata: Uint8Array, rdataStart: number): string {
    if (rdata.length < 18) {
        throw new DNSRDataDecodeError(`RRSIG rdata length ${rdata.length}`);
    }
    const view = new DataView(msg.buffer, msg.byteOffset + rdataStart, rdata.length);
    const typeCovered = view.getUint16(0);
    const algorithm   = rdata[2];
    const labels      = rdata[3];
    const originalTTL = view.getUint32(4);
    const expire      = view.getUint32(8);
    const inception   = view.getUint32(12);
    const keyTag      = view.getUint16(16);

    let signer: string, next: number;
    try {
        ({ name: signer, next } = parse_domain_name(msg, rdataStart + 18));
    } catch (err) {
        throw new DNSRDataDecodeError(`RRSIG signer: ${error_message(err)}`);
    }
    if (next > rdataStart + rdata.length) {
        throw new DNSRDataDecodeError('RRSIG signer extends past rdata');
    }
    const signature = Buffer.from(msg.subarray(next, rdataStart + rdata.length)).toString('base64');
    const typeName = qtype_mnemonic(typeCovered);
    return `${typeName} ${algorithm} ${labels} ${originalTTL} ${expire} ${inception} ${keyTag} ${signer} ${signature}`;
}

function decode_nsec(msg: Uint8Array, rdata: Uint8Array, rdataStart: number): string {
    let nextDomain: string, next: number;
    try {
        ({ name: nextDomain, next } = parse_domain_name(msg, rdataStart));
    } catch (err) {
        throw new DNSRDataDecodeError(`NSEC next: ${error_message(err)}`);
    }
    const bitmap = msg.subarray(next, rdataStart + rdata.length);
    const types = decode_bitmap(bitmap);
    return [nextDomain, ...types.map(qtype_mnemonic)].join(' ');
}

function decode_nsec3(rdata: Uint8Array): string {
    if (rdata.length < 5) {
        throw new DNSRDataDecodeError(`NSEC3 rdata length ${rdata.length}`);
    }
    const hashAlgo = rdata[0];
    const flags = rdata[1];
    const iterations = (rdata[2] << 8) | rdata[3];
    const saltLen = rdata[4];
    let pos = 5;
    if (pos + saltLen > rdata.length) {
        throw new DNSRDataDecodeError('NSEC3 salt truncated');
    }
    const salt = rdata.subarray(pos, pos + saltLen);
    pos += saltLen;
    if (pos + 1 > rdata.length) {
        throw new DNSRDataDecodeError('NSEC3 next-hash length missing');
    }
    const nextLen = rdata[pos];
    pos++;
    if (pos + nextLen > rdata.length) {
        throw new DNSRDataDecodeError('NSEC3 next-hash truncated');
    }
    const nextHash = rdata.subarray(pos, pos + nextLen);
    pos += nextLen;
    const bitmap = rdata.subarray(pos);
    const types = decode_bitmap(bitmap);
    const saltStr = salt.length === 0 ? '-' : to_hex_upper(salt);
    const parts = [
        `${hashAlgo}`,
        `${flags}`,
        `${iterations}`,
        saltStr,
        base32hex_encode(nextHash),
        ...types.map(qtype_mnemonic),
    ];
    return parts.join(' ');
}

function decode_nsec3param(rdata: Uint8Array): string {
    if (rdata.length < 5) {
        throw new DNSRDataDecodeError(`NSEC3PARAM rdata length ${rdata.length}`);
    }
    const hashAlgo = rdata[0];
    const flags = rdata[1];
    const iterations = (rdata[2] << 8) | rdata[3];
    const saltLen = rdata[4];
    if (5 + saltLen > rdata.length) {
        throw new DNSRDataDecodeError('NSEC3PARAM salt truncated');
    }
    const salt = rdata.subarray(5, 5 + saltLen);
    const saltStr = salt.length === 0 ? '-' : to_hex_upper(salt);
    return `${hashAlgo} ${flags} ${iterations} ${saltStr}`;
}

// RFC 4034 §4.1.2 NSEC type bitmap decoder. Standalone copy of the
// same logic in dnssec_rr.ts; duplicated here so the wire layer has
// no dnssec dependency (matches the Go side's wire/rdata.go local
// copy with the same rationale).
function decode_bitmap(bitmap: Uint8Array): number[] {
    const out: number[] = [];
    let pos = 0;
    while (pos < bitmap.length) {
        if (pos + 2 > bitmap.length) {
            throw new DNSRDataDecodeError('bitmap window header truncated');
        }
        const window = bitmap[pos];
        const length = bitmap[pos + 1];
        pos += 2;
        if (length === 0 || length > 32) {
            throw new DNSRDataDecodeError(`bitmap window length ${length}`);
        }
        if (pos + length > bitmap.length) {
            throw new DNSRDataDecodeError('bitmap window data truncated');
        }
        for (let i = 0; i < length; i++) {
            const byte = bitmap[pos + i];
            for (let bit = 0; bit < 8; bit++) {
                if (byte & (0x80 >> bit)) {
                    out.push((window << 8) | (i * 8 + bit));
                }
            }
        }
        pos += length;
    }
    return out;
}

// Base32hex encode (RFC 4648 "Base 32 with Extended Hex Alphabet").
// Used by NSEC3 owner labels. Inverse of the existing
// base32hex_decode in dnssec_rr.ts; reproduced here so the wire
// layer has no dnssec dependency.
function base32hex_encode(b: Uint8Array): string {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    if (b.length === 0) return '';
    const bits: number[] = [];
    for (let i = 0; i < b.length; i++) {
        for (let j = 7; j >= 0; j--) {
            bits.push((b[i] >> j) & 1);
        }
    }
    while (bits.length % 5 !== 0) bits.push(0);
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
        let v = 0;
        for (let j = 0; j < 5; j++) v = (v << 1) | bits[i + j];
        out += alphabet[v];
    }
    return out;
}

function to_hex_lower(b: Uint8Array): string {
    return Buffer.from(b).toString('hex');
}

function to_hex_upper(b: Uint8Array): string {
    return Buffer.from(b).toString('hex').toUpperCase();
}

function qtype_mnemonic(t: number): string {
    try {
        return RRTypeToString(t);
    } catch {
        return `TYPE${t}`;
    }
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
