// TLSA / SMIMEA and SVCB / HTTPS presentation-form decoders.
//
// Ports dnsdata-go `wire/rdata_svcb.go`. Each returns null when the
// RDATA has no presentation form the zone parser (zone/rr/svcb_rr.ts,
// the TLSA handler) reads back to the same octets — malformed RDATA
// included — and rdata_to_string then writes the generic form.

import { domain_name2wire, parse_domain_name } from './dns_wire';
import { format_ipv4, format_ipv6, is_ipv4_mapped, IPV4_LENGTH, IPV6_LENGTH } from './ip_format';

// usage(1) + selector(1) + matching type(1).
const TLSA_FIXED_LENGTH = 3;

// tlsa_presentation writes TLSA / SMIMEA (RFC 6698 §2.2, RFC 8162 §2)
// as `usage selector matching-type hex`. Null without certificate data.
export function tlsa_presentation(rdata: Uint8Array): string | null {
    if (rdata.length <= TLSA_FIXED_LENGTH) return null;
    const data = Buffer.from(rdata.subarray(TLSA_FIXED_LENGTH)).toString('hex');
    return `${rdata[0]} ${rdata[1]} ${rdata[2]} ${data}`;
}

// SvcParamKeys with a value format of their own (RFC 9460 §14.3.2).
const SVC_KEY_MANDATORY = 0;
const SVC_KEY_ALPN = 1;
const SVC_KEY_NO_DEFAULT_ALPN = 2;
const SVC_KEY_PORT = 3;
const SVC_KEY_IPV4HINT = 4;
const SVC_KEY_ECH = 5;
const SVC_KEY_IPV6HINT = 6;

// The RFC 9460 §14.3.2 mnemonics, indexed by key. svcb_rr.ts reads the
// same names; any other key is keyNNNNN.
const SVC_PARAM_KEY_NAMES: readonly string[] =
    ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint'];

const SVCB_MIN_LENGTH = 3;          // SvcPriority(2) + the root label(1)
const SVC_PARAM_HEADER_LENGTH = 4;  // SvcParamKey(2) + SvcParamValueLength(2)
const SVC_MANDATORY_KEY_LENGTH = 2;
const SVC_PORT_LENGTH = 2;

// svcb_presentation writes SVCB / HTTPS (RFC 9460 §2.1) as `priority
// target key=value ...`. Null for RDATA that form would not reproduce
// octet for octet: malformed, keys out of order, a target the parser
// would rewrite, or a value with no plain form.
export function svcb_presentation(rdata: Uint8Array): string | null {
    if (rdata.length < SVCB_MIN_LENGTH) return null;
    let target: string;
    let pos: number;
    try {
        ({ name: target, next: pos } = parse_domain_name(rdata, 2));
    } catch {
        return null;
    }
    if (!svcb_target_is_plain(target, rdata.subarray(2, pos))) return null;
    const parts = [String(uint16(rdata, 0)), target];
    let prev_key = -1;
    while (pos < rdata.length) {
        if (pos + SVC_PARAM_HEADER_LENGTH > rdata.length) return null;
        const key = uint16(rdata, pos);
        const n = uint16(rdata, pos + 2);
        pos += SVC_PARAM_HEADER_LENGTH;
        if (pos + n > rdata.length || key <= prev_key) return null;
        const param = svc_param_string(key, rdata.subarray(pos, pos + n));
        if (param === null) return null;
        prev_key = key;
        parts.push(param);
        pos += n;
    }
    return parts.join(' ');
}

function uint16(b: Uint8Array, pos: number): number {
    return (b[pos] << 8) | b[pos + 1];
}

// The parser lowercases the target, does not follow compression, and
// splits on whitespace.
function svcb_target_is_plain(target: string, raw: Uint8Array): boolean {
    if (/[ \t\r\n]/.test(target)) return false;
    try {
        return Buffer.from(domain_name2wire(target)).equals(Buffer.from(raw));
    } catch {
        return false;
    }
}

function svc_param_key_name(key: number): string {
    return key < SVC_PARAM_KEY_NAMES.length ? SVC_PARAM_KEY_NAMES[key] : `key${key}`;
}

// svc_param_string writes one SvcParam as `key` or `key=value`; null
// when the parser would not read the result back as v.
function svc_param_string(key: number, v: Uint8Array): string | null {
    const name = svc_param_key_name(key);
    if (key === SVC_KEY_NO_DEFAULT_ALPN) return v.length === 0 ? name : null;
    if (v.length === 0) return key >= SVC_PARAM_KEY_NAMES.length ? name : null;
    const value = svc_param_value(key, v);
    return value === null ? null : `${name}=${value}`;
}

function svc_param_value(key: number, v: Uint8Array): string | null {
    switch (key) {
        case SVC_KEY_MANDATORY: return svc_mandatory_value(v);
        case SVC_KEY_ALPN:      return svc_alpn_value(v);
        case SVC_KEY_PORT:      return v.length === SVC_PORT_LENGTH ? String(uint16(v, 0)) : null;
        case SVC_KEY_IPV4HINT:  return svc_addr_value(v, IPV4_LENGTH);
        case SVC_KEY_ECH:       return Buffer.from(v).toString('base64');
        case SVC_KEY_IPV6HINT:  return svc_addr_value(v, IPV6_LENGTH);
        default:                return Buffer.from(v).toString('hex');
    }
}

// Comma-separated key names (RFC 9460 §8). The parser sorts them, so
// they must already be in order.
function svc_mandatory_value(v: Uint8Array): string | null {
    if (v.length % SVC_MANDATORY_KEY_LENGTH !== 0) return null;
    const names: string[] = [];
    let prev = -1;
    for (let i = 0; i < v.length; i += SVC_MANDATORY_KEY_LENGTH) {
        const key = uint16(v, i);
        if (key < prev) return null;
        prev = key;
        names.push(svc_param_key_name(key));
    }
    return names.join(',');
}

// Comma-separated ALPN ids (RFC 9460 §7.1.1). The parser reads no
// escapes, so every id must be non-empty printable ASCII without `,`,
// `"` or `\`.
function svc_alpn_value(v: Uint8Array): string | null {
    const ids: string[] = [];
    let pos = 0;
    while (pos < v.length) {
        const n = v[pos];
        pos++;
        if (n === 0 || pos + n > v.length) return null;
        const id = v.subarray(pos, pos + n);
        if (!id.every(is_plain_alpn_octet)) return null;
        ids.push(String.fromCharCode(...id));
        pos += n;
    }
    return ids.join(',');
}

function is_plain_alpn_octet(c: number): boolean {
    return c > 0x20 && c < 0x7f && c !== 0x2c && c !== 0x22 && c !== 0x5c;
}

// Comma-separated addresses of size octets each (RFC 9460 §7.4). The
// Go parser rejects IPv4-mapped IPv6 addresses.
function svc_addr_value(v: Uint8Array, size: number): string | null {
    if (v.length % size !== 0) return null;
    const addrs: string[] = [];
    for (let i = 0; i < v.length; i += size) {
        const ip = v.subarray(i, i + size);
        if (size === IPV6_LENGTH && is_ipv4_mapped(ip)) return null;
        addrs.push(size === IPV4_LENGTH ? format_ipv4(ip) : format_ipv6(ip));
    }
    return addrs.join(',');
}
