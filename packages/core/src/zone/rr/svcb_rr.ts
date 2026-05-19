// SVCB (type 64) and HTTPS (type 65) Resource Records (RFC 9460)
//
// Wire format (RFC 9460 §2.2):
//   SvcPriority(2) + TargetName(uncompressed domain) + SvcParams(variable)
//
// SvcParams wire format (RFC 9460 §2.2):
//   Each param: SvcParamKey(2) + SvcParamValueLength(2) + SvcParamValue(variable)
//   Params MUST appear in strictly increasing key order.
//
// RFC 9460 §2.4.3: HTTPS RR is a SVCB-compatible type with identical wire format.
// HTTPS (type 65) uses the same RDATA encoding as SVCB (type 64).

import { WireBuilder } from '../../wire/dns_wire_util';
import { domain_name2wire } from '../../wire/dns_wire';
import { StringToRRType } from '../../types/dns_type_table';
import { ResourceRecord, ResourceRecordHandler } from '../dns_zone';
import { DNSZonePresentationFormatError } from '../../dns_exception';

// RFC 9460 §14.3.2: Initial SvcParamKey registry
const SVCPARAM_KEY_MAP: Record<string, number> = {
    'mandatory': 0,
    'alpn': 1,
    'no-default-alpn': 2,
    'port': 3,
    'ipv4hint': 4,
    'ech': 5,
    'ipv6hint': 6,
};

// RFC 9460 §2.1: SvcParam representation
interface SvcParam {
    key: number;
    value: Uint8Array;
}

// RFC 9460 §2.2: Parse a SvcParamKey from presentation format
function parseSvcParamKey(keyStr: string): number {
    const lower = keyStr.toLowerCase();
    if (lower in SVCPARAM_KEY_MAP) {
        return SVCPARAM_KEY_MAP[lower];
    }
    // RFC 9460 §2.1: Unknown keys use "keyNNNNN" format
    const m = lower.match(/^key(\d+)$/);
    if (m) return parseInt(m[1]);
    throw new DNSZonePresentationFormatError(`SVCB: unknown SvcParamKey: ${keyStr}`);
}

// RFC 9460 §7.1.1: alpn wire format: repeated (length(1) + alpn-id(variable))
function encodeAlpn(value: string): Uint8Array {
    // Presentation: comma-separated list of ALPNs, e.g. "h2,h3"
    const alpns = value.split(',');
    const parts: Uint8Array[] = [];
    for (const alpn of alpns) {
        const encoded = Buffer.from(alpn, 'utf-8');
        const buf = new Uint8Array(1 + encoded.length);
        buf[0] = encoded.length;
        buf.set(encoded, 1);
        parts.push(buf);
    }
    const total = parts.reduce((s, p) => s + p.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        result.set(p, offset);
        offset += p.length;
    }
    return result;
}

// RFC 9460 §7.2: port wire format: uint16 in network byte order
function encodePort(value: string): Uint8Array {
    const port = parseInt(value);
    const buf = new Uint8Array(2);
    buf[0] = (port >> 8) & 0xff;
    buf[1] = port & 0xff;
    return buf;
}

// RFC 9460 §7.4: ipv4hint wire format: concatenated 4-byte IPv4 addresses
function encodeIpv4Hint(value: string): Uint8Array {
    const addrs = value.split(',');
    const result = new Uint8Array(addrs.length * 4);
    for (let i = 0; i < addrs.length; i++) {
        const octets = addrs[i].trim().split('.');
        for (let j = 0; j < 4; j++) {
            result[i * 4 + j] = parseInt(octets[j]);
        }
    }
    return result;
}

// RFC 9460 §7.4: ipv6hint wire format: concatenated 16-byte IPv6 addresses
function encodeIpv6Hint(value: string): Uint8Array {
    const addrs = value.split(',');
    const result = new Uint8Array(addrs.length * 16);
    for (let i = 0; i < addrs.length; i++) {
        const bytes = ipv6ToBytes(addrs[i].trim());
        result.set(bytes, i * 16);
    }
    return result;
}

// Parse an IPv6 address to 16 bytes
function ipv6ToBytes(addr: string): Uint8Array {
    const result = new Uint8Array(16);
    // Handle :: expansion
    const parts = addr.split('::');
    let groups: string[] = [];
    if (parts.length === 2) {
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        const fill = 8 - left.length - right.length;
        groups = [...left, ...Array(fill).fill('0'), ...right];
    } else {
        groups = addr.split(':');
    }
    for (let i = 0; i < 8; i++) {
        const val = parseInt(groups[i] || '0', 16);
        result[i * 2] = (val >> 8) & 0xff;
        result[i * 2 + 1] = val & 0xff;
    }
    return result;
}

// RFC 9460 §7.3: mandatory wire format: list of uint16 keys in increasing order
function encodeMandatory(value: string): Uint8Array {
    const keys = value.split(',').map(k => parseSvcParamKey(k.trim()));
    keys.sort((a, b) => a - b);
    const result = new Uint8Array(keys.length * 2);
    for (let i = 0; i < keys.length; i++) {
        result[i * 2] = (keys[i] >> 8) & 0xff;
        result[i * 2 + 1] = keys[i] & 0xff;
    }
    return result;
}

// RFC 9460 §2.1: Encode a SvcParam value based on its key
function encodeSvcParamValue(key: number, value: string): Uint8Array {
    switch (key) {
    case 0: return encodeMandatory(value);  // mandatory
    case 1: return encodeAlpn(value);       // alpn
    case 2: return new Uint8Array(0);       // no-default-alpn (no value)
    case 3: return encodePort(value);       // port
    case 4: return encodeIpv4Hint(value);   // ipv4hint
    case 5: return new Uint8Array(Buffer.from(value, 'base64'));  // ech (base64-encoded)
    case 6: return encodeIpv6Hint(value);   // ipv6hint
    default:
        // RFC 9460 §2.1: Unknown keys with "keyNNNNN" use the value as-is (hex or escaped)
        return new Uint8Array(Buffer.from(value, 'hex'));
    }
}

// Parse SvcParams from presentation format tokens
// RFC 9460 §2.1: key=value pairs, or key alone for valueless params
function parseSvcParams(tokens: string[]): SvcParam[] {
    const params: SvcParam[] = [];
    for (const token of tokens) {
        const eqIdx = token.indexOf('=');
        let keyStr: string;
        let valueStr: string;
        if (eqIdx === -1) {
            keyStr = token;
            valueStr = '';
        } else {
            keyStr = token.substring(0, eqIdx);
            valueStr = token.substring(eqIdx + 1);
            // Remove surrounding quotes if present
            if (valueStr.startsWith('"') && valueStr.endsWith('"')) {
                valueStr = valueStr.substring(1, valueStr.length - 1);
            }
        }
        const key = parseSvcParamKey(keyStr);
        const value = encodeSvcParamValue(key, valueStr);
        params.push({ key, value });
    }
    // RFC 9460 §2.2: SvcParams MUST be in strictly increasing key order
    params.sort((a, b) => a.key - b.key);
    return params;
}

// RFC 9460 §2.2: SVCB RDATA wire format
// SvcPriority(2) + TargetName(uncompressed domain) + SvcParams
//
// SVCB (type 64) and HTTPS (type 65) share identical wire format.
// HTTPS is defined as a SVCB-compatible RR type (RFC 9460 §9.1).
export class DNSRR_SVCB extends ResourceRecordHandler {
    readonly priority: number;
    readonly target: string;
    readonly params: SvcParam[];

    constructor(rr: ResourceRecord | null, value: string) {
        super(rr);
        // Parse: "{priority} {target} [key=value ...]"
        const tokens = value.trim().split(/\s+/);
        if (tokens.length < 2) {
            throw new DNSZonePresentationFormatError("SVCB/HTTPS: Presentation format error: " + value);
        }

        this.priority = parseInt(tokens[0]);
        this.target = tokens[1];
        this.params = tokens.length > 2 ? parseSvcParams(tokens.slice(2)) : [];
    }

    // RFC 9460 §2.2: Wire format
    get_wire_body(builder: WireBuilder): void {
        const target_wire = domain_name2wire(this.target);

        // Calculate SvcParams wire length
        let paramsLen = 0;
        for (const p of this.params) {
            paramsLen += 2 + 2 + p.value.length;  // key(2) + length(2) + value
        }

        // RDLENGTH
        builder.append_uint16(2 + target_wire.length + paramsLen);

        // SvcPriority
        builder.append_uint16(this.priority);

        // TargetName (uncompressed)
        builder.append_bytes(target_wire);

        // SvcParams in key order
        for (const p of this.params) {
            builder.append_uint16(p.key);
            builder.append_uint16(p.value.length);
            builder.append_bytes(p.value);
        }
    }

    clone(): DNSRR_SVCB {
        return new DNSRR_SVCB(this._rr, this.value);
    }
}

// Register SVCB (type 64) handler

// RFC 9460 §9.1: HTTPS (type 65) uses identical wire format to SVCB (type 64).
// The handler class is shared; only the RR type code differs.
