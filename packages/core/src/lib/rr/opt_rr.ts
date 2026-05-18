// OPT Pseudo-Resource Record (RFC 6891)
//
// OPT is a meta-RR used by EDNS(0) to signal extended DNS capabilities.
// It does NOT appear in zone files. It is placed in the Additional section
// of DNS messages.
//
// RFC 6891 §6.1.2: OPT record wire format repurposes standard RR fields:
//   NAME:     0x00 (root domain, must be empty)
//   TYPE:     41 (OPT)
//   CLASS:    requestor's UDP payload size (uint16)
//   TTL:      extended RCODE(8) + version(8) + DO bit + Z(15)
//   RDLENGTH: length of RDATA
//   RDATA:    sequence of {option-code(2), option-length(2), option-data(variable)}
//
// RFC 6891 §6.1.3: OPT record cache semantics — OPT records MUST NOT be
// cached, forwarded, or stored.
//
// RFC 6891 §6.1.4: Only one OPT record is allowed per DNS message.

import { WireBuilder } from '../../wire/dns_wire_util';

// RFC 6891 §6.1.2: EDNS option code/data pair
export interface EDNSOption {
    code: number;       // option-code (uint16)
    data: Uint8Array;   // option-data
}

// Well-known EDNS option codes (RFC 6891 §9, IANA registry)
export const EDNS_OPTION_NSID = 3;          // RFC 5001: NSID
export const EDNS_OPTION_CLIENT_SUBNET = 8; // RFC 7871: Client Subnet
export const EDNS_OPTION_COOKIE = 10;       // RFC 7873: DNS Cookies
export const EDNS_OPTION_PADDING = 12;      // RFC 7830: Padding
export const EDNS_OPTION_CHAIN = 13;        // RFC 7901: Chain Query

export class DNSRR_OPT {
    readonly udp_payload_size: number;
    readonly extended_rcode: number;
    readonly version: number;
    readonly do_bit: boolean;
    readonly z: number;
    readonly options: EDNSOption[];

    constructor(params?: {
        udp_payload_size?: number;
        extended_rcode?: number;
        version?: number;
        do_bit?: boolean;
        z?: number;
        options?: EDNSOption[];
    }) {
        this.udp_payload_size = params?.udp_payload_size ?? 4096;
        this.extended_rcode = params?.extended_rcode ?? 0;
        this.version = params?.version ?? 0;
        this.do_bit = params?.do_bit ?? false;
        this.z = params?.z ?? 0;
        this.options = params?.options ?? [];
    }

    // RFC 6891 §6.1.2: Build the full OPT RR wire format
    // NAME(1, root) + TYPE(2) + CLASS/udp_size(2) + TTL/flags(4) + RDLEN(2) + RDATA(variable)
    get_wire(builder: WireBuilder): void {
        // NAME: root domain (single zero byte)
        builder.append_uint8(0);

        // TYPE: OPT (41)
        builder.append_uint16(41);

        // CLASS: requestor's UDP payload size
        builder.append_uint16(this.udp_payload_size);

        // TTL field repurposed: extended-rcode(8) + version(8) + DO(1) + Z(15)
        const ttl = ((this.extended_rcode & 0xff) << 24)
            | ((this.version & 0xff) << 16)
            | (this.do_bit ? 0x8000 : 0)
            | (this.z & 0x7fff);
        builder.append_uint32(ttl);

        // RDATA: option-code(2) + option-length(2) + option-data(variable) for each option
        let rdlen = 0;
        for (const opt of this.options) {
            rdlen += 2 + 2 + opt.data.length;
        }
        builder.append_uint16(rdlen);

        for (const opt of this.options) {
            builder.append_uint16(opt.code);
            builder.append_uint16(opt.data.length);
            builder.append_bytes(opt.data);
        }
    }

    // RFC 6891 §6.1.2: Parse OPT RR from wire format bytes
    // Input should start at the beginning of the OPT RR (after the NAME field has been consumed).
    // The data parameter should contain: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
    static from_wire(data: Uint8Array, offset: number = 0): DNSRR_OPT {
        if (data.length - offset < 10) {
            throw new Error("OPT: insufficient data for wire format");
        }

        const type = (data[offset] << 8) | data[offset + 1];
        if (type !== 41) {
            throw new Error(`OPT: expected type 41, got ${type}`);
        }

        const udp_payload_size = (data[offset + 2] << 8) | data[offset + 3];

        const ttl = ((data[offset + 4] << 24) | (data[offset + 5] << 16)
            | (data[offset + 6] << 8) | data[offset + 7]) >>> 0;
        const extended_rcode = (ttl >>> 24) & 0xff;
        const version = (ttl >>> 16) & 0xff;
        const do_bit = (ttl & 0x8000) !== 0;
        const z = ttl & 0x7fff;

        const rdlen = (data[offset + 8] << 8) | data[offset + 9];

        // Parse RDATA options
        const options: EDNSOption[] = [];
        let pos = offset + 10;
        const end = pos + rdlen;

        while (pos + 4 <= end) {
            const code = (data[pos] << 8) | data[pos + 1];
            const optlen = (data[pos + 2] << 8) | data[pos + 3];
            pos += 4;
            if (pos + optlen > end) {
                throw new Error("OPT: option data exceeds RDLENGTH");
            }
            const optdata = data.slice(pos, pos + optlen);
            options.push({ code, data: optdata });
            pos += optlen;
        }

        return new DNSRR_OPT({ udp_payload_size, extended_rcode, version, do_bit, z, options });
    }

    // Find an option by code
    find_option(code: number): EDNSOption | undefined {
        return this.options.find(o => o.code === code);
    }
}
