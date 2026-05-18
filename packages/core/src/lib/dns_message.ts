// DNS message wire-format parser.
//
// Ported from dnsdata-go `wire/message.go` (UPSTREAM_FEEDBACK.md
// UP-002, tracked in shigeya/dnsdata-js#6).
//
// Lives in the wire layer with NO dependency on dns_zone /
// dnssec_*. Higher-level adapters that lift RawRR → ResourceRecord
// live in their callers (mirroring the Go side's
// resolver/doh.Client.Resolve approach).

import { parse_domain_name } from './dns_wire';
import { DNSMessageMalformedError } from './dns_exception';

// 12-byte fixed-shape DNS message header (RFC 1035 §4.1.1).
// Flag-field bit positions per RFC 1035 §4.1.1 and RFC 4035 §3.
const FLAG_QR = 1 << 15;
const FLAG_AA = 1 << 10;
const FLAG_TC = 1 << 9;
const FLAG_RD = 1 << 8;
const FLAG_RA = 1 << 7;
const FLAG_AD = 1 << 5;
const FLAG_CD = 1 << 4;

export class Header {
    readonly id: number;
    readonly flags: number;
    readonly qdcount: number;
    readonly ancount: number;
    readonly nscount: number;
    readonly arcount: number;

    constructor(id: number, flags: number, qdcount: number, ancount: number, nscount: number, arcount: number) {
        this.id = id;
        this.flags = flags;
        this.qdcount = qdcount;
        this.ancount = ancount;
        this.nscount = nscount;
        this.arcount = arcount;
    }

    qr(): boolean { return (this.flags & FLAG_QR) !== 0; }
    aa(): boolean { return (this.flags & FLAG_AA) !== 0; }
    tc(): boolean { return (this.flags & FLAG_TC) !== 0; }
    rd(): boolean { return (this.flags & FLAG_RD) !== 0; }
    ra(): boolean { return (this.flags & FLAG_RA) !== 0; }
    ad(): boolean { return (this.flags & FLAG_AD) !== 0; }
    cd(): boolean { return (this.flags & FLAG_CD) !== 0; }
    rcode(): number { return this.flags & 0x000F; }
}

export interface Question {
    name: string;
    type: number;
    class: number;
}

// Wire-decoded resource record with RDATA still in binary form. Use
// rdata_to_string (rdata_decoder.ts) — or a higher-level adapter —
// to produce a presentation-form value.
//
// rdata is a sub-view of the original message bytes; callers must
// not mutate it. rdataStart records the absolute offset of rdata
// within the original message so callers decoding embedded domain
// names can call parse_domain_name with the right position.
export interface RawRR {
    name: string;
    type: number;
    class: number;
    ttl: number;
    rdata: Uint8Array;
    rdataStart: number;
}

export interface RawMessage {
    raw: Uint8Array;
    header: Header;
    question: Question;
    answer: RawRR[];
    authority: RawRR[];
    additional: RawRR[];
}

// parse_message decodes a DNS message from msg. The returned
// RawMessage retains a reference to msg; callers must not mutate the
// source array until they are done with the result.
//
// Only one question is accepted (matching real-world DNS practice);
// qdcount > 1 throws DNSMessageMalformedError.
export function parse_message(msg: Uint8Array): RawMessage {
    if (msg.length < 12) {
        throw new DNSMessageMalformedError(`header truncated (len=${msg.length})`);
    }

    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
    const header = new Header(
        view.getUint16(0),
        view.getUint16(2),
        view.getUint16(4),
        view.getUint16(6),
        view.getUint16(8),
        view.getUint16(10),
    );
    if (header.qdcount !== 1) {
        throw new DNSMessageMalformedError(`qdcount=${header.qdcount} (only 1 supported)`);
    }

    let pos = 12;
    let qname: string;
    try {
        const parsed = parse_domain_name(msg, pos);
        qname = parsed.name;
        pos = parsed.next;
    } catch (err) {
        throw new DNSMessageMalformedError(`question qname: ${error_message(err)}`);
    }
    if (pos + 4 > msg.length) {
        throw new DNSMessageMalformedError('question fields truncated');
    }
    const question: Question = {
        name: qname,
        type: view.getUint16(pos),
        class: view.getUint16(pos + 2),
    };
    pos += 4;

    let answer: RawRR[];
    let authority: RawRR[];
    let additional: RawRR[];
    try {
        ({ rrs: answer,     next: pos } = parse_rr_section(msg, view, pos, header.ancount));
    } catch (err) {
        throw new DNSMessageMalformedError(`answer section: ${error_message(err)}`);
    }
    try {
        ({ rrs: authority,  next: pos } = parse_rr_section(msg, view, pos, header.nscount));
    } catch (err) {
        throw new DNSMessageMalformedError(`authority section: ${error_message(err)}`);
    }
    try {
        ({ rrs: additional        } = parse_rr_section(msg, view, pos, header.arcount));
    } catch (err) {
        throw new DNSMessageMalformedError(`additional section: ${error_message(err)}`);
    }

    return { raw: msg, header, question, answer, authority, additional };
}

interface SectionResult {
    rrs: RawRR[];
    next: number;
}

function parse_rr_section(msg: Uint8Array, view: DataView, pos: number, count: number): SectionResult {
    if (count === 0) return { rrs: [], next: pos };
    const rrs: RawRR[] = [];
    for (let i = 0; i < count; i++) {
        try {
            const { rr, next } = parse_rr(msg, view, pos);
            rrs.push(rr);
            pos = next;
        } catch (err) {
            throw new DNSMessageMalformedError(`RR ${i}: ${error_message(err)}`);
        }
    }
    return { rrs, next: pos };
}

interface RRResult {
    rr: RawRR;
    next: number;
}

function parse_rr(msg: Uint8Array, view: DataView, pos: number): RRResult {
    let name: string;
    try {
        const parsed = parse_domain_name(msg, pos);
        name = parsed.name;
        pos = parsed.next;
    } catch (err) {
        throw new DNSMessageMalformedError(`owner name: ${error_message(err)}`);
    }
    if (pos + 10 > msg.length) {
        throw new DNSMessageMalformedError(`RR fixed fields truncated at ${pos}`);
    }
    const type = view.getUint16(pos);
    const klass = view.getUint16(pos + 2);
    const ttl = view.getUint32(pos + 4);
    const rdlen = view.getUint16(pos + 8);
    pos += 10;
    if (pos + rdlen > msg.length) {
        throw new DNSMessageMalformedError(
            `rdata truncated (need ${rdlen}, have ${msg.length - pos})`,
        );
    }
    const rdataStart = pos;
    const rdata = msg.subarray(pos, pos + rdlen);
    pos += rdlen;
    return {
        rr: { name, type, class: klass, ttl, rdata, rdataStart },
        next: pos,
    };
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
