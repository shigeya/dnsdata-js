// Turns a DNS response message into a [ResolverResponse]. The auth,
// DoH and DoT clients share it. Ports dnsdata-go
// `resolver/internal/message`.

import { parse_message, RawRR } from '../wire/dns_message';
import { rdata_to_string } from '../wire/rdata_decoder';
import { ResourceRecord, ns_class, ns_type } from '../zone/dns_zone';
import { RRClassName, RRTypeName } from '../types/dns_type_table';
import { ResolverResponse } from './response';

// The step of to_response that failed.
export type ResponseStep = 'parse' | 'rdata decode' | 'construct record';

// Makes the error a client throws for a failed step.
export type ResponseErrorFactory = (step: ResponseStep, message: string) => Error;

// to_response parses raw and returns its answer and authority records
// in presentation form, with the AD bit and RCODE of its header. The
// authority section carries the NSEC / NSEC3 proofs a verifier needs
// (RFC 4035 §3.1.3); the additional section (glue, EDNS OPT) is
// ignored. Failures throw the error fail makes, so each client keeps its
// own error class.
export function to_response(raw: Uint8Array, fail: ResponseErrorFactory): ResolverResponse {
    let msg;
    try {
        msg = parse_message(raw);
    } catch (err) {
        throw fail('parse', error_message(err));
    }
    const records = [...msg.answer, ...msg.authority].map((rr) => to_record(msg.raw, rr, fail));
    return { records, ad: msg.header.ad(), rcode: msg.header.rcode() };
}

function to_record(raw: Uint8Array, rr: RawRR, fail: ResponseErrorFactory): ResourceRecord {
    let value: string;
    try {
        value = rdata_to_string(raw, rr.type, rr.rdata, rr.rdataStart);
    } catch (err) {
        throw fail('rdata decode', error_message(err));
    }
    try {
        return new ResourceRecord(rr.name, rr.ttl, RRClassName(rr.class as ns_class), RRTypeName(rr.type as ns_type), value);
    } catch (err) {
        throw fail('construct record', error_message(err));
    }
}

function error_message(err: unknown): string {
    return err instanceof Error ? err.message : String(err);
}
