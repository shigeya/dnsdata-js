// DoH client `resolve` method: parse the DNS response and surface
// answer + authority records as presentation-form ResourceRecord
// values.
//
// Ports the dnsdata-go `resolver/doh/resolve.go` module (originated in
// dnsdata-go v0.1.0; tracked here as UP-007). The method is defined
// here (rather than in client.ts) via TypeScript declaration merging
// so the file layout mirrors the Go package's split:
//
//     dnsdata-go/resolver/doh/resolve.go   ⇄   src/lib/resolver/doh/resolve.ts
//
// Importing this module installs the `resolve` method on DoHClient.
// The package barrel (../doh/index.ts) re-exports both files so any
// downstream import that names DoHClient also picks up the method.

import { parse_message, RawRR } from '../../dns_message';
import { rdata_to_string } from '../../rdata_decoder';
import { ResourceRecord, ns_class, ns_type } from '../../dns_zone';
import { RRClassToString, RRTypeToString } from '../../dns_type_table';
import { DoHClient } from './client';
import { DoHResponseError } from './errors';

declare module './client' {
    interface DoHClient {
        // Run a DoH query for (name, qtype), parse the response, and
        // return its answer + authority section records as
        // presentation-form [ResourceRecord] values.
        //
        // Both sections are included so the verifier can locate
        // NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those
        // in the authority section of a NODATA / NXDOMAIN / no-DS
        // response). The additional section is intentionally ignored
        // — it carries glue and EDNS OPT, neither of which is part of
        // the validated rrset surface.
        //
        // A non-zero RCODE other than NOERROR (0) throws a
        // [DoHResponseError]; SERVFAIL surfaces because the caller
        // often wants to differentiate it from "DNS data not signed".
        //
        // The signature matches verifier.Resolver.query so a
        // method-bound reference (or thin wrapper) can be passed
        // directly:
        //
        //   const client = new DoHClient();
        //   const v = new Verifier({ resolver: { query: client.resolve.bind(client) } });
        resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResourceRecord[]>;
    }
}

DoHClient.prototype.resolve = async function resolve(
    this: DoHClient,
    name: string,
    qtype: number,
    signal?: AbortSignal,
): Promise<ResourceRecord[]> {
    const raw = await this.query(name, qtype, { signal });
    let msg;
    try {
        msg = parse_message(raw);
    } catch (err) {
        throw new DoHResponseError(error_message(err));
    }
    const rcode = msg.header.rcode();
    if (rcode !== 0) {
        throw new DoHResponseError(`RCODE=${rcode}`);
    }
    const out: ResourceRecord[] = [];
    for (const rr of msg.answer) out.push(raw_to_record(msg.raw, rr));
    for (const rr of msg.authority) out.push(raw_to_record(msg.raw, rr));
    return out;
};

function raw_to_record(raw: Uint8Array, rr: RawRR): ResourceRecord {
    let value: string;
    try {
        value = rdata_to_string(raw, rr.type, rr.rdata, rr.rdataStart);
    } catch (err) {
        throw new DoHResponseError(`rdata decode: ${error_message(err)}`);
    }
    try {
        const type_name = RRTypeToString(rr.type as ns_type);
        const class_name = RRClassToString(rr.class as ns_class);
        return new ResourceRecord(rr.name, rr.ttl, class_name, type_name, value);
    } catch (err) {
        throw new DoHResponseError(`construct record: ${error_message(err)}`);
    }
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}
