// AuthClient.resolve adapter: runs query() and lifts the wire
// response into presentation-form ResourceRecord[] values.
//
// Ports dnsdata-go `resolver/auth/resolve.go`. The method is defined
// here (rather than inside client.ts) via TypeScript declaration
// merging so the file layout mirrors the Go package's split:
//
//     dnsdata-go/resolver/auth/resolve.go ⇄ src/resolver/auth/resolve.ts
//
// Importing this module installs the `resolve` method on AuthClient.
// The package barrel (./index.ts) and the back-compat shim
// (./resolver_auth.ts) both pull this file in, so any consumer
// reaching AuthClient through either entry point sees the method.

import { parse_message, RawRR } from '../../wire/dns_message';
import { rdata_to_string } from '../../wire/rdata_decoder';
import { ResourceRecord, ns_class, ns_type } from '../../zone/dns_zone';
import { RRClassToString, RRTypeToString } from '../../types/dns_type_table';
import { AuthClient } from './client';
import { AuthResponseError, error_message } from './errors';

declare module './client' {
    interface AuthClient {
        // Run a DNS query for (name, qtype), parse the response, and
        // return its answer + authority section records as
        // presentation-form [ResourceRecord] values.
        //
        // Both sections are included so a verifier can locate
        // NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those
        // in the authority section of a NODATA / NXDOMAIN / no-DS
        // response).
        //
        // The signature matches verifier.Resolver.query so a
        // method-bound reference (or thin wrapper) can be passed
        // directly:
        //
        //   const client = new AuthClient({ servers: ['1.1.1.1'] });
        //   const v = new Verifier({ resolver: { query: client.resolve.bind(client) } });
        resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResourceRecord[]>;
    }
}

AuthClient.prototype.resolve = async function resolve(
    this: AuthClient,
    name: string,
    qtype: number,
    signal?: AbortSignal,
): Promise<ResourceRecord[]> {
    const raw = await this.query(name, qtype, { signal });
    let msg;
    try {
        msg = parse_message(raw);
    } catch (err) {
        throw new AuthResponseError(`parse: ${error_message(err)}`);
    }
    const rcode = msg.header.rcode();
    if (rcode !== 0) {
        throw new AuthResponseError(`RCODE=${rcode}`);
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
        throw new AuthResponseError(`rdata decode: ${error_message(err)}`);
    }
    try {
        const type_name = RRTypeToString(rr.type as ns_type);
        const class_name = RRClassToString(rr.class as ns_class);
        return new ResourceRecord(rr.name, rr.ttl, class_name, type_name, value);
    } catch (err) {
        throw new AuthResponseError(`construct record: ${error_message(err)}`);
    }
}
