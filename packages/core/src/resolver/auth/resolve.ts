// AuthClient.resolve adapter: runs query() and lifts the wire
// response into a structured [ResolverResponse] carrying records,
// the AD bit, and the RCODE from the parsed header.
//
// Ports dnsdata-go `resolver/auth/resolve.go`. UP-009 (this commit)
// replaces the previous bare `ResourceRecord[]` return with a
// `ResolverResponse` so consumers can observe AD / RCODE without
// re-parsing the wire message. A non-zero RCODE is **no longer**
// raised as an `AuthResponseError`; only transport- and parse-level
// failures surface as thrown errors.
//
// The method is defined here (rather than inside client.ts) via
// TypeScript declaration merging so the file layout mirrors the Go
// package's split:
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
import { ResolverResponse } from '../response';
import { AuthClient } from './client';
import { AuthResponseError, error_message } from './errors';

declare module './client' {
    interface AuthClient {
        // Run a DNS query for (name, qtype), parse the response, and
        // return its answer + authority section records together
        // with the AD bit and RCODE from the parsed header.
        //
        // Both sections are included so a verifier can locate
        // NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those
        // in the authority section of a NODATA / NXDOMAIN / no-DS
        // response).
        //
        // A non-zero RCODE is NOT an error: it surfaces in the
        // returned response's `rcode` field. Callers that want the
        // legacy "any non-zero RCODE is fatal" semantics should test
        // `resp.rcode !== 0` after a successful call.
        //
        // The signature matches verifier.Resolver.query so a
        // method-bound reference (or thin wrapper) can be passed
        // directly:
        //
        //   const client = new AuthClient({ servers: ['1.1.1.1'] });
        //   const v = new Verifier({ resolver: { query: client.resolve.bind(client) } });
        resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResolverResponse>;
    }
}

AuthClient.prototype.resolve = async function resolve(
    this: AuthClient,
    name: string,
    qtype: number,
    signal?: AbortSignal,
): Promise<ResolverResponse> {
    const raw = await this.query(name, qtype, { signal });
    let msg;
    try {
        msg = parse_message(raw);
    } catch (err) {
        throw new AuthResponseError(`parse: ${error_message(err)}`);
    }
    const records: ResourceRecord[] = [];
    for (const rr of msg.answer) records.push(raw_to_record(msg.raw, rr));
    for (const rr of msg.authority) records.push(raw_to_record(msg.raw, rr));
    return {
        records,
        ad: msg.header.ad(),
        rcode: msg.header.rcode(),
    };
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
