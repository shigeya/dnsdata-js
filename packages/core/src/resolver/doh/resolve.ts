// DoH client `resolve` method: parse the DNS response and surface
// answer + authority records together with the AD bit and RCODE from
// the response header.
//
// Ports the dnsdata-go `resolver/doh/resolve.go` module. UP-009
// (this commit) changes the return shape from a bare
// `ResourceRecord[]` to a `ResolverResponse` so consumers can observe
// the AD bit and distinguish NXDOMAIN / NODATA / SERVFAIL without
// parsing error strings. A non-zero RCODE is **no longer** raised as
// a `DoHResponseError`; only transport- and parse-level failures
// surface as thrown errors.
//
// The method is defined here (rather than in client.ts) via
// TypeScript declaration merging so the file layout mirrors the Go
// package's split:
//
//     dnsdata-go/resolver/doh/resolve.go   ⇄   src/lib/resolver/doh/resolve.ts
//
// Importing this module installs the `resolve` method on DoHClient.
// The package barrel (../doh/index.ts) re-exports both files so any
// downstream import that names DoHClient also picks up the method.

import { to_response } from '../message';
import { ResolverResponse } from '../response';
import { DoHClient } from './client';
import { DoHResponseError } from './errors';

declare module './client' {
    interface DoHClient {
        // Run a DoH query for (name, qtype), parse the response, and
        // return its answer + authority section records together with
        // the AD bit and RCODE from the parsed header.
        //
        // Both sections are included so the verifier can locate
        // NSEC / NSEC3 negative proofs (RFC 4035 §3.1.3 places those
        // in the authority section of a NODATA / NXDOMAIN / no-DS
        // response). The additional section is intentionally ignored
        // — it carries glue and EDNS OPT, neither of which is part of
        // the validated rrset surface.
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
        //   const client = new DoHClient();
        //   const v = new Verifier({ resolver: { query: client.resolve.bind(client) } });
        resolve(name: string, qtype: number, signal?: AbortSignal): Promise<ResolverResponse>;
    }
}

DoHClient.prototype.resolve = async function resolve(
    this: DoHClient,
    name: string,
    qtype: number,
    signal?: AbortSignal,
): Promise<ResolverResponse> {
    const raw = await this.query(name, qtype, { signal });
    // A parse failure carries the parser's message alone, as it always has.
    return to_response(raw, (step, message) =>
        new DoHResponseError(step === 'parse' ? message : `${step}: ${message}`));
};
