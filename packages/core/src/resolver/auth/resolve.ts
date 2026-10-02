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

import { to_response } from '../message';
import { ResolverResponse } from '../response';
import { AuthClient } from './client';
import { AuthResponseError } from './errors';

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
    return to_response(raw, (step, message) => new AuthResponseError(`${step}: ${message}`));
};
