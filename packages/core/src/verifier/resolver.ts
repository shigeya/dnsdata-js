// Transport-shaped dependency the chain walker uses to fetch DNSSEC
// data. Ports dnsdata-go `verifier/resolver.go`.

import { ResourceRecord } from '../zone/dns_zone';

// Implementations are not required to validate signatures themselves
// — the Verifier does that.
//
// Contract:
//   - name is the fully-qualified, lower-cased, trailing-dot form
//     (the Verifier normalises before calling).
//   - The returned array MUST include every record from the answer
//     section, including any RRSIG records covering the answer rrset.
//     The Verifier filters by type.
//   - An empty array with no thrown error means "name exists, rrset
//     empty" (NODATA). v0.1.0 treats NODATA / NXDOMAIN the same way.
//   - Network / parse / transport problems should be raised as
//     exceptions so Validate can convert them into [Verdict.Indeterminate]
//     wrapped in [VerifierResolverError].
//   - signal MAY be honoured for cancellation; if the resolver
//     observes an aborted signal it should throw — the Verifier
//     re-wraps it as [VerifierChainTimeoutError].
export interface Resolver {
    query(name: string, qtype: number, signal?: AbortSignal): Promise<ResourceRecord[]>;
}
