// Transport-shaped dependency the chain walker uses to fetch DNSSEC
// data. Ports dnsdata-go `verifier/resolver.go`.

import { ResolverResponse } from '../resolver/response';

// Implementations are not required to validate signatures themselves
// — the Verifier does that.
//
// Contract:
//   - name is the fully-qualified, lower-cased, trailing-dot form
//     (the Verifier normalises before calling).
//   - The returned [ResolverResponse] carries every record from the
//     answer and authority sections (including any RRSIG records
//     covering the answer rrset); the Verifier filters by type.
//   - An empty `records` array with no thrown error means "name
//     exists, rrset empty" (NODATA). For NXDOMAIN the response
//     should set `rcode = 3` (or return an empty `records` — v0.1.0
//     treats both as "no records present").
//   - Non-zero RCODE values are surfaced via [ResolverResponse.rcode],
//     not as exceptions. The Verifier classifies them itself.
//   - Network / parse / transport problems should be raised as
//     exceptions so Validate can convert them into
//     [Verdict.Indeterminate] wrapped in [VerifierResolverError].
//   - signal MAY be honoured for cancellation; if the resolver
//     observes an aborted signal it should throw — the Verifier
//     re-wraps it as [VerifierChainTimeoutError].
export interface Resolver {
    query(name: string, qtype: number, signal?: AbortSignal): Promise<ResolverResponse>;
}
