// Shared response shape returned by every DNS resolver backend in
// this module (resolver/auth, resolver/doh, and any future
// transport).
//
// Ports dnsdata-go `resolver/resolver.go` (UP-009). The Go side
// expresses this as `type Response { Records, AD, RCode }` exported
// from a new `resolver` package; we expose the same shape as a
// TypeScript interface re-exported from each transport's barrel.
//
// Backends populate Response verbatim from the wire-format header
// and answer + authority sections. RCODE classification is left to
// the caller: transport-level failures (network, parse, HTTP) come
// back as thrown errors, while a parsed DNS response — including
// SERVFAIL, NXDOMAIN, and other non-zero RCODEs — comes back as a
// resolved Response with `rcode` populated. Callers that need to
// treat non-zero RCODE as an error (such as Verifier) should do so
// explicitly.

import { ResourceRecord } from '../zone/dns_zone';

// Response is the structured return of a single resolver query. It
// carries the answer + authority records together with the two
// header fields callers commonly want to observe directly:
//
//   - ad: the responder's "I validated this" claim (RFC 4035 §3).
//     Only trustworthy on a channel you trust; meaningless for
//     direct authoritative queries.
//   - rcode: the low 4 bits of the response flags
//     (RFC 1035 §4.1.1). 0 (NOERROR) is the success case; non-zero
//     values are returned as data so callers can distinguish
//     NXDOMAIN from NODATA from SERVFAIL without parsing error
//     strings.
export interface ResolverResponse {
    records: ResourceRecord[];
    ad: boolean;
    rcode: number;
}
