// Six-state DNSSEC verdict and the worst-of combinator used by the
// chain walker. Ports dnsdata-go `verifier/verdict.go`.

// The six-state classification refining RFC 4033 §5. The original four
// strings ("secure", "insecure", "bogus", "indeterminate") keep their
// exact spellings so older JSON consumers continue to switch on them
// correctly; the two secure-negative additions use dash-separated names
// so unknown-aware readers can route them to a generic handler and
// upgrade later (DESIGN decision 12 in dnsdata-go UP-004).
export enum Verdict {
    Indeterminate   = 'indeterminate',
    Secure          = 'secure',
    // SecureNoData: the chain reached a signed zone, the qname exists,
    // and the zone produced a valid NSEC/NSEC3 proof that no rrset of
    // the requested qtype is present (RFC 4035 §5.4 / RFC 5155 §8.5).
    SecureNoData    = 'secure-nodata',
    // SecureNXDomain: the chain reached a signed zone, the qname does
    // not exist, and the zone produced a valid NSEC/NSEC3 proof of
    // non-existence including wildcard non-existence (RFC 4035 §5.4 /
    // RFC 5155 §8.4).
    SecureNXDomain  = 'secure-nxdomain',
    Insecure        = 'insecure',
    Bogus           = 'bogus',
}

// MAX_ALIAS_HOPS caps the number of CNAME / DNAME redirections a
// single validate() call is willing to follow. RFC 1035 leaves the
// limit to implementations; popular validators settle near 8–16. We
// use 10 to match dnsdata-go and surface pathological chains quickly
// while still serving real-world redirects (loop-detection by
// re-occurring qname catches the trivial ping-pong cases earlier).
export const MAX_ALIAS_HOPS = 10;

// combine_verdicts merges a per-hop verdict into the running total
// using a worst-of policy:
//
//   Bogus > Insecure > Indeterminate > Secure (any kind)
//
// The two secure-negative variants (SecureNoData, SecureNXDomain) are
// treated as equivalent to Secure for the purposes of merging — both
// indicate "the chain reached a signed conclusion". When nothing
// stronger overrides, the most specific Secure flavour (i.e. a
// secure-negative produced by the terminal hop) wins, so callers see
// the most informative successful classification.
//
// Exported for tests.
export function combine_verdicts(a: Verdict, b: Verdict): Verdict {
    if (a === Verdict.Bogus || b === Verdict.Bogus) return Verdict.Bogus;
    if (a === Verdict.Insecure || b === Verdict.Insecure) return Verdict.Insecure;
    if (a === Verdict.Indeterminate || b === Verdict.Indeterminate) return Verdict.Indeterminate;
    // Both are some flavour of Secure.
    if (b === Verdict.Secure) return a;
    return b;
}
