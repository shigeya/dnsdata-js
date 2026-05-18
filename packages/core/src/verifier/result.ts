// Result + supporting types returned by Verifier.validate.
// Ports dnsdata-go `verifier/result.go` + the internal hopOutcome
// shape used as the return value of one chain-walk hop.

import { Verdict } from './verdict';

export interface KeySummary {
    keyTag: number;
    algorithm: number;
    sep: boolean;
}

export interface DSSummary {
    keyTag: number;
    algorithm: number;
    digestType: number;
}

export interface ZoneStep {
    zone: string;
    dnskeys?: KeySummary[];
    dsDigests?: DSSummary[];
    signedBy?: KeySummary;
}

// Presentation-form RR values keyed by zone / owner so consumers
// (mailsec-probe Signals, audit views) can render the evidence
// without re-querying. Mirrors dnsdata-go `verifier.Evidence`.
export interface Evidence {
    dnskeys: Record<string, string[]>;
    dses:    Record<string, string[]>;
    // Composite key "<name>/<rrtype>" so signatures stay separable
    // per rrset.
    rrsigs:  Record<string, string[]>;
}

export interface Result {
    verdict: Verdict;
    chain: ZoneStep[];
    // insecureAt names the zone where the secure chain broke into an
    // insecure delegation (NSEC/NSEC3 proof of no-DS at the parent).
    // Empty for non-Insecure verdicts.
    insecureAt?: string;
    // insecureReason is a short, human-readable label paired with
    // insecureAt — typically naming which NSEC/NSEC3 produced the proof.
    insecureReason?: string;
    bogusAt?: string;
    bogusReason?: string;
    // negativeReason is a short, human-readable label paired with the
    // [Verdict.SecureNoData] and [Verdict.SecureNXDomain] verdicts,
    // naming the NSEC/NSEC3 record(s) that produced the proof. Empty
    // for other verdicts.
    negativeReason?: string;
    // aliases enumerates every CNAME / DNAME redirection the chain
    // walker followed before reaching the terminal qname. Empty when
    // the original qname has the requested rrset (or a negative proof)
    // directly. The terminal qname is the `target` of the last entry,
    // NOT itself an alias step.
    aliases?: AliasStep[];
    // wildcard is set when the terminal positive answer was produced
    // by wildcard expansion (RFC 4035 §5.3.4). It carries the
    // reconstructed wildcard owner, the closest encloser, the
    // next-closer name whose non-existence was proven, and a short
    // reason string naming the NSEC/NSEC3 that produced the proof.
    // The verdict on a properly-proven wildcard remains
    // [Verdict.Secure]; consumers that need to distinguish "real
    // rrset" from "wildcard-synthesised rrset" check this field.
    wildcard?: WildcardInfo;
    evidence: Evidence;
}

// WildcardInfo describes a wildcard-synthesised positive answer.
//
// source is the reconstructed wildcard owner the validator used for
// digest computation (e.g. "*.example.com."). closestEncloser is the
// deepest ancestor of the qname that exists in the zone (the same
// labels that, prefixed with "*.", form the wildcard owner).
// nextCloser is the closestEncloser's child along qname's path —
// the name whose non-existence the validator proved via NSEC or
// NSEC3. proofReason is a short, human-readable label naming the
// NSEC / NSEC3 record(s) that produced the proof.
export interface WildcardInfo {
    source:          string;
    closestEncloser: string;
    nextCloser:      string;
    proofReason:     string;
}

// AliasStep records one CNAME or DNAME hop encountered during
// resolution. Each hop is a signed redirect from `from` (the CNAME or
// DNAME owner) to `target` (the rewritten qname for the next hop).
// `zone` names the zone that signed the redirect, and `verdict` is
// the per-hop classification — useful for callers that want to know
// which hop introduced the worst-of contribution to the overall
// verdict.
export interface AliasStep {
    type:    'cname' | 'dname';
    from:    string;
    target:  string;
    zone:    string;
    verdict: Verdict;
}

// HopOutcome is the inner result of one validate_one_hop call.
// Exactly one of {terminal verdict, alias} is meaningful: when alias
// is non-null the outer Validate loop should redirect to alias.target
// and run the next hop; otherwise the hop is terminal and verdict is
// the answer.
//
// Cross-file internal: chain.ts produces it, alias.ts/wildcard.ts/
// the negative-proof modules contribute to its shape.
export interface HopOutcome {
    verdict:         Verdict;
    bogusAt?:        string;
    bogusReason?:    string;
    insecureAt?:     string;
    insecureReason?: string;
    negativeReason?: string;
    alias?:          AliasStep;
    wildcard?:       WildcardInfo;
}
