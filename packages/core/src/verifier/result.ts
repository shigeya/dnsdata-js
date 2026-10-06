// Result + supporting types returned by Verifier.validate.
// Ports dnsdata-go `verifier/result.go` + the internal hopOutcome
// shape used as the return value of one chain-walk hop.

import { Verdict } from './verdict';
import type { ReasonCode } from './reason';
import type { SigStatus } from '../dnssec/sigcheck';

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
    // The DS records at the parent that authorised the descent into the
    // zone (absent for the root).
    dsDigests?: DSSummary[];
    // The DNSKEY that verified the zone's DNSKEY rrset (the KSK). Absent
    // if validation did not reach this step, including on the step of
    // the zone where a Bogus chain failed.
    signedBy?: KeySummary;
    // signatures lists the outcome of every RRSIG examined for this
    // zone, in the order checked: the DS rrset that authorised the
    // descent into the zone (signed by the parent; none for the root),
    // the zone's DNSKEY rrset, then the positive rrsets the walker
    // verified in the zone (the answer, CNAME and DNAME rrsets). The
    // NSEC / NSEC3 records of denial proofs are not listed. A Bogus
    // chain ends with a step for the zone where it failed, holding the
    // checks that failed (dnskeys and dsDigests may then be partial).
    // Absent when empty.
    signatures?: SigCheck[];
}

// SigCheck is the outcome of checking one RRSIG. result is the
// classification DNSSecZone.check_rrsig makes, shared with
// Result.reasonCode. A KSK's RRSIG over the DNSKEY rrset counts as
// verified once the KSK matches its DS (or trust anchor).
export interface SigCheck {
    // name and rrType identify the covered rrset (rrType is the RRSIG's
    // type covered).
    name:       string;
    rrType:     number;
    keyTag:     number;
    algorithm:  number;
    signer:     string;
    // The RRSIG's validity window, as RFC 3339 UTC strings
    // ("2026-01-01T00:00:00Z", Go's time.Time in JSON).
    inception:  string;
    expiration: string;
    result:     SigStatus;
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
    // reasonCode is the machine-readable cause of a failing verdict, one
    // of the ReasonCode values ('sig-expired', 'no-ds', ...). Set
    // whenever the verdict is Bogus or Insecure, and on the
    // Indeterminate Result carried by the VerifierUnsupportedAlgoError
    // validate() rejects with when every signature used an unsupported
    // algorithm ('unsupported-algorithm'). Absent otherwise, including
    // for the secure verdicts. result_error(result) turns it into the
    // matching Error subclass.
    reasonCode?: ReasonCode;
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
    // answer is the RRset that was validated, set only when verdict is
    // [Verdict.Secure] (absent otherwise, so it never carries
    // unvalidated data). After CNAME / DNAME hops it is the terminal
    // RRset; for a wildcard answer it is the synthesised RRset at the
    // query name. Consumers should use this rather than querying the
    // name again, so that what they act on is exactly what was
    // validated.
    answer?: Answer;
}

// Answer is a validated RRset with the signatures that verified it.
export interface Answer {
    name:       string;
    type:       number;
    records:    AnswerRecord[];
    signatures: AnswerSignature[];
}

// AnswerRecord is one record of a validated RRset. value is the
// presentation form as received (RFC 3597 `\# …` for types the library
// does not decode); rdata is the base64 of the RDATA octets the
// signature covered (Go's []byte in JSON; Result stays plain JSON).
export interface AnswerRecord {
    name:  string;
    ttl:   number;
    class: number;
    type:  number;
    value: string;
    rdata: string;
}

// AnswerSignature describes an RRSIG over the answer that verified at
// the verifier's clock: who signed it and its validity window, as
// RFC 3339 UTC strings ("2026-01-01T00:00:00Z", Go's time.Time in JSON).
export interface AnswerSignature {
    keyTag:     number;
    algorithm:  number;
    signer:     string;
    labels:     number;
    inception:  string;
    expiration: string;
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
// For a CNAME `from` is the name queried in this hop; for a DNAME it is
// an ancestor of it. The name queried in a hop is the original qname
// for the first hop and the previous hop's `target` after that.
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
    reasonCode?:     ReasonCode;
    alias?:          AliasStep;
    wildcard?:       WildcardInfo;
    // answer is the verified RRset of a terminal positive hop.
    answer?:         Answer;
}
