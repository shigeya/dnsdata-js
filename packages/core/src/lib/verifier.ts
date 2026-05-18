// DNSSEC chain-of-trust validator with pluggable Resolver
//
// Ported from dnsdata-go `verifier/` package (Go → TS feedback channel,
// tracked as UPSTREAM_FEEDBACK.md UP-001 in the Go repo and
// shigeya/dnsdata-js#5 here).
//
// Scope (v0.1.0): positive validation only — every zone on the path
// from the root down to qname has a usable DNSKEY rrset and the
// qname's rrset is signed by that zone's keys. Negative proofs
// (NSEC / NSEC3 NODATA / NXDOMAIN, Insecure-vs-Bogus distinction at
// a no-DS delegation), CNAME / DNAME chasing, and wildcard
// synthesis are tracked separately (#8, #9, #10).
//
// A note on the descent loop: when the parent zone returns *no* DS
// for a candidate child name we MUST continue walking deeper
// descendants against the same currentZone, NOT bail out to leaf
// resolution. Bailing out leaf-resolves qname under a shallower
// zone's keys whenever an empty non-terminal sits between two real
// cuts (e.g. "ad.jp." between "jp." and "wide.ad.jp."). That class
// of name covers a meaningful slice of `.jp` / `.uk` mail-security
// records, so getting the loop right matters.

import * as crypto from 'crypto';
import { ResourceRecord } from './dns_zone';
import { DNSSecZone, KeyVerifyMode } from './dnssec_zone';
import {
    DNSKey,
    DNSRR_DS,
    DNSRR_NSEC,
    DNSRR_NSEC3,
    owner_hash_from_name,
} from './dnssec_rr';
import { StringToRRType, RRTypeToString } from './dns_type_table';
import {
    equal_canonical_names,
    label_count,
    last_n_labels,
} from './dnssec_util';
import {
    BUILTIN_ROOT_ANCHORS,
    RootAnchors,
} from './root_anchors';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS     = StringToRRType('DS');
const TYPE_RRSIG  = StringToRRType('RRSIG');
const TYPE_NSEC   = StringToRRType('NSEC');
const TYPE_NSEC3  = StringToRRType('NSEC3');
const TYPE_CNAME  = StringToRRType('CNAME');
const TYPE_DNAME  = StringToRRType('DNAME');

//////////////////////////////////////////////////////////// Verdict

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

//////////////////////////////////////////////////////////// Resolver

// Transport-shaped dependency the chain walker uses to fetch DNSSEC
// data. Implementations are not required to validate signatures
// themselves — the Verifier does that.
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

//////////////////////////////////////////////////////////// Errors

// All verifier-thrown errors inherit from VerifierError so callers
// can route them through one `instanceof` check at the outer
// boundary while still discriminating by subclass when they care.

export class VerifierError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierError';
    }
}

export class VerifierConfigError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierConfigError';
    }
}

export class VerifierInvalidQNameError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierInvalidQNameError';
    }
}

export class VerifierResolverError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause: unknown) {
        super(message);
        this.name = 'VerifierResolverError';
        this.cause = cause;
    }
}

export class VerifierChainTimeoutError extends VerifierError {
    public readonly cause: unknown;
    constructor(message: string, cause?: unknown) {
        super(message);
        this.name = 'VerifierChainTimeoutError';
        this.cause = cause;
    }
}

export class VerifierTrustAnchorMismatchError extends VerifierError {
    constructor(message: string) {
        super(message);
        this.name = 'VerifierTrustAnchorMismatchError';
    }
}

//////////////////////////////////////////////////////////// Result types

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

// MAX_ALIAS_HOPS caps the number of CNAME / DNAME redirections a
// single validate() call is willing to follow. RFC 1035 leaves the
// limit to implementations; popular validators settle near 8–16. We
// use 10 to match dnsdata-go and surface pathological chains quickly
// while still serving real-world redirects (loop-detection by
// re-occurring qname catches the trivial ping-pong cases earlier).
export const MAX_ALIAS_HOPS = 10;

// HopOutcome is the inner result of one validate_one_hop call.
// Exactly one of {terminal verdict, alias} is meaningful: when alias
// is non-null the outer Validate loop should redirect to alias.target
// and run the next hop; otherwise the hop is terminal and verdict is
// the answer.
interface HopOutcome {
    verdict:         Verdict;
    bogusAt?:        string;
    bogusReason?:    string;
    insecureAt?:     string;
    insecureReason?: string;
    negativeReason?: string;
    alias?:          AliasStep;
    wildcard?:       WildcardInfo;
}

//////////////////////////////////////////////////////////// Verifier

export interface VerifierOptions {
    // Required. Transport-shaped dependency that returns the answer
    // section for a (name, qtype) pair.
    resolver: Resolver;

    // Optional. Override the built-in IANA root anchors — useful for
    // test setups that mint their own root KSK.
    trustAnchors?: RootAnchors;

    // Optional. Source of "now" used when comparing against RRSIG
    // inception / expire windows. v0.1.0's underlying verify_rrsig
    // does not yet consult the clock; this option is accepted for
    // API parity with dnsdata-go and reserved for the expiry-check
    // pass that lands with UP-006 (wildcard) / SHOULD #13.
    now?: () => Date;
}

export class Verifier {
    private readonly resolver: Resolver;
    private readonly anchors: RootAnchors;
    // Reserved; consulted once verify_rrsig grows a validity-window
    // check (currently unused — kept for API parity with the Go side).
    private readonly _now: () => Date;

    constructor(opts: VerifierOptions) {
        if (!opts || !opts.resolver) {
            throw new VerifierConfigError('verifier: resolver is required');
        }
        this.resolver = opts.resolver;
        this.anchors = opts.trustAnchors ?? BUILTIN_ROOT_ANCHORS;
        this._now = opts.now ?? (() => new Date());
        // Force handler registration. dnssec_rr.ts performs this at
        // import time; the explicit reference here documents the
        // dependency and matches the Go side's `NewVerifier` →
        // `RegisterHandlers()` call (the registry is idempotent).
        void DNSKey; void DNSRR_DS;
    }

    // Walks the DNSSEC chain of trust from the root zone down to
    // (qname, qtype), chasing CNAME / DNAME redirections up to
    // [MAX_ALIAS_HOPS] hops, and returns the combined classification.
    //
    // The final verdict is the worst-of across every hop: any Bogus
    // hop yields Bogus, any Insecure hop yields Insecure, any
    // Indeterminate hop yields Indeterminate, otherwise Secure (or the
    // terminal hop's secure-negative variant). Aliases are recorded
    // in result.aliases in the order they were followed; the terminal
    // qname is the `target` of the last alias.
    //
    // Returns Result.verdict = Bogus for verified-but-broken chains
    // (including alias loops and hop-count overflow); throws
    // (VerifierError or subclass) when the chain could not be walked
    // at all (resolver failure, abort, invalid qname).
    async validate(qname: string, qtype: number, signal?: AbortSignal): Promise<Result> {
        if (!qname) {
            throw new VerifierInvalidQNameError('verifier: qname is empty');
        }
        const result: Result = {
            verdict: Verdict.Indeterminate,
            chain: [],
            evidence: { dnskeys: {}, dses: {}, rrsigs: {} },
        };

        let currentQname = normalize_qname(qname);
        const seen = new Set<string>();
        let combined: Verdict = Verdict.Indeterminate;
        let combinedSet = false;

        for (let hop = 0; hop <= MAX_ALIAS_HOPS; hop++) {
            check_aborted(signal);
            if (seen.has(currentQname)) {
                result.verdict = Verdict.Bogus;
                result.bogusAt = currentQname;
                result.bogusReason = 'alias loop detected';
                return result;
            }
            seen.add(currentQname);

            const outcome = await this.validate_one_hop(currentQname, qtype, result, signal);

            if (!combinedSet) {
                combined = outcome.verdict;
                combinedSet = true;
            } else {
                combined = combine_verdicts(combined, outcome.verdict);
            }

            if (outcome.alias) {
                outcome.alias.verdict = outcome.verdict;
                if (!result.aliases) result.aliases = [];
                result.aliases.push(outcome.alias);
                currentQname = outcome.alias.target;
                continue;
            }

            result.verdict = combined;
            // Carry the terminal hop's diagnostic strings so the
            // reported location matches the final verdict.
            if (outcome.bogusAt)       result.bogusAt = outcome.bogusAt;
            if (outcome.bogusReason)   result.bogusReason = outcome.bogusReason;
            if (outcome.insecureAt)    result.insecureAt = outcome.insecureAt;
            if (outcome.insecureReason) result.insecureReason = outcome.insecureReason;
            if (outcome.negativeReason) result.negativeReason = outcome.negativeReason;
            if (outcome.wildcard)      result.wildcard = outcome.wildcard;
            return result;
        }

        // Alias chain longer than MAX_ALIAS_HOPS without resolving.
        result.verdict = Verdict.Bogus;
        result.bogusAt = currentQname;
        result.bogusReason = `alias chain exceeded ${MAX_ALIAS_HOPS} hops`;
        return result;
    }

    // validate_one_hop runs a single chain walk + leaf resolution
    // against (qname, qtype). It mutates result.chain / result.evidence
    // as it walks, but does NOT touch result.verdict / result.aliases
    // — that is validate()'s responsibility.
    private async validate_one_hop(qname: string, qtype: number, result: Result, signal?: AbortSignal): Promise<HopOutcome> {
        // Step 1: load + verify the root zone.
        const rootZone = new DNSSecZone();
        await this.load_records(rootZone, '.', TYPE_DNSKEY, result, signal);

        const rootKSK = this.match_ksk_with_anchors(rootZone);
        if (!rootKSK) {
            return {
                verdict: Verdict.Bogus,
                bogusAt: '.',
                bogusReason: 'root KSK does not match any configured trust anchor',
            };
        }
        rootZone.add_sep('.');
        if (!rootZone.verify_rrset('.', TYPE_DNSKEY, KeyVerifyMode.KSK)) {
            return {
                verdict: Verdict.Bogus,
                bogusAt: '.',
                bogusReason: 'root DNSKEY rrset signature did not verify',
            };
        }
        if (!zone_already_in_chain(result, '.')) {
            result.chain.push(summarize_zone('.', rootZone, rootKSK));
        }

        // Step 2: descend through each label boundary that is actually
        // a zone cut. Empty non-terminals (no DS, but a deeper name IS
        // a cut) must be skipped, not treated as the leaf.
        let currentZone = rootZone;
        let currentName = '.';
        for (const childName of descendant_zones(qname)) {
            check_aborted(signal);

            const dsCount = await this.load_records(currentZone, childName, TYPE_DS, result, signal);
            if (dsCount === 0) {
                // Before treating childName as a non-cut, see whether
                // the resolver also handed us NSEC / NSEC3 records that
                // prove no DS exists at childName (RFC 4035 §5.4 /
                // RFC 5155 §8.9). A valid proof classifies this
                // delegation as Insecure; absence of proof keeps the
                // legacy "continue past non-cut" behaviour so callers
                // that ask for DS at a non-zone-cut name (e.g. qname
                // itself) still descend correctly.
                const proof = this.prove_no_ds(currentZone, childName);
                if (proof) {
                    return {
                        verdict: Verdict.Insecure,
                        insecureAt: childName,
                        insecureReason: proof,
                    };
                }
                continue;
            }

            if (!currentZone.verify_rrset(childName, TYPE_DS)) {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: childName,
                    bogusReason: `DS rrset for ${childName} did not verify under ${currentName}`,
                };
            }

            const childZone = new DNSSecZone();
            childZone.parent = currentZone;
            await this.load_records(childZone, childName, TYPE_DNSKEY, result, signal);

            const childKSK = match_ksk_with_ds(childZone, currentZone, childName);
            if (!childKSK) {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: childName,
                    bogusReason: `no DNSKEY at ${childName} matched a DS record in ${currentName}`,
                };
            }
            childZone.add_sep(childName);
            if (!childZone.verify_rrset(childName, TYPE_DNSKEY, KeyVerifyMode.KSK)) {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: childName,
                    bogusReason: `DNSKEY rrset for ${childName} did not verify under its own KSK`,
                };
            }

            if (!zone_already_in_chain(result, childName)) {
                result.chain.push(summarize_zone(childName, childZone, childKSK));
            }
            currentZone = childZone;
            currentName = childName;
        }

        check_aborted(signal);
        return this.resolve_leaf(currentZone, currentName, qname, qtype, result, signal);
    }

    // resolve_leaf handles the final step of a hop: load qname/qtype
    // into currentZone and either return a terminal verdict or surface
    // an alias hop. CNAME at qname and DNAME at any proper ancestor of
    // qname are followed; a missing rrset falls through to NSEC /
    // NSEC3 negative proofs.
    private async resolve_leaf(currentZone: DNSSecZone, currentName: string, qname: string, qtype: number, result: Result, signal?: AbortSignal): Promise<HopOutcome> {
        const added = await this.load_records(currentZone, qname, qtype, result, signal);
        if (added > 0) {
            if (!currentZone.verify_rrset(qname, qtype)) {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: currentName,
                    bogusReason: `RRSIG over ${qname}/${qtype_mnemonic(qtype)} did not verify under ${currentName}`,
                };
            }
            // Verified. RFC 4035 §5.3.2: if the covering RRSIG's Labels
            // field indicates wildcard synthesis, §5.3.4 also requires
            // a proof that the next-closer name does not exist —
            // otherwise the wildcard rrset could be replayed at a name
            // that actually has its own rrset.
            const wc = detect_wildcard(currentZone, qname, qtype);
            if (wc) {
                const proof = prove_qname_non_existence(currentZone, wc.nextCloser);
                if (!proof) {
                    return {
                        verdict: Verdict.Bogus,
                        bogusAt: currentName,
                        bogusReason: `wildcard synthesis at ${wc.source} lacks non-existence proof for ${wc.nextCloser}`,
                    };
                }
                return {
                    verdict: Verdict.Secure,
                    wildcard: { ...wc, proofReason: proof },
                };
            }
            return { verdict: Verdict.Secure };
        }

        // qtype rrset is absent. Look for a CNAME (at qname) or DNAME
        // (at a proper ancestor) BEFORE declaring NODATA. The resolver
        // may have placed those records into currentZone while answering
        // the qtype query — real DNS responses include CNAME/DNAME at
        // the same name even when the question asked for, say, A.
        // The Validate outer loop will start a fresh chain walk for the
        // rewritten target on the next hop.
        const cname = this.try_cname(currentZone, currentName, qname);
        if (cname) return cname;
        const dname = this.try_dname(currentZone, currentName, qname);
        if (dname) return dname;

        // No alias — fall back to negative-existence proofs.
        const noData = this.prove_no_data(currentZone, qname, qtype);
        if (noData) {
            return { verdict: Verdict.SecureNoData, negativeReason: noData };
        }
        const nxDomain = this.prove_nx_domain(currentZone, qname);
        if (nxDomain) {
            return { verdict: Verdict.SecureNXDomain, negativeReason: nxDomain };
        }
        return { verdict: Verdict.Indeterminate };
    }

    // try_cname looks for a CNAME rrset at qname inside currentZone,
    // verifies its signature against currentZone's keys, and packages
    // it as an AliasStep hop for validate()'s outer loop to chase.
    //
    // Returns null when no CNAME is present — the caller then tries
    // DNAME or negative-proof handling. A CNAME present but failing
    // signature verification returns a hop whose verdict is Bogus.
    private try_cname(currentZone: DNSSecZone, currentName: string, qname: string): HopOutcome | null {
        const rrset = currentZone.find_rrset(qname, TYPE_CNAME);
        if (rrset.length === 0) return null;

        const target = normalize_qname(rrset[0].value);
        if (target === '' || target === '.') {
            return {
                verdict: Verdict.Bogus,
                bogusAt: qname,
                bogusReason: 'CNAME target is empty',
            };
        }
        if (!currentZone.verify_rrset(qname, TYPE_CNAME)) {
            return {
                verdict: Verdict.Bogus,
                bogusAt: currentName,
                bogusReason: `RRSIG over ${qname}/CNAME did not verify`,
            };
        }
        return {
            verdict: Verdict.Secure,
            alias: {
                type:   'cname',
                from:   qname,
                target,
                zone:   currentName,
                verdict: Verdict.Secure,
            },
        };
    }

    // try_dname looks for a DNAME at any proper ancestor of qname.
    // RFC 6672 §3 specifies that a DNAME at OWNER rewrites every name
    // BELOW (not equal to) owner under the DNAME's target. Walks
    // qname's ancestors longest-first; the first one carrying a DNAME
    // wins. The synthesised qname is strict suffix replacement of
    // OWNER with TARGET.
    private try_dname(currentZone: DNSSecZone, currentName: string, qname: string): HopOutcome | null {
        for (const anc of ancestors_of(qname)) {
            if (equal_canonical_names(anc, qname)) {
                // DNAME at qname itself does not synthesise (RFC 6672 §3.1).
                continue;
            }
            const rrset = currentZone.find_rrset(anc, TYPE_DNAME);
            if (rrset.length === 0) continue;

            const target = normalize_qname(rrset[0].value);
            if (target === '' || target === '.') {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: anc,
                    bogusReason: 'DNAME target is empty',
                };
            }
            if (!currentZone.verify_rrset(anc, TYPE_DNAME)) {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: currentName,
                    bogusReason: `RRSIG over ${anc}/DNAME did not verify`,
                };
            }
            const synth = synthesise_dname_target(qname, anc, target);
            if (synth === '') {
                return {
                    verdict: Verdict.Bogus,
                    bogusAt: anc,
                    bogusReason: `DNAME at ${anc} could not synthesise target for ${qname}`,
                };
            }
            return {
                verdict: Verdict.Secure,
                alias: {
                    type:   'dname',
                    from:   qname,
                    target: synth,
                    zone:   currentName,
                    verdict: Verdict.Secure,
                },
            };
        }
        return null;
    }

    // Issues one resolver Query and appends every returned record to
    // z, capturing presentation values into result.evidence. Returns
    // the number of records matching qtype (so the caller can detect
    // a missing rrset).
    private async load_records(
        z: DNSSecZone,
        name: string,
        qtype: number,
        result: Result,
        signal?: AbortSignal,
    ): Promise<number> {
        check_aborted(signal);
        let records: ResourceRecord[];
        try {
            records = await this.resolver.query(name, qtype, signal);
        } catch (err: unknown) {
            if (is_abort_error(err) || signal?.aborted) {
                throw new VerifierChainTimeoutError(
                    `verifier: chain walk aborted while querying ${name}/${qtype_mnemonic(qtype)}`,
                    err,
                );
            }
            throw new VerifierResolverError(
                `verifier: resolver failed for ${name}/${qtype_mnemonic(qtype)}: ${error_message(err)}`,
                err,
            );
        }

        let matching = 0;
        for (const rr of records) {
            z.add_rr(rr);
            if (rr.type === TYPE_DNSKEY) {
                push_evidence(result.evidence.dnskeys, rr.label, rr.value);
            } else if (rr.type === TYPE_DS) {
                push_evidence(result.evidence.dses, rr.label, rr.value);
            } else if (rr.type === TYPE_RRSIG) {
                const key = `${rr.label}/${qtype_mnemonic(qtype)}`;
                push_evidence(result.evidence.rrsigs, key, rr.value);
            }
            if (rr.type === qtype) matching++;
        }
        return matching;
    }

    // Returns the first SEP-flagged DNSKEY in the root zone whose
    // DS digest matches one of the configured trust anchors.
    private match_ksk_with_anchors(rootZone: DNSSecZone): DNSKey | null {
        if (!this.anchors.ds || this.anchors.ds.length === 0) {
            return null;
        }
        const dnskeys = rootZone.find_rrset('.', TYPE_DNSKEY);
        for (const rr of dnskeys) {
            const handler = rr.get_handler();
            if (!(handler instanceof DNSKey) || !handler.is_secure_entry_point()) continue;
            for (const anchor of this.anchors.ds) {
                if (anchor.keyTag !== handler.key_tag || anchor.algorithm !== handler.algorithm) {
                    continue;
                }
                if (verify_anchor_digest(handler, anchor)) {
                    return handler;
                }
            }
        }
        return null;
    }

    //////////////////////////////////////////////////////// negative proofs

    // prove_no_ds attempts to prove from parent that childName has no
    // DS record. Returns a short human-readable reason on success, or
    // null when no usable proof is present.
    //
    // Signature verification failures simply skip that candidate proof;
    // the verifier's job here is to *try* and quietly give up if it
    // can't (RFC 4035 §5.4 / RFC 5155 §8.9).
    private prove_no_ds(parent: DNSSecZone, childName: string): string | null {
        const nsec = prove_no_ds_with_nsec(parent, childName);
        if (nsec) return nsec;
        return prove_no_ds_with_nsec3(parent, childName);
    }

    // prove_no_data attempts to prove from z that qname exists but no
    // rrset of qtype is present (RFC 4035 §5.4 / RFC 5155 §8.5).
    private prove_no_data(z: DNSSecZone, qname: string, qtype: number): string | null {
        const nsec = prove_no_data_with_nsec(z, qname, qtype);
        if (nsec) return nsec;
        return prove_no_data_with_nsec3(z, qname, qtype);
    }

    // prove_nx_domain attempts to prove from z that qname does not
    // exist as any rrset (RFC 4035 §5.4 NSEC; RFC 5155 §8.4 NSEC3
    // three-record closest-encloser proof). Both proof shapes also
    // require a wildcard non-existence component — otherwise a zone
    // with a wildcard could lie about NXDOMAIN by suppressing the
    // wildcard answer.
    private prove_nx_domain(z: DNSSecZone, qname: string): string | null {
        const nsec = prove_nx_domain_with_nsec(z, qname);
        if (nsec) return nsec;
        return prove_nx_domain_with_nsec3(z, qname);
    }
}

//////////////////////////////////////////////////////////// Helpers

// Returns the proper-suffix zone names of qname from shallowest to
// deepest, excluding the root and INCLUDING qname itself. The
// inclusion of qname lets the descent loop notice a "qname is not a
// cut" case (no DS at qname → leaf resolution).
//
//   "www.example.com." → ["com.", "example.com.", "www.example.com."]
//
// Exported for tests.
export function descendant_zones(qname: string): string[] {
    qname = normalize_qname(qname);
    if (qname === '.') return [];
    const trimmed = qname.endsWith('.') ? qname.slice(0, -1) : qname;
    const labels = trimmed.split('.');
    const out: string[] = [];
    for (let i = labels.length - 1; i >= 0; i--) {
        out.push(labels.slice(i).join('.') + '.');
    }
    return out;
}

// Lower-cases qname and ensures it ends with a single trailing dot.
// Exported for tests.
export function normalize_qname(s: string): string {
    const trimmed = s.trim().toLowerCase();
    if (trimmed === '') return '.';
    return trimmed.endsWith('.') ? trimmed : trimmed + '.';
}

// Canonical RR-type mnemonic, falling back to "TYPE<n>" for unknown
// codes — matches presentation-form rendering.
function qtype_mnemonic(t: number): string {
    try {
        return RRTypeToString(t);
    } catch {
        return `TYPE${t}`;
    }
}

function push_evidence(into: Record<string, string[]>, key: string, value: string): void {
    const list = into[key];
    if (list) list.push(value);
    else into[key] = [value];
}

function summarize_zone(zoneName: string, z: DNSSecZone, ksk: DNSKey): ZoneStep {
    const step: ZoneStep = { zone: zoneName };

    const dnskeyRRs = z.find_rrset(zoneName, TYPE_DNSKEY);
    if (dnskeyRRs.length > 0) {
        step.dnskeys = [];
        for (const rr of dnskeyRRs) {
            const h = rr.get_handler();
            if (h instanceof DNSKey) {
                step.dnskeys.push({
                    keyTag: h.key_tag,
                    algorithm: h.algorithm,
                    sep: h.is_secure_entry_point(),
                });
            }
        }
    }

    const dsRRs = z.find_rrset(zoneName, TYPE_DS);
    if (dsRRs.length > 0) {
        step.dsDigests = [];
        for (const rr of dsRRs) {
            const h = rr.get_handler();
            if (h instanceof DNSRR_DS) {
                step.dsDigests.push({
                    keyTag: h.key_tag,
                    algorithm: h.algorithm,
                    digestType: h.digest_type,
                });
            }
        }
    }

    step.signedBy = {
        keyTag: ksk.key_tag,
        algorithm: ksk.algorithm,
        sep: ksk.is_secure_entry_point(),
    };
    return step;
}

// Returns the first SEP-flagged DNSKEY in childZone whose DS digest
// matches one of the DS records present at parentZone under childName.
function match_ksk_with_ds(childZone: DNSSecZone, parentZone: DNSSecZone, childName: string): DNSKey | null {
    const dnskeys = childZone.find_rrset(childName, TYPE_DNSKEY);
    const dsRRs = parentZone.find_rrset(childName, TYPE_DS);
    if (dnskeys.length === 0 || dsRRs.length === 0) return null;

    for (const rr of dnskeys) {
        const key = rr.get_handler();
        if (!(key instanceof DNSKey) || !key.is_secure_entry_point()) continue;
        for (const dsRR of dsRRs) {
            const ds = dsRR.get_handler();
            if (!(ds instanceof DNSRR_DS)) continue;
            if (ds.key_tag !== key.key_tag || ds.algorithm !== key.algorithm) continue;
            if (ds.verify_digest(key.get_ds_digest_data())) {
                return key;
            }
        }
    }
    return null;
}

// Computes the DS digest from a candidate DNSKEY and compares it
// against an anchor record drawn from the configured trust-anchor
// set. The crypto algorithm comes from the anchor's digestType,
// matching the existing DS-digest path in dnssec_rr.ts.
function verify_anchor_digest(key: DNSKey, anchor: { digestType: number; digest: string }): boolean {
    const algo = ds_digest_algorithm(anchor.digestType);
    if (!algo) return false;
    const computed = crypto.createHash(algo).update(Buffer.from(key.get_ds_digest_data())).digest();
    const expected = Buffer.from(anchor.digest.replace(/\s+/g, ''), 'hex');
    return computed.equals(expected);
}

function ds_digest_algorithm(digestType: number): string | null {
    switch (digestType) {
        case 1: return 'sha1';
        case 2: return 'sha256';
        case 4: return 'sha384';
        default: return null;
    }
}

function check_aborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
        throw new VerifierChainTimeoutError('verifier: chain walk aborted', signal.reason);
    }
}

function is_abort_error(err: unknown): boolean {
    if (err && typeof err === 'object') {
        const e = err as { name?: string; code?: string };
        if (e.name === 'AbortError') return true;
        if (e.code === 'ABORT_ERR') return true;
    }
    return false;
}

function error_message(err: unknown): string {
    if (err instanceof Error) return err.message;
    return String(err);
}

//////////////////////////////////////////////////////////// negative proofs

// nsec_candidates pairs each NSEC handler in z with its owner name so
// canonical comparisons stay as plain string ops.
interface NsecCandidate {
    owner: string;
    nsec:  DNSRR_NSEC;
}

function nsec_candidates(z: DNSSecZone): NsecCandidate[] {
    const out: NsecCandidate[] = [];
    for (const rr of z.all_records()) {
        if (rr.type !== TYPE_NSEC) continue;
        const h = rr.get_handler();
        if (h instanceof DNSRR_NSEC) {
            out.push({ owner: rr.label, nsec: h });
        }
    }
    return out;
}

// nsec3_candidates pairs each NSEC3 handler in z with its owner name
// and pre-decoded owner-hash bytes. Records whose owner cannot be
// base32hex-decoded are silently skipped (they cannot participate in
// proofs anyway).
interface Nsec3Candidate {
    owner:     string;
    ownerHash: Uint8Array;
    nsec3:     DNSRR_NSEC3;
}

function nsec3_candidates(z: DNSSecZone): Nsec3Candidate[] {
    const out: Nsec3Candidate[] = [];
    for (const rr of z.all_records()) {
        if (rr.type !== TYPE_NSEC3) continue;
        const h = rr.get_handler();
        if (!(h instanceof DNSRR_NSEC3)) continue;
        let hash: Uint8Array;
        try { hash = owner_hash_from_name(rr.label); }
        catch { continue; }
        out.push({ owner: rr.label, ownerHash: hash, nsec3: h });
    }
    return out;
}

// prove_no_ds_with_nsec searches for a matching-owner NSEC at the
// parent with the no-DS bitmap shape. The candidate must verify under
// the parent's keys.
function prove_no_ds_with_nsec(parent: DNSSecZone, childName: string): string | null {
    for (const c of nsec_candidates(parent)) {
        if (!c.nsec.matches_name(c.owner, childName)) continue;
        if (!c.nsec.proves_no_ds()) continue;
        if (!parent.verify_rrset(c.owner, TYPE_NSEC)) continue;
        return `NSEC at ${c.owner} asserts NS without DS`;
    }
    return null;
}

// prove_no_ds_with_nsec3 searches the parent for either:
//   - A matching NSEC3 whose owner-hash equals H(childName) and whose
//     bitmap has the no-DS shape; or
//   - A covering NSEC3 whose range covers H(childName) AND has the
//     opt-out flag set (RFC 5155 §6).
// Matching denial is tried first so the cheap case wins.
function prove_no_ds_with_nsec3(parent: DNSSecZone, childName: string): string | null {
    const cands = nsec3_candidates(parent);
    if (cands.length === 0) return null;

    // Matching denial: owner-hash == hash(childName).
    for (const c of cands) {
        let target: Uint8Array;
        try {
            target = DNSRR_NSEC3.compute_hash(childName, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
        } catch { continue; }
        if (!bytes_equal(target, c.ownerHash)) continue;
        if (!c.nsec3.proves_no_ds()) continue;
        if (!parent.verify_rrset(c.owner, TYPE_NSEC3)) continue;
        return `NSEC3 at ${c.owner} (matching hash) asserts NS without DS`;
    }

    // Covering denial with opt-out.
    for (const c of cands) {
        if (!c.nsec3.has_opt_out()) continue;
        let target: Uint8Array;
        try {
            target = DNSRR_NSEC3.compute_hash(childName, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
        } catch { continue; }
        if (!c.nsec3.covers_hash(c.ownerHash, target)) continue;
        if (!parent.verify_rrset(c.owner, TYPE_NSEC3)) continue;
        return `NSEC3 at ${c.owner} opt-out covers hash of ${childName}`;
    }
    return null;
}

function prove_no_data_with_nsec(z: DNSSecZone, qname: string, qtype: number): string | null {
    for (const c of nsec_candidates(z)) {
        if (!c.nsec.matches_name(c.owner, qname)) continue;
        if (!c.nsec.proves_no_data(qtype)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC)) continue;
        return `NSEC at ${c.owner} asserts qname exists without ${qtype_mnemonic(qtype)}`;
    }
    return null;
}

function prove_no_data_with_nsec3(z: DNSSecZone, qname: string, qtype: number): string | null {
    for (const c of nsec3_candidates(z)) {
        let target: Uint8Array;
        try {
            target = DNSRR_NSEC3.compute_hash(qname, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
        } catch { continue; }
        if (!bytes_equal(target, c.ownerHash)) continue;
        if (!c.nsec3.proves_no_data(qtype)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC3)) continue;
        return `NSEC3 at ${c.owner} asserts qname exists without ${qtype_mnemonic(qtype)}`;
    }
    return null;
}

// prove_nx_domain_with_nsec needs a covering NSEC for qname AND a
// covering (or matching) NSEC for *.<closestEncloser>. The closest
// encloser is derived from the covering NSEC and qname: the longest
// ancestor of qname that is also an ancestor of the NSEC's owner or
// next_domain.
function prove_nx_domain_with_nsec(z: DNSSecZone, qname: string): string | null {
    const cands = nsec_candidates(z);

    // 1. Find any NSEC that covers qname and verifies under z's keys.
    let covering: NsecCandidate | null = null;
    for (const c of cands) {
        if (!c.nsec.covers_name(c.owner, qname)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC)) continue;
        covering = c;
        break;
    }
    if (!covering) return null;

    // 2. Compute the closest-encloser candidate: longest common
    //    ancestor of qname and one of the covering NSEC's range
    //    endpoints. Both endpoints exist as zone names, so any common
    //    ancestor with qname must also exist in the zone.
    const ce = closest_encloser_nsec(qname, covering.owner, covering.nsec.next_domain);
    if (ce === '') return null;
    const wildcard = '*.' + ce;

    // 3. Find an NSEC that either covers or matches *.<ce>. The match
    //    case is acceptable because the wildcard's own bitmap would
    //    still witness "no qname" via the covering NSEC found above.
    for (const c of cands) {
        if (!c.nsec.covers_name(c.owner, wildcard) && !c.nsec.matches_name(c.owner, wildcard)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC)) continue;
        return `NSEC at ${covering.owner} covers ${qname}, NSEC at ${c.owner} denies wildcard ${wildcard}`;
    }
    return null;
}

// prove_nx_domain_with_nsec3 implements the three-NSEC3 closest-
// encloser proof of RFC 5155 §8.4: closest-encloser match, next-closer
// cover, and wildcard cover.
function prove_nx_domain_with_nsec3(z: DNSSecZone, qname: string): string | null {
    const cands = nsec3_candidates(z);
    if (cands.length === 0) return null;

    // Walk ancestors of qname from longest to shortest. The first
    // ancestor whose hash matches some NSEC3's owner-hash is the
    // closest encloser.
    const ancestors = ancestors_of(qname);
    let ce = '';
    let ceOwner = '';
    for (const a of ancestors) {
        for (const c of cands) {
            let target: Uint8Array;
            try {
                target = DNSRR_NSEC3.compute_hash(a, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
            } catch { continue; }
            if (!bytes_equal(target, c.ownerHash)) continue;
            if (!z.verify_rrset(c.owner, TYPE_NSEC3)) continue;
            ce = a;
            ceOwner = c.owner;
            break;
        }
        if (ce !== '') break;
    }
    if (ce === '' || equal_canonical_names(ce, qname)) {
        // qname itself matches → NODATA shape, not NXDOMAIN. Or no
        // ancestor matched at all.
        return null;
    }

    // next-closer name: ce with one more label from qname prepended.
    const nc = next_closer_name(qname, ce);
    if (nc === '') return null;
    const ncOwner = find_covering_nsec3(z, cands, nc);
    if (ncOwner === '') return null;

    // wildcard: "*." + ce, must be covered by some NSEC3.
    const wildcard = '*.' + ce;
    const wcOwner = find_covering_nsec3(z, cands, wildcard);
    if (wcOwner === '') return null;

    return `NSEC3 at ${ceOwner} matches closest encloser ${ce}; ${ncOwner} covers next-closer ${nc}; ${wcOwner} covers wildcard ${wildcard}`;
}

function find_covering_nsec3(z: DNSSecZone, cands: Nsec3Candidate[], target: string): string {
    for (const c of cands) {
        let h: Uint8Array;
        try {
            h = DNSRR_NSEC3.compute_hash(target, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
        } catch { continue; }
        if (!c.nsec3.covers_hash(c.ownerHash, h)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC3)) continue;
        return c.owner;
    }
    return '';
}

// closest_encloser_nsec returns the longest name that is a suffix of
// qname AND a suffix of at least one of {owner, next}. Returns "" if
// no common ancestor exists (qname disjoint from the NSEC's range
// owners, which would itself indicate the response is inconsistent).
function closest_encloser_nsec(qname: string, owner: string, next: string): string {
    let best = '';
    for (const cand of [owner, next]) {
        const anc = longest_common_ancestor(qname, cand);
        if (label_count(anc) > label_count(best)) best = anc;
    }
    return best;
}

// ancestors_of returns qname's ancestors in canonical descending order:
// longest (qname itself) first, root last. Each entry carries the
// trailing dot.
function ancestors_of(qname: string): string[] {
    const normalized = normalize_qname(qname);
    if (normalized === '.') return ['.'];
    const trimmed = normalized.slice(0, -1);
    const labels = trimmed.split('.');
    const out: string[] = [];
    for (let i = 0; i < labels.length; i++) {
        out.push(labels.slice(i).join('.') + '.');
    }
    out.push('.');
    return out;
}

// next_closer_name returns the ancestor of qname that is one label
// longer than ce. Returns "" if ce is not actually an ancestor of
// qname or already equals qname.
function next_closer_name(qname: string, ce: string): string {
    const ancs = ancestors_of(qname);
    for (let i = 0; i < ancs.length; i++) {
        if (equal_canonical_names(ancs[i], ce)) {
            if (i === 0) return '';
            return ancs[i - 1];
        }
    }
    return '';
}

// longest_common_ancestor returns the longest name that is a suffix of
// both a and b in canonical form. The root "." is the lower bound and
// is returned when no labels match.
function longest_common_ancestor(a: string, b: string): string {
    const la = canon_labels_trim(a);
    const lb = canon_labels_trim(b);
    let matched = 0;
    for (let i = 0; i < la.length && i < lb.length; i++) {
        const ai = la[la.length - 1 - i];
        const bi = lb[lb.length - 1 - i];
        if (ai !== bi) break;
        matched++;
    }
    if (matched === 0) return '.';
    return la.slice(la.length - matched).join('.') + '.';
}

function canon_labels_trim(name: string): string[] {
    const cleaned = (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();
    if (cleaned === '') return [];
    return cleaned.split('.');
}

//////////////////////////////////////////////////////////// wildcard

// detect_wildcard reports whether the (qname, qtype) rrset in z was
// produced by wildcard expansion, by comparing the covering RRSIG's
// labels field with qname's label count (RFC 4034 §3.1.3, RFC 4035
// §5.3.2).
//
// Returns null when no synthesis is detectable. Returns a
// WildcardInfo (without proofReason — the caller fills that in after
// verifying the non-existence of the next-closer name) when synthesis
// is observed.
function detect_wildcard(z: DNSSecZone, qname: string, qtype: number): Omit<WildcardInfo, 'proofReason'> | null {
    const sigs = z.find_rrsigs(qname, qtype);
    if (sigs.length === 0) return null;
    const q_labels = label_count(qname);
    for (const sig of sigs) {
        if (sig.labels >= q_labels) continue;
        const closest = last_n_labels(qname, sig.labels);
        const next_closer = last_n_labels(qname, sig.labels + 1);
        return {
            source: '*.' + closest,
            closestEncloser: closest,
            nextCloser: next_closer,
        };
    }
    return null;
}

// prove_qname_non_existence proves that nextCloser does not exist as
// a signed name in z. RFC 4035 §5.3.4 requires this proof to
// accompany any wildcard-synthesised positive answer; without it an
// attacker could replay the wildcard rrset for a name that actually
// has its own rrset.
//
// Two proof shapes are accepted:
//   - An NSEC whose range covers nextCloser, signed under z's keys.
//   - An NSEC3 whose range covers H(nextCloser), signed under z's keys.
//
// Returns a short, human-readable reason string on success, or null
// when no usable proof is present.
function prove_qname_non_existence(z: DNSSecZone, next_closer: string): string | null {
    // NSEC first.
    for (const c of nsec_candidates(z)) {
        if (!c.nsec.covers_name(c.owner, next_closer)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC)) continue;
        return `NSEC at ${c.owner} covers next-closer ${next_closer}`;
    }
    // NSEC3.
    for (const c of nsec3_candidates(z)) {
        let target: Uint8Array;
        try {
            target = DNSRR_NSEC3.compute_hash(next_closer, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
        } catch { continue; }
        if (!c.nsec3.covers_hash(c.ownerHash, target)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC3)) continue;
        return `NSEC3 at ${c.owner} covers hash of next-closer ${next_closer}`;
    }
    return null;
}

function bytes_equal(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

//////////////////////////////////////////////////////////// alias chasing

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

// zone_already_in_chain reports whether result.chain already contains
// a ZoneStep for zoneName. Used during alias chasing so multiple hops
// over the same parent zones (e.g. "." and "com.") don't duplicate
// entries.
function zone_already_in_chain(result: Result, zoneName: string): boolean {
    for (const step of result.chain) {
        if (step.zone === zoneName) return true;
    }
    return false;
}

// synthesise_dname_target rewrites qname per RFC 6672 §5.3.1: the
// labels of qname below owner are appended to the DNAME target.
//
// Example:
//
//   qname  = "foo.bar.example.com."
//   owner  = "example.com."
//   target = "elsewhere.net."
//   →        "foo.bar.elsewhere.net."
//
// Returns "" when qname does not strictly fall under owner (mismatch
// at any aligned label, or qname.length <= owner.length); the caller
// treats that as Bogus rather than silent fall-through.
//
// Exported for tests.
export function synthesise_dname_target(qname: string, owner: string, target: string): string {
    const qLabels = canon_labels_trim(qname);
    const oLabels = canon_labels_trim(owner);
    const tLabels = canon_labels_trim(target);
    if (qLabels.length <= oLabels.length) return '';
    for (let i = 0; i < oLabels.length; i++) {
        const ql = qLabels[qLabels.length - oLabels.length + i];
        const ol = oLabels[i];
        if (ql.toLowerCase() !== ol.toLowerCase()) return '';
    }
    const prefix = qLabels.slice(0, qLabels.length - oLabels.length);
    return prefix.concat(tLabels).join('.') + '.';
}
