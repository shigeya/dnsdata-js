// Chain walker: validate, validate_one_hop, validate_root,
// descend_into, resolve_leaf, load_records, plus the supporting
// summarisation / DS-anchor helpers.
//
// Ports dnsdata-go `verifier/chain.go`.

import * as crypto from 'crypto';
import { ResourceRecord } from '../zone/dns_zone';
import { DNSSecZone, KeyVerifyMode } from '../dnssec/dnssec_zone';
import { DNSKey, DNSRR_DS } from '../dnssec/dnssec_rr';
import { StringToRRType } from '../types/dns_type_table';
import { equal_canonical_names } from '../dnssec/dnssec_util';
import { Verdict, MAX_ALIAS_HOPS, combine_verdicts } from './verdict';
import { DSSummary, HopOutcome, KeySummary, Result, SigCheck, ZoneStep } from './result';
import { SigStatus } from '../dnssec/sigcheck';
import { add_step, add_zone_sigs } from './sigcheck';
import {
    VerifierChainTimeoutError,
    VerifierInvalidQNameError,
    VerifierResolverError,
} from './errors';
import {
    type Verifier,
    check_aborted,
    error_message,
    is_abort_error,
    normalize_qname,
    qtype_mnemonic,
} from './verifier';
import { try_cname, try_dname } from './alias';
import { prove_no_ds } from './negative';
import { ancestors_of, prove_no_data, prove_nx_domain } from './leaf_negative';
import { detect_wildcard, prove_qname_non_existence } from './wildcard';
import { build_answer } from './answer';
import { ReasonCode, bogus_outcome, check_rrset } from './reason';

const TYPE_DNSKEY = StringToRRType('DNSKEY');
const TYPE_DS     = StringToRRType('DS');
const TYPE_RRSIG  = StringToRRType('RRSIG');
const TYPE_DNAME  = StringToRRType('DNAME');

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
// at all (resolver failure, abort, invalid qname). A failing verdict
// carries a machine-readable result.reasonCode; result_error(result)
// turns it into the matching Error subclass.
export async function validate(v: Verifier, qname: string, qtype: number, signal?: AbortSignal): Promise<Result> {
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
            set_bogus(result, currentQname, 'alias loop detected', ReasonCode.AliasLoop);
            return result;
        }
        seen.add(currentQname);

        const outcome = await validate_one_hop(v, currentQname, qtype, result, signal);

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

        apply_outcome(result, outcome, combined);
        return result;
    }

    // Alias chain longer than MAX_ALIAS_HOPS without resolving.
    set_bogus(result, currentQname, `alias chain exceeded ${MAX_ALIAS_HOPS} hops`, ReasonCode.AliasLimit);
    return result;
}

// apply_outcome sets the combined verdict on result and carries the
// terminal hop's diagnostic strings, so the reported location matches
// the final verdict.
function apply_outcome(result: Result, outcome: HopOutcome, combined: Verdict): void {
    result.verdict = combined;
    if (outcome.bogusAt)        result.bogusAt = outcome.bogusAt;
    if (outcome.bogusReason)    result.bogusReason = outcome.bogusReason;
    if (outcome.insecureAt)     result.insecureAt = outcome.insecureAt;
    if (outcome.insecureReason) result.insecureReason = outcome.insecureReason;
    if (outcome.reasonCode)     result.reasonCode = outcome.reasonCode;
    if (outcome.negativeReason) result.negativeReason = outcome.negativeReason;
    if (outcome.wildcard)       result.wildcard = outcome.wildcard;
    // Only a Secure result carries the answer: a Secure terminal
    // hop behind an Insecure alias hop combines to Insecure.
    if (result.verdict === Verdict.Secure && outcome.answer) {
        result.answer = outcome.answer;
    }
}

// set_bogus records a Bogus verdict decided outside a hop outcome.
function set_bogus(result: Result, at: string, reason: string, code: ReasonCode): void {
    result.verdict = Verdict.Bogus;
    result.bogusAt = at;
    result.bogusReason = reason;
    result.reasonCode = code;
}

// new_zone returns an empty zone whose RRSIG checks use the verifier's
// clock (RFC 4035 §5.3.1: a signature outside its validity window does
// not verify) and whose handlers come from the verifier's registry.
function new_zone(v: Verifier): DNSSecZone {
    const zone = new DNSSecZone();
    zone.set_clock(v.now);
    zone.set_registry(v.registry);
    return zone;
}

// validate_one_hop runs a single chain walk + leaf resolution
// against (qname, qtype). It mutates result.chain / result.evidence
// as it walks, but does NOT touch result.verdict / result.aliases
// — that is validate()'s responsibility.
async function validate_one_hop(v: Verifier, qname: string, qtype: number, result: Result, signal?: AbortSignal): Promise<HopOutcome> {
    // Step 1: load + verify the root zone.
    const root = await validate_root(v, result, signal);
    if (!(root instanceof DNSSecZone)) return root;

    // Step 2: descend through each label boundary that is actually
    // a zone cut. Empty non-terminals (no DS, but a deeper name IS
    // a cut) must be skipped, not treated as the leaf.
    let currentZone = root;
    let currentName = '.';
    for (const childName of descendant_zones(qname)) {
        check_aborted(signal);
        const d = await descend_into(v, currentZone, currentName, childName, result, signal);
        if (d.status === 'descended' || d.status === 'bogus') {
            add_step(result, summarize_zone(childName, d.zone ?? null, currentZone,
                d.status === 'descended' ? d.ksk : null, d.sigs));
        }
        switch (d.status) {
        case 'descended':
            currentZone = d.zone;
            currentName = childName;
            break;
        case 'insecure':
            return {
                verdict: Verdict.Insecure,
                insecureAt: childName,
                insecureReason: d.reason,
                reasonCode: ReasonCode.NoDS,
            };
        case 'bogus':
            return bogus_outcome(childName, d.reason, d.code);
        case 'no-cut':
            // childName is not a zone cut under currentZone: most often
            // qname itself (leaf resolution follows the loop), but it
            // can be an empty non-terminal between two real cuts.
            break;
        }
    }

    check_aborted(signal);
    return resolve_leaf(v, currentZone, currentName, qname, qtype, result, signal);
}

// validate_root loads the root DNSKEY rrset, matches it against the
// configured trust anchors, and verifies the rrset signature. It adds
// the root's step to the chain and returns the root zone, or the Bogus
// outcome when the root does not validate.
async function validate_root(v: Verifier, result: Result, signal?: AbortSignal): Promise<DNSSecZone | HopOutcome> {
    const rootZone = new_zone(v);
    await load_records(v, rootZone, '.', TYPE_DNSKEY, result, signal);

    // Only the anchor-matched keys are trusted; the DNSKEY rrset counts
    // as verified only through an RRSIG made by one of them.
    const rootKSKs = match_ksks_with_anchors(v, rootZone);
    if (rootKSKs.length === 0) {
        add_step(result, summarize_zone('.', rootZone, null, null, []));
        return bogus_outcome('.', 'root KSK does not match any configured trust anchor',
            ReasonCode.TrustAnchorMismatch);
    }
    trust_keys(rootZone, rootKSKs);
    const check = check_rrset(rootZone, '.', TYPE_DNSKEY, KeyVerifyMode.KSK, result);
    if (!check.ok) {
        add_step(result, summarize_zone('.', rootZone, null, null, check.sigs));
        return bogus_outcome('.', 'root DNSKEY rrset signature did not verify', check.code);
    }
    add_step(result, summarize_zone('.', rootZone, null, signing_ksk(rootKSKs, check.sigs), check.sigs));
    return rootZone;
}

// signing_ksk returns the authenticated KSK that signed a zone's DNSKEY
// rrset: the first of ksks named by a verified RRSIG in sigs (the DNSKEY
// rrset's checks), or the first of ksks when none is (which a verified
// rrset rules out).
function signing_ksk(ksks: DNSKey[], sigs: readonly SigCheck[]): DNSKey {
    for (const s of sigs) {
        if (s.result !== SigStatus.Verified) continue;
        const k = ksks.find((key) => key.key_tag === s.keyTag && key.algorithm === s.algorithm);
        if (k !== undefined) return k;
    }
    return ksks[0];
}

// Descent is the outcome of one descend_into step.
// sigs are the DS, then DNSKEY, RRSIG checks made; zone is the child
// zone once its DNSKEYs are loaded.
type Descent =
    | { status: 'descended'; zone: DNSSecZone; ksk: DNSKey; sigs: SigCheck[] }
    | { status: 'insecure'; reason: string }
    | { status: 'no-cut' }
    | { status: 'bogus'; reason: string; code?: ReasonCode; zone?: DNSSecZone; sigs: SigCheck[] };

// descend_into walks one level of the chain: load and verify the DS
// rrset for childName at parentZone, then load and verify the DNSKEY
// rrset for childName, returning the child zone if both verify.
//
// When the parent returns no DS records, it looks in the same response
// for an NSEC / NSEC3 proof of no-DS: a valid proof makes childName an
// Insecure delegation; without one childName is not a zone cut, so a
// DS query at a non-cut name (e.g. qname itself) still proceeds to leaf
// resolution.
async function descend_into(v: Verifier, parentZone: DNSSecZone, parentName: string, childName: string,
                            result: Result, signal?: AbortSignal): Promise<Descent> {
    const dsCount = await load_records(v, parentZone, childName, TYPE_DS, result, signal);
    if (dsCount === 0) return no_ds_descent(parentZone, childName);

    const dsCheck = check_rrset(parentZone, childName, TYPE_DS, KeyVerifyMode.None, result);
    if (!dsCheck.ok) {
        return {
            status: 'bogus', reason: `DS rrset for ${childName} did not verify under ${parentName}`,
            code: dsCheck.code, sigs: dsCheck.sigs,
        };
    }

    // The child zone is parented at parentZone so that
    // verify_delegation_signer finds the DS records there.
    const zone = new_zone(v);
    zone.parent = parentZone;
    await load_records(v, zone, childName, TYPE_DNSKEY, result, signal);

    // Only the keys matching the validated DS rrset are trusted.
    const match = match_ksks_with_ds(zone, parentZone, parentName, childName);
    if (!Array.isArray(match)) return { status: 'bogus', ...match, zone, sigs: dsCheck.sigs };
    trust_keys(zone, match);

    const dnskeyCheck = check_rrset(zone, childName, TYPE_DNSKEY, KeyVerifyMode.KSK, result);
    const sigs = [...dsCheck.sigs, ...dnskeyCheck.sigs];
    if (!dnskeyCheck.ok) {
        return {
            status: 'bogus', reason: `DNSKEY rrset for ${childName} did not verify under its own KSK`,
            code: dnskeyCheck.code, zone, sigs,
        };
    }
    return { status: 'descended', zone, ksk: signing_ksk(match, dnskeyCheck.sigs), sigs };
}

// no_ds_descent classifies a childName for which parentZone returned no
// DS: an Insecure delegation when a no-DS proof verifies, otherwise not
// a zone cut.
function no_ds_descent(parentZone: DNSSecZone, childName: string): Descent {
    // A name below a DNAME is never a zone cut (RFC 6672 §2.4), and
    // denial records for the DNAME owner say nothing about it
    // (RFC 6840 §4.1). Leaf resolution follows the DNAME.
    if (below_dname(parentZone, childName)) return { status: 'no-cut' };
    // RFC 4035 §5.4 / RFC 5155 §8.9: a valid proof that no DS exists
    // classifies this delegation as Insecure.
    const proof = prove_no_ds(parentZone, childName);
    return proof ? { status: 'insecure', reason: proof } : { status: 'no-cut' };
}

// trust_keys authenticates each of keys as a KSK of z.
function trust_keys(z: DNSSecZone, keys: DNSKey[]): void {
    for (const key of keys) z.add_trusted_key(key);
}

// resolve_leaf handles the final step of a hop: load qname/qtype
// into currentZone and either return a terminal verdict or surface
// an alias hop. CNAME at qname and DNAME at any proper ancestor of
// qname are followed; a missing rrset falls through to NSEC /
// NSEC3 negative proofs.
async function resolve_leaf(v: Verifier, currentZone: DNSSecZone, currentName: string, qname: string, qtype: number, result: Result, signal?: AbortSignal): Promise<HopOutcome> {
    const added = await load_records(v, currentZone, qname, qtype, result, signal);
    if (added > 0) {
        const check = check_rrset(currentZone, qname, qtype, KeyVerifyMode.None, result);
        add_zone_sigs(result, currentName, check.sigs);
        if (!check.ok) {
            return bogus_outcome(currentName,
                `RRSIG over ${qname}/${qtype_mnemonic(qtype)} did not verify under ${currentName}`, check.code);
        }
        const answer = build_answer(currentZone, qname, qtype);
        // Verified. RFC 4035 §5.3.2: if the covering RRSIG's Labels
        // field indicates wildcard synthesis, §5.3.4 also requires
        // a proof that the next-closer name does not exist —
        // otherwise the wildcard rrset could be replayed at a name
        // that actually has its own rrset.
        const wc = detect_wildcard(currentZone, qname, qtype);
        if (wc) {
            const proof = prove_qname_non_existence(currentZone, wc.nextCloser);
            if (!proof) {
                return bogus_outcome(currentName,
                    `wildcard synthesis at ${wc.source} lacks non-existence proof for ${wc.nextCloser}`,
                    ReasonCode.WildcardProofMissing);
            }
            return {
                verdict: Verdict.Secure,
                wildcard: { ...wc, proofReason: proof },
                answer,
            };
        }
        return { verdict: Verdict.Secure, answer };
    }

    // qtype rrset is absent. Look for a CNAME (at qname) or DNAME
    // (at a proper ancestor) BEFORE declaring NODATA. The resolver
    // may have placed those records into currentZone while answering
    // the qtype query — real DNS responses include CNAME/DNAME at
    // the same name even when the question asked for, say, A.
    // The Validate outer loop will start a fresh chain walk for the
    // rewritten target on the next hop.
    //
    // DNAME goes first: a DNAME answer also carries the CNAME
    // synthesised from it, and that CNAME has no RRSIG of its own
    // (RFC 6672 §5.3.1), so trying CNAME first would report the signed
    // DNAME as Bogus. The target is derived from the DNAME; the
    // synthesised CNAME is not used.
    const dname = try_dname(currentZone, currentName, qname, result);
    if (dname) return dname;
    const cname = try_cname(currentZone, currentName, qname, result);
    if (cname) return cname;

    // No alias — fall back to negative-existence proofs.
    const noData = prove_no_data(currentZone, qname, qtype);
    if (noData) {
        return { verdict: Verdict.SecureNoData, negativeReason: noData };
    }
    const nxDomain = prove_nx_domain(currentZone, qname);
    if (nxDomain) {
        return { verdict: Verdict.SecureNXDomain, negativeReason: nxDomain };
    }
    return { verdict: Verdict.Indeterminate };
}

// Issues one resolver Query and appends every returned record to
// z, capturing presentation values into result.evidence. Returns
// the number of records matching qtype (so the caller can detect
// a missing rrset).
//
// When a Cache is attached (via VerifierOptions.cache) the lookup
// goes through the cache first; a hit reuses the previously fetched
// records and skips the resolver entirely. Both hits and fresh
// fetches feed the same `apply_records` path so `result.evidence`
// is populated identically in either case. Resolver errors are
// NEVER cached.
async function load_records(
    v: Verifier,
    z: DNSSecZone,
    name: string,
    qtype: number,
    result: Result,
    signal?: AbortSignal,
): Promise<number> {
    check_aborted(signal);
    if (v.cache) {
        const cached = v.cache.get(name, qtype);
        if (cached !== undefined) {
            return apply_records(cached, z, name, qtype, result);
        }
    }

    let resp;
    try {
        resp = await v.resolver.query(name, qtype, signal);
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
    // Non-zero RCODE is surfaced as data by the resolver layer but
    // is a hard error for chain validation (RFC 4035 §5): we cannot
    // prove anything from a SERVFAIL or REFUSED. NXDOMAIN (3) and
    // NODATA (records empty, RCODE 0) are handled downstream as "no
    // records present" and need their own NSEC/NSEC3 proofs.
    if (resp.rcode !== 0 && resp.rcode !== 3) {
        throw new VerifierResolverError(
            `verifier: resolver returned RCODE=${resp.rcode} for ${name}/${qtype_mnemonic(qtype)}`,
        );
    }

    const records = resp.records;
    if (v.cache) v.cache.put(name, qtype, records);
    return apply_records(records, z, name, qtype, result);
}

// Appends each record to z, updates result.evidence for the
// DNSSEC-bookkeeping types, and returns the count of records of type
// qtype owned by name. Shared by the resolver-miss and cache-hit paths
// so the two produce indistinguishable bookkeeping.
//
// The owner check matters for recursive resolvers: they follow a
// CNAME or DNAME themselves and put the target's rrset (same type,
// different owner) into the same answer. Counting those would make
// the caller look for a qname rrset that is not there.
//
// A DNSKEY is taken only from the answer to the DNSKEY query for its
// own owner name, the rrset the descent authenticates. One carried in
// any other answer is dropped (from z and from result.evidence): once
// in z it would sign data checked in KeyVerifyMode.None without having
// been authenticated.
function apply_records(records: ResourceRecord[], z: DNSSecZone, name: string, qtype: number, result: Result): number {
    let matching = 0;
    for (const rr of records) {
        if (rr.type === TYPE_DNSKEY && (qtype !== TYPE_DNSKEY || !equal_canonical_names(rr.label, name))) {
            continue;
        }
        z.add_rr(rr);
        if (rr.type === TYPE_DNSKEY) {
            push_evidence(result.evidence.dnskeys, rr.label, rr.value);
        } else if (rr.type === TYPE_DS) {
            push_evidence(result.evidence.dses, rr.label, rr.value);
        } else if (rr.type === TYPE_RRSIG) {
            const key = `${rr.label}/${qtype_mnemonic(qtype)}`;
            push_evidence(result.evidence.rrsigs, key, rr.value);
        }
        if (rr.type === qtype && equal_canonical_names(rr.label, name)) matching++;
    }
    return matching;
}

// Returns every DNSKEY in the root zone whose DS digest matches one of
// the configured trust anchors. The SEP flag is not required
// (RFC 4034 §2.1.1).
function match_ksks_with_anchors(v: Verifier, rootZone: DNSSecZone): DNSKey[] {
    const anchors = v.anchors.ds ?? [];
    return rootZone.find_dnskeys('.').filter((key) =>
        anchors.some((anchor) =>
            anchor.keyTag === key.key_tag && anchor.algorithm === key.algorithm &&
            verify_anchor_digest(key, anchor)));
}

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

function push_evidence(into: Record<string, string[]>, key: string, value: string): void {
    const list = into[key];
    if (list) list.push(value);
    else into[key] = [value];
}

// summarize_zone collects a ZoneStep for the result chain. The DNSKEYs
// are read from z (null when the walk did not load them), the DS
// records from parent, which the descent loaded them into (null for the
// root). ksk is null on the step of a zone that did not validate.
function summarize_zone(zoneName: string, z: DNSSecZone | null, parent: DNSSecZone | null, ksk: DNSKey | null,
                        sigs: SigCheck[]): ZoneStep {
    const step: ZoneStep = { zone: zoneName };
    const dnskeys = z === null ? [] : summarize_dnskeys(zoneName, z);
    if (dnskeys.length > 0) step.dnskeys = dnskeys;
    const dsDigests = parent === null ? [] : summarize_ds(zoneName, parent);
    if (dsDigests.length > 0) step.dsDigests = dsDigests;
    if (ksk !== null) {
        step.signedBy = {
            keyTag: ksk.key_tag,
            algorithm: ksk.algorithm,
            sep: ksk.is_secure_entry_point(),
        };
    }
    if (sigs.length > 0) step.signatures = sigs;
    return step;
}

// summarize_dnskeys lists the DNSKEYs at zoneName held by z.
function summarize_dnskeys(zoneName: string, z: DNSSecZone): KeySummary[] {
    return z.find_rrset(zoneName, TYPE_DNSKEY)
        .map((rr) => z.handler(rr))
        .filter((h): h is DNSKey => h instanceof DNSKey)
        .map((h) => ({ keyTag: h.key_tag, algorithm: h.algorithm, sep: h.is_secure_entry_point() }));
}

// summarize_ds lists the DS records for zoneName held by parent.
function summarize_ds(zoneName: string, parent: DNSSecZone): DSSummary[] {
    return parent.find_rrset(zoneName, TYPE_DS)
        .map((rr) => parent.handler(rr))
        .filter((h): h is DNSRR_DS => h instanceof DNSRR_DS)
        .map((h) => ({ keyTag: h.key_tag, algorithm: h.algorithm, digestType: h.digest_type }));
}

// Returns every DNSKEY in childZone whose DS digest matches one of the
// DS records at parentZone under childName (the caller has validated
// that DS rrset), or why there is none: the child has no DNSKEY rrset
// (no-dnskey), or no key matches (ds-mismatch). The SEP flag is not
// required (RFC 4034 §2.1.1).
function match_ksks_with_ds(childZone: DNSSecZone, parentZone: DNSSecZone, parentName: string,
                            childName: string): DNSKey[] | { reason: string; code: ReasonCode } {
    if (childZone.find_rrset(childName, TYPE_DNSKEY).length === 0) {
        return { reason: `no DNSKEY records at ${childName}`, code: ReasonCode.NoDNSKEY };
    }
    const dses = parentZone.find_rrset(childName, TYPE_DS)
        .map((rr) => parentZone.handler(rr))
        .filter((h): h is DNSRR_DS => h instanceof DNSRR_DS);
    const ksks = childZone.find_dnskeys(childName).filter((key) =>
        dses.some((ds) =>
            ds.key_tag === key.key_tag && ds.algorithm === key.algorithm &&
            ds.verify_digest(key.get_ds_digest_data())));
    if (ksks.length > 0) return ksks;
    return { reason: `no DNSKEY at ${childName} matched a DS record in ${parentName}`, code: ReasonCode.DSMismatch };
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

// below_dname reports whether z holds a DNAME at a proper ancestor of
// name. Whether it verifies is left to leaf resolution: skipping a
// no-DS proof can only make the verdict stricter.
function below_dname(z: DNSSecZone, name: string): boolean {
    return ancestors_of(name).some((anc) =>
        !equal_canonical_names(anc, name) && z.find_rrset(anc, TYPE_DNAME).length > 0);
}

