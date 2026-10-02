// NODATA and NXDOMAIN proof primitives + name-handling helpers.
// Ports dnsdata-go `verifier/leaf_negative.go`.

import { DNSSecZone } from '../dnssec/dnssec_zone';
import { DNSRR_NSEC3 } from '../dnssec/dnssec_rr';
import { StringToRRType } from '../types/dns_type_table';
import { equal_canonical_names, label_count } from '../dnssec/dnssec_util';
import {
    NsecCandidate,
    Nsec3Candidate,
    nsec_candidates,
    nsec3_candidates,
    bytes_equal,
} from './negative';
import { qtype_mnemonic, normalize_qname } from './verifier';

const TYPE_NSEC  = StringToRRType('NSEC');
const TYPE_NSEC3 = StringToRRType('NSEC3');

// prove_no_data_with_nsec accepts three NODATA shapes: a matching NSEC
// without qtype; an empty non-terminal (a covering NSEC whose next name
// is below qname); and wildcard NODATA (RFC 4035 §3.1.3.4: qname is
// covered, and the NSEC matching *.<closest encloser> lacks qtype).
export function prove_no_data_with_nsec(z: DNSSecZone, qname: string, qtype: number): string | null {
    const cands = nsec_candidates(z);
    const match = find_nsec(z, cands, c => c.nsec.matches_name(c.owner, qname) && c.nsec.proves_no_data(qtype));
    if (match) {
        return `NSEC at ${match.owner} asserts qname exists without ${qtype_mnemonic(qtype)}`;
    }

    const covering = find_nsec(z, cands, c => c.nsec.covers_name(c.owner, qname));
    if (!covering) return null;
    if (is_strict_subdomain(covering.nsec.next_domain, qname)) {
        return `NSEC at ${covering.owner} covers empty non-terminal ${qname} (next name ${covering.nsec.next_domain} is below it)`;
    }

    const ce = closest_encloser_nsec(qname, covering.owner, covering.nsec.next_domain);
    if (ce === '') return null;
    const wildcard = wildcard_at(ce);
    const wc = find_nsec(z, cands, c => c.nsec.matches_name(c.owner, wildcard) && c.nsec.proves_no_data(qtype));
    if (!wc) return null;
    return `NSEC at ${covering.owner} covers ${qname}, NSEC at ${wc.owner} asserts wildcard ${wildcard} exists without ${qtype_mnemonic(qtype)}`;
}

// prove_no_data_with_nsec3 accepts a matching NSEC3 without qtype (an
// empty non-terminal has its own NSEC3, so this covers it too) and
// wildcard NODATA (RFC 5155 §8.7: closest-encloser proof plus an NSEC3
// matching *.<ce> without qtype).
export function prove_no_data_with_nsec3(z: DNSSecZone, qname: string, qtype: number): string | null {
    const cands = nsec3_candidates(z);
    for (const c of cands) {
        if (!nsec3_matches(z, c, qname) || !c.nsec3.proves_no_data(qtype)) continue;
        return `NSEC3 at ${c.owner} asserts qname exists without ${qtype_mnemonic(qtype)}`;
    }

    const proof = closest_encloser_proof_nsec3(z, cands, qname);
    if (!proof) return null;
    const wildcard = wildcard_at(proof.ce);
    for (const c of cands) {
        if (!nsec3_matches(z, c, wildcard) || !c.nsec3.proves_no_data(qtype)) continue;
        return `${describe_ce_proof(proof)}; NSEC3 at ${c.owner} asserts wildcard ${wildcard} exists without ${qtype_mnemonic(qtype)}`;
    }
    return null;
}

// prove_nx_domain_with_nsec needs a covering NSEC for qname AND a
// covering NSEC for *.<closestEncloser>. The closest encloser is
// derived from the covering NSEC and qname: the longest ancestor of
// qname that is also an ancestor of the NSEC's owner or next_domain.
//
// A covering NSEC whose next name is below qname proves qname is an
// empty non-terminal, and an NSEC matching the wildcard proves the
// wildcard exists; neither is NXDOMAIN.
export function prove_nx_domain_with_nsec(z: DNSSecZone, qname: string): string | null {
    const cands = nsec_candidates(z);

    const covering = find_nsec(z, cands, c => c.nsec.covers_name(c.owner, qname));
    if (!covering || is_strict_subdomain(covering.nsec.next_domain, qname)) return null;

    // Both endpoints of the covering NSEC exist as zone names, so any
    // common ancestor with qname must also exist in the zone.
    const ce = closest_encloser_nsec(qname, covering.owner, covering.nsec.next_domain);
    if (ce === '' || equal_canonical_names(ce, qname)) return null;
    const wildcard = wildcard_at(ce);

    const denial = find_nsec(z, cands, c => c.nsec.covers_name(c.owner, wildcard));
    if (!denial) return null;
    return `NSEC at ${covering.owner} covers ${qname}, NSEC at ${denial.owner} denies wildcard ${wildcard}`;
}

// prove_nx_domain_with_nsec3 implements the three-NSEC3 closest-
// encloser proof of RFC 5155 §8.4: closest-encloser match, next-closer
// cover, and wildcard cover.
export function prove_nx_domain_with_nsec3(z: DNSSecZone, qname: string): string | null {
    const cands = nsec3_candidates(z);
    const proof = closest_encloser_proof_nsec3(z, cands, qname);
    if (!proof) return null;

    // wildcard: "*." + ce, must be covered by some NSEC3.
    const wildcard = wildcard_at(proof.ce);
    const wcOwner = find_covering_nsec3(z, cands, wildcard);
    if (wcOwner === '') return null;
    return `${describe_ce_proof(proof)}; ${wcOwner} covers wildcard ${wildcard}`;
}

// find_nsec returns the first candidate that satisfies pred and whose
// signature verifies under z's keys, or null.
function find_nsec(z: DNSSecZone, cands: NsecCandidate[], pred: (c: NsecCandidate) => boolean): NsecCandidate | null {
    for (const c of cands) {
        if (pred(c) && z.verify_rrset(c.owner, TYPE_NSEC)) return c;
    }
    return null;
}

// Nsec3CEProof is a verified RFC 5155 §8.3 closest-encloser proof.
interface Nsec3CEProof {
    ce: string;       // closest encloser
    ceOwner: string;  // the NSEC3 matching it
    nc: string;       // next closer name
    ncOwner: string;  // the NSEC3 covering it
}

function describe_ce_proof(p: Nsec3CEProof): string {
    return `NSEC3 at ${p.ceOwner} matches closest encloser ${p.ce}; ${p.ncOwner} covers next-closer ${p.nc}`;
}

// closest_encloser_proof_nsec3 finds the closest encloser of qname (the
// longest proper ancestor with a matching NSEC3) and an NSEC3 covering
// the next closer name. Returns null when qname itself matches (not a
// non-existence case) or either half of the proof is missing.
function closest_encloser_proof_nsec3(z: DNSSecZone, cands: Nsec3Candidate[], qname: string): Nsec3CEProof | null {
    for (const a of ancestors_of(qname)) {
        const match = cands.find(c => nsec3_matches(z, c, a));
        if (!match) continue;
        if (equal_canonical_names(a, qname)) return null;
        const nc = next_closer_name(qname, a);
        if (nc === '') return null;
        const ncOwner = find_covering_nsec3(z, cands, nc);
        if (ncOwner === '') return null;
        return { ce: a, ceOwner: match.owner, nc, ncOwner };
    }
    return null;
}

// nsec3_matches reports whether c's owner hash equals H(name) under c's
// own parameters and c verifies under z's keys.
function nsec3_matches(z: DNSSecZone, c: Nsec3Candidate, name: string): boolean {
    let h: Uint8Array;
    try {
        h = DNSRR_NSEC3.compute_hash(name, c.nsec3.hash_algorithm, c.nsec3.iterations, c.nsec3.salt);
    } catch { return false; }
    return bytes_equal(h, c.ownerHash) && z.verify_rrset(c.owner, TYPE_NSEC3);
}

// wildcard_at returns the wildcard name directly below ce.
function wildcard_at(ce: string): string {
    return ce === '.' ? '*.' : '*.' + ce;
}

// is_strict_subdomain reports whether name is below (not equal to)
// parent.
function is_strict_subdomain(name: string, parent: string): boolean {
    if (canon_labels_trim(name).length <= canon_labels_trim(parent).length) return false;
    return equal_canonical_names(longest_common_ancestor(name, parent), parent);
}

export function find_covering_nsec3(z: DNSSecZone, cands: Nsec3Candidate[], target: string): string {
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
export function closest_encloser_nsec(qname: string, owner: string, next: string): string {
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
export function ancestors_of(qname: string): string[] {
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
export function next_closer_name(qname: string, ce: string): string {
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
export function longest_common_ancestor(a: string, b: string): string {
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

export function canon_labels_trim(name: string): string[] {
    const cleaned = (name.endsWith('.') ? name.slice(0, -1) : name).toLowerCase();
    if (cleaned === '') return [];
    return cleaned.split('.');
}

// prove_no_data attempts to prove from z that no rrset of qtype is
// present at qname although the answer is not NXDOMAIN: qname exists
// without qtype (RFC 4035 §5.4, RFC 5155 §8.5), qname is an empty
// non-terminal, or wildcard NODATA (RFC 4035 §3.1.3.4, RFC 5155 §8.7).
export function prove_no_data(z: DNSSecZone, qname: string, qtype: number): string | null {
    const nsec = prove_no_data_with_nsec(z, qname, qtype);
    if (nsec) return nsec;
    return prove_no_data_with_nsec3(z, qname, qtype);
}

// prove_nx_domain attempts to prove from z that qname does not exist
// as any rrset (RFC 4035 §5.4 NSEC; RFC 5155 §8.4 NSEC3 three-record
// closest-encloser proof). Both proof shapes also require a wildcard
// non-existence component — otherwise a zone with a wildcard could
// lie about NXDOMAIN by suppressing the wildcard answer.
export function prove_nx_domain(z: DNSSecZone, qname: string): string | null {
    const nsec = prove_nx_domain_with_nsec(z, qname);
    if (nsec) return nsec;
    return prove_nx_domain_with_nsec3(z, qname);
}
