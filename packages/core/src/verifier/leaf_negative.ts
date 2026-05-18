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

export function prove_no_data_with_nsec(z: DNSSecZone, qname: string, qtype: number): string | null {
    for (const c of nsec_candidates(z)) {
        if (!c.nsec.matches_name(c.owner, qname)) continue;
        if (!c.nsec.proves_no_data(qtype)) continue;
        if (!z.verify_rrset(c.owner, TYPE_NSEC)) continue;
        return `NSEC at ${c.owner} asserts qname exists without ${qtype_mnemonic(qtype)}`;
    }
    return null;
}

export function prove_no_data_with_nsec3(z: DNSSecZone, qname: string, qtype: number): string | null {
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
export function prove_nx_domain_with_nsec(z: DNSSecZone, qname: string): string | null {
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
export function prove_nx_domain_with_nsec3(z: DNSSecZone, qname: string): string | null {
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

// prove_no_data attempts to prove from z that qname exists but no
// rrset of qtype is present (RFC 4035 §5.4 / RFC 5155 §8.5).
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
