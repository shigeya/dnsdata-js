// NSEC / NSEC3 candidate collection + no-DS proof primitives.
// Ports dnsdata-go `verifier/negative.go`.

import { DNSSecZone } from '../dnssec/dnssec_zone';
import { DNSRR_NSEC, DNSRR_NSEC3, owner_hash_from_name } from '../dnssec/dnssec_rr';
import { StringToRRType } from '../types/dns_type_table';

const TYPE_NSEC  = StringToRRType('NSEC');
const TYPE_NSEC3 = StringToRRType('NSEC3');

// nsec_candidates pairs each NSEC handler in z with its owner name so
// canonical comparisons stay as plain string ops.
export interface NsecCandidate {
    owner: string;
    nsec:  DNSRR_NSEC;
}

export function nsec_candidates(z: DNSSecZone): NsecCandidate[] {
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
export interface Nsec3Candidate {
    owner:     string;
    ownerHash: Uint8Array;
    nsec3:     DNSRR_NSEC3;
}

export function nsec3_candidates(z: DNSSecZone): Nsec3Candidate[] {
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

export function bytes_equal(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// prove_no_ds_with_nsec searches for a matching-owner NSEC at the
// parent with the no-DS bitmap shape. The candidate must verify under
// the parent's keys.
export function prove_no_ds_with_nsec(parent: DNSSecZone, childName: string): string | null {
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
export function prove_no_ds_with_nsec3(parent: DNSSecZone, childName: string): string | null {
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

// prove_no_ds attempts to prove from parent that childName has no
// DS record. Returns a short human-readable reason on success, or
// null when no usable proof is present.
//
// Signature verification failures simply skip that candidate proof;
// the verifier's job here is to *try* and quietly give up if it
// can't (RFC 4035 §5.4 / RFC 5155 §8.9).
export function prove_no_ds(parent: DNSSecZone, childName: string): string | null {
    const nsec = prove_no_ds_with_nsec(parent, childName);
    if (nsec) return nsec;
    return prove_no_ds_with_nsec3(parent, childName);
}
