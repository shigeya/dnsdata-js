// Wildcard-synthesised positive answer support.
// Ports dnsdata-go `verifier/wildcard.go`.

import { DNSSecZone } from '../dnssec/dnssec_zone';
import { DNSRR_NSEC3 } from '../dnssec/dnssec_rr';
import { StringToRRType } from '../types/dns_type_table';
import { label_count, last_n_labels } from '../dnssec/dnssec_util';
import { WildcardInfo } from './result';
import {
    nsec_candidates,
    nsec3_candidates,
} from './negative';

const TYPE_NSEC  = StringToRRType('NSEC');
const TYPE_NSEC3 = StringToRRType('NSEC3');

// detect_wildcard reports whether the (qname, qtype) rrset in z was
// produced by wildcard expansion, by comparing the covering RRSIG's
// labels field with qname's label count (RFC 4034 §3.1.3, RFC 4035
// §5.3.2).
//
// Returns null when no synthesis is detectable. Returns a
// WildcardInfo (without proofReason — the caller fills that in after
// verifying the non-existence of the next-closer name) when synthesis
// is observed.
export function detect_wildcard(z: DNSSecZone, qname: string, qtype: number): Omit<WildcardInfo, 'proofReason'> | null {
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
export function prove_qname_non_existence(z: DNSSecZone, next_closer: string): string | null {
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
