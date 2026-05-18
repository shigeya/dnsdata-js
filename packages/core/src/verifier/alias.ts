// CNAME / DNAME chasing helpers for the chain walker.
// Ports dnsdata-go `verifier/alias.go`.

import { DNSSecZone } from '../dnssec/dnssec_zone';
import { StringToRRType } from '../types/dns_type_table';
import { equal_canonical_names } from '../dnssec/dnssec_util';
import { Verdict } from './verdict';
import { HopOutcome } from './result';
import { normalize_qname } from './verifier';
import { ancestors_of, canon_labels_trim } from './leaf_negative';

const TYPE_CNAME = StringToRRType('CNAME');
const TYPE_DNAME = StringToRRType('DNAME');

// try_cname looks for a CNAME rrset at qname inside currentZone,
// verifies its signature against currentZone's keys, and packages
// it as an AliasStep hop for validate()'s outer loop to chase.
//
// Returns null when no CNAME is present — the caller then tries
// DNAME or negative-proof handling. A CNAME present but failing
// signature verification returns a hop whose verdict is Bogus.
export function try_cname(currentZone: DNSSecZone, currentName: string, qname: string): HopOutcome | null {
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
export function try_dname(currentZone: DNSSecZone, currentName: string, qname: string): HopOutcome | null {
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
