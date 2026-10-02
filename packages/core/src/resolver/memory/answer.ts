// How one zone answers a query. Ports dnsdata-go
// `resolver/memory/answer.go`.

import { ResourceRecord } from '../../zone/dns_zone';
import { ResolverResponse } from '../response';
import { labels, next_closer, normalize, wildcard_of } from './names';
import { TYPE_CNAME, TYPE_DNAME, TYPE_DS, TYPE_NS, TYPE_NSEC, ZoneIndex } from './zone_index';

export const RCODE_NOERROR = 0;
export const RCODE_NXDOMAIN = 3;
export const RCODE_REFUSED = 5;

// answer builds the response of one zone to (name, qtype); name is
// normalized and at or below the apex.
export function answer(idx: ZoneIndex, name: string, qtype: number): ResolverResponse {
    const cut = idx.cut_above(name);
    if (cut !== null && !(qtype === TYPE_DS && name === cut)) {
        return referral(idx, cut);
    }
    if (idx.records(name).length > 0) {
        return existing(idx, name, qtype);
    }
    if (idx.has_name(name)) {
        // Empty non-terminal: NODATA.
        return response(RCODE_NOERROR, no_data_proof(idx, name));
    }
    const dname = idx.dname_above(name);
    if (dname !== null) {
        return dname_answer(idx, name, dname);
    }
    return missing(idx, name, qtype);
}

// dname_answer answers a name below the DNAME at owner: the signed DNAME
// and the CNAME synthesised from it (RFC 6672 §5.3.1), owned by name,
// unsigned, with the DNAME's TTL.
function dname_answer(idx: ZoneIndex, name: string, owner: string): ResolverResponse {
    const dname = idx.with_sigs(owner, TYPE_DNAME);
    const target = normalize(idx.rrset(owner, TYPE_DNAME)[0].value);
    const prefix = labels(name).slice(0, labels(name).length - labels(owner).length);
    const synthesised = new ResourceRecord(
        name, dname[0].ttl, dname[0].rrclass, TYPE_CNAME, [...prefix, ...labels(target)].join('.') + '.',
    );
    return response(RCODE_NOERROR, [...dname, synthesised]);
}

// referral answers a name at or below a delegation point: the NS
// RRset, and the signed DS RRset or the proof there is none.
function referral(idx: ZoneIndex, cut: string): ResolverResponse {
    const ds = idx.with_sigs(cut, TYPE_DS);
    const proof = ds.length > 0 ? ds : no_data_proof(idx, cut);
    return response(RCODE_NOERROR, [...idx.rrset(cut, TYPE_NS), ...proof]);
}

// existing answers a name that owns records: the RRset, a CNAME to
// follow, or NODATA.
function existing(idx: ZoneIndex, name: string, qtype: number): ResolverResponse {
    const rs = idx.with_sigs(name, qtype);
    if (rs.length > 0) return response(RCODE_NOERROR, rs);
    if (qtype !== TYPE_CNAME) {
        const cname = idx.with_sigs(name, TYPE_CNAME);
        if (cname.length > 0) return response(RCODE_NOERROR, cname);
    }
    return response(RCODE_NOERROR, no_data_proof(idx, name));
}

// missing answers a name that does not exist: wildcard synthesis when
// `*.<closest encloser>` exists (RFC 4035 §3.1.3.3), NXDOMAIN otherwise.
// A wildcard CNAME is synthesised for a query of any type
// (RFC 4592 §3.3.3).
function missing(idx: ZoneIndex, name: string, qtype: number): ResolverResponse {
    const ce = idx.closest_encloser(name);
    const wildcard = wildcard_of(ce);
    if (idx.records(wildcard).length === 0) {
        return response(RCODE_NXDOMAIN, nx_domain_proof(idx, name, ce));
    }
    const proof = next_closer_proof(idx, name, ce);
    let rs = idx.with_sigs(wildcard, qtype);
    if (rs.length === 0 && qtype !== TYPE_CNAME) {
        rs = idx.with_sigs(wildcard, TYPE_CNAME);
    }
    if (rs.length === 0) {
        // Wildcard NODATA (RFC 5155 §7.2.5 for NSEC3).
        return response(RCODE_NOERROR, [...encloser_proof(idx, ce), ...proof, ...no_data_proof(idx, wildcard)]);
    }
    return response(RCODE_NOERROR, [...rs.map((rr) => copy_as(rr, name)), ...proof]);
}

// no_data_proof proves that name has no RRset of the asked type: the
// NSEC at name, or for an empty non-terminal the NSEC covering it; the
// NSEC3 matching name (RFC 5155 §7.2.3), or without one (opt-out) the
// closest provable encloser proof (§7.2.4).
function no_data_proof(idx: ZoneIndex, name: string): ResourceRecord[] {
    const chain = idx.nsec3;
    if (chain === null) {
        const nsec = idx.with_sigs(name, TYPE_NSEC);
        return nsec.length > 0 ? nsec : idx.covering_nsec(name);
    }
    const owner = chain.matching(name);
    return owner !== null ? idx.nsec3_at(owner) : idx.closest_encloser_proof(chain, name).proof;
}

// nx_domain_proof proves that name does not exist and that no wildcard
// at its closest encloser ce does: NSECs covering both, or the closest
// encloser proof and the NSEC3 covering the wildcard (RFC 5155 §7.2.2).
function nx_domain_proof(idx: ZoneIndex, name: string, ce: string): ResourceRecord[] {
    const chain = idx.nsec3;
    if (chain === null) {
        return [...idx.covering_nsec(name), ...idx.covering_nsec(wildcard_of(ce))];
    }
    const { proof, encloser } = idx.closest_encloser_proof(chain, name);
    return [...proof, ...idx.nsec3_at(chain.covering(wildcard_of(encloser)))];
}

// next_closer_proof proves that the next closer name of name below its
// closest encloser ce does not exist, as a wildcard answer needs
// (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6).
function next_closer_proof(idx: ZoneIndex, name: string, ce: string): ResourceRecord[] {
    const chain = idx.nsec3;
    if (chain === null) return idx.covering_nsec(next_closer(name, ce));
    return idx.nsec3_at(chain.covering(next_closer(name, ce)));
}

// encloser_proof is the NSEC3 matching the closest encloser ce, which
// NSEC3 wildcard NODATA adds (RFC 5155 §7.2.5); NSEC needs none.
function encloser_proof(idx: ZoneIndex, ce: string): ResourceRecord[] {
    const chain = idx.nsec3;
    return chain === null ? [] : idx.nsec3_at(chain.matching(ce));
}

// response copies records (so callers cannot alter the authority) and
// drops duplicates.
function response(rcode: number, records: readonly ResourceRecord[]): ResolverResponse {
    const seen = new Set<string>();
    const out: ResourceRecord[] = [];
    for (const rr of records) {
        const key = `${rr.label}\0${rr.type}\0${rr.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(copy_as(rr, rr.label));
    }
    return { records: out, ad: false, rcode };
}

// copy_as returns a fresh copy of rr with the given owner.
function copy_as(rr: ResourceRecord, owner: string): ResourceRecord {
    return new ResourceRecord(owner, rr.ttl, rr.rrclass, rr.type, rr.value);
}
