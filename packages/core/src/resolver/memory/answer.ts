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
        // Empty non-terminal: NODATA, proven by the NSEC spanning it.
        return response(RCODE_NOERROR, idx.covering_nsec(name));
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
// RRset, and the signed DS RRset or the NSEC proving there is none.
function referral(idx: ZoneIndex, cut: string): ResolverResponse {
    const ds = idx.with_sigs(cut, TYPE_DS);
    const proof = ds.length > 0 ? ds : idx.with_sigs(cut, TYPE_NSEC);
    return response(RCODE_NOERROR, [...idx.rrset(cut, TYPE_NS), ...proof]);
}

// existing answers a name that owns records: the RRset, a CNAME to
// follow, or NODATA with the name's NSEC.
function existing(idx: ZoneIndex, name: string, qtype: number): ResolverResponse {
    const rs = idx.with_sigs(name, qtype);
    if (rs.length > 0) return response(RCODE_NOERROR, rs);
    if (qtype !== TYPE_CNAME) {
        const cname = idx.with_sigs(name, TYPE_CNAME);
        if (cname.length > 0) return response(RCODE_NOERROR, cname);
    }
    return response(RCODE_NOERROR, idx.with_sigs(name, TYPE_NSEC));
}

// missing answers a name that does not exist: wildcard synthesis when
// `*.<closest encloser>` exists (RFC 4035 §3.1.3.3), NXDOMAIN otherwise.
// A wildcard CNAME is synthesised for a query of any type
// (RFC 4592 §3.3.3).
function missing(idx: ZoneIndex, name: string, qtype: number): ResolverResponse {
    const ce = idx.closest_encloser(name);
    const wildcard = wildcard_of(ce);
    if (idx.records(wildcard).length === 0) {
        return response(RCODE_NXDOMAIN, [...idx.covering_nsec(name), ...idx.covering_nsec(wildcard)]);
    }
    const proof = idx.covering_nsec(next_closer(name, ce));
    let rs = idx.with_sigs(wildcard, qtype);
    if (rs.length === 0 && qtype !== TYPE_CNAME) {
        rs = idx.with_sigs(wildcard, TYPE_CNAME);
    }
    if (rs.length === 0) {
        return response(RCODE_NOERROR, [...proof, ...idx.with_sigs(wildcard, TYPE_NSEC)]);
    }
    return response(RCODE_NOERROR, [...rs.map((rr) => copy_as(rr, name)), ...proof]);
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
