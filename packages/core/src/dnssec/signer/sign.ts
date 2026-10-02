// Whole-zone signing. Ports dnsdata-go `dnssec/signer/sign.go`.

import { RRTypeName } from '../../types/dns_type_table';
import { ResourceRecord, Zone } from '../../zone/dns_zone';
import { DNSSecZone } from '../dnssec_zone';
import { SignerError, error_message } from './errors';
import { Key } from './key';
import { is_at_or_below, is_fqdn, rrsig_labels, same_name } from './names';
import {
    DEFAULT_TTL,
    TYPE_DNSKEY,
    TYPE_DS,
    TYPE_NSEC,
    TYPE_NSEC3,
    TYPE_NSEC3PARAM,
    ZoneView,
    build_nsec,
    is_generated_type,
    register_handlers,
    soa_at,
} from './nsec';
import { NSEC3Options, build_nsec3 } from './nsec3';

const MILLISECONDS_PER_SECOND = 1000;

// SignOptions controls [sign_zone].
export interface SignOptions {
    // inception and expiration bound every RRSIG. Both are required; the
    // signer never reads the clock, so windows in the past or the future
    // can be produced on purpose.
    inception: Date;
    expiration: Date;
    // TTL of the DNSKEY records added at the apex; 0 or absent uses the
    // SOA TTL, or 3600 without an SOA.
    dnskeyTTL?: number;
    // Passed to [build_nsec] or [build_nsec3]; 0 or absent derives it
    // from the SOA.
    nsecTTL?: number;
    // When set, the denial chain is NSEC3 ([build_nsec3]) with these
    // parameters instead of NSEC. `{}` is RFC 9276.
    nsec3?: NSEC3Options;
}

// The RRSIG window in seconds since the epoch.
interface Window {
    inception: number;
    expiration: number;
}

// sign_zone returns a signed copy of z, whose records must all be at or
// below apex. The input is not modified.
//
// The copy gets the keys' DNSKEY records at the apex (added to any
// DNSKEY already there), an NSEC chain ([build_nsec]) or with
// opts.nsec3 an NSEC3 chain and NSEC3PARAM ([build_nsec3]), and an
// RRSIG over every authoritative RRset: at a delegation point only DS
// and NSEC are signed, every NSEC3 is, and glue below a delegation is
// not signed. With both KSKs (SEP
// flag) and ZSKs among keys, the KSKs sign the DNSKEY RRset and the ZSKs
// sign everything else; otherwise every key signs every RRset (combined
// signing keys). RRSIG / NSEC / NSEC3 / NSEC3PARAM records already in z
// are dropped, so a signed zone can be signed again.
//
// sign_zone registers the bundled RR handlers (as registerAllHandlers
// does; registration is idempotent), since every record must encode to
// be ordered and signed. Throws SignerError for bad arguments, records
// outside apex, or records that do not encode.
export function sign_zone(z: Zone, apex: string, keys: readonly Key[], opts: SignOptions): Zone {
    register_handlers();
    const window = check_sign_args(apex, keys, opts);
    const out = copy_unsigned(z, apex);
    for (const rr of new_dnskeys(out, apex, keys, opts.dnskeyTTL ?? 0)) out.add_rr(rr);
    for (const rr of build_chain(out, apex, opts)) out.add_rr(rr);
    for (const rr of sign_rrsets(out, apex, keys, window)) out.add_rr(rr);
    return out;
}

// build_chain returns the NSEC chain, or the NSEC3 chain and NSEC3PARAM.
function build_chain(z: Zone, apex: string, opts: SignOptions): ResourceRecord[] {
    if (opts.nsec3 !== undefined) return build_nsec3(z, apex, opts.nsecTTL ?? 0, opts.nsec3);
    return build_nsec(z, apex, opts.nsecTTL ?? 0);
}

function check_sign_args(apex: string, keys: readonly Key[], opts: SignOptions): Window {
    if (!is_fqdn(apex)) {
        throw new SignerError(`apex "${apex}" is not fully qualified`);
    }
    if (!keys || keys.length === 0) {
        throw new SignerError('no keys');
    }
    for (const k of keys) {
        if (!same_name(k.owner, apex)) {
            throw new SignerError(`key ${k.key_tag} is for ${k.owner}, not ${apex}`);
        }
    }
    if (!is_valid_date(opts?.inception) || !is_valid_date(opts?.expiration)) {
        throw new SignerError('inception and expiration are required');
    }
    return { inception: unix_seconds(opts.inception), expiration: unix_seconds(opts.expiration) };
}

function is_valid_date(d: unknown): d is Date {
    return d instanceof Date && !Number.isNaN(d.getTime());
}

function unix_seconds(d: Date): number {
    return Math.floor(d.getTime() / MILLISECONDS_PER_SECOND);
}

// copy_unsigned copies z without generated records, as fresh records.
function copy_unsigned(z: Zone, apex: string): DNSSecZone {
    const out = new DNSSecZone();
    for (const rr of z.all_records()) {
        if (is_generated_type(rr.type)) continue;
        if (!is_at_or_below(rr.label, apex)) {
            throw new SignerError(`${rr.label} is outside the zone ${apex}`);
        }
        out.add_rr(new ResourceRecord(rr.label, rr.ttl, rr.rrclass, rr.type, rr.value));
    }
    return out;
}

// new_dnskeys returns the DNSKEY records of keys not already at the apex.
function new_dnskeys(out: Zone, apex: string, keys: readonly Key[], ttl: number): ResourceRecord[] {
    const dnskey_ttl = ttl !== 0 ? ttl : (soa_at(out, apex)?.ttl ?? DEFAULT_TTL);
    const seen = new Set(out.find_rrset(apex, TYPE_DNSKEY).map((rr) => rr.value));
    const added: ResourceRecord[] = [];
    for (const k of keys) {
        const value = k.dnskey_value();
        if (seen.has(value)) continue;
        seen.add(value);
        added.push(new ResourceRecord(apex, dnskey_ttl, 'IN', TYPE_DNSKEY, value));
    }
    return added;
}

// sign_rrsets returns the RRSIG records for every RRset that must be
// signed in out, whose denial chain is already in place.
function sign_rrsets(out: DNSSecZone, apex: string, keys: readonly Key[], window: Window): ResourceRecord[] {
    const view = ZoneView.of(out, apex);
    // ZoneView skips generated types, so the chain's are added here.
    const { chain, chain_owners } = chain_types_of(out, view);
    const { ksks, zsks } = split_keys(keys);
    const sigs: ResourceRecord[] = [];
    const sign = (owner: string, t: number): void => {
        for (const k of t === TYPE_DNSKEY ? ksks : zsks) {
            sigs.push(sign_rrset(out, owner, t, apex, k, window));
        }
    };
    for (const owner of view.owners) {
        if (view.is_occluded(owner)) continue;
        const cut = view.is_cut(owner);
        for (const t of [...view.types_at(owner), ...(chain.get(owner.toLowerCase()) ?? [])]) {
            if (cut && t !== TYPE_DS && t !== TYPE_NSEC) continue;
            sign(owner, t);
        }
    }
    for (const owner of chain_owners) {
        for (const t of chain.get(owner.toLowerCase()) ?? []) sign(owner, t);
    }
    return sigs;
}

// chain_types_of returns the NSEC / NSEC3 / NSEC3PARAM types in z by
// lower-cased owner, and in record order the owners that hold nothing
// else (the hashed NSEC3 owners).
function chain_types_of(z: Zone, view: ZoneView): { chain: Map<string, number[]>; chain_owners: string[] } {
    const chain = new Map<string, number[]>();
    const chain_owners: string[] = [];
    for (const rr of z.all_records()) {
        if (rr.type !== TYPE_NSEC && rr.type !== TYPE_NSEC3 && rr.type !== TYPE_NSEC3PARAM) continue;
        const key = rr.label.toLowerCase();
        const at = chain.get(key);
        if (at === undefined) {
            chain.set(key, [rr.type]);
            if (view.types_at(key).length === 0) chain_owners.push(rr.label);
        } else if (!at.includes(rr.type)) {
            at.push(rr.type);
        }
    }
    return { chain, chain_owners };
}

// split_keys returns the DNSKEY signers and the other signers: KSKs and
// ZSKs when both kinds are present, otherwise all keys for both.
function split_keys(keys: readonly Key[]): { ksks: readonly Key[]; zsks: readonly Key[] } {
    const ksks = keys.filter((k) => k.is_ksk());
    const zsks = keys.filter((k) => !k.is_ksk());
    if (ksks.length === 0 || zsks.length === 0) return { ksks: keys, zsks: keys };
    return { ksks, zsks };
}

// sign_rrset signs the (owner, rrtype) RRset of out with k. The RRSIG
// Labels field comes from rrsig_labels, not from counting dots.
function sign_rrset(out: DNSSecZone, owner: string, rrtype: number, apex: string,
                    k: Key, window: Window): ResourceRecord {
    const ttl = out.find_rr(owner, rrtype)?.ttl ?? 0;
    let sig: ResourceRecord | null;
    try {
        // sign_rr returns null when the RRset is empty.
        sig = out.sign_rr(owner, ttl, rrtype, k.signing_key(apex),
            window.inception, window.expiration, rrsig_labels(owner));
    } catch (e) {
        throw new SignerError(`sign ${owner}/${RRTypeName(rrtype)}: ${error_message(e)}`);
    }
    if (sig === null) {
        throw new SignerError(`no ${RRTypeName(rrtype)} RRset at ${owner}`);
    }
    return sig;
}
