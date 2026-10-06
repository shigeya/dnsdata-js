// DNSSEC Zone methods
//
// Ported from wide-cpp-lib/wide/dns/dnssec_zone.hpp / dnssec_zone.cpp

import { WireBuilder, compare_uint8arrays } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { StringToRRType, RRTypeName } from '../types/dns_type_table';
import { Zone, ResourceRecord, ResourceRecordHandler } from '../zone/dns_zone';
import { Registry, default_registry } from '../zone/registry';
import { GENERIC_RDATA_MARKER } from '../zone/generic';
import { DNSZoneRDataFormatError } from '../dns_exception';
import { DNSKey, RRSig, DNSRR_DS } from './dnssec_rr';
import { label_count, last_n_labels } from './dnssec_util';
// As of P8, RR handler registration is opt-in via registerAllHandlers()
// (or the per-pkg register_dnssec_handlers / register_legacy_handlers
// functions). Importing this file no longer triggers any registration.

export enum KeyVerifyMode {
    None = 0,
    ZSK  = 0x01,
    KSK  = 0x02,
    CSK  = 0x04,
}

// Octets of RDLENGTH that prefix each RR body built by get_wire_body.
const RDLENGTH_OCTETS = 2;
const MILLISECONDS_PER_SECOND = 1000;

// The types register_dnssec_handlers installs.
const DNSSEC_HANDLER_TYPES: ReadonlySet<number> = new Set(
    ['DNSKEY', 'CDNSKEY', 'RRSIG', 'DS', 'CDS', 'NSEC', 'NSEC3', 'NSEC3PARAM'].map((t) => StringToRRType(t)));

// registration_for names the call that registers an encoder for type,
// in the default registry or (own_registry) in the zone's own one.
function registration_for(type: number, own_registry: boolean): string {
    if (own_registry) {
        return DNSSEC_HANDLER_TYPES.has(type)
            ? 'register_dnssec_handlers_into(registry)'
            : 'register_legacy_handlers_into(registry) on the zone\'s registry';
    }
    return DNSSEC_HANDLER_TYPES.has(type)
        ? 'register_dnssec_handlers()'
        : 'registerAllHandlers() or register_legacy_handlers()';
}

// key_identity names one exact DNSKEY: its owner (case-insensitive) and
// its whole RDATA (flags, protocol, algorithm, public key). Two keys
// that share a key tag but differ in any RDATA octet differ here.
function key_identity(key: DNSKey): string {
    return [
        key.label.toLowerCase(),
        key.flags,
        key.protocol,
        key.algorithm,
        Buffer.from(key.key_data).toString('hex'),
    ].join(' ');
}

// Record handlers (DNSKEY, RRSIG, DS, ...) are resolved through the
// zone's Registry ([DNSSecZone.set_registry]; the default registry when
// none is set), both for lookups and for the RDATA encoding of digest
// targets.
export class DNSSecZone extends Zone {
    private seps: string[] = [];
    private trusted_keys: Set<string> = new Set();
    private _parent: DNSSecZone | null = null;
    private _now: (() => Date) | null = null;
    private _registry: Registry | null = null;

    get parent(): DNSSecZone | null { return this._parent; }
    set parent(zone: DNSSecZone | null) { this._parent = zone; }

    // set_registry makes the zone resolve record handlers through
    // registry; null means default_registry(). Fill it with
    // register_dnssec_handlers_into (and register_legacy_handlers_into
    // for the zone types). Ports dnsdata-go `Zone.SetRegistry`.
    set_registry(registry: Registry | null): void {
        this._registry = registry;
    }

    // get_registry returns the registry the zone resolves handlers
    // through.
    get_registry(): Registry {
        return this._registry ?? default_registry();
    }

    // handler returns rr's handler from the zone's registry.
    handler(rr: ResourceRecord): ResourceRecordHandler | null {
        return rr.get_handler(this.get_registry());
    }

    // set_clock makes [verify_rrsig] reject an RRSIG whose validity
    // window (RFC 4034 §3.1.5, RFC 4035 §5.3.1) does not contain now().
    // Both ends are inclusive. With no clock set (the default, or null)
    // the window is not checked. Ports dnsdata-go `Zone.SetClock`.
    set_clock(now: (() => Date) | null): void {
        this._now = now;
    }

    // within_validity reports whether rrsig's window contains the
    // zone's clock, or true when no clock is set.
    private within_validity(rrsig: RRSig): boolean {
        if (this._now === null) return true;
        const t = Math.floor(this._now().getTime() / MILLISECONDS_PER_SECOND);
        return rrsig.inception <= t && t <= rrsig.expire;
    }

    // add_sep marks name as a secure entry point. The mark is
    // informational only: it does not authenticate any key. Use
    // [add_trusted_key] for the specific keys that are trusted.
    add_sep(name: string): void {
        this.seps.push(name);
    }

    is_secure_entry_point(name: string): boolean {
        return this.seps.indexOf(name) !== -1;
    }

    // add_trusted_key records key as authenticated from outside the
    // zone: it matched a configured trust anchor, or a DS record of the
    // already-validated parent DS rrset. [verify_ksk] accepts exactly
    // these keys (owner + full RDATA), never another key that only
    // shares the owner name or the key tag.
    add_trusted_key(key: DNSKey): void {
        this.trusted_keys.add(key_identity(key));
    }

    is_trusted_key(key: DNSKey): boolean {
        return this.trusted_keys.has(key_identity(key));
    }

    find_rrsigs(name: string, type_covered: number, signer?: string): RRSig[] {
        const rrsig_type = StringToRRType('RRSIG');
        const candidates = this.find_rrset(name, rrsig_type);
        const type_str = RRTypeName(type_covered);
        const result: RRSig[] = [];

        for (const rr of candidates) {
            // Quick check: value should start with the type name, unless
            // it is RFC 3597 generic RDATA (decoded by get_handler).
            if (!rr.value.startsWith(type_str + ' ') && !rr.value.startsWith(GENERIC_RDATA_MARKER + ' ')) continue;

            const handler = this.handler(rr);
            if (handler instanceof RRSig && handler.type_covered === type_covered) {
                if (!signer || handler.signer === signer) {
                    result.push(handler);
                }
            }
        }
        return result;
    }

    // find_dnskeys returns every DNSKEY at signer_name matching keytag
    // and algorithm (each filter applies only when given). Key tags
    // are not unique (RFC 4034 Appendix B), so a verifier must try
    // every candidate.
    find_dnskeys(signer_name: string, keytag?: number, algorithm?: number): DNSKey[] {
        const dnskey_type = StringToRRType('DNSKEY');
        const result: DNSKey[] = [];
        for (const rr of this.find_rrset(signer_name, dnskey_type)) {
            const handler = this.handler(rr);
            if (!(handler instanceof DNSKey)) continue;
            if (keytag !== undefined && handler.key_tag !== keytag) continue;
            if (algorithm !== undefined && handler.algorithm !== algorithm) continue;
            result.push(handler);
        }
        return result;
    }

    // find_dnskey returns the first DNSKEY found by [find_dnskeys], or
    // null. Do not use it to pick the key that verifies an RRSIG.
    find_dnskey(signer_name: string, keytag?: number): DNSKey | null {
        return this.find_dnskeys(signer_name, keytag)[0] ?? null;
    }

    // Build the data-to-sign per RFC4034 Section 6.2
    create_digest_target(rrsig: RRSig, name: string, type: number): Uint8Array | null {
        const rrset = this.find_rrset(name, type);
        if (rrset.length === 0) return null;

        // RFC 4035 §5.3.2: when the covering RRSIG's Labels count is
        // fewer than the rrset's owner-name label count, the answer was
        // produced by wildcard expansion. The validator reconstructs
        // the original wildcard owner ("*." + the right-most
        // rrsig.labels labels of name) and computes the digest header
        // with that owner instead of the synthesised qname — otherwise
        // the digest target won't match the one the authoritative
        // signer produced. Signers that set Labels correctly produce
        // matching digests; same function, same semantics on both sides.
        const expected_labels = label_count(name);
        const wildcard_synthesis = rrsig.labels < expected_labels;
        let header: Uint8Array;
        if (wildcard_synthesis) {
            const wildcard_owner = '*.' + last_n_labels(name, rrsig.labels);
            header = wire_header_for_owner(wildcard_owner, rrset[0].type, rrset[0].rrclass);
        } else {
            const header_builder = new WireBuilder();
            rrset[0].get_wire_header(header_builder);
            header = header_builder.build();
        }

        // Build wire body (RDLENGTH || RDATA) for each RR.
        const bodies: Uint8Array[] = [];
        for (const rr of rrset) {
            const body_builder = new WireBuilder();
            rr.get_wire_body(body_builder, this.get_registry());
            const body = body_builder.build();
            if (body.length < RDLENGTH_OCTETS) {
                const own = this.get_registry() !== default_registry();
                throw new DNSZoneRDataFormatError(
                    `no encoder for ${rr.label} ${RRTypeName(rr.type)} (call ${registration_for(rr.type, own)}, ` +
                    'or keep the received RDATA with new_resource_record_with_rdata)');
            }
            bodies.push(body);
        }

        // Assemble: RRSIG RDATA (no sig) + for each sorted body: header + originalTTL + body
        const out = new WireBuilder();
        out.append_bytes(rrsig.get_rdata_digest_target());
        for (const body of canonical_rrset_order(bodies)) {
            out.append_bytes(header);
            out.append_uint32(rrsig.original_ttl);
            out.append_bytes(body);
        }
        return out.build();
    }

    // Verify a single RRSIG. A signature outside its validity window
    // fails when a clock is set (see [set_clock]).
    //
    // The RRSIG verifies when some DNSKEY at its signer with its key
    // tag and algorithm both verifies the signature octets and is
    // authorised for mode (see [key_authorised]). Every such DNSKEY is
    // tried, since key tags collide. The SEP flag plays no part
    // (RFC 4034 §2.1.1).
    verify_rrsig(name: string, type: number, rrsig: RRSig,
                 mode: KeyVerifyMode = KeyVerifyMode.None): boolean {
        if (!this.within_validity(rrsig)) return false;

        const candidates = this.find_dnskeys(rrsig.signer, rrsig.key_tag, rrsig.algorithm);
        if (candidates.length === 0) return false;

        const digest_target = this.create_digest_target(rrsig, name, type);
        if (!digest_target) return false;

        return candidates.some((dnskey) =>
            dnskey.verify(digest_target, rrsig.signature) && this.key_authorised(dnskey, mode));
    }

    // key_authorised reports whether dnskey may sign under mode:
    //   None — any key (the caller has authenticated the DNSKEY rrset).
    //   KSK  — dnskey itself is authenticated ([verify_ksk]).
    //   ZSK  — dnskey belongs to a DNSKEY rrset that verifies in KSK
    //          mode ([verify_zsk]).
    //   CSK  — either of the above.
    //   any other value — no key (fails closed).
    private key_authorised(dnskey: DNSKey, mode: KeyVerifyMode): boolean {
        switch (mode) {
        case KeyVerifyMode.None:
            return true;
        case KeyVerifyMode.KSK:
            return this.verify_ksk(dnskey);
        case KeyVerifyMode.ZSK:
            return this.verify_zsk(dnskey);
        case KeyVerifyMode.CSK:
            return this.verify_ksk(dnskey) || this.verify_zsk(dnskey);
        default:
            return false;
        }
    }

    // Verify RRSIGs for an RRset (RFC 4035: any-valid semantics)
    verify_rrset(name: string, type: number,
                 mode: KeyVerifyMode = KeyVerifyMode.None,
                 signer?: string): boolean {
        const rrsigs = this.find_rrsigs(name, type, signer);
        if (rrsigs.length === 0) return false;

        // RFC 4035 Section 5.3.3: An RRset is considered valid if at least
        // one RRSIG can be validated. A resolver should not treat a failed
        // RRSIG as evidence that the RRset is bogus if other RRSIGs exist.
        for (const rrsig of rrsigs) {
            if (this.verify_rrsig(name, type, rrsig, mode)) {
                return true;
            }
        }
        return false;
    }

    // verify_ksk reports whether dnskey is authenticated from outside
    // the zone (a trusted key, or a DS match in the parent).
    verify_ksk(dnskey: DNSKey): boolean {
        return this.verify_delegation_signer(dnskey);
    }

    // verify_zsk reports whether the DNSKEY rrset holding dnskey
    // verifies under an authenticated key ([verify_ksk]).
    verify_zsk(dnskey: DNSKey): boolean {
        return this.verify_rrset(dnskey.label, StringToRRType('DNSKEY'), KeyVerifyMode.KSK);
    }

    // Verify DS RRset RRSIG using parent zone's keys
    verify_ds_rrset(child_name: string): boolean {
        if (!this._parent) return false;
        return this._parent.verify_rrset(child_name, StringToRRType('DS'));
    }

    // verify_delegation_signer reports whether dnskey is authenticated:
    // it was added with [add_trusted_key], or its DS digest matches a DS
    // record at its owner in the parent zone. The caller must have
    // validated that parent DS rrset. The zone's own DS records (which
    // nothing has validated) and its SEP marks are not consulted.
    verify_delegation_signer(dnskey: DNSKey): boolean {
        if (this.is_trusted_key(dnskey)) return true;

        // RFC 4035: DS records reside in the parent zone
        if (!this._parent) return false;
        const ds_type = StringToRRType('DS');
        const ds_records = this._parent.find_rrset(dnskey.label, ds_type);
        if (ds_records.length === 0) return false;

        // RFC 4035: any-valid semantics — at least one supported DS must match
        for (const ds_rr of ds_records) {
            const handler = this.handler(ds_rr);
            // Support DS digest types: 1 (SHA-1), 2 (SHA-256), 4 (SHA-384)
            if (handler instanceof DNSRR_DS && (handler.digest_type === 1 || handler.digest_type === 2 || handler.digest_type === 4)) {
                if (this.verify_delegation_signer_with_ds(dnskey, handler)) {
                    return true;
                }
            }
        }
        return false;
    }

    verify_delegation_signer_with_ds(dnskey: DNSKey, ds: DNSRR_DS): boolean {
        if (dnskey.algorithm !== ds.algorithm) return false;
        const key_digest = dnskey.get_ds_digest_data();
        return ds.verify_digest(key_digest);
    }

    // Sign an RRset and return a new RRSIG ResourceRecord.
    //
    // labelsOverride, when supplied, replaces the RRSIG's Labels count
    // before digest computation. Used to emulate authoritative-server
    // wildcard expansion (RFC 4035 §5.3.2): the rrset itself lives at a
    // synthesised qname, but the signer wrote Labels = closest-encloser
    // label count so validators can detect the synthesis. Without the
    // override, [RRSig] derives Labels from the owner name and the
    // digest target lands at the synthesised qname instead of the
    // wildcard owner.
    sign_rr(label: string, ttl: number, type: number,
            key: DNSKey, inception: number, expire: number,
            labelsOverride?: number): ResourceRecord | null {
        const rrsig = new RRSig(null, label, ttl, type, inception, expire, key);
        if (labelsOverride !== undefined) {
            rrsig.labels = labelsOverride;
        }

        const digest_target = this.create_digest_target(rrsig, label, type);
        if (!digest_target) return null;

        const signature = key.sign(digest_target);

        // Reconstruct the RRSIG with signature in its value string
        const sig_b64 = Buffer.from(signature).toString('base64');
        const rrsig_value = `${RRTypeName(type)} ${key.algorithm} ${rrsig.labels} ` +
            `${ttl} ${expire} ${inception} ${key.key_tag} ${key.label} ${sig_b64}`;

        return new ResourceRecord(label, ttl, 'IN', 'RRSIG', rrsig_value);
    }
}

// canonical_rrset_order returns the RR bodies (each RDLENGTH || RDATA)
// in RFC 4034 §6.3 canonical order: sorted by the RDATA alone, so the
// RDLENGTH prefix does not take part ("absence of an octet sorts
// before a zero octet"), with duplicate RRs removed. Duplicates arise
// when two responses deposit the same record, e.g. one NSEC answering
// both a DS probe and the leaf query. dnsdata-go UF-005.
function canonical_rrset_order(bodies: readonly Uint8Array[]): Uint8Array[] {
    const sorted = [...bodies].sort((a, b) =>
        compare_uint8arrays(a.subarray(RDLENGTH_OCTETS), b.subarray(RDLENGTH_OCTETS)));
    return sorted.filter((body, i) => i === 0 || compare_uint8arrays(body, sorted[i - 1]) !== 0);
}

// wire_header_for_owner emits the canonical RR-header bytes
// (owner_name(wire) + type(uint16) + class(uint16)) for an explicit
// owner. Used by [DNSSecZone.create_digest_target] when wildcard
// reconstruction overrides the rrset's literal owner.
function wire_header_for_owner(owner: string, rrtype: number, rrclass: number): Uint8Array {
    const builder = new WireBuilder();
    builder.append_bytes(domain_name2wire(owner));
    builder.append_uint16(rrtype);
    builder.append_uint16(rrclass);
    return builder.build();
}
