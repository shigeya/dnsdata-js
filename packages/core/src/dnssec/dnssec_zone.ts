// DNSSEC Zone methods
//
// Ported from wide-cpp-lib/wide/dns/dnssec_zone.hpp / dnssec_zone.cpp

import { WireBuilder, compare_uint8arrays } from '../wire/dns_wire_util';
import { domain_name2wire } from '../wire/dns_wire';
import { StringToRRType, RRTypeToString } from '../types/dns_type_table';
import { Zone, ResourceRecord } from '../zone/dns_zone';
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

export class DNSSecZone extends Zone {
    private seps: string[] = [];
    private _parent: DNSSecZone | null = null;

    get parent(): DNSSecZone | null { return this._parent; }
    set parent(zone: DNSSecZone | null) { this._parent = zone; }

    add_sep(name: string): void {
        this.seps.push(name);
    }

    is_secure_entry_point(name: string): boolean {
        return this.seps.indexOf(name) !== -1;
    }

    find_rrsigs(name: string, type_covered: number, signer?: string): RRSig[] {
        const rrsig_type = StringToRRType('RRSIG');
        const candidates = this.find_rrset(name, rrsig_type);
        const type_str = RRTypeToString(type_covered);
        const result: RRSig[] = [];

        for (const rr of candidates) {
            // Quick check: value should start with the type name
            if (!rr.value.startsWith(type_str + ' ')) continue;

            const handler = rr.get_handler();
            if (handler instanceof RRSig && handler.type_covered === type_covered) {
                if (!signer || handler.signer === signer) {
                    result.push(handler);
                }
            }
        }
        return result;
    }

    find_dnskey(signer_name: string, keytag?: number): DNSKey | null {
        const dnskey_type = StringToRRType('DNSKEY');
        const candidates = this.find_rrset(signer_name, dnskey_type);

        for (const rr of candidates) {
            const handler = rr.get_handler();
            if (handler instanceof DNSKey) {
                if (keytag === undefined || handler.key_tag === keytag) {
                    return handler;
                }
            }
        }
        return null;
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

        // Build wire body for each RR, then sort by binary order
        const bodies: Uint8Array[] = [];
        for (const rr of rrset) {
            const body_builder = new WireBuilder();
            rr.get_wire_body(body_builder);
            bodies.push(body_builder.build());
        }
        bodies.sort(compare_uint8arrays);

        // Assemble: RRSIG RDATA (no sig) + for each sorted body: header + originalTTL + body
        const out = new WireBuilder();
        out.append_bytes(rrsig.get_rdata_digest_target());
        for (const body of bodies) {
            out.append_bytes(header);
            out.append_uint32(rrsig.original_ttl);
            out.append_bytes(body);
        }
        return out.build();
    }

    // Verify a single RRSIG
    verify_rrsig(name: string, type: number, rrsig: RRSig,
                 mode: KeyVerifyMode = KeyVerifyMode.None): boolean {
        // Find the corresponding DNSKEY
        const dnskey = this.find_dnskey(rrsig.signer, rrsig.key_tag);
        if (!dnskey) return false;

        switch (mode) {
        case KeyVerifyMode.ZSK:
            if (!dnskey.is_secure_entry_point()) {
                if (!this.verify_zsk(dnskey)) return false;
            }
            break;

        case KeyVerifyMode.KSK:
            if (dnskey.is_secure_entry_point()) {
                if (!this.verify_ksk(dnskey)) return false;
                if (type === StringToRRType('DNSKEY')) {
                    // Signature on DNSKEY using ZSK is ignored for KSK mode
                    return true;
                }
            }
            break;

        case KeyVerifyMode.CSK:
            // CSK (Combined Signing Key) acts as both KSK and ZSK
            if (dnskey.is_secure_entry_point()) {
                if (!this.verify_ksk(dnskey)) return false;
            }
            break;
        }

        const digest_target = this.create_digest_target(rrsig, name, type);
        if (!digest_target) return false;

        return dnskey.verify(digest_target, rrsig.signature);
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

    verify_ksk(dnskey: DNSKey): boolean {
        return this.verify_delegation_signer(dnskey);
    }

    verify_zsk(dnskey: DNSKey): boolean {
        return this.verify_rrset(dnskey.label, StringToRRType('DNSKEY'), KeyVerifyMode.KSK);
    }

    // Verify DS RRset RRSIG using parent zone's keys
    verify_ds_rrset(child_name: string): boolean {
        if (!this._parent) return false;
        return this._parent.verify_rrset(child_name, StringToRRType('DS'));
    }

    verify_delegation_signer(dnskey: DNSKey): boolean {
        if (this.is_secure_entry_point(dnskey.label)) {
            return true; // trust anchor reached
        }

        // RFC 4035: DS records reside in the parent zone
        const ds_source = this._parent || this;
        const ds_type = StringToRRType('DS');
        const ds_records = ds_source.find_rrset(dnskey.label, ds_type);
        if (ds_records.length === 0) return false;

        // RFC 4035: any-valid semantics — at least one supported DS must match
        for (const ds_rr of ds_records) {
            const handler = ds_rr.get_handler();
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
        const rrsig_value = `${RRTypeToString(type)} ${key.algorithm} ${rrsig.labels} ` +
            `${ttl} ${expire} ${inception} ${key.key_tag} ${key.label} ${sig_b64}`;

        return new ResourceRecord(label, ttl, 'IN', 'RRSIG', rrsig_value);
    }
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
