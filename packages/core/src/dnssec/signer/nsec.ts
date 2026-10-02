// NSEC chain construction of the zone signer. Ports dnsdata-go
// `dnssec/signer/nsec.go`.

import { StringToRRType, RRTypeName } from '../../types/dns_type_table';
import { ResourceRecord, Zone } from '../../zone/dns_zone';
import { register_legacy_handlers } from '../../zone/handlers';
import { register_dnssec_handlers } from '../handlers';
import { SignerError, error_message } from './errors';
import { is_at_or_below, same_name } from './names';

export const TYPE_NS = StringToRRType('NS');
export const TYPE_SOA = StringToRRType('SOA');
export const TYPE_DS = StringToRRType('DS');
export const TYPE_RRSIG = StringToRRType('RRSIG');
export const TYPE_NSEC = StringToRRType('NSEC');
export const TYPE_DNSKEY = StringToRRType('DNSKEY');
export const TYPE_NSEC3 = StringToRRType('NSEC3');
export const TYPE_NSEC3PARAM = StringToRRType('NSEC3PARAM');

// Types produced by signing, dropped from the input before (re-)signing.
const GENERATED_TYPES: ReadonlySet<number> = new Set([TYPE_RRSIG, TYPE_NSEC, TYPE_NSEC3, TYPE_NSEC3PARAM]);

// TTL of DNSKEY and NSEC records when the zone has no SOA to derive
// one from.
export const DEFAULT_TTL = 3600;

// Index of MINIMUM among the SOA RDATA fields.
const SOA_MINIMUM_FIELD = 6;

// is_generated_type reports whether t is produced by signing.
export function is_generated_type(t: number): boolean {
    return GENERATED_TYPES.has(t);
}

// register_handlers installs the bundled RR handlers (the same set as
// registerAllHandlers) so that every record type the signer meets can be
// encoded. Registration is idempotent.
export function register_handlers(): void {
    register_dnssec_handlers();
    register_legacy_handlers();
}

// ZoneView is the part of a zone that signing looks at: the owners in
// canonical order, the types present at each, and the delegation
// points. Generated types are ignored.
export class ZoneView {
    private constructor(
        readonly owners: readonly string[],                     // canonical order, each once
        private readonly types: ReadonlyMap<string, readonly number[]>, // lower-cased owner → types
        private readonly cuts: readonly string[],               // delegation points (NS below the apex)
    ) {}

    // of reads z and throws SignerError for records outside apex or that
    // do not encode.
    static of(z: Zone, apex: string): ZoneView {
        const owners: string[] = [];
        const types = new Map<string, number[]>();
        const cuts: string[] = [];
        for (const rr of canonical_records(z)) {
            if (is_generated_type(rr.type)) continue;
            if (!is_at_or_below(rr.label, apex)) {
                throw new SignerError(`${rr.label} is outside the zone ${apex}`);
            }
            const key = rr.label.toLowerCase();
            const at = types.get(key);
            if (at === undefined) {
                owners.push(rr.label);
                types.set(key, [rr.type]);
            } else if (!at.includes(rr.type)) {
                at.push(rr.type);
            }
            if (rr.type === TYPE_NS && !same_name(rr.label, apex) && !cuts.includes(rr.label)) {
                cuts.push(rr.label);
            }
        }
        return new ZoneView(owners, types, cuts);
    }

    // types_at returns the types present at owner.
    types_at(owner: string): readonly number[] {
        return this.types.get(owner.toLowerCase()) ?? [];
    }

    // is_cut reports whether name is a delegation point.
    is_cut(name: string): boolean {
        return this.cuts.some((c) => same_name(c, name));
    }

    // is_occluded reports whether name lies strictly below a delegation
    // point (glue or occluded data): not authoritative, not signed, no NSEC.
    is_occluded(name: string): boolean {
        return this.cuts.some((c) => !same_name(c, name) && is_at_or_below(name, c));
    }

    // bitmap_text lists the types for owner's NSEC in presentation form.
    bitmap_text(owner: string): string {
        return type_names([...this.chain_types(owner), TYPE_RRSIG, TYPE_NSEC]);
    }

    // chain_types returns the types at owner that a denial bitmap lists:
    // at a delegation point only NS and DS.
    chain_types(owner: string): number[] {
        const cut = this.is_cut(owner);
        return this.types_at(owner).filter((t) => !cut || t === TYPE_NS || t === TYPE_DS);
    }

    // is_signed reports whether owner has a signed RRset: any
    // authoritative name does, a delegation point only with DS.
    is_signed(owner: string): boolean {
        return !this.is_cut(owner) || this.types_at(owner).includes(TYPE_DS);
    }
}

// type_names returns ts sorted, once each, as space-separated mnemonics.
export function type_names(ts: readonly number[]): string {
    return [...new Set(ts)].sort((a, b) => a - b).map((t) => RRTypeName(t)).join(' ');
}

function canonical_records(z: Zone): ResourceRecord[] {
    try {
        return z.records_canonical();
    } catch (e) {
        throw new SignerError(error_message(e));
    }
}

// build_nsec returns the NSEC chain for the zone at apex (RFC 4034 §4,
// RFC 4035 §2.3): one NSEC per authoritative owner name in canonical
// order, the last pointing back to the apex. Each bitmap lists the
// types at the owner plus RRSIG and NSEC; at a delegation point only NS
// and DS count; names below a delegation (glue) and empty non-terminals
// get none. Existing RRSIG / NSEC / NSEC3 records in z are ignored.
//
// ttl 0 (the default) uses min(SOA TTL, SOA MINIMUM) (RFC 9077), or
// 3600 without an SOA at the apex. Like sign_zone, it registers the
// bundled handlers.
export function build_nsec(z: Zone, apex: string, ttl = 0): ResourceRecord[] {
    register_handlers();
    const view = ZoneView.of(z, apex);
    const nsec_ttl = chain_ttl(z, apex, ttl);
    const owners = view.owners.filter((o) => !view.is_occluded(o));
    return owners.map((owner, i) => {
        const next = i + 1 < owners.length ? owners[i + 1] : apex;
        return new ResourceRecord(owner, nsec_ttl, 'IN', TYPE_NSEC, `${next} ${view.bitmap_text(owner)}`);
    });
}

// chain_ttl is ttl, or for 0 the RFC 9077 TTL of nsec_ttl_of.
export function chain_ttl(z: Zone, apex: string, ttl: number): number {
    return ttl === 0 ? nsec_ttl_of(z, apex) : ttl;
}

// soa_at returns the apex SOA record, or null.
export function soa_at(z: Zone, apex: string): ResourceRecord | null {
    return z.all_records().find((rr) => rr.type === TYPE_SOA && same_name(rr.label, apex)) ?? null;
}

// nsec_ttl_of is min(SOA TTL, SOA MINIMUM) per RFC 9077, or DEFAULT_TTL.
function nsec_ttl_of(z: Zone, apex: string): number {
    const soa = soa_at(z, apex);
    if (soa === null) return DEFAULT_TTL;
    const fields = soa.value.trim().split(/\s+/);
    const minimum = fields.length > SOA_MINIMUM_FIELD ? fields[SOA_MINIMUM_FIELD] : '';
    if (!/^\d+$/.test(minimum)) return soa.ttl;
    return Math.min(soa.ttl, parseInt(minimum, 10));
}
